//! 站内信路由 — port of server/src/routes/inbox.ts (mounted at /api/inbox).
//!
//! The TS module installs `fastify.addHook('onRequest', fastify.authenticate)`
//! for every route and then re-checks the admin role INSIDE the /admin/*
//! handlers, so everything maps to `AuthUser` with manual role checks (NOT
//! `AdminAuth`).
//!
//! Endpoint map:
//! - GET    /                          authenticate -> AuthUser
//! - GET    /unread-count              authenticate -> AuthUser
//! - POST   /{id}/read                 authenticate -> AuthUser
//! - POST   /read-all                  authenticate -> AuthUser
//! - DELETE /{id}                      authenticate -> AuthUser
//! - DELETE /read                      authenticate -> AuthUser
//! - POST   /admin/broadcast           authenticate -> AuthUser + manual admin check
//! - POST   /hosts/{hostId}/notify     authenticate -> AuthUser + manual owner/admin check
//! - POST   /admin/send/{userId}       authenticate -> AuthUser + manual admin check
//! - POST   /instances/{instanceId}/notify  authenticate -> AuthUser + manual owner/admin check
//!
//! Reported deviations:
//! - sendHostAnnouncementEmail (nodemailer direct-send) is not ported: the
//!   single-recipient "direct" email mode reports failedCount=1 with a
//!   tracing::warn instead of sending. The multi-recipient "queued" mode IS
//!   fully ported (host_notification_email_tasks + advisory lock 4102/1).
//! - isSmtpEnabled is a real port (system_configs + AES decrypt), so the
//!   400 SMTP_NOT_CONFIGURED gate behaves identically.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::AuthUser;
use crate::db::{advisory_lock_namespace, try_advisory_transaction_lock};
use crate::error::{code, ApiError};
use crate::libs::crypto;
use crate::response::parse_pagination;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list_messages))
        .route("/unread-count", get(unread_count))
        .route("/read-all", post(read_all))
        .route("/read", axum::routing::delete(delete_read))
        .route("/{id}/read", post(mark_read))
        .route("/{id}", axum::routing::delete(delete_message))
        .route("/admin/broadcast", post(admin_broadcast))
        .route("/hosts/{host_id}/notify", post(host_notify))
        .route("/admin/send/{user_id}", post(admin_send))
        .route("/instances/{instance_id}/notify", post(instance_notify))
}

// ===========================================================================
// helpers
// ===========================================================================

/// TS `Date` fields serialize as ISO strings through Fastify's JSON encoder.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// JS `Number(id)` param semantics: NaN -> 400 INVALID_ID; non-integral /
/// out-of-range values would fail Prisma's Int validation -> 500.
fn js_number_id(raw: &str) -> Result<i32, ApiError> {
    let t = raw.trim();
    let v: f64 = if t.is_empty() {
        0.0
    } else {
        t.parse::<f64>()
            .map_err(|_| ApiError::bad_request(code::INVALID_ID))?
    };
    if v.is_nan() {
        return Err(ApiError::bad_request(code::INVALID_ID));
    }
    if !v.is_finite() || v.fract() != 0.0 || !(i32::MIN as f64..=i32::MAX as f64).contains(&v) {
        return Err(ApiError::internal(format!(
            "Prisma Int argument out of range: {v}"
        )));
    }
    Ok(v as i32)
}

/// JS string length (UTF-16 code units).
fn js_len(s: &str) -> usize {
    s.chars().map(|c| c.len_utf16()).sum()
}

/// TS shape for the manual title/content validation failures:
/// `400 { error: 'TITLE_REQUIRED', message: 'Title is required' }` etc.
fn manual_error(error: &str, message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": error, "message": message })),
    )
        .into_response()
}

/// Validate title/content exactly like the TS handlers do (also used where a
/// Fastify schema exists — those checks are duplicated there in TS too).
/// Returns the trimmed values on success.
fn validate_title_content(body: &Value) -> Result<(String, String), Response> {
    let title = body.get("title");
    let content = body.get("content");

    let title_str = match title {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(_)) | Some(Value::Bool(_)) | Some(Value::Object(_))
        | Some(Value::Array(_)) => {
            // typeof title !== 'string' -> TITLE_REQUIRED branch.
            return Err(manual_error("TITLE_REQUIRED", "Title is required"));
        }
        Some(Value::Null) | None => {
            return Err(manual_error("TITLE_REQUIRED", "Title is required"));
        }
    };
    if title_str.trim().is_empty() {
        return Err(manual_error("TITLE_REQUIRED", "Title is required"));
    }
    if js_len(&title_str) > 200 {
        return Err(manual_error("TITLE_TOO_LONG", "Title is too long"));
    }

    let content_str = match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(_)) | Some(Value::Bool(_)) | Some(Value::Object(_))
        | Some(Value::Array(_)) => {
            return Err(manual_error("CONTENT_REQUIRED", "Content is required"));
        }
        Some(Value::Null) | None => {
            return Err(manual_error("CONTENT_REQUIRED", "Content is required"));
        }
    };
    if content_str.trim().is_empty() {
        return Err(manual_error("CONTENT_REQUIRED", "Content is required"));
    }
    if js_len(&content_str) > 5000 {
        return Err(manual_error("CONTENT_TOO_LONG", "Content is too long"));
    }

    Ok((title_str.trim().to_string(), content_str.trim().to_string()))
}

// ===========================================================================
// db helpers (port of db/inbox.ts + db/announcements.ts + db/hosts.ts)
// ===========================================================================

#[derive(Debug, FromRow)]
struct InboxMessageRow {
    id: i32,
    user_id: i32,
    event_type: String,
    title: String,
    content: String,
    is_read: bool,
    data: Option<Value>,
    created_at: DateTime<Utc>,
}

async fn get_inbox_messages(
    state: &SharedAppState,
    user_id: i32,
    page: i64,
    page_size: i64,
    is_read: Option<bool>,
) -> Result<(Vec<InboxMessageRow>, i64), ApiError> {
    let mut sql = String::from(
        "SELECT id, user_id, event_type, title, content, is_read, data, created_at \
         FROM inbox_messages WHERE user_id = $1",
    );
    let mut count_sql =
        String::from("SELECT COUNT(*) FROM inbox_messages WHERE user_id = $1");
    if is_read.is_some() {
        sql.push_str(" AND is_read = $2");
        count_sql.push_str(" AND is_read = $2");
    }
    sql.push_str(if is_read.is_some() {
        " ORDER BY created_at DESC OFFSET $3 LIMIT $4"
    } else {
        " ORDER BY created_at DESC OFFSET $2 LIMIT $3"
    });

    let mut q = sqlx::query_as::<_, InboxMessageRow>(&sql).bind(user_id);
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(user_id);
    if let Some(r) = is_read {
        q = q.bind(r);
        cq = cq.bind(r);
    }
    q = q.bind((page - 1) * page_size).bind(page_size);

    let messages = q.fetch_all(&state.db).await?;
    let total = cq.fetch_one(&state.db).await?;
    Ok((messages, total))
}

fn inbox_message_json(msg: &InboxMessageRow) -> Value {
    json!({
        "id": msg.id,
        "userId": msg.user_id,
        "eventType": msg.event_type,
        "title": msg.title,
        "content": msg.content,
        "isRead": msg.is_read,
        "data": msg.data,
        "createdAt": iso(msg.created_at),
    })
}

async fn get_unread_count(state: &SharedAppState, user_id: i32) -> Result<i64, ApiError> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM inbox_messages WHERE user_id = $1 AND is_read = FALSE",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(count.0)
}

async fn mark_as_read(state: &SharedAppState, id: i32, user_id: i32) -> Result<bool, ApiError> {
    let result = sqlx::query("UPDATE inbox_messages SET is_read = TRUE WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(result.rows_affected() > 0)
}

async fn mark_all_as_read(state: &SharedAppState, user_id: i32) -> Result<u64, ApiError> {
    let result = sqlx::query("UPDATE inbox_messages SET is_read = TRUE WHERE user_id = $1 AND is_read = FALSE")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(result.rows_affected())
}

async fn delete_message_by_id(
    state: &SharedAppState,
    id: i32,
    user_id: i32,
) -> Result<bool, ApiError> {
    let result = sqlx::query("DELETE FROM inbox_messages WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(result.rows_affected() > 0)
}

async fn delete_read_messages(state: &SharedAppState, user_id: i32) -> Result<u64, ApiError> {
    let result = sqlx::query("DELETE FROM inbox_messages WHERE user_id = $1 AND is_read = TRUE")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(result.rows_affected())
}

async fn create_inbox_message(
    state: &SharedAppState,
    user_id: i32,
    event_type: &str,
    title: &str,
    content: &str,
    data: Value,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO inbox_messages (user_id, event_type, title, content, data) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(event_type)
    .bind(title)
    .bind(content)
    .bind(data)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// db/inbox.ts createBulkMessages: createMany -> rows inserted.
async fn create_bulk_messages(
    state: &SharedAppState,
    user_ids: &[i32],
    event_type: &str,
    title: &str,
    content: &str,
    data: Value,
) -> Result<u64, ApiError> {
    if user_ids.is_empty() {
        return Ok(0);
    }
    let result = sqlx::query(
        "INSERT INTO inbox_messages (user_id, event_type, title, content, data) \
         SELECT u, $2, $3, $4, $5 FROM unnest($1::int[]) AS u",
    )
    .bind(user_ids)
    .bind(event_type)
    .bind(title)
    .bind(content)
    .bind(data)
    .execute(&state.db)
    .await?;
    Ok(result.rows_affected())
}

/// db/inbox.ts getAllActiveUserIds.
async fn get_all_active_user_ids(state: &SharedAppState) -> Result<Vec<i32>, ApiError> {
    let rows: Vec<(i32,)> = sqlx::query_as("SELECT id FROM users WHERE status = 'active'")
        .fetch_all(&state.db)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// db/inbox.ts getUniqueRecipientsByHostId: distinct userId with username and
/// email; empty/None instanceIds means "all instances on the host".
#[derive(Debug, sqlx::FromRow)]
struct HostRecipient {
    user_id: i32,
    username: String,
    email: Option<String>,
}

async fn get_unique_recipients_by_host_id(
    state: &SharedAppState,
    host_id: i32,
    instance_ids: Option<&Vec<i32>>,
) -> Result<Vec<HostRecipient>, ApiError> {
    let filter_by_ids = matches!(instance_ids, Some(ids) if !ids.is_empty());
    let sql = if filter_by_ids {
        "SELECT DISTINCT ON (i.user_id) i.user_id, u.username, u.email \
         FROM instances i JOIN users u ON u.id = i.user_id \
         WHERE i.host_id = $1 AND i.status <> 'deleted' AND i.id = ANY($2) \
         ORDER BY i.user_id ASC"
    } else {
        "SELECT DISTINCT ON (i.user_id) i.user_id, u.username, u.email \
         FROM instances i JOIN users u ON u.id = i.user_id \
         WHERE i.host_id = $1 AND i.status <> 'deleted' \
         ORDER BY i.user_id ASC"
    };

    let mut q = sqlx::query_as::<_, HostRecipient>(sql).bind(host_id);
    if filter_by_ids {
        q = q.bind(instance_ids.unwrap());
    }
    let rows = q.fetch_all(&state.db).await?;
    Ok(rows)
}

/// db/announcements.ts createAnnouncement.
#[allow(clippy::too_many_arguments)]
async fn create_announcement(
    state: &SharedAppState,
    announcement_type: &str,
    sender_id: i32,
    title: &str,
    content: &str,
    recipient_count: i64,
    host_id: Option<i32>,
    target_user_id: Option<i32>,
    instance_id: Option<i32>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO announcements (type, sender_id, title, content, recipient_count, host_id, target_user_id, instance_id) \
         VALUES ($1::\"AnnouncementType\", $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(announcement_type)
    .bind(sender_id)
    .bind(title)
    .bind(content)
    .bind(recipient_count as i32)
    .bind(host_id)
    .bind(target_user_id)
    .bind(instance_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// db/hosts.ts getHostById (only the fields the routes use).
#[derive(Debug, sqlx::FromRow)]
struct HostRow {
    id: i32,
    user_id: i32,
    name: String,
}

async fn get_host_by_id(state: &SharedAppState, id: i32) -> Result<Option<HostRow>, ApiError> {
    let row = sqlx::query_as::<_, HostRow>("SELECT id, user_id, name FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    Ok(row)
}

#[derive(Debug, sqlx::FromRow)]
struct InstanceRow {
    id: i32,
    user_id: i32,
    host_id: i32,
    name: String,
    status: String,
}

/// db/instances.ts getInstanceById (only the fields the route uses).
async fn get_instance_by_id(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<InstanceRow>, ApiError> {
    let row = sqlx::query_as::<_, InstanceRow>(
        "SELECT id, user_id, host_id, name, status::text AS status FROM instances WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

// ===========================================================================
// db helper (port of lib/mailer.ts isSmtpEnabled + getSmtpConfig)
// ===========================================================================

async fn get_system_config_raw(
    state: &SharedAppState,
    key: &str,
) -> Result<Option<String>, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT value FROM system_configs WHERE key = $1")
            .bind(key)
            .fetch_optional(&state.db)
            .await?;
    Ok(row.and_then(|(v,)| v))
}

const SMTP_SENSITIVE_KEYS: &[&str] = &["smtp_password"];

/// db/system-config.ts getSystemConfig with decrypt=true semantics for the
/// sensitive SMTP password (AES `iv:tag:ciphertext`; null on decrypt failure).
async fn get_system_config(
    state: &SharedAppState,
    key: &str,
) -> Result<Option<String>, ApiError> {
    let value = get_system_config_raw(state, key).await?;
    let Some(value) = value else {
        return Ok(None);
    };
    if SMTP_SENSITIVE_KEYS.contains(&key) && value.contains(':') {
        return match crypto::decrypt_sensitive_data(&state.config.encryption_key, &value) {
            Ok(plain) => Ok(Some(plain)),
            Err(_) => Ok(None),
        };
    }
    Ok(Some(value))
}

/// lib/mailer.ts isSmtpEnabled: enabled && host && username && password.
async fn is_smtp_enabled(state: &SharedAppState) -> Result<bool, ApiError> {
    let enabled = match get_system_config(state, "smtp_enabled").await? {
        Some(v) => v == "true" || v == "1",
        None => false,
    };
    if !enabled {
        return Ok(false);
    }
    let host = get_system_config(state, "smtp_host").await?.unwrap_or_default();
    let username = get_system_config(state, "smtp_username")
        .await?
        .unwrap_or_default();
    let password = get_system_config(state, "smtp_password")
        .await?
        .unwrap_or_default();
    Ok(!host.is_empty() && !username.is_empty() && !password.is_empty())
}

// ===========================================================================
// db helper (port of db/host-notification-email-tasks.ts
// enqueueHostNotificationEmailTasks)
// ===========================================================================

const HOST_NOTIFICATION_EMAIL_INTERVAL_MS: i64 = 60 * 1000;
const ADVISORY_LOCK_RETRY_LIMIT: usize = 20;
const ADVISORY_LOCK_RETRY_DELAY_MS: u64 = 100;

struct EmailTaskInput {
    user_id: i32,
    host_id: i32,
    email: String,
    username: String,
    host_name: String,
    title: String,
    content: String,
}

async fn enqueue_host_notification_email_tasks(
    state: &SharedAppState,
    tasks: Vec<EmailTaskInput>,
) -> Result<i64, ApiError> {
    if tasks.is_empty() {
        return Ok(0);
    }

    for attempt in 0..ADVISORY_LOCK_RETRY_LIMIT {
        let mut tx = state.db.begin().await?;
        let locked = try_advisory_transaction_lock(
            &mut tx,
            advisory_lock_namespace::HOST_NOTIFICATION_EMAIL,
            1,
        )
        .await?;

        if !locked {
            drop(tx);
            tokio::time::sleep(std::time::Duration::from_millis(
                ADVISORY_LOCK_RETRY_DELAY_MS * (attempt as u64 + 1),
            ))
            .await;
            continue;
        }

        let latest_queued: Option<(DateTime<Utc>,)> = sqlx::query_as(
            "SELECT scheduled_for FROM host_notification_email_tasks \
             WHERE status IN ('PENDING', 'PROCESSING') \
             ORDER BY scheduled_for DESC, id DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;

        let latest_attempted: Option<(Option<DateTime<Utc>>,)> = sqlx::query_as(
            "SELECT started_at FROM host_notification_email_tasks \
             WHERE started_at IS NOT NULL \
             ORDER BY started_at DESC, id DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;

        let interval = chrono::Duration::milliseconds(HOST_NOTIFICATION_EMAIL_INTERVAL_MS);
        let mut base_time = Utc::now();
        if let Some((scheduled_for,)) = latest_queued {
            base_time = base_time.max(scheduled_for + interval);
        }
        if let Some((Some(started_at),)) = latest_attempted {
            base_time = base_time.max(started_at + interval);
        }

        let user_ids: Vec<i32> = tasks.iter().map(|t| t.user_id).collect();
        let host_ids: Vec<i32> = tasks.iter().map(|t| t.host_id).collect();
        let emails: Vec<String> = tasks.iter().map(|t| t.email.clone()).collect();
        let usernames: Vec<String> = tasks.iter().map(|t| t.username.clone()).collect();
        let host_names: Vec<String> = tasks.iter().map(|t| t.host_name.clone()).collect();
        let titles: Vec<String> = tasks.iter().map(|t| t.title.clone()).collect();
        let contents: Vec<String> = tasks.iter().map(|t| t.content.clone()).collect();
        let scheduled: Vec<DateTime<Utc>> = tasks
            .iter()
            .enumerate()
            .map(|(index, _)| base_time + chrono::Duration::milliseconds(
                HOST_NOTIFICATION_EMAIL_INTERVAL_MS * index as i64,
            ))
            .collect();

        let result = sqlx::query(
            "INSERT INTO host_notification_email_tasks \
             (user_id, host_id, email, username, host_name, title, content, scheduled_for) \
             SELECT u, h, e, un, hn, ti, c, s \
             FROM unnest($1::int[], $2::int[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::timestamptz[]) \
             AS t(u, h, e, un, hn, ti, c, s)",
        )
        .bind(&user_ids)
        .bind(&host_ids)
        .bind(&emails)
        .bind(&usernames)
        .bind(&host_names)
        .bind(&titles)
        .bind(&contents)
        .bind(&scheduled)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        return Ok(result.rows_affected() as i64);
    }

    Err(ApiError::internal(
        "Failed to acquire host notification email queue lock",
    ))
}

// ===========================================================================
// GET / — 获取站内信列表
// ===========================================================================

async fn list_messages(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let is_read_filter = match params.get("isRead").map(|s| s.as_str()) {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    };

    // db.parsePagination defaults + getInboxMessages clamps pageSize to 100
    // and page to >= 1.
    let pagination = parse_pagination(&params, 20, None);
    let page = pagination.page.max(1);
    let page_size = pagination.page_size.clamp(1, 100);

    let (messages, total) =
        get_inbox_messages(&state, user.id, page, page_size, is_read_filter).await?;

    let items: Vec<Value> = messages.iter().map(inbox_message_json).collect();
    Ok(Json(json!({
        "messages": items,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "totalPages": (total + page_size - 1) / page_size,
    })))
}

// ===========================================================================
// GET /unread-count — 获取未读消息数量
// ===========================================================================

async fn unread_count(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let count = get_unread_count(&state, user.id).await?;
    Ok(Json(json!({ "count": count })))
}

// ===========================================================================
// POST /{id}/read — 标记单条消息为已读
// ===========================================================================

async fn mark_read(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let message_id = js_number_id(&id)?;

    let success = mark_as_read(&state, message_id, user.id).await?;
    if !success {
        return Err(ApiError::not_found(code::MESSAGE_NOT_FOUND));
    }
    Ok(Json(json!({ "success": true })))
}

// ===========================================================================
// POST /read-all — 标记所有消息为已读
// ===========================================================================

async fn read_all(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let count = mark_all_as_read(&state, user.id).await?;
    Ok(Json(json!({ "success": true, "count": count })))
}

// ===========================================================================
// DELETE /{id} — 删除单条消息
// ===========================================================================

async fn delete_message(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let message_id = js_number_id(&id)?;

    let success = delete_message_by_id(&state, message_id, user.id).await?;
    if !success {
        return Err(ApiError::not_found(code::MESSAGE_NOT_FOUND));
    }
    Ok(Json(json!({ "success": true })))
}

// ===========================================================================
// DELETE /read — 删除所有已读消息
// ===========================================================================

async fn delete_read(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let count = delete_read_messages(&state, user.id).await?;
    Ok(Json(json!({ "success": true, "count": count })))
}

// ===========================================================================
// POST /admin/broadcast — 管理员发送全站站内信
// ===========================================================================

async fn admin_broadcast(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    // 检查管理员权限 (manual check in TS).
    if user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let (title, content) = match validate_title_content(&body) {
        Ok(v) => v,
        Err(response) => return Ok(response),
    };

    // 获取所有活跃用户
    let user_ids = get_all_active_user_ids(&state).await?;
    if user_ids.is_empty() {
        return Ok((StatusCode::OK, Json(json!({ "success": true, "count": 0 }))).into_response());
    }

    // 批量发送
    let count = create_bulk_messages(
        &state,
        &user_ids,
        "system_announcement",
        &title,
        &content,
        json!({ "senderId": user.id }),
    )
    .await?;

    // 保存公告记录
    create_announcement(
        &state,
        "system_broadcast",
        user.id,
        &title,
        &content,
        count as i64,
        None,
        None,
        None,
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(json!({ "success": true, "count": count })),
    )
        .into_response())
}

// ===========================================================================
// POST /hosts/{hostId}/notify — 节点所有者通知实例用户
// ===========================================================================

/// Fastify schema for the notify body:
/// title (1..200), content (1..5000), instanceIds (int array 1..100 items),
/// sendEmail (boolean). Failures -> 400 { error, code: VALIDATION_ERROR, details? }.
fn validate_host_notify_body(
    body: &Value,
) -> Result<(String, String, Option<Vec<i32>>, bool), ApiError> {
    let obj = match body.as_object() {
        Some(o) => o,
        None => {
            return Err(ApiError::with_message(
                code::VALIDATION_ERROR,
                StatusCode::BAD_REQUEST,
                "body must be object",
            ))
        }
    };

    let mut messages: Vec<String> = Vec::new();
    for field in ["title", "content"] {
        if !obj.contains_key(field) {
            messages.push(format!("{field} is required"));
        }
    }

    let title = obj.get("title").and_then(Value::as_str);
    match title {
        Some(t) => {
            let len = js_len(t);
            if len < 1 {
                messages.push("title is too short".to_string());
            } else if len > 200 {
                messages.push("title is too long".to_string());
            }
        }
        None => {
            if obj.get("title").is_some() {
                messages.push("title must be string".to_string());
            }
        }
    }

    let content = obj.get("content").and_then(Value::as_str);
    match content {
        Some(c) => {
            let len = js_len(c);
            if len < 1 {
                messages.push("content is too short".to_string());
            } else if len > 5000 {
                messages.push("content is too long".to_string());
            }
        }
        None => {
            if obj.get("content").is_some() {
                messages.push("content must be string".to_string());
            }
        }
    }

    let mut instance_ids: Option<Vec<i32>> = None;
    if let Some(v) = obj.get("instanceIds") {
        match v.as_array() {
            Some(arr) => {
                if arr.is_empty() {
                    messages.push("instanceIds must NOT have fewer than 1 items".to_string());
                } else if arr.len() > 100 {
                    messages
                        .push("instanceIds must NOT have more than 100 items".to_string());
                }
                let mut ids = Vec::with_capacity(arr.len());
                for (index, item) in arr.iter().enumerate() {
                    match item.as_i64() {
                        Some(n) => {
                            if n < i32::MIN as i64 || n > i32::MAX as i64 {
                                messages
                                    .push(format!("instanceIds/{index} must be integer"));
                            } else {
                                ids.push(n as i32);
                            }
                        }
                        None => {
                            messages.push(format!("instanceIds/{index} must be integer"));
                        }
                    }
                }
                instance_ids = Some(ids);
            }
            None => messages.push("instanceIds must be array".to_string()),
        }
    }

    let mut send_email = false;
    if let Some(v) = obj.get("sendEmail") {
        match v.as_bool() {
            Some(b) => send_email = b,
            None => messages.push("sendEmail must be boolean".to_string()),
        }
    }

    if !messages.is_empty() {
        let first = messages[0].clone();
        let mut err =
            ApiError::with_message(code::VALIDATION_ERROR, StatusCode::BAD_REQUEST, first);
        if messages.len() > 1 {
            err = err.with_details(messages.join(", "));
        }
        return Err(err);
    }

    let title = title.unwrap_or_default().to_string();
    let content = content.unwrap_or_default().to_string();
    Ok((title, content, instance_ids, send_email))
}

async fn host_notify(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(host_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    // Fastify validates the body schema before the handler runs.
    let (raw_title, raw_content, instance_ids, send_email) =
        validate_host_notify_body(&body)?;

    let host_id_num = js_number_id(&host_id)?;

    // 检查节点是否存在
    let host = get_host_by_id(&state, host_id_num)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;

    // 检查是否是节点所有者或管理员
    if host.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    // 参数验证 (TS re-checks manually; unreachable via the schema but kept).
    let (title, content) = match validate_title_content(&json!({
        "title": raw_title,
        "content": raw_content,
    })) {
        Ok(v) => v,
        Err(_) => {
            return Ok(manual_error("TITLE_REQUIRED", "Title is required"));
        }
    };

    // 获取目标用户（去重）
    let recipients =
        get_unique_recipients_by_host_id(&state, host_id_num, instance_ids.as_ref()).await?;
    let user_ids: Vec<i32> = recipients.iter().map(|r| r.user_id).collect();
    let email_recipients: Vec<&HostRecipient> = if send_email {
        recipients
            .iter()
            .filter(|r| r.email.as_deref().map(|e| !e.trim().is_empty()).unwrap_or(false))
            .collect()
    } else {
        Vec::new()
    };

    if send_email && !email_recipients.is_empty() {
        let smtp_enabled = is_smtp_enabled(&state).await?;
        if !smtp_enabled {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "SMTP_NOT_CONFIGURED",
                    "message": "SMTP is not configured",
                })),
            )
                .into_response());
        }
    }

    if user_ids.is_empty() {
        let mut body = json!({ "success": true, "count": 0 });
        if send_email {
            body["email"] = json!({
                "requested": true,
                "mode": "none",
                "sentCount": 0,
                "queuedCount": 0,
                "skippedCount": 0,
                "failedCount": 0,
            });
        }
        return Ok((StatusCode::OK, Json(body)).into_response());
    }

    // 构建带节点署名的消息内容
    let message_content = format!("{content}\n\n来自节点：{}", host.name);

    // 批量发送
    let count = create_bulk_messages(
        &state,
        &user_ids,
        "host_announcement",
        &title,
        &message_content,
        json!({ "hostId": host.id, "hostName": host.name, "senderId": user.id }),
    )
    .await?;

    // 保存公告记录
    create_announcement(
        &state,
        "host_broadcast",
        user.id,
        &title,
        &content,
        count as i64,
        Some(host.id),
        None,
        None,
    )
    .await?;

    if !send_email {
        return Ok((
            StatusCode::OK,
            Json(json!({ "success": true, "count": count })),
        )
            .into_response());
    }

    let mut email_summary = json!({
        "requested": true,
        "mode": "none",
        "sentCount": 0,
        "queuedCount": 0,
        "skippedCount": recipients.len() as i64 - email_recipients.len() as i64,
        "failedCount": 0,
    });

    if recipients.len() == 1 && email_recipients.len() == 1 {
        // Direct send mode — nodemailer is not ported, so report the failure
        // exactly where the TS would report a failed send.
        email_summary["mode"] = json!("direct");
        email_summary["failedCount"] = json!(1);
        tracing::error!(
            "[Inbox] Failed to send direct host announcement email to user {}: SMTP stack not ported to the Rust server",
            email_recipients[0].user_id
        );
    } else if !email_recipients.is_empty() {
        email_summary["mode"] = json!("queued");
        let tasks: Vec<EmailTaskInput> = email_recipients
            .iter()
            .map(|r| EmailTaskInput {
                user_id: r.user_id,
                host_id: host.id,
                email: r.email.clone().unwrap_or_default().trim().to_string(),
                username: r.username.clone(),
                host_name: host.name.clone(),
                title: title.clone(),
                content: content.clone(),
            })
            .collect();
        match enqueue_host_notification_email_tasks(&state, tasks).await {
            Ok(queued) => {
                email_summary["queuedCount"] = json!(queued);
                email_summary["failedCount"] =
                    json!((email_recipients.len() as i64 - queued).max(0));
            }
            Err(err) => {
                email_summary["failedCount"] = json!(email_recipients.len() as i64);
                tracing::error!(
                    "[Inbox] Failed to enqueue host announcement emails for host {host_id_num}: {err:?}"
                );
            }
        }
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "success": true,
            "count": count,
            "email": email_summary,
        })),
    )
        .into_response())
}

// ===========================================================================
// POST /admin/send/{userId} — 管理员发送站内信给特定用户
// ===========================================================================

async fn admin_send(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    // 检查管理员权限 (manual check in TS).
    if user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let target_user_id = js_number_id(&user_id)?;

    // 检查目标用户是否存在
    let target: Option<(String,)> =
        sqlx::query_as("SELECT username FROM users WHERE id = $1")
            .bind(target_user_id)
            .fetch_optional(&state.db)
            .await?;
    if target.is_none() {
        return Err(ApiError::not_found(code::USER_NOT_FOUND));
    }

    // 不允许给自己发消息
    if target_user_id == user.id {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "CANNOT_MESSAGE_SELF",
                "message": "Cannot send message to yourself",
            })),
        )
            .into_response());
    }

    let (title, content) = match validate_title_content(&body) {
        Ok(v) => v,
        Err(response) => return Ok(response),
    };

    // 创建消息
    create_inbox_message(
        &state,
        target_user_id,
        "admin_message",
        &title,
        &content,
        json!({ "senderId": user.id }),
    )
    .await?;

    // 保存通知记录
    create_announcement(
        &state,
        "admin_message",
        user.id,
        &title,
        &content,
        1,
        None,
        Some(target_user_id),
        None,
    )
    .await?;

    Ok((StatusCode::OK, Json(json!({ "success": true }))).into_response())
}

// ===========================================================================
// POST /instances/{instanceId}/notify — 宿主机所有者发送站内信给特定实例用户
// ===========================================================================

async fn instance_notify(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(instance_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let instance_id_num = js_number_id(&instance_id)?;

    // 获取实例信息
    let instance = get_instance_by_id(&state, instance_id_num)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;

    // 检查实例是否已删除
    if instance.status == "deleted" {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "INSTANCE_DELETED",
                "message": "Instance has been deleted",
            })),
        )
            .into_response());
    }

    // 获取宿主机信息
    let host = get_host_by_id(&state, instance.host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;

    // 检查是否是宿主机所有者或管理员
    if host.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    // 不允许给自己发消息
    if instance.user_id == user.id {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "CANNOT_MESSAGE_SELF",
                "message": "Cannot send message to yourself",
            })),
        )
            .into_response());
    }

    let (title, content) = match validate_title_content(&body) {
        Ok(v) => v,
        Err(response) => return Ok(response),
    };

    // 构建带节点署名的消息内容
    let message_content = format!("{content}\n\n来自节点：{}", host.name);

    // 创建消息给实例用户
    create_inbox_message(
        &state,
        instance.user_id,
        "host_message",
        &title,
        &message_content,
        json!({
            "hostId": host.id,
            "hostName": host.name,
            "instanceId": instance.id,
            "instanceName": instance.name,
            "senderId": user.id,
        }),
    )
    .await?;

    // 保存通知记录
    create_announcement(
        &state,
        "host_message",
        user.id,
        &title,
        &content,
        1,
        Some(host.id),
        Some(instance.user_id),
        Some(instance.id),
    )
    .await?;

    Ok((StatusCode::OK, Json(json!({ "success": true }))).into_response())
}
