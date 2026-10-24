//! 公告/通知历史记录路由 — port of server/src/routes/announcements.ts
//! (mounted at /api/announcements).
//!
//! The TS module installs `fastify.addHook('onRequest', fastify.authenticate)`
//! for every route and then re-checks the admin role INSIDE two handlers, so
//! all three endpoints map to `AuthUser` with manual role checks (NOT
//! `AdminAuth`).
//!
//! Endpoint map:
//! - GET /      authenticate -> AuthUser + manual admin check (403 FORBIDDEN)
//! - GET /my    authenticate -> AuthUser
//! - GET /{id}  authenticate -> AuthUser + manual owner/admin check

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::AuthUser;
use crate::error::{code, ApiError};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list_announcements))
        .route("/my", get(my_announcements))
        .route("/{id}", get(get_announcement))
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

// ===========================================================================
// db helpers (port of db/announcements.ts)
// ===========================================================================

#[derive(Debug, FromRow)]
struct AnnouncementRow {
    id: i32,
    #[sqlx(rename = "type")]
    announcement_type: String,
    title: String,
    content: String,
    recipient_count: i32,
    host_id: Option<i32>,
    target_user_id: Option<i32>,
    instance_id: Option<i32>,
    created_at: DateTime<Utc>,
    sender_id: Option<i32>,
    sender_username: Option<String>,
    host_name: Option<String>,
}

async fn get_announcement_list(
    state: &SharedAppState,
    pagination: crate::response::Pagination,
    announcement_type: Option<&str>,
) -> Result<(Vec<AnnouncementRow>, i64), ApiError> {
    let mut sql = String::from(
        "SELECT a.id, a.type::text AS type, a.title, a.content, a.recipient_count, \
         a.host_id, a.target_user_id, a.instance_id, a.created_at, \
         a.sender_id, s.username AS sender_username, h.name AS host_name \
         FROM announcements a \
         JOIN users s ON s.id = a.sender_id \
         LEFT JOIN hosts h ON h.id = a.host_id \
         WHERE 1 = 1",
    );
    let mut count_sql = String::from("SELECT COUNT(*) FROM announcements a WHERE 1 = 1");
    if announcement_type.is_some() {
        sql.push_str(" AND a.type = $1::\"AnnouncementType\"");
        count_sql.push_str(" AND a.type = $1::\"AnnouncementType\"");
    }
    sql.push_str(if announcement_type.is_some() {
        " ORDER BY a.created_at DESC OFFSET $2 LIMIT $3"
    } else {
        " ORDER BY a.created_at DESC OFFSET $1 LIMIT $2"
    });

    let mut q = sqlx::query_as::<_, AnnouncementRow>(&sql);
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(t) = announcement_type {
        q = q.bind(t);
        cq = cq.bind(t);
    }
    q = q.bind(pagination.skip).bind(pagination.take);

    let items = q.fetch_all(&state.db).await?;
    let total = cq.fetch_one(&state.db).await?;
    Ok((items, total))
}

async fn get_host_owner_announcement_list(
    state: &SharedAppState,
    sender_id: i32,
    pagination: crate::response::Pagination,
    host_id: Option<i32>,
) -> Result<(Vec<AnnouncementRow>, i64), ApiError> {
    // senderId + type IN ('host_broadcast','host_message') + optional hostId.
    // Prisma `if (hostId)` is falsy for 0/NaN, so 0 means "no filter".
    let mut sql = String::from(
        "SELECT a.id, a.type::text AS type, a.title, a.content, a.recipient_count, \
         a.host_id, a.target_user_id, a.instance_id, a.created_at, \
         NULL::int AS sender_id, NULL::text AS sender_username, h.name AS host_name \
         FROM announcements a \
         LEFT JOIN hosts h ON h.id = a.host_id \
         WHERE a.sender_id = $1 AND a.type IN ('host_broadcast', 'host_message')",
    );
    let mut count_sql = String::from(
        "SELECT COUNT(*) FROM announcements a \
         WHERE a.sender_id = $1 AND a.type IN ('host_broadcast', 'host_message')",
    );
    if host_id.is_some() {
        sql.push_str(" AND a.host_id = $2");
        count_sql.push_str(" AND a.host_id = $2");
    }
    sql.push_str(if host_id.is_some() {
        " ORDER BY a.created_at DESC OFFSET $3 LIMIT $4"
    } else {
        " ORDER BY a.created_at DESC OFFSET $2 LIMIT $3"
    });

    let mut q = sqlx::query_as::<_, AnnouncementRow>(&sql).bind(sender_id);
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(sender_id);
    if let Some(h) = host_id {
        q = q.bind(h);
        cq = cq.bind(h);
    }
    q = q.bind(pagination.skip).bind(pagination.take);

    let items = q.fetch_all(&state.db).await?;
    let total = cq.fetch_one(&state.db).await?;
    Ok((items, total))
}

async fn get_announcement_by_id(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<AnnouncementRow>, ApiError> {
    let row = sqlx::query_as::<_, AnnouncementRow>(
        "SELECT a.id, a.type::text AS type, a.title, a.content, a.recipient_count, \
         a.host_id, a.target_user_id, a.instance_id, a.created_at, \
         a.sender_id, s.username AS sender_username, h.name AS host_name \
         FROM announcements a \
         JOIN users s ON s.id = a.sender_id \
         LEFT JOIN hosts h ON h.id = a.host_id \
         WHERE a.id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

// ===========================================================================
// GET / — 获取公告历史列表（管理员）
// ===========================================================================

async fn list_announcements(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    // 检查管理员权限 (TS checks inside the handler, not via a decorator).
    if user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let announcement_type = params.get("type").map(|s| s.as_str());
    let pagination = crate::response::parse_pagination(&params, 20, None);

    let (items, total) =
        get_announcement_list(&state, pagination, announcement_type).await?;

    let list: Vec<Value> = items
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "type": a.announcement_type,
                "title": a.title,
                "content": a.content,
                "recipientCount": a.recipient_count,
                "hostId": a.host_id,
                "targetUserId": a.target_user_id,
                "instanceId": a.instance_id,
                "createdAt": iso(a.created_at),
                "sender": {
                    "id": a.sender_id,
                    "username": a.sender_username,
                },
                "host": match a.host_id {
                    Some(_) => json!({ "id": a.host_id, "name": a.host_name }),
                    None => Value::Null,
                },
            })
        })
        .collect();

    Ok(Json(json!({
        "items": list,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
        "totalPages": (total + pagination.page_size - 1) / pagination.page_size.max(1),
    })))
}

// ===========================================================================
// GET /my — 获取宿主机所有者的公告历史
// ===========================================================================

/// JS parseInt base-10: optional sign + leading digits, else NaN.
fn js_parse_int(raw: &str) -> Option<i64> {
    let s = raw.trim_start();
    let bytes = s.as_bytes();
    let mut idx = 0usize;
    let mut sign = 1i64;
    if idx < bytes.len() && (bytes[idx] == b'+' || bytes[idx] == b'-') {
        if bytes[idx] == b'-' {
            sign = -1;
        }
        idx += 1;
    }
    let start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == start {
        return None; // NaN
    }
    s[start..idx].parse::<i64>().ok().map(|v| sign * v)
}

async fn my_announcements(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    // hostId ? parseInt(hostId, 10) : undefined — a NaN parse result is falsy
    // downstream (`if (hostId)`), so unparseable/0 values mean "no filter".
    // A parsed value outside the Int range fails Prisma validation -> 500.
    let host_id = match params.get("hostId") {
        Some(raw) if !raw.is_empty() => match js_parse_int(raw) {
            Some(v) if v == 0 => None,
            Some(v) if v >= i32::MIN as i64 && v <= i32::MAX as i64 => Some(v as i32),
            Some(_) => {
                return Err(ApiError::internal("Prisma Int argument out of range"));
            }
            None => None,
        },
        _ => None,
    };

    let pagination = crate::response::parse_pagination(&params, 20, None);
    let (items, total) =
        get_host_owner_announcement_list(&state, user.id, pagination, host_id).await?;

    let list: Vec<Value> = items
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "type": a.announcement_type,
                "title": a.title,
                "content": a.content,
                "recipientCount": a.recipient_count,
                "hostId": a.host_id,
                "targetUserId": a.target_user_id,
                "instanceId": a.instance_id,
                "createdAt": iso(a.created_at),
                "host": match a.host_id {
                    Some(_) => json!({ "id": a.host_id, "name": a.host_name }),
                    None => Value::Null,
                },
            })
        })
        .collect();

    Ok(Json(json!({
        "items": list,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
        "totalPages": (total + pagination.page_size - 1) / pagination.page_size.max(1),
    })))
}

// ===========================================================================
// GET /{id} — 获取公告详情
// ===========================================================================

/// TS: reply.code(404).send({ error: 'ANNOUNCEMENT_NOT_FOUND', message: ... })
/// — note the non-standard shape (no `code` field).
fn announcement_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "ANNOUNCEMENT_NOT_FOUND",
            "message": "Announcement not found",
        })),
    )
        .into_response()
}

async fn get_announcement(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let announcement_id = js_number_id(&id)?;

    let announcement = get_announcement_by_id(&state, announcement_id).await?;
    let Some(announcement) = announcement else {
        return Ok(announcement_not_found());
    };

    // 检查权限：管理员可以查看所有，宿主机所有者只能查看自己发送的
    if user.role != "admin" && announcement.sender_id != Some(user.id) {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    Ok(Json(json!({
        "id": announcement.id,
        "type": announcement.announcement_type,
        "senderId": announcement.sender_id,
        "title": announcement.title,
        "content": announcement.content,
        "recipientCount": announcement.recipient_count,
        "hostId": announcement.host_id,
        "targetUserId": announcement.target_user_id,
        "instanceId": announcement.instance_id,
        "createdAt": iso(announcement.created_at),
        "sender": {
            "id": announcement.sender_id,
            "username": announcement.sender_username,
        },
        "host": match announcement.host_id {
            Some(_) => json!({ "id": announcement.host_id, "name": announcement.host_name }),
            None => Value::Null,
        },
    }))
    .into_response())
}
