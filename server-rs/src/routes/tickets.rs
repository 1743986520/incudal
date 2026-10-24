//! 工单系统路由 — port of server/src/routes/tickets.ts (+ db/tickets.ts).
//! Mounted at /api/tickets; all endpoints authenticate (AuthUser), admin
//! checks inline like the TS (requireAdmin only on message delete).
//!
//! Create/reply accept JSON or multipart (≤6 images, 50MB each, magic-byte
//! MIME verification) with Lsky uploads and rollback cleanup; the attachment
//! content endpoint is an SSRF-guarded authenticated proxy.

use axum::body::Bytes;
use axum::extract::{FromRequest, Multipart, Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sqlx::FromRow;
use std::collections::HashMap;

use crate::auth::{AdminAuth, AuthUser};
use crate::error::{code, ApiError};
use crate::libs::incus::incus_tls::{default_dns_resolver, is_public_host_address};
use crate::libs::instance_common::iso;
use crate::libs::lsky::{
    delete_ticket_image_from_lsky, upload_ticket_image_to_lsky, LskyUploadResult,
};
use crate::state::SharedAppState;

const VALID_CATEGORIES: [&str; 4] = ["general", "billing", "technical", "abuse"];
const VALID_PRIORITIES: [&str; 4] = ["low", "normal", "high", "urgent"];
const VALID_STATUSES: [&str; 4] = ["open", "in_progress", "resolved", "closed"];
const MAX_TICKET_IMAGES: usize = 6;
const MAX_TICKET_IMAGE_SIZE: usize = 50 * 1024 * 1024;
const MAX_PROXY_RESPONSE: usize = 20 * 1024 * 1024;
const ALLOWED_MIME: [&str; 5] = ["image/jpeg", "image/png", "image/webp", "image/gif", "image/avif"];

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", post(create).get(my_list))
        .route("/pending-count", get(pending_count))
        .route("/my-hosts", get(my_hosts))
        .route("/hosts/{hostId}", get(host_list))
        .route("/attachments/{attachmentId}/content", get(attachment_content))
        .route("/{id}", get(detail))
        .route("/{id}/messages", get(messages).post(reply))
        .route("/{id}/messages/{messageId}", axum::routing::delete(delete_message))
        .route("/{id}/status", axum::routing::patch(update_status))
        .route("/{id}/close", post(close))
}

fn parse_id_str(raw: &str) -> Result<i32, ApiError> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))
}

// ==================== image sniffing (TS detectImageMimeType) ====================

fn detect_image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return Some("image/jpeg");
    }
    if bytes.len() >= 8
        && bytes[..8] == [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
    {
        return Some("image/png");
    }
    if bytes.len() >= 6 && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        let brand = &bytes[8..12];
        if brand == b"avif" || brand == b"avis" {
            return Some("image/avif");
        }
    }
    None
}

// ==================== payload parsing (JSON or multipart) ====================

struct ParsedImage {
    bytes: Vec<u8>,
    filename: String,
    content_type: String,
}

struct ParsedPayload {
    fields: HashMap<String, String>,
    images: Vec<ParsedImage>,
}

async fn read_ticket_payload(
    state: &SharedAppState,
    req: Request,
) -> Result<ParsedPayload, ApiError> {
    let headers = req.headers().clone();
    let is_multipart = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("multipart/form-data"))
        .unwrap_or(false);

    if !is_multipart {
        let bytes = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024)
            .await
            .map_err(|e| ApiError::validation(e.to_string()))?;
        let mut fields = HashMap::new();
        if let Ok(body) = serde_json::from_slice::<Map<String, Value>>(&bytes) {
            for (key, value) in body {
                if let Some(s) = value.as_str() {
                    fields.insert(key.clone(), s.to_string());
                } else if !value.is_null() {
                    fields.insert(key.clone(), value.to_string());
                }
            }
        }
        return Ok(ParsedPayload { fields, images: Vec::new() });
    }

    let (parts, body) = req.into_parts();
    let multipart_req = Request::from_parts(parts, body);
    let mut multipart = Multipart::from_request(multipart_req, state)
        .await
        .map_err(|e| ApiError::validation(e.to_string()))?;
    let mut fields = HashMap::new();
    let mut images = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::validation(e.to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        let Some(file_name) = field.file_name().map(|s| s.to_string()) else {
            let value = field.text().await.unwrap_or_default();
            fields.insert(name, value);
            continue;
        };
        if name != "images" {
            continue;
        }
        let mime = field
            .content_type()
            .unwrap_or("")
            .to_string();
        if !ALLOWED_MIME.contains(&mime.as_str()) {
            return Err(ApiError::bad_request(code::INVALID_PARAMS)
                .with_details("Only JPG, PNG, WebP, GIF and AVIF images are supported"));
        }
        if images.len() >= MAX_TICKET_IMAGES {
            return Err(ApiError::bad_request(code::INVALID_PARAMS)
                .with_details(format!("A ticket message can contain at most {MAX_TICKET_IMAGES} images")));
        }
        let bytes = field
            .bytes()
            .await
            .map_err(|e| ApiError::validation(e.to_string()))?;
        if bytes.is_empty() {
            continue;
        }
        if bytes.len() > MAX_TICKET_IMAGE_SIZE {
            return Err(ApiError::bad_request(code::INVALID_PARAMS)
                .with_details("Each image must be no larger than 50MB"));
        }
        let detected = detect_image_mime(&bytes);
        if detected != Some(mime.as_str()) {
            return Err(ApiError::bad_request(code::INVALID_PARAMS)
                .with_details("Uploaded file content does not match its declared image type"));
        }
        images.push(ParsedPayload_image(bytes.to_vec(), file_name, mime));
        let _ = file_name; // silence: consumed above via helper
    }
    Ok(ParsedPayload { fields, images })
}

fn ParsedPayload_image(bytes: Vec<u8>, filename: String, content_type: String) -> ParsedImage {
    ParsedImage {
        bytes,
        filename,
        content_type,
    }
}

// ==================== Lsky upload / cleanup ====================

#[derive(Clone)]
struct UploadedAttachment {
    provider_file_id: Option<String>,
    provider_version: String,
    filename: String,
    original_name: String,
    mime_type: String,
    size_bytes: i64,
    width: Option<i64>,
    height: Option<i64>,
    url: String,
    thumbnail_url: Option<String>,
}

async fn upload_ticket_images(
    state: &SharedAppState,
    images: Vec<ParsedImage>,
) -> Result<Vec<UploadedAttachment>, ApiError> {
    let mut uploaded = Vec::new();
    for image in images {
        match upload_ticket_image_to_lsky(
            state,
            &image.filename,
            &image.content_type,
            image.bytes.clone(),
            image.bytes.len() as i64,
        )
        .await
        {
            Ok((LskyUploadResult { provider_file_id, filename, mime_type, size_bytes, width, height, url, thumbnail_url }, version)) => {
                uploaded.push(UploadedAttachment {
                    provider_file_id,
                    provider_version: version.to_string(),
                    filename,
                    original_name: image.filename.clone(),
                    mime_type,
                    size_bytes,
                    width,
                    height,
                    url,
                    thumbnail_url,
                });
            }
            Err(message) => {
                cleanup_uploaded(&state, &uploaded).await;
                return Err(ApiError::bad_request(code::INVALID_PARAMS).with_details(message));
            }
        }
    }
    Ok(uploaded)
}

async fn cleanup_uploaded(state: &SharedAppState, attachments: &[UploadedAttachment]) {
    for a in attachments {
        let _ = delete_ticket_image_from_lsky(state, &a.provider_version, a.provider_file_id.as_deref()).await;
    }
}

async fn cleanup_attachment_rows(state: &SharedAppState, rows: &[(String, Option<String>)]) {
    for (version, file_id) in rows {
        let _ = delete_ticket_image_from_lsky(state, version, file_id.as_deref()).await;
    }
}

// ==================== access / rows ====================

struct TicketAccess {
    can_access: bool,
    is_owner: bool,
    is_creator: bool,
}

async fn can_user_access_ticket(
    state: &SharedAppState,
    user: &AuthUser,
    ticket_id: i32,
) -> Result<TicketAccess, ApiError> {
    let row: Option<(i32, Option<i32>)> = sqlx::query_as(
        "SELECT t.user_id, h.user_id FROM tickets t LEFT JOIN hosts h ON h.id = t.host_id WHERE t.id = $1",
    )
    .bind(ticket_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((ticket_creator, host_owner)) = row else {
        return Ok(TicketAccess { can_access: false, is_owner: false, is_creator: false });
    };
    let is_admin = user.role == "admin";
    let is_owner = host_owner == Some(user.id);
    let is_creator = ticket_creator == user.id;
    Ok(TicketAccess {
        can_access: is_creator || is_owner || is_admin,
        is_owner: is_owner || is_admin,
        is_creator,
    })
}

#[derive(Debug, FromRow)]
struct TicketCoreRow {
    id: i32,
    user_id: i32,
    host_id: Option<i32>,
    instance_id: Option<i32>,
    subject: String,
    category: String,
    priority: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    closed_at: Option<DateTime<Utc>>,
}

const TICKET_CORE: &str = "id, user_id, host_id, instance_id, subject, category::text AS category, \
    priority::text AS priority, status::text AS status, created_at, updated_at, resolved_at, closed_at";

/// getTicketById serialization (user/host/instance/messageCount/lastMessage).
async fn ticket_detail_json(state: &SharedAppState, ticket: &TicketCoreRow) -> Result<Value, ApiError> {
    let user: (String, String, Option<String>) = sqlx::query_as(
        "SELECT username, avatar_style, avatar_badge_id FROM users WHERE id = $1",
    )
    .bind(ticket.user_id)
    .fetch_one(&state.db)
    .await?;
    let host: Option<(i32, String, i32, String)> = match ticket.host_id {
        Some(host_id) => sqlx::query_as(
            "SELECT id, name, user_id, country_code FROM hosts WHERE id = $1",
        )
        .bind(host_id)
        .fetch_optional(&state.db)
        .await?,
        None => None,
    };
    let instance: Option<(i32, String, String, Option<String>, Option<String>, Option<String>, i32, i32, i32, String, Option<String>)> =
        match ticket.instance_id {
            Some(instance_id) => sqlx::query_as(
                "SELECT i.id, i.name, i.status::text, i.icon_badge_id, i.ipv4, i.ipv6, \
                        i.cpu, i.memory, i.disk, i.image, p.name \
                 FROM instances i LEFT JOIN packages p ON p.id = i.package_id WHERE i.id = $1",
            )
            .bind(instance_id)
            .fetch_optional(&state.db)
            .await?,
            None => None,
        };
    let (message_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ticket_messages WHERE ticket_id = $1",
    )
    .bind(ticket.id)
    .fetch_one(&state.db)
    .await?;
    let last: Option<(String, bool, DateTime<Utc>)> = sqlx::query_as(
        "SELECT content, is_from_owner, created_at FROM ticket_messages \
         WHERE ticket_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(ticket.id)
    .fetch_optional(&state.db)
    .await?;

    let instance_json = if let Some((id, name, status, badge, ipv4, ipv6, cpu, memory, disk, image, package_name)) = instance {
        let image_name = if image.is_empty() { None } else { image_name_for(state, &image).await };
        json!({
            "id": id, "name": name, "status": status, "iconBadgeId": badge,
            "ipv4": ipv4, "ipv6": ipv6, "cpu": cpu, "memory": memory, "disk": disk,
            "image": image, "imageName": image_name, "packageName": package_name,
        })
    } else {
        Value::Null
    };

    Ok(json!({
        "id": ticket.id,
        "userId": ticket.user_id,
        "hostId": ticket.host_id,
        "instanceId": ticket.instance_id,
        "subject": ticket.subject,
        "category": ticket.category,
        "priority": ticket.priority,
        "status": ticket.status,
        "createdAt": iso(ticket.created_at),
        "updatedAt": iso(ticket.updated_at),
        "resolvedAt": ticket.resolved_at.map(iso).unwrap_or(Value::Null),
        "closedAt": ticket.closed_at.map(iso).unwrap_or(Value::Null),
        "user": { "id": ticket.user_id, "username": user.0, "avatarStyle": user.1, "avatarBadgeId": user.2 },
        "host": host.map(|(id, name, user_id, country)| json!({
            "id": id, "name": name, "userId": user_id, "countryCode": country,
        })).unwrap_or(Value::Null),
        "instance": instance_json,
        "messageCount": message_count,
        "lastMessage": last.map(|(content, is_from_owner, created_at)| json!({
            "content": content, "isFromOwner": is_from_owner, "createdAt": iso(created_at),
        })).unwrap_or(Value::Null),
    }))
}

async fn image_name_for(state: &SharedAppState, remote_alias: &str) -> Option<String> {
    sqlx::query_scalar("SELECT name FROM system_images WHERE remote_alias = $1")
        .bind(remote_alias)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
}

// ==================== list helper ====================

#[derive(Deserialize)]
struct ListQuery {
    status: Option<String>,
    search: Option<String>,
    page: Option<String>,
    #[serde(rename = "pageSize")]
    page_size: Option<String>,
    #[serde(rename = "hostId")]
    host_id: Option<String>,
    #[serde(rename = "sourceType")]
    source_type: Option<String>,
}

fn valid_status_filter(status: &Option<String>) -> Result<Option<String>, ApiError> {
    match status.as_deref() {
        None | Some("") => Ok(None),
        Some("active") => Ok(Some("active".into())),
        Some(s) if VALID_STATUSES.contains(&s) => Ok(Some(s.to_string())),
        Some(_) => Err(ApiError::bad_request(code::INVALID_PARAMS).with_details("Invalid status")),
    }
}

fn page_of(query: &ListQuery, default_size: i64, max_size: i64) -> (i64, i64) {
    let mut params = HashMap::new();
    if let Some(p) = &query.page {
        params.insert("page".to_string(), p.clone());
    }
    if let Some(ps) = &query.page_size {
        params.insert("pageSize".to_string(), ps.clone());
    }
    let pagination = crate::response::parse_pagination(&params, default_size, Some(max_size));
    (pagination.page, pagination.page_size)
}

/// WHERE fragment builder shared by the three list endpoints.
fn list_where(
    base: &str,
    status: &Option<String>,
    search: &Option<String>,
) -> (String, Vec<String>) {
    let mut clauses = vec![base.to_string()];
    match status.as_deref() {
        Some("active") => clauses.push("t.status::text != 'closed'".into()),
        Some(s) => clauses.push(format!("t.status::text = '{s}'")),
        None => {}
    }
    if let Some(term) = search.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(id) = term.parse::<i32>() {
            clauses.push(format!(
                "(t.id = {id} OR t.subject ILIKE '%{}%')",
                term.replace('\'', "''")
            ));
        } else {
            clauses.push(format!("t.subject ILIKE '%{}%'", term.replace('\'', "''")));
        }
    }
    (clauses.join(" AND "), Vec::new())
}

async fn list_tickets(
    state: &SharedAppState,
    where_sql: &str,
    page: i64,
    page_size: i64,
) -> Result<Value, ApiError> {
    let rows = sqlx::query_as::<_, TicketCoreRow>(&format!(
        "SELECT {TICKET_CORE} FROM tickets t WHERE {where_sql} \
         ORDER BY t.updated_at DESC LIMIT {limit} OFFSET {offset}",
        limit = page_size,
        offset = (page - 1) * page_size,
    ))
    .fetch_all(&state.db)
    .await?;
    let (total,): (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM tickets t WHERE {where_sql}"
    ))
    .fetch_one(&state.db)
    .await?;

    let mut tickets = Vec::new();
    for row in &rows {
        tickets.push(ticket_detail_json(state, row).await?);
    }
    Ok(json!({
        "tickets": tickets,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "totalPages": (total + page_size - 1) / page_size.max(1),
    }))
}

async fn host_display_name(state: &SharedAppState, host_id: Option<i32>) -> String {
    match host_id {
        Some(hid) => sqlx::query_scalar("SELECT name FROM hosts WHERE id = $1")
            .bind(hid)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "系统".into()),
        None => "系统".into(),
    }
}

async fn hosted_owner_if_user_role(state: &SharedAppState, host_id: Option<i32>) -> Option<i32> {
    let hid = host_id?;
    sqlx::query_scalar(
        "SELECT CASE WHEN (SELECT role::text FROM users WHERE id = hosts.user_id) = 'user' THEN hosts.user_id ELSE NULL END FROM hosts WHERE id = $1",
    )
    .bind(hid)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
}

async fn notify_ticket_event(
    state: &SharedAppState,
    to: i32,
    event: &str,
    title: &str,
    body_text: &str,
    subject: &str,
) {
    crate::routes::users::create_inbox_notification(
        state,
        to,
        event,
        title,
        body_text,
        json!({ "subject": subject }),
    )
    .await;
}

// ===========================================================================
// POST / — 创建工单
// ===========================================================================

async fn create(
    State(state): State<SharedAppState>,
    user: AuthUser,
    req: Request,
) -> Result<Response, ApiError> {
    let enabled: Option<String> =
        sqlx::query_scalar("SELECT value FROM system_configs WHERE key = 'ticket_enabled'")
            .fetch_optional(&state.db)
            .await?;
    if enabled.as_deref() == Some("false") {
        return Err(ApiError::forbidden(code::FORBIDDEN)
            .with_details("Ticket creation is disabled"));
    }

    let payload = read_ticket_payload(&state, req).await?;
    let fields = &payload.fields;
    let instance_id = fields.get("instanceId").and_then(|v| v.parse::<i32>().ok());
    let subject = fields.get("subject").cloned().unwrap_or_default().trim().to_string();
    let category = fields.get("category").cloned().unwrap_or_default().trim().to_string();
    let priority = fields.get("priority").cloned().unwrap_or_default().trim().to_string();
    let content = fields.get("content").cloned().unwrap_or_default().trim().to_string();

    let subject_len = subject.chars().count();
    if subject_len < 2 || subject_len > 200 {
        return Err(ApiError::bad_request(code::INVALID_PARAMS)
            .with_details("Subject must be 2-200 characters"));
    }
    if content.chars().count() > 5000 {
        return Err(ApiError::bad_request(code::INVALID_PARAMS)
            .with_details("Content must be 0-5000 characters"));
    }
    if payload.images.is_empty() && content.chars().count() < 10 {
        return Err(ApiError::bad_request(code::INVALID_PARAMS)
            .with_details("Content must be 10-5000 characters when no images are attached"));
    }
    if !category.is_empty() && !VALID_CATEGORIES.contains(&category.as_str()) {
        return Err(ApiError::bad_request(code::INVALID_PARAMS).with_details("Invalid category"));
    }
    if !priority.is_empty() && !VALID_PRIORITIES.contains(&priority.as_str()) {
        return Err(ApiError::bad_request(code::INVALID_PARAMS).with_details("Invalid priority"));
    }

    let mut host_id: Option<i32> = None;
    let mut host_owner_role: Option<(i32, String, String)> = None; // (owner_id, name, role)
    let mut instance_name: Option<String> = None;
    if let Some(instance_id) = instance_id {
        let instance: Option<(i32, i32, i32, String)> = sqlx::query_as(
            "SELECT id, user_id, host_id, name FROM instances WHERE id = $1",
        )
        .bind(instance_id)
        .fetch_optional(&state.db)
        .await?;
        let Some((_, owner, host, name)) = instance else {
            return Err(ApiError::bad_request(code::INSTANCE_NOT_FOUND));
        };
        if owner != user.id {
            return Err(ApiError::bad_request(code::INSTANCE_NOT_FOUND));
        }
        host_id = Some(host);
        instance_name = Some(name);
        let host_info: Option<(i32, String, String)> = sqlx::query_as(
            "SELECT user_id, name, (SELECT role::text FROM users WHERE id = hosts.user_id) FROM hosts WHERE id = $1",
        )
        .bind(host)
        .fetch_optional(&state.db)
        .await?;
        host_owner_role = host_info;
    }

    let uploaded = if payload.images.is_empty() {
        Vec::new()
    } else {
        upload_ticket_images(&state, payload.images).await?
    };

    // createTicket 事务
    let created: Result<(i32, i32), sqlx::Error> = async {
        let mut tx = state.db.begin().await?;
        let ticket: (i32,) = sqlx::query_as(
            "INSERT INTO tickets (user_id, host_id, instance_id, subject, category, priority) \
             VALUES ($1, $2, $3, $4, $5::\"TicketCategory\", $6::\"TicketPriority\") RETURNING id",
        )
        .bind(user.id)
        .bind(host_id)
        .bind(instance_id)
        .bind(&subject)
        .bind(if category.is_empty() { "general" } else { &category })
        .bind(if priority.is_empty() { "normal" } else { &priority })
        .fetch_one(&mut *tx)
        .await?;
        let message: (i32,) = sqlx::query_as(
            "INSERT INTO ticket_messages (ticket_id, sender_id, content, is_from_owner) \
             VALUES ($1, $2, $3, false) RETURNING id",
        )
        .bind(ticket.0)
        .bind(user.id)
        .bind(&content)
        .fetch_one(&mut *tx)
        .await?;
        for a in &uploaded {
            sqlx::query(
                "INSERT INTO ticket_message_attachments \
                 (ticket_id, message_id, uploader_id, provider, provider_version, provider_file_id, \
                  filename, original_name, mime_type, size_bytes, width, height, url, thumbnail_url) \
                 VALUES ($1, $2, $3, 'lsky', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            )
            .bind(ticket.0)
            .bind(message.0)
            .bind(user.id)
            .bind(&a.provider_version)
            .bind(&a.provider_file_id)
            .bind(&a.filename)
            .bind(&a.original_name)
            .bind(&a.mime_type)
            .bind(a.size_bytes)
            .bind(a.width)
            .bind(a.height)
            .bind(&a.url)
            .bind(&a.thumbnail_url)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok((ticket.0, message.0))
    }
    .await;

    match created {
        Ok((ticket_id, message_id)) => {
            // 通知：托管节点 → 节点所有者；官方/无实例 → 所有管理员
            let (subject_notif, username) = (subject.clone(), user.username.clone());
            let host_label = host_owner_role
                .as_ref()
                .map(|(_, name, _)| name.clone())
                .unwrap_or_else(|| "系统".into());
            let instance_label = instance_name.unwrap_or_else(|| "无".into());
            let notify = async |to: i32| {
                crate::routes::users::create_inbox_notification(
                    &state,
                    to,
                    "ticket_created",
                    "🎫 新工单",
                    &format!(
                        "用户「{username}」提交了工单「{subject_notif}」（节点：{host_label}，实例：{instance_label}）"
                    ),
                    json!({ "username": username, "subject": subject_notif }),
                )
                .await;
            };
            match &host_owner_role {
                Some((owner_id, _, role)) if role != "admin" => notify(*owner_id).await,
                _ => {
                    let admins: Vec<i32> = sqlx::query_scalar(
                        "SELECT id FROM users WHERE role = 'admin' AND status = 'active'",
                    )
                    .fetch_all(&state.db)
                    .await
                    .unwrap_or_default();
                    for admin in admins {
                        notify(admin).await;
                    }
                }
            }

            Ok((
                StatusCode::CREATED,
                Json(json!({
                    "message": "Ticket created successfully",
                    "ticket": { "id": ticket_id, "messageId": message_id },
                })),
            )
                .into_response())
        }
        Err(err) => {
            cleanup_uploaded(&state, &uploaded).await;
            Err(ApiError::from_sql(err))
        }
    }
}

// ===========================================================================
// GET / — 我的工单
// ===========================================================================

async fn my_list(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let status = valid_status_filter(&query.status)?;
    let (page, page_size) = page_of(&query, 10, 100);
    let (where_sql, _) = list_where("t.user_id = $1", &status, &query.search);
    // bind user id safely: replace placeholder
    let where_sql = where_sql.replace("$1", &user.id.to_string());
    Ok(Json(list_tickets(&state, &where_sql, page, page_size).await?))
}

// ===========================================================================
// GET /pending-count
// ===========================================================================

async fn pending_count(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let is_admin = user.role == "admin";
    let user_count: i64 = if is_admin {
        0
    } else {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM tickets WHERE user_id = $1 AND status::text IN ('open','in_progress')")
            .bind(user.id)
            .fetch_one(&state.db)
            .await?
            .0
    };
    let owner_count: i64 = if is_admin {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM tickets WHERE status::text IN ('open','in_progress')")
            .fetch_one(&state.db)
            .await?
            .0
    } else {
        sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM tickets t JOIN hosts h ON h.id = t.host_id \
             WHERE h.user_id = $1 AND t.status::text IN ('open','in_progress')",
        )
        .bind(user.id)
        .fetch_one(&state.db)
        .await?
        .0
    };
    let host_count: i64 = if is_admin {
        0
    } else {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM hosts WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&state.db)
            .await?
            .0
    };
    Ok(Json(json!({
        "userTickets": user_count,
        "hostTickets": owner_count,
        "total": user_count + owner_count,
        "isHostOwner": is_admin || host_count > 0,
    })))
}

// ===========================================================================
// GET /attachments/:id/content — 鉴权代理
// ===========================================================================

async fn attachment_content(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(attachment_id): Path<String>,
) -> Result<Response, ApiError> {
    let attachment_id = parse_id_str(&attachment_id)?;
    let attachment: Option<(i32, String)> = sqlx::query_as(
        "SELECT ticket_id, url FROM ticket_message_attachments WHERE id = $1",
    )
    .bind(attachment_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((ticket_id, url)) = attachment else {
        return Err(ApiError::not_found(code::NOT_FOUND));
    };
    let access = can_user_access_ticket(&state, &user, ticket_id).await?;
    if !access.can_access {
        return Err(ApiError::not_found(code::NOT_FOUND));
    }

    // SSRF guard（withSafePublicFetch）
    let fetch = async {
        let parsed = url::Url::parse(&url).map_err(|_| "invalid url")?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err("invalid scheme".to_string());
        }
        let hostname = parsed.host_str().ok_or("no host")?;
        if !is_public_host_address(hostname) {
            let port = parsed.port_or_known_default().unwrap_or(443);
            let resolved = default_dns_resolver(hostname, port).await?;
            if resolved.is_empty() || resolved.iter().all(|a| !is_public_host_address(a)) {
                return Err("non-public target".to_string());
            }
        }
        let response = state
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| "fetch failed".to_string())?;
        if !response.status().is_success() {
            return Err("upstream invalid".to_string());
        }
        if let Some(len) = response.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()) {
            if let Ok(len) = len.parse::<usize>() {
                if len > MAX_PROXY_RESPONSE {
                    return Err("too large".to_string());
                }
            }
        }
        let bytes = response.bytes().await.map_err(|_| "read failed".to_string())?;
        if bytes.len() > MAX_PROXY_RESPONSE {
            return Err("too large".to_string());
        }
        Ok::<Bytes, String>(bytes)
    }
    .await;

    let bytes = match fetch {
        Ok(bytes) => bytes,
        Err(reason) => {
            tracing::warn!("Blocked unsafe ticket attachment target ({reason}): {url}");
            return Err(ApiError::internal("Failed to load remote image"));
        }
    };

    // magic-byte re-check vs stored mime
    let stored_mime: Option<String> = sqlx::query_scalar(
        "SELECT mime_type FROM ticket_message_attachments WHERE id = $1",
    )
    .bind(attachment_id)
    .fetch_one(&state.db)
    .await?;
    let stored_mime = stored_mime.unwrap_or_default();
    if detect_image_mime(&bytes) != Some(stored_mime.as_str()) {
        return Err(ApiError::internal("Remote attachment is not a valid image"));
    }

    let mut response = (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "private, no-store"),
            (header::CONTENT_TYPE, stored_mime.as_str()),
        ],
        bytes,
    )
        .into_response();
    response.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

// ===========================================================================
// GET /:id — 详情
// ===========================================================================

async fn detail(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let ticket_id = parse_id_str(&id)?;
    let access = can_user_access_ticket(&state, &user, ticket_id).await?;
    if !access.can_access {
        return Err(ApiError::not_found(code::NOT_FOUND));
    }
    let ticket: Option<TicketCoreRow> = sqlx::query_as(&format!(
        "SELECT {TICKET_CORE} FROM tickets t WHERE t.id = $1"
    ))
    .bind(ticket_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(ticket) = ticket else {
        return Err(ApiError::not_found(code::NOT_FOUND));
    };
    Ok(Json(json!({
        "ticket": ticket_detail_json(&state, &ticket).await?,
        "isOwner": access.is_owner,
        "isCreator": access.is_creator,
    })))
}

// ===========================================================================
// GET /:id/messages + POST /:id/messages
// ===========================================================================

type AttachmentRow = (
    i32, i32, i32, i32, String, Option<String>, String, String, String, i64,
    Option<i64>, Option<i64>, String, Option<String>,
);

fn attachment_json(row: &AttachmentRow) -> Value {
    json!({
        "id": row.0, "ticketId": row.1, "messageId": row.2, "uploaderId": row.3,
        "provider": "lsky", "providerVersion": row.4, "providerFileId": row.5,
        "filename": row.6, "originalName": row.7, "mimeType": row.8, "sizeBytes": row.9,
        "width": row.10, "height": row.11, "url": row.12, "thumbnailUrl": row.13,
    })
}

async fn messages(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let ticket_id = parse_id_str(&id)?;
    let access = can_user_access_ticket(&state, &user, ticket_id).await?;
    if !access.can_access {
        return Err(ApiError::not_found(code::NOT_FOUND));
    }
    let (page, page_size) = page_of(&query, 50, 100);

    let rows: Vec<(i32, i32, i32, String, bool, DateTime<Utc>, String, String, Option<String>)> =
        sqlx::query_as(
            "SELECT m.id, m.ticket_id, m.sender_id, m.content, m.is_from_owner, m.created_at, \
                    u.username, u.avatar_style, u.avatar_badge_id \
             FROM ticket_messages m JOIN users u ON u.id = m.sender_id \
             WHERE m.ticket_id = $1 ORDER BY m.created_at ASC LIMIT $2 OFFSET $3",
        )
        .bind(ticket_id)
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(&state.db)
        .await?;
    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ticket_messages WHERE ticket_id = $1",
    )
    .bind(ticket_id)
    .fetch_one(&state.db)
    .await?;

    let mut list = Vec::new();
    for (id, t_id, sender_id, content, is_from_owner, created_at, username, avatar_style, avatar_badge) in &rows {
        let attachments: Vec<AttachmentRow> = sqlx::query_as(
            "SELECT id, ticket_id, message_id, uploader_id, provider_version, provider_file_id, \
                    filename, original_name, mime_type, size_bytes, width, height, url, thumbnail_url \
             FROM ticket_message_attachments WHERE message_id = $1 ORDER BY id ASC",
        )
        .bind(id)
        .fetch_all(&state.db)
        .await?;
        list.push(json!({
            "id": id, "ticketId": t_id, "senderId": sender_id, "content": content,
            "isFromOwner": is_from_owner, "createdAt": iso(*created_at),
            "attachments": attachments.iter().map(attachment_json).collect::<Vec<_>>(),
            "sender": { "id": sender_id, "username": username, "avatarStyle": avatar_style, "avatarBadgeId": avatar_badge },
        }));
    }

    Ok(Json(json!({
        "messages": list,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "totalPages": (total + page_size - 1) / page_size.max(1),
    })))
}

async fn reply(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let ticket_id = parse_id_str(&id)?;
    let payload = read_ticket_payload(&state, req).await?;
    let content = payload.fields.get("content").cloned().unwrap_or_default().trim().to_string();

    if content.chars().count() > 5000 {
        return Err(ApiError::bad_request(code::INVALID_PARAMS)
            .with_details("Content must be 0-5000 characters"));
    }
    if payload.images.is_empty() && content.is_empty() {
        return Err(ApiError::bad_request(code::INVALID_PARAMS)
            .with_details("Content must be 1-5000 characters when no images are attached"));
    }

    let access = can_user_access_ticket(&state, &user, ticket_id).await?;
    if !access.can_access {
        return Err(ApiError::not_found(code::NOT_FOUND));
    }
    let ticket: Option<(String, Option<i32>, i32, String)> = sqlx::query_as(
        "SELECT subject, host_id, user_id, status::text FROM tickets WHERE id = $1",
    )
    .bind(ticket_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((subject, host_id, creator_id, status)) = ticket else {
        return Err(ApiError::not_found(code::NOT_FOUND));
    };
    if status == "closed" {
        return Err(ApiError::bad_request(code::INVALID_PARAMS)
            .with_details("Cannot reply to a closed ticket"));
    }

    let uploaded = if payload.images.is_empty() {
        Vec::new()
    } else {
        upload_ticket_images(&state, payload.images).await?
    };

    let created: Result<i32, sqlx::Error> = async {
        let mut tx = state.db.begin().await?;
        let message: (i32,) = sqlx::query_as(
            "INSERT INTO ticket_messages (ticket_id, sender_id, content, is_from_owner) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(ticket_id)
        .bind(user.id)
        .bind(&content)
        .bind(access.is_owner)
        .fetch_one(&mut *tx)
        .await?;
        for a in &uploaded {
            sqlx::query(
                "INSERT INTO ticket_message_attachments \
                 (ticket_id, message_id, uploader_id, provider, provider_version, provider_file_id, \
                  filename, original_name, mime_type, size_bytes, width, height, url, thumbnail_url) \
                 VALUES ($1, $2, $3, 'lsky', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            )
            .bind(ticket_id)
            .bind(message.0)
            .bind(user.id)
            .bind(&a.provider_version)
            .bind(&a.provider_file_id)
            .bind(&a.filename)
            .bind(&a.original_name)
            .bind(&a.mime_type)
            .bind(a.size_bytes)
            .bind(a.width)
            .bind(a.height)
            .bind(&a.url)
            .bind(&a.thumbnail_url)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("UPDATE tickets SET updated_at = now() WHERE id = $1")
            .bind(ticket_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(message.0)
    }
    .await;

    match created {
        Ok(message_id) => {
            // 通知（与 TS 相同的路由分支）
            let host_label = host_display_name(&state, host_id).await;
            let hosted_owner = hosted_owner_if_user_role(&state, host_id).await;
            let body_text = format!(
                "工单「{subject}」有新回复（来自 {username}，节点：{host_label}）",
                username = user.username
            );
            let notify = |to: i32| {
                notify_ticket_event(&state, to, "ticket_replied", "💬 工单新回复", &body_text, &subject)
            };
            if access.is_owner {
                notify(creator_id).await;
            } else if let Some(owner) = hosted_owner {
                notify(owner).await;
            } else {
                let admins: Vec<i32> = sqlx::query_scalar(
                    "SELECT id FROM users WHERE role = 'admin' AND status = 'active'",
                )
                .fetch_all(&state.db)
                .await
                .unwrap_or_default();
                for admin in admins {
                    notify(admin).await;
                }
            }

            Ok((
                StatusCode::CREATED,
                Json(json!({ "message": "Message added successfully", "data": { "id": message_id } })),
            )
                .into_response())
        }
        Err(err) => {
            cleanup_uploaded(&state, &uploaded).await;
            Err(ApiError::from_sql(err))
        }
    }
}

// ===========================================================================
// DELETE /:id/messages/:messageId (admin)
// ===========================================================================

async fn delete_message(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path((id, message_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let ticket_id = parse_id_str(&id)?;
    let message_id = parse_id_str(&message_id)?;

    let belongs: Option<i32> = sqlx::query_scalar(
        "SELECT ticket_id FROM ticket_messages WHERE id = $1",
    )
    .bind(message_id)
    .fetch_optional(&state.db)
    .await?;
    if belongs != Some(ticket_id) {
        return Err(ApiError::not_found(code::NOT_FOUND));
    }

    let attachments: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT provider_version, provider_file_id FROM ticket_message_attachments WHERE message_id = $1",
    )
    .bind(message_id)
    .fetch_all(&state.db)
    .await?;

    sqlx::query("DELETE FROM ticket_messages WHERE id = $1")
        .bind(message_id)
        .execute(&state.db)
        .await?;
    if !attachments.is_empty() {
        cleanup_attachment_rows(&state, &attachments).await;
    }
    Ok(Json(json!({ "message": "Message deleted successfully" })))
}

// ===========================================================================
// PATCH /:id/status
// ===========================================================================

#[derive(Deserialize)]
struct StatusBody {
    status: Option<String>,
}

async fn update_status(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<StatusBody>>,
) -> Result<Json<Value>, ApiError> {
    let ticket_id = parse_id_str(&id)?;
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let Some(status) = body
        .status
        .as_deref()
        .filter(|s| VALID_STATUSES.contains(s))
    else {
        return Err(ApiError::bad_request(code::INVALID_PARAMS).with_details("Invalid status"));
    };

    let access = can_user_access_ticket(&state, &user, ticket_id).await?;
    if !access.can_access || !access.is_owner {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let ticket: Option<(String, i32)> =
        sqlx::query_as("SELECT subject, user_id FROM tickets WHERE id = $1")
            .bind(ticket_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((subject, creator_id)) = ticket else {
        return Err(ApiError::not_found(code::NOT_FOUND));
    };

    sqlx::query(&format!(
        "UPDATE tickets SET status = $2::\"TicketStatus\", resolved_at = CASE WHEN '{status}'='resolved' THEN now() ELSE NULL END, \
         closed_at = CASE WHEN '{status}'='closed' THEN now() ELSE NULL END, updated_at = now() WHERE id = $1"
    ))
    .bind(ticket_id)
    .bind(status)
    .execute(&state.db)
    .await?;

    crate::routes::users::create_inbox_notification(
        &state,
        creator_id,
        "ticket_status_changed",
        "📌 工单状态更新",
        &format!("工单「{subject}」状态已更新为 {status}"),
        json!({ "subject": subject, "newStatus": status }),
    )
    .await;

    Ok(Json(json!({ "message": "Status updated successfully", "status": status })))
}

// ===========================================================================
// POST /:id/close
// ===========================================================================

async fn close(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let ticket_id = parse_id_str(&id)?;
    let access = can_user_access_ticket(&state, &user, ticket_id).await?;
    if !access.can_access {
        return Err(ApiError::not_found(code::NOT_FOUND));
    }

    let ticket: Option<(String, Option<i32>, i32, String)> = sqlx::query_as(
        "SELECT subject, host_id, user_id, status::text FROM tickets WHERE id = $1",
    )
    .bind(ticket_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((subject, host_id, creator_id, status)) = ticket else {
        return Err(ApiError::not_found(code::NOT_FOUND));
    };
    if status == "closed" {
        return Err(ApiError::bad_request(code::INVALID_PARAMS).with_details("Ticket is already closed"));
    }

    sqlx::query(
        "UPDATE tickets SET status = 'closed', closed_at = now(), updated_at = now() WHERE id = $1",
    )
    .bind(ticket_id)
    .execute(&state.db)
    .await?;

    let host_label = host_display_name(&state, host_id).await;
    let body_text = format!("工单「{subject}」已由 {} 关闭（节点：{host_label}）", user.username);
    let hosted_owner = hosted_owner_if_user_role(&state, host_id).await;
    let notify = |to: i32| {
        notify_ticket_event(&state, to, "ticket_closed", "✅ 工单已关闭", &body_text, &subject)
    };
    if access.is_creator {
        if let Some(owner) = hosted_owner {
            notify(owner).await;
        } else {
            let admins: Vec<i32> = sqlx::query_scalar(
                "SELECT id FROM users WHERE role = 'admin' AND status = 'active'",
            )
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
            for admin in admins {
                notify(admin).await;
            }
        }
    } else {
        notify(creator_id).await;
    }

    Ok(Json(json!({ "message": "Ticket closed successfully" })))
}

// ===========================================================================
// GET /hosts/:hostId + /my-hosts
// ===========================================================================

async fn host_list(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(host_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let host_id = parse_id_str(&host_id)?;
    let host_owner: Option<i32> = sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
        .bind(host_id)
        .fetch_optional(&state.db)
        .await?;
    let Some(owner) = host_owner else {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    };
    if owner != user.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    let status = valid_status_filter(&query.status)?;
    let (page, page_size) = page_of(&query, 10, 100);
    let (where_sql, _) = list_where(&format!("t.host_id = {host_id}"), &status, &query.search);
    Ok(Json(list_tickets(&state, &where_sql, page, page_size).await?))
}

async fn my_hosts(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let is_admin = user.role == "admin";
    let status = valid_status_filter(&query.status)?;

    let source_type = query.source_type.as_deref();
    if let Some(st) = source_type {
        if !["all", "user", "official", "hosted"].contains(&st) {
            return Err(ApiError::bad_request(code::INVALID_PARAMS).with_details("Invalid source type"));
        }
    }
    if !is_admin {
        if let Some(st) = source_type {
            if st != "all" && st != "hosted" {
                return Err(ApiError::forbidden(code::FORBIDDEN));
            }
        }
    }
    let host_id = query.host_id.as_deref().and_then(|v| v.parse::<i32>().ok());
    if host_id.is_some() && source_type == Some("user") {
        return Err(ApiError::bad_request(code::INVALID_PARAMS)
            .with_details("User tickets cannot be filtered by host"));
    }
    if let Some(hid) = host_id {
        if !is_admin {
            let owner: Option<i32> = sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
                .bind(hid)
                .fetch_optional(&state.db)
                .await?;
            if owner != Some(user.id) {
                return Err(ApiError::forbidden(code::FORBIDDEN));
            }
        }
    }

    let (page, page_size) = page_of(&query, 10, 100);
    // 管理员 → 所有工单；普通用户 → 自己节点的工单
    let mut base = if is_admin {
        "1=1".to_string()
    } else {
        format!("t.host_id IN (SELECT id FROM hosts WHERE user_id = {})", user.id)
    };
    match source_type {
        Some("user") => base.push_str(" AND t.host_id IS NULL"),
        Some("official") => {
            base.push_str(" AND t.host_id IN (SELECT h.id FROM hosts h JOIN users u ON u.id = h.user_id WHERE u.role = 'admin')")
        }
        Some("hosted") => {
            base.push_str(" AND t.host_id IN (SELECT h.id FROM hosts h JOIN users u ON u.id = h.user_id WHERE u.role != 'admin')")
        }
        _ => {}
    }
    if let Some(hid) = host_id {
        base.push_str(&format!(" AND t.host_id = {hid}"));
    }
    let (where_sql, _) = list_where(&base, &status, &query.search);
    Ok(Json(list_tickets(&state, &where_sql, page, page_size).await?))
}
