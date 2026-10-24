//! 通知渠道管理路由 — port of server/src/routes/notifications.ts
//! (+ db/notifications.ts log/stats queries; notifier.testNotificationChannel
//! best-effort: Telegram/Discord/Webhook send for real via state.http, email
//! reports a stub failure; a notification_logs row records the attempt).
//!
//! All endpoints use `fastify.authenticate` → AuthUser; channels are strictly
//! per-owner (admins manage system-level channels elsewhere).

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sqlx::FromRow;

use crate::auth::AuthUser;
use crate::error::{code, ApiError};
use crate::libs::incus::incus_tls::{default_dns_resolver, is_public_host_address};
use crate::libs::instance_common::iso;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list).post(add))
        .route("/{id}", get(get_one).patch(axum::routing::patch(update)).delete(remove))
        .route("/{id}/test", post(test_channel))
        .route("/{id}/toggle", post(toggle))
        .route("/logs", get(logs))
        .route("/stats", get(stats))
        .route("/global-channels", get(global_channels))
}

fn parse_id_str(raw: &str) -> Result<i32, ApiError> {
    // TS uses Number() (strict full-string parse).
    raw.trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))
}

#[derive(Debug, FromRow)]
struct ChannelRow {
    id: i32,
    user_id: i32,
    #[sqlx(rename = "type")]
    channel_type: String,
    name: String,
    config: Value,
    enabled: bool,
    created_at: DateTime<Utc>,
}

const CHANNEL_COLUMNS: &str = "id, user_id, type::text AS \"type\", name, config, enabled, created_at";

async fn get_channel(state: &SharedAppState, id: i32) -> Result<Option<ChannelRow>, ApiError> {
    Ok(sqlx::query_as::<_, ChannelRow>(&format!(
        "SELECT {CHANNEL_COLUMNS} FROM notification_channels WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?)
}

async fn owned_channel(
    state: &SharedAppState,
    user: &AuthUser,
    id: i32,
) -> Result<ChannelRow, ApiError> {
    let channel = get_channel(state, id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::NOTIFICATION_CHANNEL_NOT_FOUND))?;
    if channel.user_id != user.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    Ok(channel)
}

fn config_map(config: &Value) -> Map<String, Value> {
    config.as_object().cloned().unwrap_or_default()
}

/// routes validateConfig.
fn validate_config(channel_type: &str, config: &Map<String, Value>) -> Result<(), String> {
    match channel_type {
        "telegram" => {
            if config.get("botToken").and_then(Value::as_str).unwrap_or("").is_empty()
                || config.get("chatId").is_none()
            {
                return Err("Please provide Bot Token and Chat ID".into());
            }
        }
        "discord" => {
            let url = config.get("webhookUrl").and_then(Value::as_str).unwrap_or("");
            if url.is_empty() {
                return Err("Please provide Discord Webhook URL".into());
            }
            if !url.starts_with("https://discord.com/api/webhooks/") {
                return Err("Invalid Discord Webhook URL".into());
            }
        }
        "webhook" => {
            let url = config.get("url").and_then(Value::as_str).unwrap_or("");
            if url.is_empty() {
                return Err("Please provide Webhook URL".into());
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err("Invalid Webhook URL".into());
            }
        }
        "email" => {
            if config.get("email").is_none() {
                return Err("Please provide email address".into());
            }
        }
        _ => {}
    }
    Ok(())
}

/// routes validateOutboundConfig — SSRF guard for generic webhook URLs
/// (outbound-security.assertSafeWebhookUrl: http(s) + public hostname).
async fn validate_outbound_config(
    channel_type: &str,
    config: &Map<String, Value>,
) -> Result<(), String> {
    if channel_type != "webhook" {
        return Ok(());
    }
    let Some(url) = config.get("url").and_then(Value::as_str) else {
        return Ok(());
    };
    let parsed = url::Url::parse(url).map_err(|_| "Webhook URL must use http or https".to_string())?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("Webhook URL must use http or https".into());
    }
    let hostname = parsed
        .host_str()
        .ok_or_else(|| "Webhook URL must use http or https".to_string())?
        .to_string();
    if !is_public_host_address(&hostname) {
        let port = parsed.port_or_known_default().unwrap_or(443);
        let resolved = default_dns_resolver(&hostname, port).await?;
        if resolved.is_empty() || resolved.iter().all(|a| !is_public_host_address(a)) {
            return Err("Webhook target must resolve to a public address".into());
        }
    }
    Ok(())
}

fn config_preview(channel_type: &str, config: &Value) -> String {
    let cfg = config_map(config);
    match channel_type {
        "telegram" => format!(
            "Chat ID: {}",
            cfg.get("chatId").map(|v| v.to_string()).filter(|s| s != "\"\"" && s != "null").map(|s| s.trim_matches('"').to_string()).unwrap_or_else(|| "Not set".into())
        ),
        "discord" => match cfg.get("webhookUrl").and_then(Value::as_str) {
            Some(u) if !u.is_empty() => {
                let tail: String = u.chars().rev().take(20).collect::<Vec<_>>().into_iter().rev().collect();
                format!("Webhook: ...{tail}")
            }
            _ => "Not set".into(),
        },
        "webhook" => match cfg.get("url").and_then(Value::as_str) {
            Some(u) if !u.is_empty() => match url::Url::parse(u) {
                Ok(parsed) => format!("URL: {}", parsed.host_str().unwrap_or("Invalid")),
                Err(_) => "URL: Invalid".into(),
            },
            _ => "Not set".into(),
        },
        "email" => cfg
            .get("email")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Not set".into()),
        _ => "Unknown type".into(),
    }
}

fn mask_sensitive_config(channel_type: &str, config: &Map<String, Value>) -> Value {
    let mut masked = config.clone();
    match channel_type {
        "telegram" => {
            if let Some(token) = masked.get("botToken").and_then(Value::as_str) {
                if !token.is_empty() {
                    let head: String = token.chars().take(10).collect();
                    let tail: String = token.chars().rev().take(5).collect::<Vec<_>>().into_iter().rev().collect();
                    masked.insert("botToken".into(), json!(format!("{head}...{tail}")));
                }
            }
        }
        "discord" => {
            if let Some(u) = masked.get("webhookUrl").and_then(Value::as_str) {
                if !u.is_empty() {
                    let head: String = u.chars().take(50).collect();
                    masked.insert("webhookUrl".into(), json!(format!("{head}...")));
                }
            }
        }
        "webhook" => {
            if masked.get("secret").map_or(false, |s| !s.is_null()) {
                masked.insert("secret".into(), json!("***已设置***"));
            }
        }
        _ => {}
    }
    Value::Object(masked)
}

// ===========================================================================
// GET / — 列表
// ===========================================================================

async fn list(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let channels = sqlx::query_as::<_, ChannelRow>(&format!(
        "SELECT {CHANNEL_COLUMNS} FROM notification_channels WHERE user_id = $1 \
         ORDER BY created_at ASC"
    ))
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;

    let items: Vec<Value> = channels
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "type": c.channel_type,
                "name": c.name,
                "enabled": c.enabled,
                "configPreview": config_preview(&c.channel_type, &c.config),
                "createdAt": iso(c.created_at),
            })
        })
        .collect();
    Ok(Json(json!({ "channels": items })))
}

// ===========================================================================
// GET /:id — 详情（掩码配置）
// ===========================================================================

async fn get_one(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let channel_id = parse_id_str(&id)?;
    let channel = owned_channel(&state, &user, channel_id).await?;
    Ok(Json(json!({
        "channel": {
            "id": channel.id,
            "type": channel.channel_type,
            "name": channel.name,
            "config": mask_sensitive_config(&channel.channel_type, &config_map(&channel.config)),
            "enabled": channel.enabled,
            "createdAt": iso(channel.created_at),
        }
    })))
}

// ===========================================================================
// POST / — 添加
// ===========================================================================

#[derive(Deserialize)]
struct AddBody {
    #[serde(rename = "type")]
    channel_type: Option<String>,
    name: Option<String>,
    config: Option<Value>,
    enabled: Option<bool>,
}

async fn add(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<AddBody>>,
) -> Result<Response, ApiError> {
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let channel_type = body
        .channel_type
        .filter(|t| ["telegram", "discord", "webhook", "email"].contains(&t.as_str()))
        .ok_or_else(|| ApiError::validation("type must be equal to one of the allowed values"))?;
    let name = body
        .name
        .filter(|n| (1..=50).contains(&n.chars().count()))
        .ok_or_else(|| ApiError::validation("name must be between 1 and 50 characters"))?;
    let config = body
        .config
        .filter(Value::is_object)
        .ok_or_else(|| ApiError::validation("config must be object"))?;
    let enabled = body.enabled.unwrap_or(true);

    let config = config_map(&config);
    validate_config(&channel_type, &config)
        .map_err(|e| ApiError::bare(axum::http::StatusCode::BAD_REQUEST, e))?;
    validate_outbound_config(&channel_type, &config)
        .await
        .map_err(|e| ApiError::bare(axum::http::StatusCode::BAD_REQUEST, e))?;

    let row: (i32,) = sqlx::query_as(
        "INSERT INTO notification_channels (user_id, type, name, config, enabled) \
         VALUES ($1, $2::\"NotificationChannelType\", $3, $4, $5) RETURNING id",
    )
    .bind(user.id)
    .bind(&channel_type)
    .bind(&name)
    .bind(Value::Object(config))
    .bind(enabled)
    .fetch_one(&state.db)
    .await?;

    crate::routes::users::create_log(
        &state,
        user.id,
        "notification",
        "notification.add",
        &format!("Added {channel_type} notification channel \"{name}\""),
        "success",
    )
    .await;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "message": "Notification channel added",
            "channel": { "id": row.0, "type": channel_type, "name": name, "enabled": enabled },
        })),
    )
        .into_response())
}

// ===========================================================================
// PATCH /:id — 更新
// ===========================================================================

#[derive(Deserialize)]
struct UpdateBody {
    name: Option<String>,
    config: Option<Value>,
    enabled: Option<bool>,
}

async fn update(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<UpdateBody>>,
) -> Result<Json<Value>, ApiError> {
    let channel_id = parse_id_str(&id)?;
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    if let Some(name) = &body.name {
        if !(1..=50).contains(&name.chars().count()) {
            return Err(ApiError::validation("name must be between 1 and 50 characters"));
        }
    }
    if let Some(config) = &body.config {
        if !config.is_object() {
            return Err(ApiError::validation("config must be object"));
        }
    }

    let channel = owned_channel(&state, &user, channel_id).await?;

    if let Some(config) = &body.config {
        let config = config_map(config);
        validate_config(&channel.channel_type, &config)
            .map_err(|e| ApiError::bare(axum::http::StatusCode::BAD_REQUEST, e))?;
        validate_outbound_config(&channel.channel_type, &config)
            .await
            .map_err(|e| ApiError::bare(axum::http::StatusCode::BAD_REQUEST, e))?;
    }

    // Partial update (name/config/enabled when present).
    sqlx::query(
        "UPDATE notification_channels SET \
         name = COALESCE($1, name), \
         config = CASE WHEN $2::boolean THEN $3 ELSE config END, \
         enabled = COALESCE($4, enabled) \
         WHERE id = $5",
    )
    .bind(body.name.as_deref())
    .bind(body.config.is_some())
    .bind(body.config.as_ref().map(|c| c.clone()))
    .bind(body.enabled)
    .bind(channel_id)
    .execute(&state.db)
    .await?;

    let mut changes: Vec<String> = Vec::new();
    if let Some(name) = &body.name {
        changes.push(format!("name -> \"{name}\""));
    }
    if body.config.is_some() {
        changes.push("config updated".into());
    }
    if let Some(enabled) = body.enabled {
        changes.push(format!("enabled -> {enabled}"));
    }

    crate::routes::users::create_log(
        &state,
        user.id,
        "notification",
        "notification.update",
        &format!(
            "Updated {} notification channel \"{}\": {}",
            channel.channel_type,
            channel.name,
            changes.join(", ")
        ),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Notification channel updated" })))
}

// ===========================================================================
// DELETE /:id
// ===========================================================================

async fn remove(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let channel_id = parse_id_str(&id)?;
    let channel = owned_channel(&state, &user, channel_id).await?;

    sqlx::query("DELETE FROM notification_channels WHERE id = $1")
        .bind(channel_id)
        .execute(&state.db)
        .await?;

    crate::routes::users::create_log(
        &state,
        user.id,
        "notification",
        "notification.delete",
        &format!(
            "Deleted {} notification channel \"{}\"",
            channel.channel_type, channel.name
        ),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Notification channel deleted" })))
}

// ===========================================================================
// POST /:id/test — 测试发送
// ===========================================================================

async fn test_channel(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let channel_id = parse_id_str(&id)?;
    let channel = owned_channel(&state, &user, channel_id).await?;
    let config = config_map(&channel.config);

    let message = format!("Incudal test notification ({})", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    let send: Result<(), String> = match channel.channel_type.as_str() {
        "telegram" => {
            let token = config
                .get("botToken")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let chat_id = config.get("chatId").cloned().unwrap_or(Value::Null);
            match state
                .http
                .post(format!("https://api.telegram.org/bot{token}/sendMessage"))
                .json(&json!({ "chat_id": chat_id, "text": message }))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => Ok(()),
                Ok(r) => Err(format!("HTTP {}", r.status())),
                Err(e) => Err(e.to_string()),
            }
        }
        "discord" | "webhook" => {
            let url = if channel.channel_type == "discord" {
                config.get("webhookUrl").and_then(Value::as_str).unwrap_or_default()
            } else {
                config.get("url").and_then(Value::as_str).unwrap_or_default()
            };
            match state
                .http
                .post(url)
                .json(&json!({ "content": message, "text": message }))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => Ok(()),
                Ok(r) => Err(format!("HTTP {}", r.status())),
                Err(e) => Err(e.to_string()),
            }
        }
        "email" => Err("SMTP sending is not available in the Rust server".into()),
        other => Err(format!("Unknown channel type: {other}")),
    };

    let (status, error) = match &send {
        Ok(()) => ("sent", None),
        Err(e) => ("failed", Some(e.clone())),
    };
    let _ = sqlx::query(
        "INSERT INTO notification_logs (channel_id, event_type, message, status, error) \
         VALUES ($1, 'test', $2, $3::\"NotificationLogStatus\", $4)",
    )
    .bind(channel.id)
    .bind(&message)
    .bind(status)
    .bind(&error)
    .execute(&state.db)
    .await;

    match send {
        Ok(()) => Ok(Json(json!({ "message": "Test notification sent" }))),
        Err(e) => Err(ApiError::with_message(
            "TEST_FAILED",
            axum::http::StatusCode::BAD_REQUEST,
            format!("Test failed: {e}"),
        )),
    }
}

// ===========================================================================
// POST /:id/toggle
// ===========================================================================

async fn toggle(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let channel_id = parse_id_str(&id)?;
    let channel = owned_channel(&state, &user, channel_id).await?;

    let new_enabled = !channel.enabled;
    sqlx::query("UPDATE notification_channels SET enabled = $2 WHERE id = $1")
        .bind(channel_id)
        .bind(new_enabled)
        .execute(&state.db)
        .await?;

    crate::routes::users::create_log(
        &state,
        user.id,
        "notification",
        if new_enabled { "notification.enable" } else { "notification.disable" },
        &format!(
            "{} {} notification channel \"{}\"",
            if new_enabled { "Enabled" } else { "Disabled" },
            channel.channel_type,
            channel.name
        ),
        "success",
    )
    .await;

    Ok(Json(json!({
        "message": if new_enabled { "Notification channel enabled" } else { "Notification channel disabled" },
        "enabled": new_enabled,
    })))
}

// ===========================================================================
// GET /logs — 通知历史（分页）
// ===========================================================================

#[derive(Deserialize)]
struct LogsQuery {
    page: Option<String>,
    #[serde(rename = "pageSize")]
    page_size: Option<String>,
    status: Option<String>,
}

#[derive(Debug, FromRow)]
struct LogRow {
    id: i32,
    channel_id: i32,
    event_type: String,
    message: String,
    #[sqlx(rename = "status")]
    log_status: String,
    error: Option<String>,
    created_at: DateTime<Utc>,
    channel_name: Option<String>,
    channel_type: Option<String>,
}

async fn logs(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Value>, ApiError> {
    let params: HashMap<String, String> = [
        Some(("page".to_string(), query.page.unwrap_or_default())),
        Some(("pageSize".to_string(), query.page_size.unwrap_or_default())),
    ]
    .into_iter()
    .flatten()
    .collect();
    let pagination = crate::response::parse_pagination(&params, 20, Some(100));

    let valid_status = query.status.as_deref().filter(|s| ["pending", "sent", "failed"].contains(s));

    let rows = sqlx::query_as::<_, LogRow>(
        "SELECT l.id, l.channel_id, l.event_type, l.message, l.status::text AS status, \
                l.error, l.created_at, c.name AS channel_name, c.type::text AS channel_type \
         FROM notification_logs l JOIN notification_channels c ON c.id = l.channel_id \
         WHERE c.user_id = $1 AND ($2::text IS NULL OR l.status::text = $2) \
         ORDER BY l.created_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(user.id)
    .bind(valid_status)
    .bind(pagination.take)
    .bind(pagination.skip)
    .fetch_all(&state.db)
    .await?;

    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM notification_logs l JOIN notification_channels c ON c.id = l.channel_id \
         WHERE c.user_id = $1 AND ($2::text IS NULL OR l.status::text = $2)",
    )
    .bind(user.id)
    .bind(valid_status)
    .fetch_one(&state.db)
    .await?;

    let logs: Vec<Value> = rows
        .iter()
        .map(|l| {
            json!({
                "id": l.id,
                "channelId": l.channel_id,
                "channelName": l.channel_name,
                "channelType": l.channel_type,
                "eventType": l.event_type,
                "message": l.message,
                "status": l.log_status,
                "error": l.error,
                "createdAt": iso(l.created_at),
            })
        })
        .collect();

    Ok(Json(json!({
        "logs": logs,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
    })))
}

// ===========================================================================
// GET /stats
// ===========================================================================

async fn stats(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let (total, sent, failed, pending): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), \
                COUNT(*) FILTER (WHERE status::text = 'sent'), \
                COUNT(*) FILTER (WHERE status::text = 'failed'), \
                COUNT(*) FILTER (WHERE status::text = 'pending') \
         FROM notification_logs l JOIN notification_channels c ON c.id = l.channel_id \
         WHERE c.user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(json!({ "stats": { "total": total, "sent": sent, "failed": failed, "pending": pending } })))
}

// ===========================================================================
// GET /global-channels — 托管用户绑定套餐用
// ===========================================================================

async fn global_channels(
    State(state): State<SharedAppState>,
    _user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(i32, String, String, Value)> = sqlx::query_as(
        "SELECT id, name, type::text, config FROM notification_channels \
         WHERE is_global = true AND enabled = true ORDER BY created_at ASC",
    )
    .fetch_all(&state.db)
    .await?;

    let channels: Vec<Value> = rows
        .iter()
        .map(|(id, name, channel_type, config)| {
            let cfg = config_map(config);
            json!({
                "id": id,
                "name": name,
                "type": channel_type,
                "configPreview": format!(
                    "Chat ID: {}",
                    cfg.get("chatId").and_then(Value::as_i64).map(|v| v.to_string())
                        .or_else(|| cfg.get("chatId").and_then(Value::as_str).map(|s| s.to_string()))
                        .unwrap_or_else(|| "N/A".into())
                ),
            })
        })
        .collect();
    Ok(Json(json!({ "channels": channels })))
}
