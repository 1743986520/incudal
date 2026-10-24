//! 管理员全局通知渠道 — port of server/src/routes/admin-notification-channels.ts.
//! Mounted at /api/admin/notification-channels; all endpoints authenticateAdmin.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::auth::AdminAuth;
use crate::error::ApiError;
use crate::libs::instance_common::iso;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(detail).patch(axum::routing::patch(update)).delete(remove))
        .route("/{id}/test", post(test_channel))
}

fn bad(message: impl Into<String>) -> ApiError {
    ApiError::bare(StatusCode::BAD_REQUEST, message)
}

fn not_found() -> ApiError {
    ApiError::bare(StatusCode::NOT_FOUND, "Channel not found")
}

fn parse_id(raw: &str) -> Result<i32, ApiError> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| bad("Invalid ID"))
}

fn config_of(raw: &Value) -> Map<String, Value> {
    raw.as_object().cloned().unwrap_or_default()
}

fn telegram_preview(config: &Map<String, Value>) -> String {
    let chat_id = config
        .get("chatId")
        .map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .filter(|s| !s.is_empty() && s != "null" && s != "\"\"")
        .unwrap_or_else(|| "Not set".into());
    format!("Chat ID: {chat_id}")
}

fn mask_bot_token(config: &Map<String, Value>) -> Value {
    let mut masked = config.clone();
    if let Some(token) = masked.get("botToken").and_then(Value::as_str) {
        if !token.is_empty() {
            let head: String = token.chars().take(8).collect();
            let tail: String = token.chars().rev().take(5).collect::<Vec<_>>().into_iter().rev().collect();
            masked.insert("botToken".into(), json!(format!("{head}...{tail}")));
        }
    }
    Value::Object(masked)
}

async fn global_channel(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<(i32, String, bool, Value, DateTime<Utc>)>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT id, name, enabled, config, created_at FROM notification_channels \
         WHERE id = $1 AND is_global = true",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?)
}

async fn list(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(i32, String, String, bool, Value, DateTime<Utc>, i64)> = sqlx::query_as(
        "SELECT c.id, c.name, c.type::text, c.enabled, c.config, c.created_at, \
                (SELECT COUNT(*) FROM packages p WHERE p.release_channel_id = c.id) \
         FROM notification_channels c WHERE c.is_global = true ORDER BY c.created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    let channels: Vec<Value> = rows
        .iter()
        .map(|(id, name, channel_type, enabled, config, created_at, bound)| {
            json!({
                "id": id,
                "name": name,
                "type": channel_type,
                "enabled": enabled,
                "boundPackages": bound,
                "configPreview": telegram_preview(&config_of(config)),
                "createdAt": iso(*created_at),
            })
        })
        .collect();
    Ok(Json(json!({ "channels": channels })))
}

async fn detail(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&id)?;
    let channel = global_channel(&state, id).await?.ok_or_else(not_found)?;
    let (id, name, enabled, config, created_at) = channel;
    Ok(Json(json!({
        "channel": {
            "id": id,
            "name": name,
            "type": "telegram",
            "enabled": enabled,
            "config": mask_bot_token(&config_of(&config)),
            "createdAt": iso(created_at),
        }
    })))
}

#[derive(Deserialize)]
struct CreateBody {
    name: Option<String>,
    #[serde(rename = "botToken")]
    bot_token: Option<String>,
    #[serde(rename = "chatId")]
    chat_id: Option<serde_json::Value>,
    enabled: Option<bool>,
}

async fn create(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    body: Option<Json<CreateBody>>,
) -> Result<Response, ApiError> {
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let name = body
        .name
        .filter(|n| (1..=50).contains(&n.chars().count()))
        .ok_or_else(|| ApiError::validation("name must be between 1 and 50 characters"))?;
    let bot_token = body
        .bot_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| ApiError::validation("botToken must NOT have fewer than 1 characters"))?;
    let chat_id = body
        .chat_id
        .clone()
        .filter(|v| !v.is_null() && !v.to_string().is_empty())
        .ok_or_else(|| ApiError::validation("chatId must NOT have fewer than 1 characters"))?;
    let enabled = body.enabled.unwrap_or(true);

    if !bot_token.contains(':') {
        return Err(bad("Invalid Bot Token format (should contain a colon)"));
    }

    let chat_id_display = chat_id.as_str().map(|s| s.to_string()).unwrap_or_else(|| chat_id.to_string());
    let row: (i32,) = sqlx::query_as(
        "INSERT INTO notification_channels (user_id, type, name, config, enabled, is_global) \
         VALUES ($1, 'telegram', $2, $3, $4, true) RETURNING id",
    )
    .bind(admin.0.id)
    .bind(&name)
    .bind(json!({ "botToken": bot_token, "chatId": chat_id }))
    .bind(enabled)
    .fetch_one(&state.db)
    .await?;

    crate::routes::users::create_log(
        &state,
        admin.0.id,
        "notification",
        "admin.global_channel.create",
        &format!("Created global TG channel \"{name}\" (chatId: {chat_id_display})"),
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Global notification channel created",
            "channel": { "id": row.0, "name": name, "type": "telegram", "enabled": enabled },
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
struct UpdateBody {
    name: Option<String>,
    #[serde(rename = "botToken")]
    bot_token: Option<String>,
    #[serde(rename = "chatId")]
    chat_id: Option<serde_json::Value>,
    enabled: Option<bool>,
}

async fn update(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
    body: Option<Json<UpdateBody>>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&id)?;
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    if let Some(name) = &body.name {
        if !(1..=50).contains(&name.chars().count()) {
            return Err(ApiError::validation("name must be between 1 and 50 characters"));
        }
    }

    let existing = global_channel(&state, id).await?.ok_or_else(not_found)?;
    let (_, existing_name, _, existing_config, _) = &existing;
    let existing_config = config_of(existing_config);

    // Merge config: new values win, else keep existing.
    let config_changed = body.bot_token.is_some() || body.chat_id.is_some();
    let new_config = json!({
        "botToken": body.bot_token.clone()
            .filter(|t| !t.is_empty())
            .map(Value::String)
            .or_else(|| existing_config.get("botToken").cloned())
            .unwrap_or(Value::Null),
        "chatId": body.chat_id.clone()
            .filter(|v| !v.is_null())
            .or_else(|| existing_config.get("chatId").cloned())
            .unwrap_or(Value::Null),
    });

    sqlx::query(
        "UPDATE notification_channels SET \
         name = COALESCE($1, name), \
         enabled = COALESCE($2, enabled), \
         config = CASE WHEN $3::boolean THEN $4 ELSE config END \
         WHERE id = $5",
    )
    .bind(body.name.as_deref())
    .bind(body.enabled)
    .bind(config_changed)
    .bind(new_config)
    .bind(id)
    .execute(&state.db)
    .await?;

    crate::routes::users::create_log(
        &state,
        admin.0.id,
        "notification",
        "admin.global_channel.update",
        &format!("Updated global TG channel \"{existing_name}\""),
        "success",
    )
    .await;
    Ok(Json(json!({ "message": "Channel updated" })))
}

async fn remove(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&id)?;
    let channel = global_channel(&state, id).await?.ok_or_else(not_found)?;
    let (_, name, ..) = channel;

    sqlx::query("DELETE FROM notification_channels WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;

    crate::routes::users::create_log(
        &state,
        admin.0.id,
        "notification",
        "admin.global_channel.delete",
        &format!("Deleted global TG channel \"{name}\""),
        "success",
    )
    .await;
    Ok(Json(json!({ "message": "Channel deleted" })))
}

async fn test_channel(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = parse_id(&id)?;
    let channel = global_channel(&state, id).await?.ok_or_else(not_found)?;
    let (_, _, _, config, _) = channel;
    let config = config_of(&config);
    let token = config
        .get("botToken")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let chat_id = config.get("chatId").cloned().unwrap_or(Value::Null);

    let message = format!("Incudal global channel test ({})", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    let result = state
        .http
        .post(format!("https://api.telegram.org/bot{token}/sendMessage"))
        .json(&json!({ "chat_id": chat_id, "text": message }))
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => Ok(Json(json!({ "message": "Test notification sent successfully" }))),
        Ok(resp) => Err(bad(format!("Test failed: HTTP {}", resp.status()))),
        Err(e) => Err(bad(format!("Test failed: {e}"))),
    }
}
