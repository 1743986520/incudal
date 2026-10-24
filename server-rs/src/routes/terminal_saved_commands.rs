//! 终端保存命令路由 — port of server/src/routes/terminal-saved-commands.ts
//! (+ db/terminal-saved-commands.ts: AES-GCM field encryption at rest,
//! normalizeCommandLabel/normalizeDescription, 100-per-user cap, 16KB limit).
//!
//! All endpoints use `fastify.authenticate` → AuthUser.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::AuthUser;
use crate::error::{code, ApiError};
use crate::libs::crypto::{decrypt_sensitive_data, encrypt_sensitive_data};
use crate::libs::instance_common::iso;
use crate::state::SharedAppState;

const MAX_COMMANDS_PER_USER: i64 = 100;
const MAX_COMMAND_SIZE: usize = 16 * 1024;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", put(update).delete(remove))
}

/// Raw row: name/command/description are encrypted at rest.
#[derive(Debug, FromRow)]
struct SavedCommandRow {
    id: i32,
    user_id: i32,
    name: String,
    command: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const ROW_COLUMNS: &str =
    "id, user_id, name, command, description, created_at, updated_at";

/// db mapTerminalSavedCommand: decrypt encrypted fields. Tampered ciphertext
/// fails closed (500) like the TS decryptSensitiveData; legacy plaintext rows
/// pass through; empty decrypt results fall back to the stored value (`|| x`).
fn decrypt_field(
    key: &[u8; 32],
    value: &str,
) -> Result<String, ApiError> {
    let decrypted = decrypt_sensitive_data(key, value)
        .map_err(|_| ApiError::internal("SENSITIVE_DATA_DECRYPTION_FAILED"))?;
    Ok(if decrypted.is_empty() { value.to_string() } else { decrypted })
}

fn map_row(state: &SharedAppState, row: &SavedCommandRow) -> Result<Value, ApiError> {
    let key = &state.config.encryption_key;
    let name = decrypt_field(key, &row.name)?;
    let command = decrypt_field(key, &row.command)?;
    let description = match &row.description {
        Some(d) => Some(decrypt_field(key, d)?),
        None => None,
    };
    Ok(json!({
        "id": row.id,
        "userId": row.user_id,
        "name": name,
        "command": command,
        "description": description,
        "createdAt": iso(row.created_at),
        "updatedAt": iso(row.updated_at),
    }))
}

// db normalizeCommandLabel: collapse \r\n\t runs to a space, strip C0/DEL, trim.
fn normalize_command_label(value: &str) -> String {
    let collapsed: String = value
        .chars()
        .map(|c| if c == '\r' || c == '\n' || c == '\t' { ' ' } else { c })
        .collect();
    collapsed
        .chars()
        .filter(|c| !matches!(u32::from(*c), 0x00..=0x1f | 0x7f))
        .collect::<String>()
        .trim()
        .to_string()
}

// db normalizeDescription: \r\n -> \n, strip control chars, trim; empty -> None.
fn normalize_description(value: Option<&str>) -> Option<String> {
    let value = value?;
    let normalized: String = value
        .replace("\r\n", "\n")
        .chars()
        .filter(|c| !matches!(u32::from(*c), 0x00..=0x1f | 0x7f))
        .collect::<String>()
        .trim()
        .to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

// ===========================================================================
// GET / — 列表
// ===========================================================================

async fn list(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query_as::<_, SavedCommandRow>(&format!(
        "SELECT {ROW_COLUMNS} FROM terminal_saved_commands \
         WHERE user_id = $1 ORDER BY updated_at DESC, id DESC"
    ))
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    let commands: Vec<Value> = rows
        .iter()
        .map(|r| map_row(&state, r))
        .collect::<Result<_, _>>()?;
    Ok(Json(json!({ "commands": commands })))
}

// ===========================================================================
// POST / — 创建
// ===========================================================================

#[derive(Deserialize)]
struct CreateBody {
    name: Option<String>,
    command: Option<String>,
    description: Option<serde_json::Value>,
}

async fn create(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<CreateBody>>,
) -> Result<Response, ApiError> {
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let name = body
        .name
        .filter(|n| (1..=80).contains(&n.chars().count()))
        .ok_or_else(|| ApiError::validation("name must be between 1 and 80 characters"))?;
    let command = body
        .command
        .filter(|c| (1..=16384).contains(&c.chars().count()))
        .ok_or_else(|| ApiError::validation("command must be between 1 and 16384 characters"))?;
    let description = match &body.description {
        None | Some(Value::Null) => None,
        Some(Value::String(d)) if d.chars().count() <= 300 => Some(d.clone()),
        Some(Value::String(_)) => {
            return Err(ApiError::validation(
                "description must NOT have more than 300 characters",
            ))
        }
        Some(_) => {
            return Err(ApiError::validation("description must be string or null"))
        }
    };

    let name = normalize_command_label(&name);
    if name.is_empty() {
        return Err(command_error("INVALID_NAME"));
    }
    if command.trim().is_empty() {
        return Err(command_error("INVALID_COMMAND"));
    }
    if command.len() > MAX_COMMAND_SIZE {
        return Err(command_error("COMMAND_TOO_LARGE"));
    }
    let description = normalize_description(description.as_deref());

    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM terminal_saved_commands WHERE user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;
    if count >= MAX_COMMANDS_PER_USER {
        return Err(command_error("MAX_COMMANDS_REACHED"));
    }

    let key = &state.config.encryption_key;
    let row = sqlx::query_as::<_, SavedCommandRow>(&format!(
        "INSERT INTO terminal_saved_commands (user_id, name, command, description, updated_at) \
         VALUES ($1, $2, $3, $4, now()) RETURNING {ROW_COLUMNS}"
    ))
    .bind(user.id)
    .bind(encrypt_sensitive_data(key, &name))
    .bind(encrypt_sensitive_data(key, &command))
    .bind(description.as_deref().map(|d| encrypt_sensitive_data(key, d)))
    .fetch_one(&state.db)
    .await?;

    crate::routes::users::create_log(
        &state,
        user.id,
        "terminal",
        "terminal.saved_command.create",
        &format!("Created terminal saved command \"{name}\""),
        "success",
    )
    .await;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "message": "Saved terminal command created",
            "command": map_row(&state, &row)?,
        })),
    )
        .into_response())
}

// ===========================================================================
// PUT /:id — 更新
// ===========================================================================

#[derive(Deserialize)]
struct UpdateBody {
    name: Option<String>,
    command: Option<String>,
    description: Option<serde_json::Value>,
}

fn parse_id(raw: &str) -> Result<i32, ApiError> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))
}

async fn update(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<UpdateBody>>,
) -> Result<Json<Value>, ApiError> {
    let command_id = parse_id(&id)?;
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;

    let existing = sqlx::query_as::<_, SavedCommandRow>(&format!(
        "SELECT {ROW_COLUMNS} FROM terminal_saved_commands \
         WHERE id = $1 AND user_id = $2 LIMIT 1"
    ))
    .bind(command_id)
    .bind(user.id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| command_error("NOT_FOUND"))?;
    let existing = map_row(&state, &existing)?;

    let next_name = match &body.name {
        Some(n) if (1..=80).contains(&n.chars().count()) => normalize_command_label(n),
        Some(_) => {
            return Err(ApiError::validation("name must be between 1 and 80 characters"))
        }
        None => existing["name"].as_str().unwrap_or_default().to_string(),
    };
    let next_command = match &body.command {
        Some(c) if (1..=16384).contains(&c.chars().count()) => c.clone(),
        Some(_) => {
            return Err(ApiError::validation("command must be between 1 and 16384 characters"))
        }
        None => existing["command"].as_str().unwrap_or_default().to_string(),
    };
    let next_description = match &body.description {
        None => existing["description"].as_str().map(|s| s.to_string()),
        Some(Value::Null) => None,
        Some(Value::String(d)) if d.chars().count() <= 300 => normalize_description(Some(d)),
        Some(Value::String(_)) => {
            return Err(ApiError::validation(
                "description must NOT have more than 300 characters",
            ))
        }
        Some(_) => return Err(ApiError::validation("description must be string or null")),
    };

    if next_name.is_empty() {
        return Err(command_error("INVALID_NAME"));
    }
    if next_command.trim().is_empty() {
        return Err(command_error("INVALID_COMMAND"));
    }
    if next_command.len() > MAX_COMMAND_SIZE {
        return Err(command_error("COMMAND_TOO_LARGE"));
    }

    let key = &state.config.encryption_key;
    let row = sqlx::query_as::<_, SavedCommandRow>(&format!(
        "UPDATE terminal_saved_commands SET name = $1, command = $2, description = $3, \
         updated_at = now() WHERE id = $4 AND user_id = $5 RETURNING {ROW_COLUMNS}"
    ))
    .bind(encrypt_sensitive_data(key, &next_name))
    .bind(encrypt_sensitive_data(key, &next_command))
    .bind(next_description.as_deref().map(|d| encrypt_sensitive_data(key, d)))
    .bind(command_id)
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    crate::routes::users::create_log(
        &state,
        user.id,
        "terminal",
        "terminal.saved_command.update",
        &format!("Updated terminal saved command \"{next_name}\" (#{command_id})"),
        "success",
    )
    .await;

    Ok(Json(json!({
        "message": "Saved terminal command updated",
        "command": map_row(&state, &row)?,
    })))
}

// ===========================================================================
// DELETE /:id — 删除
// ===========================================================================

async fn remove(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let command_id = parse_id(&id)?;

    let result = sqlx::query(
        "DELETE FROM terminal_saved_commands WHERE id = $1 AND user_id = $2",
    )
    .bind(command_id)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found(code::NOT_FOUND));
    }

    crate::routes::users::create_log(
        &state,
        user.id,
        "terminal",
        "terminal.saved_command.delete",
        &format!("Deleted terminal saved command #{command_id}"),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Saved terminal command deleted" })))
}

/// `{ error: message, code }` with the route's status mapping.
fn command_error(code_str: &'static str) -> ApiError {
    let (status, message) = match code_str {
        "INVALID_NAME" => (axum::http::StatusCode::BAD_REQUEST, "Command name is required"),
        "INVALID_COMMAND" => (axum::http::StatusCode::BAD_REQUEST, "Command content is required"),
        "COMMAND_TOO_LARGE" => (
            axum::http::StatusCode::BAD_REQUEST,
            "Command content too large (max 16KB)",
        ),
        "MAX_COMMANDS_REACHED" => (
            axum::http::StatusCode::BAD_REQUEST,
            "Maximum saved terminal commands reached (100)",
        ),
        "NOT_FOUND" => (axum::http::StatusCode::NOT_FOUND, "Saved command not found"),
        _ => (axum::http::StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
    };
    ApiError::with_message(code_str, status, message)
}
