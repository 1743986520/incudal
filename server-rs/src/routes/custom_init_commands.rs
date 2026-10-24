//! 用户自定义初始化命令路由 — port of server/src/routes/custom-init-commands.ts
//! (+ db/custom-init-commands.ts: 50-per-user cap, 64KB limit, distros stored
//! as a JSON string column, name/description trimmed).
//!
//! All endpoints use `fastify.authenticateUser` → UserOnlyAuth.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::UserOnlyAuth;
use crate::error::{code, ApiError};
use crate::libs::instance_common::iso;
use crate::state::SharedAppState;

const VALID_DISTROS: [&str; 7] = ["ubuntu", "debian", "rhel", "alpine", "arch", "suse", "all"];
const MAX_COMMANDS_PER_USER: i64 = 50;
const MAX_COMMAND_SIZE: usize = 64 * 1024;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/available", get(available))
        .route("/distros", get(distros))
        .route("/{id}", get(get_one).put(update).delete(remove))
}

#[derive(Debug, FromRow)]
struct CommandRow {
    id: i32,
    user_id: i32,
    name: String,
    command: String,
    /// JSON-encoded string array.
    distros: String,
    description: Option<String>,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const ROW_COLUMNS: &str =
    "id, user_id, name, command, distros, description, enabled, created_at, updated_at";

fn parse_distros(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default()
}

/// route truncateText: JS substring is UTF-16-based; chars() matches for BMP.
fn truncate_text(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut s: String = text.chars().take(max).collect();
    s.push_str("...");
    s
}

fn line_count(command: &str) -> usize {
    command.split('\n').filter(|l| !l.trim().is_empty()).count()
}

fn parse_id(raw: &str) -> Result<i32, ApiError> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))
}

fn invalid_distros_response(invalid: Vec<String>) -> Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "Invalid distros",
            "details": { "invalidDistros": invalid, "validDistros": VALID_DISTROS },
        })),
    )
        .into_response()
}

// ===========================================================================
// GET / — 列表（带预览）
// ===========================================================================

async fn list(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query_as::<_, CommandRow>(&format!(
        "SELECT {ROW_COLUMNS} FROM custom_init_commands \
         WHERE user_id = $1 ORDER BY created_at DESC"
    ))
    .bind(user.0.id)
    .fetch_all(&state.db)
    .await?;

    let commands: Vec<Value> = rows
        .iter()
        .map(|cmd| {
            json!({
                "id": cmd.id,
                "name": cmd.name,
                "commandPreview": truncate_text(&cmd.command, 100),
                "commandLineCount": line_count(&cmd.command),
                "distros": parse_distros(&cmd.distros),
                "description": cmd.description,
                "enabled": cmd.enabled,
                "createdAt": iso(cmd.created_at),
                "updatedAt": iso(cmd.updated_at),
            })
        })
        .collect();
    Ok(Json(json!({ "commands": commands })))
}

// ===========================================================================
// GET /available?distro=... — 适配发行版的启用命令
// ===========================================================================

#[derive(Deserialize)]
struct AvailableQuery {
    distro: Option<String>,
}

async fn available(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Query(query): Query<AvailableQuery>,
) -> Result<Json<Value>, ApiError> {
    let distro = query
        .distro
        .ok_or_else(|| ApiError::validation("querystring must have required property 'distro'"))?;

    let rows = sqlx::query_as::<_, CommandRow>(&format!(
        "SELECT {ROW_COLUMNS} FROM custom_init_commands \
         WHERE user_id = $1 AND enabled = true ORDER BY created_at DESC"
    ))
    .bind(user.0.id)
    .fetch_all(&state.db)
    .await?;

    let commands: Vec<Value> = rows
        .iter()
        .filter(|cmd| {
            let distros = parse_distros(&cmd.distros);
            distros.iter().any(|d| d == "all" || d == &distro)
        })
        .map(|cmd| {
            json!({
                "id": cmd.id,
                "name": cmd.name,
                "commandLineCount": line_count(&cmd.command),
                "distros": parse_distros(&cmd.distros),
                "description": cmd.description,
            })
        })
        .collect();
    Ok(Json(json!({ "commands": commands })))
}

// ===========================================================================
// GET /distros — 静态发行版列表（前端按 id 翻译）
// ===========================================================================

async fn distros() -> Json<Value> {
    Json(json!({
        "distros": [
            { "id": "ubuntu", "icon": "ubuntu" },
            { "id": "debian", "icon": "debian" },
            { "id": "rhel", "icon": "almalinux" },
            { "id": "alpine", "icon": "alpine" },
            { "id": "arch", "icon": "arch" },
            { "id": "suse", "icon": "opensuse" },
            { "id": "all", "icon": "linux" },
        ]
    }))
}

// ===========================================================================
// GET /:id — 详情（仅所有者）
// ===========================================================================

async fn get_one(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let cmd_id = parse_id(&id)?;

    let cmd = sqlx::query_as::<_, CommandRow>(&format!(
        "SELECT {ROW_COLUMNS} FROM custom_init_commands WHERE id = $1"
    ))
    .bind(cmd_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found(code::NOT_FOUND))?;

    if cmd.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    Ok(Json(json!({
        "command": {
            "id": cmd.id,
            "name": cmd.name,
            "command": cmd.command,
            "distros": parse_distros(&cmd.distros),
            "description": cmd.description,
            "enabled": cmd.enabled,
            "createdAt": iso(cmd.created_at),
            "updatedAt": iso(cmd.updated_at),
        }
    })))
}

// ===========================================================================
// POST / — 创建
// ===========================================================================

#[derive(Deserialize)]
struct CreateBody {
    name: Option<String>,
    command: Option<String>,
    distros: Option<Vec<String>>,
    description: Option<String>,
}

/// `{ error: message }` (no code field) — the route's own error shape.
fn route_error(status: axum::http::StatusCode, message: &str) -> ApiError {
    ApiError::with_message("", status, message)
}

async fn create(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    body: Option<Json<CreateBody>>,
) -> Result<Response, ApiError> {
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let name = body
        .name
        .filter(|n| (1..=100).contains(&n.chars().count()))
        .ok_or_else(|| ApiError::validation("name must be between 1 and 100 characters"))?;
    let command = body
        .command
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::validation("command must NOT have fewer than 1 characters"))?;
    let distros = body
        .distros
        .filter(|d| !d.is_empty())
        .ok_or_else(|| ApiError::validation("distros must NOT have fewer than 1 items"))?;
    if let Some(d) = &body.description {
        if d.chars().count() > 500 {
            return Err(ApiError::validation(
                "description must NOT have more than 500 characters",
            ));
        }
    }

    let invalid: Vec<String> = distros
        .iter()
        .filter(|d| !VALID_DISTROS.contains(&d.as_str()))
        .cloned()
        .collect();
    if !invalid.is_empty() {
        return Ok(invalid_distros_response(invalid));
    }

    // db createCustomInitCommand checks
    if command.len() > MAX_COMMAND_SIZE {
        return Err(route_error(
            axum::http::StatusCode::BAD_REQUEST,
            "Command content too large (max 64KB)",
        ));
    }
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM custom_init_commands WHERE user_id = $1",
    )
    .bind(user.0.id)
    .fetch_one(&state.db)
    .await?;
    if count >= MAX_COMMANDS_PER_USER {
        return Err(route_error(
            axum::http::StatusCode::BAD_REQUEST,
            "Maximum command templates reached (50)",
        ));
    }

    let row: (i32,) = sqlx::query_as(
        "INSERT INTO custom_init_commands (user_id, name, command, distros, description) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(user.0.id)
    .bind(name.trim())
    .bind(&command)
    .bind(serde_json::to_string(&distros).unwrap_or_else(|_| "[]".into()))
    .bind(body.description.as_deref().map(|d| d.trim()).filter(|d| !d.is_empty()))
    .fetch_one(&state.db)
    .await?;

    crate::routes::users::create_log(
        &state,
        user.0.id,
        "custom_init_command",
        "custom_init_command.create",
        &format!("Created init command template \"{name}\""),
        "success",
    )
    .await;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({ "message": "Init command created", "id": row.0 })),
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
    distros: Option<Vec<String>>,
    description: Option<serde_json::Value>,
    enabled: Option<bool>,
}

async fn update(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
    body: Option<Json<UpdateBody>>,
) -> Result<Response, ApiError> {
    let cmd_id = parse_id(&id)?;
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;

    if let Some(name) = &body.name {
        if !(1..=100).contains(&name.chars().count()) {
            return Err(ApiError::validation("name must be between 1 and 100 characters"));
        }
    }
    if let Some(command) = &body.command {
        if command.is_empty() {
            return Err(ApiError::validation(
                "command must NOT have fewer than 1 characters",
            ));
        }
    }
    let mut invalid_distros: Option<Vec<String>> = None;
    if let Some(distros) = &body.distros {
        if distros.is_empty() {
            return Err(ApiError::validation("distros must NOT have fewer than 1 items"));
        }
        let invalid: Vec<String> = distros
            .iter()
            .filter(|d| !VALID_DISTROS.contains(&d.as_str()))
            .cloned()
            .collect();
        if !invalid.is_empty() {
            invalid_distros = Some(invalid);
        }
    }
    if let Some(Value::String(d)) = &body.description {
        if d.chars().count() > 500 {
            return Err(ApiError::validation(
                "description must NOT have more than 500 characters",
            ));
        }
    }

    // Ownership check (findFirst id+userId).
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT id FROM custom_init_commands WHERE id = $1 AND user_id = $2",
    )
    .bind(cmd_id)
    .bind(user.0.id)
    .fetch_optional(&state.db)
    .await?;
    if exists.is_none() {
        return Err(route_error(
            axum::http::StatusCode::NOT_FOUND,
            "Command not found",
        ));
    }

    if let Some(command) = &body.command {
        if command.len() > MAX_COMMAND_SIZE {
            return Err(route_error(
                axum::http::StatusCode::BAD_REQUEST,
                "Command content too large (max 64KB)",
            ));
        }
    }
    if let Some(invalid) = invalid_distros {
        return Ok(invalid_distros_response(invalid));
    }

    // Partial update mirroring updateData assembly.
    let next_name = body.name.as_ref().map(|n| n.trim().to_string());
    let next_distros = body
        .distros
        .as_ref()
        .map(|d| serde_json::to_string(d).unwrap_or_else(|_| "[]".into()));
    let next_description: Option<Option<String>> = match &body.description {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(d)) => {
            let trimmed = d.trim().to_string();
            Some(if trimmed.is_empty() { None } else { Some(trimmed) })
        }
        Some(_) => return Err(ApiError::validation("description must be string or null")),
    };

    sqlx::query(
        "UPDATE custom_init_commands SET \
         name = COALESCE($1, name), \
         command = COALESCE($2, command), \
         distros = COALESCE($3, distros), \
         description = CASE WHEN $4::boolean THEN $5 ELSE description END, \
         enabled = COALESCE($6, enabled), \
         updated_at = now() \
         WHERE id = $7 AND user_id = $8",
    )
    .bind(next_name)
    .bind(body.command.as_deref())
    .bind(next_distros)
    .bind(next_description.is_some())
    .bind(next_description.clone().flatten())
    .bind(body.enabled)
    .bind(cmd_id)
    .bind(user.0.id)
    .execute(&state.db)
    .await?;

    crate::routes::users::create_log(
        &state,
        user.0.id,
        "custom_init_command",
        "custom_init_command.update",
        &format!("Updated init command template ID {cmd_id}"),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Init command updated" })).into_response())
}

// ===========================================================================
// DELETE /:id — 删除
// ===========================================================================

async fn remove(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let cmd_id = parse_id(&id)?;

    let result =
        sqlx::query("DELETE FROM custom_init_commands WHERE id = $1 AND user_id = $2")
            .bind(cmd_id)
            .bind(user.0.id)
            .execute(&state.db)
            .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found(code::NOT_FOUND));
    }

    crate::routes::users::create_log(
        &state,
        user.0.id,
        "custom_init_command",
        "custom_init_command.delete",
        &format!("Deleted init command template ID {cmd_id}"),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Init command deleted" })))
}
