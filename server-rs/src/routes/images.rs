//! 镜像管理路由 — port of server/src/routes/images.ts (mounted at /api/images).
//!
//! Endpoints (all JWT):
//! - GET    /system      authenticate      user-facing list (visible, filtered)
//! - GET    /admin       authenticate+admin full list incl. hidden
//! - POST   /admin       authenticate+admin create
//! - PATCH  /admin/{id}  authenticate+admin update
//! - DELETE /admin/{id}  authenticate+admin delete
//!
//! The db/images.ts helpers are ported inline (private fns). The admin list
//! serializes full Prisma rows with camelCase keys + ISO dates, matching the
//! Fastify JSON encoder on Prisma objects.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, patch};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::{AdminAuth, AuthUser};
use crate::error::{code, ApiError};
use crate::routes::users::create_log;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/system", get(list_visible_images))
        .route("/admin", get(admin_list_images).post(admin_create_image))
        .route("/admin/{id}", patch(admin_update_image).delete(admin_delete_image))
}

// ===========================================================================
// helpers (db/images.ts + lib/architecture.ts)
// ===========================================================================

/// normalizeArchitecture: arm aliases -> aarch64, everything else -> x86_64.
fn normalize_architecture(value: Option<&str>) -> &'static str {
    let normalized = value.map(str::trim).map(str::to_lowercase);
    match normalized.as_deref() {
        Some("aarch64") | Some("arm64") => "aarch64",
        Some("x86_64") | Some("amd64") | Some("x64") | Some("x86") => "x86_64",
        _ => "x86_64",
    }
}

type ImageType = &'static str; // container | vm | both

/// 128MB 内存限制只能使用的发行版（轻量级系统）. The visible-image queries
/// inline the same list in SQL; the helper stays for the availability checks
/// that belong to the instances route family.
#[allow(dead_code)]
const LOW_MEMORY_ALLOWED_DISTROS: &[&str] = &["alpine", "debian"];
const LOW_MEMORY_THRESHOLD: i64 = 128; // MB

#[derive(Debug, Clone, FromRow)]
struct SystemImageRow {
    pub id: i32,
    pub name: String,
    #[sqlx(rename = "remote_alias")]
    pub remote_alias: String,
    #[sqlx(rename = "os_type")]
    pub os_type: String,
    pub architecture: String,
    #[sqlx(rename = "instance_type")]
    pub instance_type: Option<String>,
    pub icon: String,
    pub sort_order: i32,
    pub hidden: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const IMAGE_COLUMNS: &str = "id, name, remote_alias, os_type, architecture, \
    instance_type, icon, sort_order, hidden, created_at, updated_at";

fn image_instance_type(image: &SystemImageRow) -> ImageType {
    match image.instance_type.as_deref() {
        Some("container") => "container",
        Some("vm") => "vm",
        _ => "both",
    }
}

fn is_image_compatible_with_target_type(image_type: ImageType, target_type: &str) -> bool {
    if target_type == "both" {
        return true;
    }
    image_type == "both" || image_type == target_type
}

#[allow(dead_code)]
fn is_image_compatible_with_low_memory(image: &SystemImageRow, memory: Option<i64>) -> bool {
    let Some(memory) = memory else {
        return true;
    };
    if memory > LOW_MEMORY_THRESHOLD {
        return true;
    }
    LOW_MEMORY_ALLOWED_DISTROS.contains(&image.icon.to_lowercase().as_str())
}

fn image_json(image: &SystemImageRow) -> Value {
    json!({
        "id": image.id,
        "name": image.name,
        "remoteAlias": image.remote_alias,
        "osType": image.os_type,
        "architecture": image.architecture,
        "instanceType": image.instance_type.clone().filter(|v| !v.is_empty()).unwrap_or_else(|| "both".to_string()),
        "icon": image.icon,
        "sortOrder": image.sort_order,
        "hidden": image.hidden,
        "createdAt": iso(image.created_at),
        "updatedAt": iso(image.updated_at),
    })
}

/// TS `Date` fields serialize as ISO strings through Fastify's JSON encoder.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// JS parseInt(value, 10) prefix semantics: leading digits win, no digits -> NaN.
fn js_parse_int(raw: &str) -> Option<i64> {
    let t = raw.trim_start();
    let bytes = t.as_bytes();
    let mut end = 0usize;
    if bytes.first().map(|b| *b == b'-' || *b == b'+').unwrap_or(false) {
        end += 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && (bytes[0] == b'-' || bytes[0] == b'+')) {
        return None;
    }
    t[..end].parse().ok()
}

/// JS parseInt + Prisma Int argument validation: NaN -> 400 INVALID_ID here,
/// because the TS route checks `!hostIdNum || Number.isNaN(hostIdNum)` for
/// hostId. (parseInt never returns Inf, so no range case.)
fn parse_query_int(raw: &str) -> Option<i64> {
    js_parse_int(raw)
}

async fn get_all_system_images(
    state: &SharedAppState,
) -> Result<Vec<SystemImageRow>, ApiError> {
    let rows = sqlx::query_as::<_, SystemImageRow>(&format!(
        "SELECT {IMAGE_COLUMNS} FROM system_images ORDER BY sort_order ASC, id ASC"
    ))
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(rows)
}

/// db.getVisibleSystemImages.
async fn get_visible_system_images(
    state: &SharedAppState,
    instance_type: Option<&str>,
    memory: Option<i64>,
    host_id: Option<i32>,
) -> Result<Vec<SystemImageRow>, ApiError> {
    let Some(host_id) = host_id else {
        let mut conditions = vec!["hidden = false".to_string()];
        if let Some(it) = instance_type {
            conditions.push(format!(
                "instance_type IN ('{}', 'both')",
                it.replace('\'', "''")
            ));
        }
        if memory.is_some_and(|m| m <= LOW_MEMORY_THRESHOLD) {
            conditions.push("icon IN ('alpine', 'debian')".to_string());
        }
        let rows = sqlx::query_as::<_, SystemImageRow>(&format!(
            "SELECT {IMAGE_COLUMNS} FROM system_images WHERE {} \
             ORDER BY sort_order ASC, id ASC",
            conditions.join(" AND ")
        ))
        .fetch_all(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
        return Ok(rows);
    };

    let host: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT architecture, instance_type::text AS instance_type \
         FROM hosts WHERE id = $1",
    )
    .bind(host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;

    let Some((host_architecture, host_instance_type_raw)) = host else {
        return Ok(Vec::new());
    };

    let host_architecture = normalize_architecture(Some(&host_architecture));
    let host_instance_type: ImageType = match host_instance_type_raw.as_deref() {
        Some("vm") => "vm",
        _ => "container",
    };
    let allowed_image_ids: Vec<i32> = sqlx::query_as(
        "SELECT image_id FROM host_allowed_images WHERE host_id = $1",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from_sql)?
    .into_iter()
    .map(|(id,): (i32,)| id)
    .collect();

    let mut conditions = vec![
        "hidden = false".to_string(),
        format!("architecture = '{host_architecture}'"),
    ];
    if memory.is_some_and(|m| m <= LOW_MEMORY_THRESHOLD) {
        conditions.push("icon IN ('alpine', 'debian')".to_string());
    }
    if !allowed_image_ids.is_empty() {
        let id_list = allowed_image_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        conditions.push(format!("id IN ({id_list})"));
    }
    let images = sqlx::query_as::<_, SystemImageRow>(&format!(
        "SELECT {IMAGE_COLUMNS} FROM system_images WHERE {} \
         ORDER BY sort_order ASC, id ASC",
        conditions.join(" AND ")
    ))
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from_sql)?;

    Ok(images
        .into_iter()
        .filter(|image| {
            let image_type = image_instance_type(image);
            if !is_image_compatible_with_target_type(image_type, host_instance_type) {
                return false;
            }
            if let Some(it) = instance_type {
                if !is_image_compatible_with_target_type(image_type, it) {
                    return false;
                }
            }
            true
        })
        .collect())
}

async fn get_system_image_by_id(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<SystemImageRow>, ApiError> {
    let row = sqlx::query_as::<_, SystemImageRow>(&format!(
        "SELECT {IMAGE_COLUMNS} FROM system_images WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(row)
}

/// Maps a unique-violation (Prisma P2002) to the TS 400 INVALID_NAME response.
fn unique_violation(err: sqlx::Error) -> ApiError {
    let is_unique = err
        .as_database_error()
        .and_then(|e| e.code().map(|c| c.into_owned()))
        .map(|c| c == "23505")
        .unwrap_or(false);
    if is_unique {
        // apiError(ErrorCode.INVALID_NAME, 'Remote alias already exists')
        ApiError::with_message(code::INVALID_NAME, StatusCode::BAD_REQUEST, "Remote alias already exists")
    } else {
        ApiError::from_sql(err)
    }
}

// ===========================================================================
// handlers
// ===========================================================================

async fn list_visible_images(
    State(state): State<SharedAppState>,
    _user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let image_type = params.get("type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let memory = params
        .get("memory")
        .and_then(|s| parse_query_int(s));
    let host_id = params
        .get("hostId")
        .and_then(|s| parse_query_int(s))
        .map(|v| v as i32);

    // TS: if (hostId && (!hostIdNum || Number.isNaN(hostIdNum))) -> 400.
    // hostIdNum is falsy only when parseInt returned 0 or NaN.
    if params.get("hostId").map(|s| !s.is_empty()).unwrap_or(false) {
        let parsed = params.get("hostId").and_then(|s| parse_query_int(s));
        match parsed {
            None => return Err(ApiError::bad_request(code::INVALID_ID)),
            Some(v) if v == 0 => return Err(ApiError::bad_request(code::INVALID_ID)),
            _ => {}
        }
    }

    // The TS passes the raw query string through to the Prisma filter
    // (instanceType IN (<type>, 'both')) without runtime validation.
    let images = get_visible_system_images(&state, image_type, memory, host_id).await?;

    let payload: Vec<Value> = images
        .iter()
        .map(|img| {
            json!({
                "id": img.id,
                "name": img.name,
                "remoteAlias": img.remote_alias,
                "osType": img.os_type,
                "architecture": img.architecture,
                "instanceType": image_instance_type(img),
                "icon": img.icon,
            })
        })
        .collect();

    Ok(Json(json!({ "success": true, "images": payload })))
}

async fn admin_list_images(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    let images = get_all_system_images(&state).await?;
    Ok(Json(json!({
        "success": true,
        "images": images.iter().map(image_json).collect::<Vec<_>>(),
    })))
}

#[derive(Default, serde::Deserialize)]
struct ImageBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    remote_alias: Option<String>,
    #[serde(default)]
    os_type: Option<String>,
    #[serde(default)]
    architecture: Option<String>,
    #[serde(default)]
    instance_type: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    sort_order: Option<Value>,
    #[serde(default)]
    hidden: Option<bool>,
}

async fn admin_create_image(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Json(body): Json<ImageBody>,
) -> Result<Json<Value>, ApiError> {
    let name = body.name.clone().unwrap_or_default();
    let remote_alias = body.remote_alias.clone().unwrap_or_default();
    let icon = body.icon.clone().unwrap_or_default();

    if name.is_empty() || remote_alias.is_empty() || icon.is_empty() {
        return Err(ApiError::bad_request(code::INVALID_NAME));
    }

    // sortOrder = data.sortOrder || 0 (JS ||: 0/NaN -> 0); a non-integral or
    // out-of-range number fails Prisma's Int validation -> 500.
    let sort_order = match &body.sort_order {
        Some(Value::Number(n)) => match n.as_i64() {
            Some(v) if v >= i32::MIN as i64 && v <= i32::MAX as i64 => v,
            Some(_) => return Err(ApiError::internal("Prisma Int argument out of range")),
            None => return Err(ApiError::internal("Prisma Int argument out of range")),
        },
        _ => 0,
    };
    let architecture = normalize_architecture(body.architecture.as_deref());
    let instance_type = match body.instance_type.as_deref() {
        Some("container") | Some("vm") | Some("both") => body.instance_type.clone().unwrap(),
        _ => "both".to_string(),
    };
    let os_type = body
        .os_type
        .clone()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "Linux".to_string());
    let hidden = body.hidden.unwrap_or(false);

    let row = sqlx::query_as::<_, SystemImageRow>(&format!(
        "INSERT INTO system_images (name, remote_alias, os_type, architecture, \
         instance_type, icon, sort_order, hidden) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {IMAGE_COLUMNS}"
    ))
    .bind(&name)
    .bind(&remote_alias)
    .bind(&os_type)
    .bind(architecture)
    .bind(&instance_type)
    .bind(&icon)
    .bind(sort_order as i32)
    .bind(hidden)
    .fetch_one(&state.db)
    .await
    .map_err(unique_violation)?;

    create_log(
        &state,
        admin.0.id,
        "images",
        "create",
        &format!("Created system image: {name} ({remote_alias})"),
        "success",
    )
    .await;

    Ok(Json(json!({ "success": true, "image": image_json(&row) })))
}

async fn admin_update_image(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id_raw): Path<String>,
    Json(body): Json<ImageBody>,
) -> Result<Json<Value>, ApiError> {
    // TS: parseInt(request.params.id); NaN -> Prisma validation error -> 500.
    let id: i32 = match js_parse_int(&id_raw) {
        Some(v) if v >= i32::MIN as i64 && v <= i32::MAX as i64 => v as i32,
        Some(_) => return Err(ApiError::internal("Prisma Int argument out of range")),
        None => return Err(ApiError::internal("Prisma Int argument out of range")),
    };

    let existing = get_system_image_by_id(&state, id).await?;
    if existing.is_none() {
        return Err(ApiError::not_found(code::NOT_FOUND));
    }

    // updateSystemImage spreads only the provided fields.
    let mut sets: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if let Some(v) = &body.name {
        binds.push(v.clone());
        sets.push(format!("name = ${}", binds.len()));
    }
    if let Some(v) = &body.remote_alias {
        binds.push(v.clone());
        sets.push(format!("remote_alias = ${}", binds.len()));
    }
    if let Some(v) = &body.os_type {
        binds.push(v.clone());
        sets.push(format!("os_type = ${}", binds.len()));
    }
    if body.architecture.is_some() {
        binds.push(normalize_architecture(body.architecture.as_deref()).to_string());
        sets.push(format!("architecture = ${}", binds.len()));
    }
    if let Some(v) = &body.instance_type {
        binds.push(v.clone());
        sets.push(format!("instance_type = ${}", binds.len()));
    }
    if let Some(v) = &body.icon {
        binds.push(v.clone());
        sets.push(format!("icon = ${}", binds.len()));
    }
    if let Some(Value::Number(n)) = &body.sort_order {
        binds.push(n.as_i64().unwrap_or(0).to_string());
        sets.push(format!("sort_order = ${}::int", binds.len()));
    }
    if let Some(v) = body.hidden {
        binds.push(v.to_string());
        sets.push(format!("hidden = ${}::boolean", binds.len()));
    }

    let image = if sets.is_empty() {
        // Prisma update with empty data still touches updated_at.
        sqlx::query_as::<_, SystemImageRow>(&format!(
            "UPDATE system_images SET updated_at = now() WHERE id = $1 RETURNING {IMAGE_COLUMNS}"
        ))
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(unique_violation)?
    } else {
        let sql = format!(
            "UPDATE system_images SET {} WHERE id = {} RETURNING {IMAGE_COLUMNS}",
            sets.join(", "),
            id
        );
        let mut query = sqlx::query_as::<_, SystemImageRow>(&sql);
        for value in &binds {
            query = query.bind(value);
        }
        query
            .fetch_one(&state.db)
            .await
            .map_err(unique_violation)?
    };

    create_log(
        &state,
        admin.0.id,
        "images",
        "update",
        &format!("Updated system image: {}", image.name),
        "success",
    )
    .await;

    Ok(Json(json!({ "success": true, "image": image_json(&image) })))
}

async fn admin_delete_image(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id_raw): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id: i32 = match js_parse_int(&id_raw) {
        Some(v) if v >= i32::MIN as i64 && v <= i32::MAX as i64 => v as i32,
        _ => return Err(ApiError::internal("Prisma Int argument out of range")),
    };

    let existing = get_system_image_by_id(&state, id).await?;
    let Some(existing) = existing else {
        return Err(ApiError::not_found(code::NOT_FOUND));
    };

    sqlx::query("DELETE FROM system_images WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(ApiError::from_sql)?;

    create_log(
        &state,
        admin.0.id,
        "images",
        "delete",
        &format!("Deleted system image: {}", existing.name),
        "success",
    )
    .await;

    Ok(Json(json!({ "success": true })))
}
