//! 日志管理路由 — port of server/src/routes/logs.ts (mounted at /api/logs).
//!
//! Endpoints:
//! - GET /         authenticate (admin sees everything, users only their rows)
//! - GET /modules  authenticate (admin: distinct modules; user: fixed list)
//!
//! The DB helper getLogsPaginated (db/logs.ts) is ported inline, including the
//! Prisma `contains` semantics: the search value is concatenated into the LIKE
//! pattern WITHOUT escaping, so `%`/`_` in user input act as wildcards on the
//! wire (Prisma does not escape either).

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::Row;

use crate::auth::AuthUser;
use crate::error::{code, ApiError};
use crate::response::parse_pagination;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list_logs))
        .route("/modules", get(list_modules))
}

/// TS `Date` fields serialize as ISO strings through Fastify's JSON encoder.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

async fn list_logs(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let module = params.get("module").map(|s| s.as_str()).unwrap_or("");
    let search = params.get("search").map(|s| s.as_str()).unwrap_or("");
    let instance_id_raw = params.get("instanceId").map(|s| s.as_str()).unwrap_or("");
    let instance_name = params.get("instanceName").map(|s| s.as_str()).unwrap_or("");
    let user_id = if user.role == "admin" {
        None
    } else {
        Some(user.id)
    };

    // TS: instanceIdNum = instanceId ? Number(instanceId) : undefined, then
    // reject when not an integer or <= 0 ("" is falsy and skipped above).
    let instance_id_num: Option<i64> = if instance_id_raw.is_empty() {
        None
    } else {
        let parsed: f64 = instance_id_raw
            .trim()
            .parse()
            .map_err(|_| ApiError::bad_request(code::INVALID_ID))?;
        if !parsed.is_finite() || parsed.fract() != 0.0 || parsed <= 0.0 {
            return Err(ApiError::bad_request(code::INVALID_ID));
        }
        Some(parsed as i64)
    };

    // parsePagination(request.query) then getLogsPaginated clamps pageSize 1..100.
    let pagination = parse_pagination(&params, 20, None);
    let page = pagination.page.max(1);
    let page_size = pagination.page_size.clamp(1, 100);
    let skip = (page - 1) * page_size;

    // ---- build the where clause (module / userId / search / instance filter) ----
    let mut conditions: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if !module.is_empty() {
        binds.push(module.to_string());
        conditions.push(format!("l.module = ${}", binds.len()));
    }
    if let Some(uid) = user_id {
        binds.push(uid.to_string());
        conditions.push(format!("l.user_id = ${}::int", binds.len()));
    }
    if !search.is_empty() {
        // Prisma `contains, mode insensitive` -> ILIKE '%<value>%' (unescaped);
        // the same parameter feeds all three OR branches.
        binds.push(format!("%{search}%"));
        let p = format!("${}", binds.len());
        conditions.push(format!(
            "(l.content ILIKE {p} OR l.action ILIKE {p} OR u.username ILIKE {p})"
        ));
    }
    // combineWhereWithAnd: instanceId wins over instanceName (else-if in TS).
    if let Some(instance_id) = instance_id_num {
        binds.push(instance_id.to_string());
        conditions.push(format!("l.instance_id = ${}::int", binds.len()));
    } else if !instance_name.is_empty() {
        binds.push(format!(r#"%instance "{instance_name}"%"#));
        conditions.push(format!("l.content ILIKE ${}", binds.len()));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!(
        "SELECT COUNT(*)::bigint AS total FROM logs l \
         LEFT JOIN users u ON u.id = l.user_id {where_clause}"
    );
    let mut count_query = sqlx::query(&count_sql);
    for value in &binds {
        count_query = count_query.bind(value);
    }
    let total: i64 = count_query
        .fetch_one(&state.db)
        .await
        .map_err(ApiError::from_sql)?
        .try_get(0)
        .map_err(ApiError::from_sql)?;

    let limit_placeholder = binds.len() + 1;
    binds.push(page_size.to_string());
    let offset_placeholder = binds.len() + 1;
    binds.push(skip.to_string());
    let page_sql = format!(
        "SELECT l.id, l.user_id, l.instance_id, u.username, l.module, l.action, \
         l.content, l.result, l.created_at \
         FROM logs l LEFT JOIN users u ON u.id = l.user_id {where_clause} \
         ORDER BY l.created_at DESC \
         LIMIT ${limit_placeholder}::int OFFSET ${offset_placeholder}::int"
    );
    let mut page_query = sqlx::query(&page_sql);
    for value in &binds {
        page_query = page_query.bind(value);
    }
    let rows = page_query
        .fetch_all(&state.db)
        .await
        .map_err(ApiError::from_sql)?;

    let mut logs: Vec<Value> = Vec::with_capacity(rows.len());
    for row in &rows {
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(ApiError::from_sql)?;
        logs.push(json!({
            "id": row.try_get::<i32, _>("id").map_err(ApiError::from_sql)?,
            "user_id": row.try_get::<Option<i32>, _>("user_id").map_err(ApiError::from_sql)?,
            "instance_id": row.try_get::<Option<i32>, _>("instance_id").map_err(ApiError::from_sql)?,
            "username": row.try_get::<Option<String>, _>("username").map_err(ApiError::from_sql)?,
            "module": row.try_get::<String, _>("module").map_err(ApiError::from_sql)?,
            "action": row.try_get::<String, _>("action").map_err(ApiError::from_sql)?,
            "content": row.try_get::<String, _>("content").map_err(ApiError::from_sql)?,
            "result": row.try_get::<String, _>("result").map_err(ApiError::from_sql)?,
            "created_at": iso(created_at),
        }));
    }

    // Math.ceil(total / pageSize)
    let total_pages = (total + page_size - 1) / page_size;

    Ok(Json(json!({
        "success": true,
        "logs": logs,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "totalPages": total_pages,
    })))
}

async fn list_modules(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    // 管理员可以看到所有模块
    if user.role == "admin" {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT DISTINCT module FROM logs ORDER BY module ASC")
                .fetch_all(&state.db)
                .await
                .map_err(ApiError::from_sql)?;
        let modules: Vec<String> = rows.into_iter().map(|(m,)| m).collect();
        return Ok(Json(json!({ "success": true, "modules": modules })));
    }

    // 普通用户只能看到与自己相关的模块
    let user_modules = [
        "security",
        "instance",
        "snapshot",
        "backup",
        "personal",
        "ssh_key",
        "notification",
    ];
    Ok(Json(json!({ "success": true, "modules": user_modules })))
}
