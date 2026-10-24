//! 快照管理路由 — port of server/src/routes/snapshots.ts.
//!
//! Mounted at /api/instances (same prefix as instances.ts upstream); the
//! instances router merges this module. All endpoints use
//! `fastify.authenticateUser` → UserOnlyAuth (admins are rejected upstream
//! too — faithful port).
//!
//! Validation notes: Fastify AJV failures are approximated with
//! `{error, code:"VALIDATION_ERROR"}` (message wording differs slightly);
//! `Number(param)` id parsing is a strict full-string i32 parse ("12abc" →
//! 400 INVALID_ID, matching Number() → NaN → 400).

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::UserOnlyAuth;
use crate::error::{code, ApiError};
use crate::libs::incus::incus_snapshots as incus;
use crate::libs::instance_common::{
    check_snapshot_quota, check_transfer_lock, create_log_with_instance, ensure_instance_not_suspended,
    get_host_for_incus, get_incus_client_for_host, get_instance_with_permission,
    send_snapshot_notification, iso,
};
use axum::response::IntoResponse;

use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/{instanceId}/snapshots", get(list_snapshots).post(create_snapshot))
        .route(
            "/{instanceId}/snapshots/{snapshotId}",
            axum::routing::delete(delete_snapshot),
        )
        .route(
            "/{instanceId}/snapshots/{snapshotId}/restore",
            post(restore_snapshot),
        )
        .route(
            "/{instanceId}/snapshot-policy",
            get(get_policy).put(put_policy),
        )
}

fn parse_id(raw: &str) -> Result<i32, ApiError> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))
}

#[derive(Debug, FromRow)]
struct SnapshotRow {
    id: i32,
    incus_name: String,
    name: String,
    description: Option<String>,
    stateful: bool,
    size: i32,
    created_at: DateTime<Utc>,
}

const SNAPSHOT_COLUMNS: &str = "id, incus_name, name, description, stateful, size, created_at";

fn snapshot_json(s: &SnapshotRow) -> Value {
    json!({
        "id": s.id,
        "name": s.name,
        "incusName": s.incus_name,
        "description": s.description,
        "stateful": s.stateful,
        "size": s.size,
        "created_at": iso(s.created_at),
    })
}

// ===========================================================================
// GET /:instanceId/snapshots — 快照列表（顶层数组）
// ===========================================================================

async fn list_snapshots(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id(&instance_id)?;
    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    let snapshots = sqlx::query_as::<_, SnapshotRow>(&format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM snapshots WHERE instance_id = $1 ORDER BY created_at DESC"
    ))
    .bind(instance_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(json!(snapshots.iter().map(snapshot_json).collect::<Vec<_>>())))
}

// ===========================================================================
// POST /:instanceId/snapshots — 创建快照
// ===========================================================================

#[derive(Deserialize)]
struct CreateSnapshotBody {
    name: Option<String>,
    description: Option<String>,
}

fn operation_failed(action: &str) -> ApiError {
    ApiError::with_message("OPERATION_FAILED", axum::http::StatusCode::INTERNAL_SERVER_ERROR, action)
}

async fn create_snapshot(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(instance_id): Path<String>,
    body: Option<Json<Value>>,
) -> Result<axum::response::Response, ApiError> {
    let instance_id = parse_id(&instance_id)?;

    // AJV schema: name required, 1-50 chars; description ≤ 200.
    let (name, description) = match body {
        Some(Json(v)) if v.is_object() => {
            let name = v.get("name").and_then(|n| n.as_str());
            let name = match name {
                Some(n) if (1..=50).contains(&n.chars().count()) => n.to_string(),
                _ if name.is_some() => {
                    return Err(ApiError::validation("name must be between 1 and 50 characters"))
                }
                _ => return Err(ApiError::validation("body must have required property 'name'")),
            };
            let description = match v.get("description").and_then(|d| d.as_str()) {
                Some(d) if d.chars().count() <= 200 => Some(d.to_string()),
                Some(_) => {
                    return Err(ApiError::validation(
                        "description must NOT have more than 200 characters",
                    ))
                }
                None => None,
            };
            (name, description)
        }
        _ => return Err(ApiError::validation("body must be object")),
    };

    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;
    ensure_instance_not_suspended(&instance)?;

    if !matches!(instance.status.as_str(), "running" | "stopped") {
        return Err(ApiError::bad_request(code::INSTANCE_STATUS_INVALID));
    }

    check_transfer_lock(&state, instance_id).await?;
    check_snapshot_quota(&state, instance_id).await?;

    let timestamp = chrono::Utc::now().timestamp_millis();
    let incus_name = format!(
        "snap-{}-{timestamp}",
        name.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
            .collect::<String>()
    );

    let host = get_host_for_incus(&state, instance.host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;

    let client = get_incus_client_for_host(&state, &host).await?;
    let result = async {
        incus::create_snapshot(&client, &instance.incus_id, &incus_name).await?;

        let row: (i32,) = sqlx::query_as(
            "INSERT INTO snapshots (instance_id, incus_name, name, description, stateful) \
             VALUES ($1, $2, $3, $4, false) RETURNING id",
        )
        .bind(instance_id)
        .bind(&incus_name)
        .bind(&name)
        .bind(&description)
        .fetch_one(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
        Ok::<i32, ApiError>(row.0)
    }
    .await;

    match result {
        Ok(snapshot_id) => {
            send_snapshot_notification(
                &state,
                user.0.id,
                "snapshot_created",
                &instance.name,
                &name,
                Some(&host.name),
            )
            .await;
            create_log_with_instance(
                &state,
                user.0.id,
                "snapshot",
                "snapshot.create",
                &format!(
                    "Created snapshot \"{name}\" for instance \"{}\" [host: {}]",
                    instance.name, host.name
                ),
                "success",
                Some(instance_id),
            )
            .await;
            Ok((
                axum::http::StatusCode::CREATED,
                Json(json!({
                    "message": "Snapshot created",
                    "snapshot": {
                        "id": snapshot_id,
                        "name": name,
                        "incusName": incus_name,
                        "description": description,
                        "stateful": false,
                    }
                })),
            )
                .into_response())
        }
        Err(err) => {
            // Incus 细节只留在服务端日志与操作日志（审查项 P3-04）
            tracing::error!("create snapshot failed: {err:?}");
            create_log_with_instance(
                &state,
                user.0.id,
                "snapshot",
                "snapshot.create",
                &format!("Failed to create snapshot: {err}"),
                "failed",
                Some(instance_id),
            )
            .await;
            Err(operation_failed("创建快照失败，请稍后重试"))
        }
    }
}

// ===========================================================================
// DELETE /:instanceId/snapshots/:snapshotId — 删除快照
// ===========================================================================

async fn delete_snapshot(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((instance_id, snapshot_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id(&instance_id)?;
    let snapshot_id = parse_id(&snapshot_id)?;

    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    // TS getSnapshotById then snapshot.instance_id !== instanceId → 404;
    // the AND instance_id filter is equivalent.
    let snapshot = sqlx::query_as::<_, SnapshotRow>(&format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM snapshots WHERE id = $1 AND instance_id = $2"
    ))
    .bind(snapshot_id)
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found(code::SNAPSHOT_NOT_FOUND))?;

    check_transfer_lock(&state, instance_id).await?;

    let host = get_host_for_incus(&state, instance.host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;

    let client = get_incus_client_for_host(&state, &host).await?;
    let result = async {
        incus::delete_snapshot(&client, &instance.incus_id, &snapshot.incus_name).await?;
        sqlx::query("DELETE FROM snapshots WHERE id = $1")
            .bind(snapshot_id)
            .execute(&state.db)
            .await
            .map_err(ApiError::from_sql)?;
        Ok::<(), ApiError>(())
    }
    .await;

    match result {
        Ok(()) => {
            send_snapshot_notification(
                &state,
                user.0.id,
                "snapshot_deleted",
                &instance.name,
                &snapshot.name,
                Some(&host.name),
            )
            .await;
            create_log_with_instance(
                &state,
                user.0.id,
                "snapshot",
                "snapshot.delete",
                &format!(
                    "Deleted snapshot \"{}\" of instance \"{}\" [host: {}]",
                    snapshot.name, instance.name, host.name
                ),
                "success",
                Some(instance_id),
            )
            .await;
            Ok(Json(json!({ "message": "Snapshot deleted" })))
        }
        Err(err) => {
            tracing::error!("delete snapshot failed: {err:?}");
            create_log_with_instance(
                &state,
                user.0.id,
                "snapshot",
                "snapshot.delete",
                &format!("Failed to delete snapshot: {err}"),
                "failed",
                Some(instance_id),
            )
            .await;
            Err(operation_failed("删除快照失败，请稍后重试"))
        }
    }
}

// ===========================================================================
// POST /:instanceId/snapshots/:snapshotId/restore — 恢复快照
// ===========================================================================

async fn restore_snapshot(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((instance_id, snapshot_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id(&instance_id)?;
    let snapshot_id = parse_id(&snapshot_id)?;

    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    let snapshot = sqlx::query_as::<_, SnapshotRow>(&format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM snapshots WHERE id = $1 AND instance_id = $2"
    ))
    .bind(snapshot_id)
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found(code::SNAPSHOT_NOT_FOUND))?;

    ensure_instance_not_suspended(&instance)?;

    if instance.status != "stopped" {
        return Err(ApiError::bad_request(code::SNAPSHOT_RESTORE_REQUIRES_STOP));
    }

    check_transfer_lock(&state, instance_id).await?;

    let host = get_host_for_incus(&state, instance.host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;

    let client = get_incus_client_for_host(&state, &host).await?;
    let result = incus::restore_snapshot(&client, &instance.incus_id, &snapshot.incus_name).await;

    match result {
        Ok(_) => {
            send_snapshot_notification(
                &state,
                user.0.id,
                "snapshot_restored",
                &instance.name,
                &snapshot.name,
                Some(&host.name),
            )
            .await;
            create_log_with_instance(
                &state,
                user.0.id,
                "snapshot",
                "snapshot.restore",
                &format!(
                    "Restored instance \"{}\" to snapshot \"{}\" [host: {}]",
                    instance.name, snapshot.name, host.name
                ),
                "success",
                Some(instance_id),
            )
            .await;
            Ok(Json(json!({ "message": "Snapshot restored" })))
        }
        Err(err) => {
            tracing::error!("restore snapshot failed: {err:?}");
            create_log_with_instance(
                &state,
                user.0.id,
                "snapshot",
                "snapshot.restore",
                &format!("Failed to restore snapshot: {err}"),
                "failed",
                Some(instance_id),
            )
            .await;
            Err(operation_failed("恢复快照失败，请稍后重试"))
        }
    }
}

// ===========================================================================
// GET / PUT /:instanceId/snapshot-policy — 自动快照策略
// ===========================================================================

#[derive(Debug, FromRow)]
struct PolicyRow {
    enabled: bool,
    interval_minutes: i32,
    last_run_at: Option<DateTime<Utc>>,
    next_run_at: Option<DateTime<Utc>>,
}

async fn get_policy(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id(&instance_id)?;
    let _instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    let policy = sqlx::query_as::<_, PolicyRow>(
        "SELECT enabled, interval_minutes, last_run_at, next_run_at \
         FROM snapshot_policies WHERE instance_id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?;

    Ok(Json(match policy {
        Some(p) => json!({
            "enabled": p.enabled,
            // TS: policy.intervalMinutes || 360
            "interval_minutes": if p.interval_minutes == 0 { 360 } else { p.interval_minutes },
            "last_run_at": p.last_run_at.map(iso).unwrap_or(Value::Null),
            "next_run_at": p.next_run_at.map(iso).unwrap_or(Value::Null),
        }),
        None => json!({
            "enabled": false,
            "interval_minutes": 360,
            "last_run_at": null,
            "next_run_at": null,
        }),
    }))
}

#[derive(Deserialize)]
struct PutPolicyBody {
    enabled: Option<bool>,
    #[serde(rename = "intervalMinutes")]
    interval_minutes: Option<i64>,
}

async fn put_policy(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(instance_id): Path<String>,
    body: Option<Json<PutPolicyBody>>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id(&instance_id)?;

    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let enabled = body
        .enabled
        .ok_or_else(|| ApiError::validation("body must have required property 'enabled'"))?;
    let interval = body.interval_minutes.unwrap_or(360);
    if ![10, 60, 360, 1440].contains(&interval) {
        return Err(ApiError::validation(
            "intervalMinutes must be equal to one of the allowed values: 10, 60, 360, 1440",
        ));
    }

    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    if enabled {
        match instance.snapshot_limit {
            Some(limit) if limit > 0 => {}
            _ => return Err(ApiError::bad_request(code::QUOTA_NOT_ALLOCATED)),
        }
    }

    sqlx::query(
        "INSERT INTO snapshot_policies (instance_id, enabled, interval_minutes, created_at, updated_at) \
         VALUES ($1, $2, $3, now(), now()) \
         ON CONFLICT (instance_id) \
         DO UPDATE SET enabled = EXCLUDED.enabled, interval_minutes = EXCLUDED.interval_minutes, \
         updated_at = now()",
    )
    .bind(instance_id)
    .bind(enabled)
    .bind(interval as i32)
    .execute(&state.db)
    .await?;

    Ok(Json(json!({ "message": "Auto snapshot policy updated" })))
}
