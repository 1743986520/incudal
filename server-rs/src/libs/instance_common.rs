//! Shared instance helpers reused across instance-family route modules:
//! - permission checks (lib/permission.ts checkInstancePermission / getInstanceWithPermission)
//! - transfer-lock + suspension guards (routes/instances/helpers.ts)
//! - instance snapshot quota check (db/quota-operations.ts checkSnapshotQuota)
//! - slim host row + Incus client access (same pattern as routes/hosts.rs)
//! - audit log with instance id + inbox notification for snapshot events

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::AuthUser;
use crate::error::{code, ApiError};
use crate::libs::incus::{IncusClient, PoolHost};
use crate::state::SharedAppState;

/// Subset of `instances` columns shared by instance-family modules.
/// Column names are the schema.prisma @map names; enums read as ::text.
#[derive(Debug, Clone, FromRow)]
pub struct InstanceRow {
    pub id: i32,
    pub user_id: i32,
    pub host_id: i32,
    pub package_id: Option<i32>,
    pub package_plan_id: Option<i32>,
    pub incus_id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub suspend_reason: Option<String>,
    pub snapshot_limit: Option<i32>,
    pub backup_limit: Option<i32>,
    pub port_limit: Option<i32>,
    pub cpu: i32,
    pub memory: i32,
    pub disk: i32,
}

pub const INSTANCE_COLUMNS: &str = "id, user_id, host_id, package_id, package_plan_id, incus_id, \
     name, image, status::text AS status, suspend_reason, snapshot_limit, backup_limit, \
     port_limit, cpu, memory, disk";

/// Host columns needed to reach the Incus client pool (mirrors hosts.rs
/// pool_host_from; kept slim because this module only connects).
#[derive(Debug, Clone, FromRow)]
pub struct HostForIncus {
    pub id: i32,
    pub name: String,
    pub url: String,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub server_certificate: Option<String>,
    pub server_fingerprint: Option<String>,
    pub allow_private_network: bool,
}

const HOST_FOR_INCUS_COLUMNS: &str =
    "id, name, url, cert_path, key_path, server_certificate, server_fingerprint, \
     allow_private_network";

pub fn pool_host_from(host: &HostForIncus) -> PoolHost {
    PoolHost {
        id: host.id as i64,
        url: host.url.clone(),
        cert_path: host.cert_path.clone(),
        key_path: host.key_path.clone(),
        server_certificate: host.server_certificate.clone(),
        server_fingerprint: host.server_fingerprint.clone(),
        allow_private_network: host.allow_private_network,
    }
}

pub async fn get_host_for_incus(
    state: &SharedAppState,
    host_id: i32,
) -> Result<Option<HostForIncus>, ApiError> {
    let row = sqlx::query_as::<_, HostForIncus>(&format!(
        "SELECT {HOST_FOR_INCUS_COLUMNS} FROM hosts WHERE id = $1"
    ))
    .bind(host_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

pub async fn get_incus_client_for_host(
    state: &SharedAppState,
    host: &HostForIncus,
) -> Result<std::sync::Arc<IncusClient>, ApiError> {
    state
        .incus_pool
        .get_incus_client(&pool_host_from(host))
        .await
        .map_err(|e| ApiError::internal(format!("incus client unavailable: {e:?}")))
}

pub async fn get_instance_by_id(
    state: &SharedAppState,
    instance_id: i32,
) -> Result<Option<InstanceRow>, ApiError> {
    let row = sqlx::query_as::<_, InstanceRow>(&format!(
        "SELECT {INSTANCE_COLUMNS} FROM instances WHERE id = $1"
    ))
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// lib/permission.ts checkInstancePermission: admin > owner > host owner.
async fn check_instance_permission(
    state: &SharedAppState,
    user: &AuthUser,
    instance: &InstanceRow,
) -> bool {
    if user.role == "admin" {
        return true;
    }
    if instance.user_id == user.id {
        return true;
    }
    let host_owner: Option<i32> = sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
        .bind(instance.host_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    host_owner == Some(user.id)
}

/// lib/permission.ts getInstanceWithPermission: 404 INSTANCE_NOT_FOUND /
/// 403 FORBIDDEN, else the instance row.
pub async fn get_instance_with_permission(
    state: &SharedAppState,
    user: &AuthUser,
    instance_id: i32,
) -> Result<InstanceRow, ApiError> {
    let instance = get_instance_by_id(state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if !check_instance_permission(state, user, &instance).await {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    Ok(instance)
}

/// routes/instances/helpers.ts checkTransferLock: 400 TRANSFER_INSTANCE_LOCKED
/// when a pending/processing transfer exists.
pub async fn check_transfer_lock(state: &SharedAppState, instance_id: i32) -> Result<(), ApiError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instance_transfers \
         WHERE instance_id = $1 AND status IN ('pending','processing')",
    )
    .bind(instance_id)
    .fetch_one(&state.db)
    .await?;
    if count > 0 {
        return Err(ApiError::bad_request(code::TRANSFER_INSTANCE_LOCKED));
    }
    Ok(())
}

/// routes/instances/helpers.ts ensureInstanceNotSuspended: expired suspensions
/// get the dedicated code (403).
pub fn ensure_instance_not_suspended(instance: &InstanceRow) -> Result<(), ApiError> {
    if instance.status != "suspended" {
        return Ok(());
    }
    if instance.suspend_reason.as_deref() == Some("expired") {
        Err(ApiError::new(code::INSTANCE_SUSPENDED_EXPIRED, axum::http::StatusCode::FORBIDDEN))
    } else {
        Err(ApiError::new(code::INSTANCE_SUSPENDED, axum::http::StatusCode::FORBIDDEN))
    }
}

/// db/quota-operations.ts checkSnapshotQuota: 400 QUOTA_SNAPSHOT_EXCEEDED with
/// the TS detail message (allocation vs. full).
pub async fn check_snapshot_quota(
    state: &SharedAppState,
    instance_id: i32,
) -> Result<(), ApiError> {
    let row: Option<(Option<i32>, i64)> = sqlx::query_as(
        "SELECT snapshot_limit, (SELECT COUNT(*) FROM snapshots WHERE instance_id = $1) \
         FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((limit_opt, current)) = row else {
        return Err(ApiError::bad_request(code::QUOTA_SNAPSHOT_EXCEEDED)
            .with_details("Instance not found"));
    };
    let limit = limit_opt.unwrap_or(0);
    if limit == 0 {
        return Err(ApiError::bad_request(code::QUOTA_SNAPSHOT_EXCEEDED)
            .with_details("Snapshot quota not allocated for this instance"));
    }
    if current >= limit as i64 {
        return Err(ApiError::bad_request(code::QUOTA_SNAPSHOT_EXCEEDED).with_details(format!(
            "Instance snapshot quota full ({current}/{limit})"
        )));
    }
    Ok(())
}

/// db/logs.ts createLog with the instance id option (snapshots/billing routes
/// pass { instanceId }); fire-and-forget like the TS helper.
pub async fn create_log_with_instance(
    state: &SharedAppState,
    user_id: i32,
    module: &str,
    action: &str,
    content: &str,
    result: &str,
    instance_id: Option<i32>,
) {
    let insert = sqlx::query(
        "INSERT INTO logs (user_id, instance_id, module, action, content, result) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(user_id)
    .bind(instance_id)
    .bind(module)
    .bind(action)
    .bind(content)
    .bind(result)
    .execute(&state.db)
    .await;
    if let Err(err) = insert {
        tracing::warn!("create_log_with_instance failed (ignored): {err}");
    }
}

/// lib/notifier.ts sendNotification for snapshot events: the always-created
/// inbox message (EVENT_TEMPLATES titles/messages verbatim); external
/// Telegram/Discord/webhook fan-out is stubbed like the other ports.
pub async fn send_snapshot_notification(
    state: &SharedAppState,
    user_id: i32,
    event_type: &str,
    instance_name: &str,
    snapshot_name: &str,
    host_name: Option<&str>,
) {
    let host_line = host_name.map(|h| format!("\n节点: {h}")).unwrap_or_default();
    let (title, message) = match event_type {
        "snapshot_created" => (
            "✅ 快照创建成功",
            format!("实例「{instance_name}」的快照「{snapshot_name}」创建成功{host_line}"),
        ),
        "snapshot_restored" => (
            "🔄 快照恢复成功",
            format!("实例「{instance_name}」已从快照「{snapshot_name}」恢复{host_line}"),
        ),
        "snapshot_deleted" => (
            "🗑️ 快照已删除",
            format!("实例「{instance_name}」的快照「{snapshot_name}」已删除"),
        ),
        other => {
            tracing::warn!("send_snapshot_notification: unhandled event {other} (stub)");
            return;
        }
    };
    let data = json!({ "instanceName": instance_name, "snapshotName": snapshot_name });
    let insert = sqlx::query(
        "INSERT INTO inbox_messages (user_id, event_type, title, content, data) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(event_type)
    .bind(title)
    .bind(&message)
    .bind(data)
    .execute(&state.db)
    .await;
    if let Err(err) = insert {
        tracing::warn!("send_snapshot_notification failed (ignored): {err}");
    } else {
        tracing::debug!("send_snapshot_notification: external channels stubbed for {event_type}");
    }
}

/// Fastify Date serialization: ISO 8601 UTC with millisecond precision.
pub fn iso(ts: DateTime<Utc>) -> Value {
    json!(ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}
