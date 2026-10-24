//! 资源池路由 — port of server/src/routes/resource-pool.ts.
//! Mounted at /api/resource-pool. All endpoints authenticateUser →
//! UserOnlyAuth. Apply holds a per-instance distributed lock across
//! deduct → Incus patch → DB update with per-step compensation and a
//! resource-pool refund when any step fails.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::UserOnlyAuth;
use crate::error::{code, ApiError};
use crate::libs::incus::incus_instances::{
    patch_instance_resources, InstanceResourcePatch,
};
use crate::libs::instance_common::{
    create_log_with_instance, get_host_for_incus, get_incus_client_for_host,
};
use crate::libs::resource_pool::{
    add_to_resource_pool, adjust_host_resources, deduct_from_resource_pool,
    get_user_resource_pool, release_lock, acquire_lock, update_instance_resources,
};
use crate::state::SharedAppState;

const RESOURCE_TYPE_NAMES: &[(&str, &str)] = &[
    ("c", "CPU"), ("r", "内存"), ("d", "硬盘"), ("t", "流量"),
];
const RESOURCE_TYPE_UNITS: &[(&str, &str)] = &[("c", "%"), ("r", "MB"), ("d", "MB"), ("t", "GB")];

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(pool))
        .route("/apply", post(apply))
        .route("/logs", get(logs))
        .route("/instances", get(instances))
}

// ===========================================================================
// GET / — 资源池余量
// ===========================================================================

async fn pool(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(get_user_resource_pool(&state.db, user.0.id).await?))
}

// ===========================================================================
// POST /apply — 应用资源到实例
// ===========================================================================

#[derive(Deserialize)]
struct ApplyBody {
    instance_id: Option<serde_json::Value>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    amount: Option<serde_json::Value>,
}

#[derive(Debug, FromRow)]
struct ApplyInstanceRow {
    id: i32,
    user_id: i32,
    host_id: i32,
    name: String,
    incus_id: String,
    status: String,
    billing_mode: String,
    cpu: i32,
    memory: i32,
    disk: i32,
    monthly_traffic_limit: Option<i64>,
}

async fn apply(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    body: Option<Json<ApplyBody>>,
) -> Result<Response, ApiError> {
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let instance_id = body
        .instance_id
        .as_ref()
        .and_then(Value::as_i64)
        .filter(|id| *id >= 1)
        .ok_or_else(|| ApiError::validation("instanceId must be >= 1"))? as i32;
    let resource_type = body
        .resource_type
        .as_deref()
        .filter(|t| ["c", "r", "d", "t"].contains(t))
        .ok_or_else(|| ApiError::validation("resourceType must be equal to one of the allowed values"))?
        .to_string();
    let amount = body
        .amount
        .as_ref()
        .and_then(Value::as_i64)
        .filter(|a| *a >= 1)
        .ok_or_else(|| ApiError::validation("amount must be >= 1"))?;

    let lock_key = format!("resource-pool:apply:{instance_id}");
    let Some(lock_owner) = acquire_lock(&state.db, &lock_key, 120_000, 5_000).await? else {
        return Err(ApiError::with_message(
            "RESOURCE_OPERATION_BUSY",
            StatusCode::CONFLICT,
            "RESOURCE_OPERATION_BUSY",
        ));
    };

    let result = apply_locked(&state, &user.0, instance_id, &resource_type, amount).await;
    release_lock(&state.db, &lock_key, &lock_owner).await;

    match result {
        Ok(value) => Ok(Json(value).into_response()),
        Err((status, value)) => Ok((status, Json(value)).into_response()),
    }
}

type ApplyOutcome = Result<Value, (StatusCode, Value)>;

async fn apply_locked(
    state: &SharedAppState,
    user: &crate::auth::AuthUser,
    instance_id: i32,
    resource_type: &str,
    amount: i64,
) -> ApplyOutcome {
    let instance = sqlx::query_as::<_, ApplyInstanceRow>(
        "SELECT id, user_id, host_id, name, incus_id, status::text AS status, \
                billing_mode::text AS billing_mode, cpu, memory, disk, monthly_traffic_limit \
         FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, json!(e.to_string())))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, json!({ "error": "Instance not found", "code": "INSTANCE_NOT_FOUND" })))?;

    // 小时计费实例必须走小时计费的验证/结算路径
    if instance.billing_mode == "hourly" {
        return Err((
            StatusCode::BAD_REQUEST,
            json!({
                "error": "Hourly instances cannot use resource-pool credits",
                "code": "HOURLY_RESOURCE_POOL_UNSUPPORTED",
            }),
        ));
    }
    if instance.user_id != user.id {
        return Err((StatusCode::FORBIDDEN, json!({ "error": "Access denied", "code": "FORBIDDEN" })));
    }
    if !matches!(instance.status.as_str(), "running" | "stopped") {
        return Err((StatusCode::BAD_REQUEST, json!({ "error": "Instance status invalid", "code": "INSTANCE_STATUS_INVALID" })));
    }

    let host = get_host_for_incus(state, instance.host_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, json!(e.error)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, json!({ "error": "Host not found", "code": "HOST_NOT_FOUND" })))?;
    let host_instance_type = sqlx::query_scalar::<_, String>(
        "SELECT instance_type::text FROM hosts WHERE id = $1",
    )
    .bind(instance.host_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or_else(|_| "container".into());
    let is_vm = host_instance_type == "vm";

    if resource_type == "c" && is_vm && amount % 100 != 0 {
        return Err((StatusCode::BAD_REQUEST, json!({ "error": "KVM CPU must be a multiple of 100", "code": "RESOURCE_POOL_KVM_CPU_MULTIPLE" })));
    }
    if resource_type == "r" && is_vm && amount % 128 != 0 {
        return Err((StatusCode::BAD_REQUEST, json!({ "error": "KVM memory must be a multiple of 128MB", "code": "RESOURCE_POOL_KVM_MEMORY_MULTIPLE" })));
    }
    if resource_type == "d" && is_vm && amount % 1024 != 0 {
        return Err((StatusCode::BAD_REQUEST, json!({ "error": "KVM disk must be a multiple of 1GB", "code": "RESOURCE_POOL_KVM_DISK_MULTIPLE" })));
    }
    if (resource_type == "r" || resource_type == "d") && is_vm && instance.status != "stopped" {
        return Err((StatusCode::BAD_REQUEST, json!({ "error": "KVM must be stopped", "code": "RESOURCE_POOL_VM_MUST_STOP" })));
    }

    // 扣减资源池（条件递减）
    let deducted = deduct_from_resource_pool(
        state,
        user.id,
        resource_type,
        amount,
        instance_id,
        Some(&format!("应用到实例 {}", instance.name)),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, json!(e.to_string())))?;
    if !deducted {
        return Err((StatusCode::BAD_REQUEST, json!({ "error": "Insufficient resource pool", "code": "RESOURCE_POOL_INSUFFICIENT" })));
    }

    // 应用
    let mut incus_applied = false;
    let mut db_applied = false;
    let mut host_applied = false;

    let apply_result: Result<(), String> = async {
        match resource_type {
            "c" | "r" | "d" => {
                let (new_value, patch_field) = if resource_type == "c" {
                    (instance.cpu as i64 + amount, "c")
                } else if resource_type == "r" {
                    (instance.memory as i64 + amount, "r")
                } else {
                    (instance.disk as i64 + amount, "d")
                };
                let client = get_incus_client_for_host(state, &host)
                    .await
                    .map_err(|e| e.error)?;
                let patch = InstanceResourcePatch {
                    cpu: if patch_field == "c" { Some(new_value) } else { None },
                    memory: if patch_field == "r" { Some(new_value) } else { None },
                    disk: if patch_field == "d" { Some(new_value) } else { None },
                };
                patch_instance_resources(&client, &instance.incus_id, patch)
                    .await
                    .map_err(|e| e.to_string())?;
                incus_applied = true;

                update_instance_resources(
                    state,
                    instance_id,
                    if patch_field == "c" { Some(new_value as i32) } else { None },
                    if patch_field == "r" { Some(new_value as i32) } else { None },
                    if patch_field == "d" { Some(new_value as i32) } else { None },
                    None,
                )
                .await
                .map_err(|e| e.to_string())?;
                db_applied = true;

                adjust_host_resources(
                    state,
                    instance.host_id,
                    if patch_field == "c" { Some(amount) } else { None },
                    if patch_field == "r" { Some(amount) } else { None },
                    if patch_field == "d" { Some(amount) } else { None },
                )
                .await
                .map_err(|e| e.to_string())?;
                host_applied = true;
            }
            "t" => {
                let traffic_bytes = amount * 1024 * 1024 * 1024;
                let new_limit = instance.monthly_traffic_limit.unwrap_or(0) + traffic_bytes;
                update_instance_resources(state, instance_id, None, None, None, Some(Some(new_limit)))
                    .await
                    .map_err(|e| e.to_string())?;
                db_applied = true;
            }
            _ => {}
        }
        Ok(())
    }
    .await;

    match apply_result {
        Ok(()) => {
            let type_name = RESOURCE_TYPE_NAMES
                .iter()
                .find(|(k, _)| *k == resource_type)
                .map(|(_, v)| *v)
                .unwrap_or(resource_type);
            let unit = RESOURCE_TYPE_UNITS
                .iter()
                .find(|(k, _)| *k == resource_type)
                .map(|(_, v)| *v)
                .unwrap_or("");
            create_log_with_instance(
                state,
                user.id,
                "resource_pool",
                "apply.success",
                &format!("Applied {amount}{unit} {type_name} to instance {}", instance.name),
                "success",
                Some(instance_id),
            )
            .await;
            Ok(json!({
                "message": "Resource applied successfully",
                "resourceType": resource_type,
                "amount": amount,
                "instanceId": instance_id,
                "instanceName": instance.name,
            }))
        }
        Err(apply_error) => {
            tracing::error!("resource-pool apply failed: {apply_error}");
            // 逐步补偿：host → instance db → incus → 资源池退款
            if host_applied {
                let _ = adjust_host_resources(
                    state,
                    instance.host_id,
                    if resource_type == "c" { Some(-amount) } else { None },
                    if resource_type == "r" { Some(-amount) } else { None },
                    if resource_type == "d" { Some(-amount) } else { None },
                )
                .await;
            }
            if db_applied && resource_type != "t" {
                let _ = update_instance_resources(
                    state,
                    instance_id,
                    if resource_type == "c" { Some(instance.cpu) } else { None },
                    if resource_type == "r" { Some(instance.memory) } else { None },
                    if resource_type == "d" { Some(instance.disk) } else { None },
                    None,
                )
                .await;
            }
            if incus_applied {
                if let Ok(client) = get_incus_client_for_host(state, &host).await {
                    let patch = InstanceResourcePatch {
                        cpu: if resource_type == "c" { Some(instance.cpu as i64) } else { None },
                        memory: if resource_type == "r" { Some(instance.memory as i64) } else { None },
                        disk: if resource_type == "d" { Some(instance.disk as i64) } else { None },
                    };
                    let _ = patch_instance_resources(&client, &instance.incus_id, patch).await;
                }
            }
            let refund = add_to_resource_pool(
                state,
                user.id,
                resource_type,
                amount,
                "refund",
                Some(&format!("资源应用失败，自动退还到实例 {}", instance.name)),
            )
            .await;
            if let Err(err) = refund {
                tracing::error!("Failed to compensate resource-pool deduction: {err}");
            }
            create_log_with_instance(
                state,
                user.id,
                "resource_pool",
                "apply.failed",
                &format!("Failed to apply resource to instance {}", instance.name),
                "failed",
                Some(instance_id),
            )
            .await;
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": "Internal server error", "code": "INTERNAL_ERROR" }),
            ))
        }
    }
}

// ===========================================================================
// GET /logs
// ===========================================================================

#[derive(Deserialize)]
struct LogsQuery {
    action: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    limit: Option<String>,
    offset: Option<String>,
}

#[derive(Debug, FromRow)]
struct PoolLogRow {
    id: i32,
    action: String,
    resource_type: String,
    amount: i64,
    remark: Option<String>,
    instance_id: Option<i32>,
    instance_name: Option<String>,
    created_at: DateTime<Utc>,
}

async fn logs(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Value>, ApiError> {
    let action = query.action.as_deref().filter(|a|
        ["checkin", "redeem", "admin_grant", "system_grant", "lottery", "apply", "refund", "system_redeem"].contains(a));
    let resource_type = query.resource_type.as_deref().filter(|t| ["c", "r", "d", "t", "p"].contains(t));
    let limit = query.limit.as_deref().and_then(|v| v.parse::<i64>().ok()).filter(|v| *v >= 1).unwrap_or(20);
    let offset = query.offset.as_deref().and_then(|v| v.parse::<i64>().ok()).filter(|v| *v >= 0).unwrap_or(0);

    let rows = sqlx::query_as::<_, PoolLogRow>(
        "SELECT l.id, l.action::text AS action, l.resource_type::text AS resource_type, \
                l.amount, l.remark, l.instance_id, i.name AS instance_name, l.created_at \
         FROM resource_pool_logs l LEFT JOIN instances i ON i.id = l.instance_id \
         WHERE l.user_id = $1 \
           AND ($2::text IS NULL OR l.action::text = $2) \
           AND ($3::text IS NULL OR l.resource_type::text = $3) \
         ORDER BY l.created_at DESC LIMIT $4 OFFSET $5",
    )
    .bind(user.0.id)
    .bind(action)
    .bind(resource_type)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM resource_pool_logs WHERE user_id = $1 \
         AND ($2::text IS NULL OR action::text = $2) \
         AND ($3::text IS NULL OR resource_type::text = $3)",
    )
    .bind(user.0.id)
    .bind(action)
    .bind(resource_type)
    .fetch_one(&state.db)
    .await?;

    let records: Vec<Value> = rows
        .iter()
        .map(|l| {
            json!({
                "id": l.id,
                "action": l.action,
                "resourceType": l.resource_type,
                "amount": l.amount,
                "remark": l.remark,
                "instance": l.instance_id.map(|iid| json!({
                    "id": iid,
                    "name": l.instance_name,
                })).unwrap_or(Value::Null),
                "createdAt": crate::libs::instance_common::iso(l.created_at),
            })
        })
        .collect();
    Ok(Json(json!({ "records": records, "total": total })))
}

// ===========================================================================
// GET /instances — 可应用资源的实例（排除小时计费）
// ===========================================================================

#[derive(Debug, FromRow)]
struct PoolInstanceRow {
    id: i32,
    name: String,
    status: String,
    billing_mode: String,
    cpu: i32,
    memory: i32,
    disk: i32,
    monthly_traffic_limit: Option<i64>,
    package_plan_id: Option<i32>,
    host_id: i32,
    host_name: String,
    host_location: Option<String>,
    host_country: String,
    host_instance_type: String,
}

async fn instances(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query_as::<_, PoolInstanceRow>(
        "SELECT i.id, i.name, i.status::text AS status, i.billing_mode::text AS billing_mode, \
                i.cpu, i.memory, i.disk, \
                i.monthly_traffic_limit, i.package_plan_id, \
                h.id AS host_id, h.name AS host_name, h.location AS host_location, \
                h.country_code AS host_country, h.instance_type::text AS host_instance_type \
         FROM instances i JOIN hosts h ON h.id = i.host_id \
         WHERE i.user_id = $1 AND i.status::text IN ('running','stopped') \
           AND h.enable_resource_pool = true \
         ORDER BY i.name ASC",
    )
    .bind(user.0.id)
    .fetch_all(&state.db)
    .await?;

    let items: Vec<Value> = rows
        .iter()
        .filter(|r| r.billing_mode != "hourly")
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "status": r.status,
                "cpu": r.cpu,
                "memory": r.memory,
                "disk": r.disk,
                "monthlyTrafficLimit": r.monthly_traffic_limit.map(|v| Value::String(v.to_string())).unwrap_or(Value::Null),
                "isPaid": r.package_plan_id.is_some(),
                "instanceType": r.host_instance_type,
                "host": {
                    "id": r.host_id,
                    "name": r.host_name,
                    "location": r.host_location,
                    "countryCode": r.host_country,
                },
            })
        })
        .collect();
    Ok(Json(json!({ "instances": items })))
}
