//! 批量配置修改路由 — port of server/src/routes/batch-config.ts
//! (mounted at /api/hosts — MERGED with routes::hosts::router()).
//!
//! Endpoints:
//! - POST /{id}/instances/batch-config   authenticate (admin or host owner)
//!
//! Incus calls stay OUTSIDE any DB transaction (each instance update is an
//! independent sequence of Incus PATCH/PUT + separate DB updates, mirroring
//! the TS). The db/index.ts helpers used here (getHostById, adjustHostResources,
//! updateInstanceResources, updateInstanceQuota, updateInstanceSwap,
//! updateInstanceConfig, getActiveTaskForInstance) are ported as private fns.
//! The Fastify JSON-schema body validation is replicated manually with the
//! same 400 { error, code: "VALIDATION_ERROR" } shape from app.ts.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use futures::stream::{self, StreamExt};
use serde_json::{json, Map, Value};

use crate::auth::AuthUser;
use crate::error::{code, ApiError};
use crate::libs::incus::incus_client::IncusClient;
use crate::libs::incus::incus_instances::{
    get_instance, patch_instance_resources, update_instance, InstanceResourcePatch,
};
use crate::libs::incus::incus_pool::PoolHost;
use crate::libs::incus::instance_swap::{resolve_effective_swap_size, resolve_incus_swap_value};
use crate::routes::users::create_log;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new().route("/{id}/instances/batch-config", post(batch_config))
}

// ===========================================================================
// helpers
// ===========================================================================

const BATCH_CONFIG_CONCURRENCY: usize = 10;
const RETRYABLE_ERRORS: &[&str] = &[
    "ETIMEDOUT",
    "ECONNREFUSED",
    "ECONNRESET",
    "context deadline exceeded",
    "timeout",
];

fn is_retryable_error(error: &str) -> bool {
    let lower = error.to_lowercase();
    RETRYABLE_ERRORS
        .iter()
        .any(|e| lower.contains(&e.to_lowercase()))
}

fn validation(message: &str) -> ApiError {
    ApiError::validation(message)
}

/// JS Number(id) for the host param: NaN -> 400 INVALID_ID; non-integral or
/// out-of-i32 values fail Prisma Int validation -> 500.
fn js_number_id(raw: &str) -> Result<i32, ApiError> {
    let t = raw.trim();
    let v: f64 = if t.is_empty() {
        0.0
    } else {
        t.parse::<f64>()
            .map_err(|_| ApiError::bad_request(code::INVALID_ID))?
    };
    if v.is_nan() {
        return Err(ApiError::bad_request(code::INVALID_ID));
    }
    if !v.is_finite() || v.fract() != 0.0 || !(i32::MIN as f64..=i32::MAX as f64).contains(&v) {
        return Err(ApiError::internal(format!(
            "Prisma Int argument out of range: {v}"
        )));
    }
    Ok(v as i32)
}

fn get_i64(config: &Map<String, Value>, key: &str) -> Option<Option<i64>> {
    match config.get(key) {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::Number(n)) => Some(Some(n.as_i64().unwrap_or(0))),
        Some(_) => None,
    }
}

fn get_f64(config: &Map<String, Value>, key: &str) -> Option<Option<f64>> {
    match config.get(key) {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::Number(n)) => Some(Some(n.as_f64().unwrap_or(0.0))),
        Some(_) => None,
    }
}

fn get_bool(config: &Map<String, Value>, key: &str) -> Option<Option<bool>> {
    match config.get(key) {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::Bool(b)) => Some(Some(*b)),
        Some(_) => None,
    }
}

fn get_str(config: &Map<String, Value>, key: &str) -> Option<Option<String>> {
    match config.get(key) {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(s)) => Some(Some(s.clone())),
        Some(_) => None,
    }
}

/// JSON-schema range check: integer|null within [min, max].
fn validate_int_field(
    config: &Map<String, Value>,
    key: &str,
    min: i64,
    max: Option<i64>,
) -> Result<(), ApiError> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Number(n)) => {
            let v = n.as_i64().ok_or_else(|| validation(&format!("{key} must be integer")))?;
            if v < min {
                return Err(validation(&format!("{key} must be >= {min}")));
            }
            if let Some(max) = max {
                if v > max {
                    return Err(validation(&format!("{key} must be <= {max}")));
                }
            }
            Ok(())
        }
        Some(_) => Err(validation(&format!("{key} must be integer"))),
    }
}

/// The Fastify body schema of POST /:id/instances/batch-config.
fn validate_config_schema(config: &Map<String, Value>) -> Result<(), ApiError> {
    let int_checks: &[(&str, i64, Option<i64>)] = &[
        ("cpu", 1, None),
        ("memory", 1, None),
        ("swapSize", 0, Some(1_048_576)),
        ("portLimit", 1, Some(1000)),
        ("snapshotLimit", 0, Some(1000)),
        ("backupLimit", 0, Some(1000)),
        ("siteLimit", 0, Some(1000)),
        ("limitsReadIops", 0, None),
        ("limitsWriteIops", 0, None),
        ("limitsProcesses", 0, None),
        ("limitsCpuPriority", 0, Some(10)),
        ("bootAutostartPriority", 0, Some(100)),
        ("bootAutostartDelay", 5, Some(600)),
        ("bootHostShutdownTimeout", 30, Some(600)),
    ];
    for (key, min, max) in int_checks {
        validate_int_field(config, key, *min, *max)?;
    }
    if let Some(v) = config.get("disk") {
        match v {
            Value::Null => {}
            Value::Number(n) if n.as_f64().is_some_and(|d| d >= 1.0) => {}
            _ => return Err(validation("disk must be >= 1")),
        }
    }
    for key in ["monthlyTrafficLimit", "limitsRead", "limitsWrite", "limitsIngress", "limitsEgress"] {
        if let Some(v) = config.get(key) {
            if !matches!(v, Value::Null | Value::String(_)) {
                return Err(validation(&format!("{key} must be string")));
            }
        }
    }
    for key in ["swapEnabled", "nested", "privileged"] {
        if let Some(v) = config.get(key) {
            if !matches!(v, Value::Bool(_)) {
                return Err(validation(&format!("{key} must be boolean")));
            }
        }
    }
    if let Some(v) = config.get("bootAutostart") {
        if !matches!(v, Value::Bool(_) | Value::Null) {
            return Err(validation("bootAutostart must be boolean"));
        }
    }
    Ok(())
}

/// JS BigInt(string): optional sign, optional 0x/0o/0b prefix, digits only.
fn js_bigint_from_string(raw: &str) -> Result<i64, String> {
    let t = raw.trim();
    let (sign, rest) = match t.strip_prefix('-') {
        Some(r) => (-1i128, r),
        None => (1i128, t.strip_prefix('+').unwrap_or(t)),
    };
    let value = if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        i128::from_str_radix(hex, 16).map_err(|_| format!("Cannot convert {raw} to a BigInt"))?
    } else if let Some(oct) = rest.strip_prefix("0o").or_else(|| rest.strip_prefix("0O")) {
        i128::from_str_radix(oct, 8).map_err(|_| format!("Cannot convert {raw} to a BigInt"))?
    } else if let Some(bin) = rest.strip_prefix("0b").or_else(|| rest.strip_prefix("0B")) {
        i128::from_str_radix(bin, 2).map_err(|_| format!("Cannot convert {raw} to a BigInt"))?
    } else {
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("Cannot convert {raw} to a BigInt"));
        }
        rest.parse::<i128>()
            .map_err(|_| format!("Cannot convert {raw} to a BigInt"))?
    };
    let signed = sign * value;
    if signed > i64::MAX as i128 || signed < i64::MIN as i128 {
        return Err(format!(
            "Unable to fit value {signed} into a 64-bit signed integer"
        ));
    }
    Ok(signed as i64)
}

// ===========================================================================
// db helpers (db/index.ts + db/instance-tasks.ts)
// ===========================================================================

#[derive(Debug, Clone)]
struct BatchInstanceRow {
    pub id: i32,
    pub incus_id: String,
    pub name: String,
    pub cpu: i32,
    pub memory: i32,
    pub disk: i32,
    pub swap_enabled: bool,
    pub swap_size: Option<i32>,
    pub package_instance_type: Option<String>,
    pub plan_swap_size: Option<i32>,
}

/// db.getHostById (subset the batch route needs).
async fn get_host_row(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<(i32, String)>, ApiError> {
    let row: Option<(i32, String)> =
        sqlx::query_as("SELECT user_id, name FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(ApiError::from_sql)?;
    Ok(row)
}

async fn fetch_batch_instances(
    state: &SharedAppState,
    host_id: i32,
    instance_ids: &[i32],
) -> Result<Vec<BatchInstanceRow>, ApiError> {
    let rows: Vec<(
        i32,
        String,
        String,
        i32,
        i32,
        i32,
        bool,
        Option<i32>,
        Option<String>,
        Option<i32>,
    )> = sqlx::query_as(
        "SELECT i.id, i.incus_id, i.name, i.cpu, i.memory, i.disk, i.swap_enabled, \
         i.swap_size, p.instance_type::text AS package_instance_type, pp.swap_size \
         FROM instances i \
         LEFT JOIN packages p ON p.id = i.package_id \
         LEFT JOIN package_plans pp ON pp.id = i.package_plan_id \
         WHERE i.id = ANY($1) AND i.host_id = $2 \
         AND i.status::text NOT IN ('deleted', 'creating')",
    )
    .bind(instance_ids)
    .bind(host_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from_sql)?;

    Ok(rows
        .into_iter()
        .map(
            |(id, incus_id, name, cpu, memory, disk, swap_enabled, swap_size, pkg_type, plan_swap)| {
                BatchInstanceRow {
                    id,
                    incus_id,
                    name,
                    cpu,
                    memory,
                    disk,
                    swap_enabled,
                    swap_size,
                    package_instance_type: pkg_type,
                    plan_swap_size: plan_swap,
                }
            },
        )
        .collect())
}

/// getActiveTaskForInstance -> taskType string for the error message.
async fn get_active_task_for_instance(
    state: &SharedAppState,
    instance_id: i32,
) -> Result<Option<String>, ApiError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT task_type::text AS task_type FROM instance_tasks \
         WHERE instance_id = $1 AND status::text IN ('PENDING', 'PROCESSING') \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(row.map(|(t,)| t))
}

/// db.adjustHostResources (atomic increments; zero deltas are skipped).
async fn adjust_host_resources(
    state: &SharedAppState,
    host_id: i32,
    cpu_used: i64,
    memory_used: i64,
    disk_used: i64,
) -> Result<(), ApiError> {
    if cpu_used == 0 && memory_used == 0 && disk_used == 0 {
        return Ok(());
    }
    sqlx::query(
        "UPDATE hosts SET cpu_used = cpu_used + $2, memory_used = memory_used + $3, \
         disk_used = disk_used + $4 WHERE id = $1",
    )
    .bind(host_id)
    .bind(cpu_used as i32)
    .bind(memory_used as i32)
    .bind(disk_used as i32)
    .execute(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(())
}

// ===========================================================================
// handler
// ===========================================================================

async fn batch_config(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> Result<Json<Value>, ApiError> {
    // An empty body fails the Fastify schema with "instanceIds is required".
    let Json(body) = body.unwrap_or(Json(json!({})));
    let host_id = js_number_id(&id)?;

    let Value::Object(body) = body else {
        return Err(validation("body must be object"));
    };
    let Some(Value::Array(instance_ids_raw)) = body.get("instanceIds").cloned() else {
        return Err(validation("instanceIds is required"));
    };
    if instance_ids_raw.is_empty() {
        return Err(validation("instanceIds must NOT have fewer than 1 items"));
    }
    if instance_ids_raw.len() > 1000 {
        return Err(validation("instanceIds must NOT have more than 1000 items"));
    }
    let mut instance_ids: Vec<i32> = Vec::with_capacity(instance_ids_raw.len());
    for raw in &instance_ids_raw {
        match raw.as_i64() {
            Some(v) if v >= i32::MIN as i64 && v <= i32::MAX as i64 => instance_ids.push(v as i32),
            _ => return Err(validation("instanceIds must be integer")),
        }
    }
    let Some(config) = body.get("config").cloned() else {
        return Err(validation("config is required"));
    };
    let Value::Object(config) = config else {
        return Err(validation("config must be object"));
    };
    validate_config_schema(&config)?;

    // 验证宿主机存在且属于当前用户
    let host = get_host_row(&state, host_id).await?;
    let Some((host_user_id, host_name)) = host else {
        return Err(ApiError::not_found(code::HOST_NOT_FOUND));
    };

    // 权限检查：管理员或宿主机所有者可以批量修改配置
    if user.role != "admin" && host_user_id != user.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    // 检查是否有任何配置要修改
    if config.is_empty() {
        return Err(ApiError::bad_request(code::CONFIG_NO_CHANGES));
    }

    // 获取所有目标实例并验证它们属于该宿主机
    let instances = fetch_batch_instances(&state, host_id, &instance_ids).await?;
    if instances.is_empty() {
        return Err(ApiError::bare(StatusCode::BAD_REQUEST, "没有找到可修改的实例"));
    }

    // 判断是否需要连接 Incus
    let needs_incus = has_incus_config(&config);
    let client: Option<Arc<IncusClient>> = if needs_incus {
        let (url, cert_path, key_path, server_certificate, server_fingerprint, allow_private) =
            sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>, Option<String>, bool)>(
                "SELECT url, cert_path, key_path, server_certificate, server_fingerprint, \
                 allow_private_network FROM hosts WHERE id = $1",
            )
            .bind(host_id)
            .fetch_optional(&state.db)
            .await
            .map_err(ApiError::from_sql)?
            .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
        match state
            .incus_pool
            .get_incus_client(&PoolHost {
                id: host_id as i64,
                url,
                cert_path,
                key_path,
                server_certificate,
                server_fingerprint,
                allow_private_network: allow_private,
            })
            .await
        {
            Ok(client) => Some(client),
            Err(err) => {
                return Err(ApiError::bare(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("无法连接到宿主机: {err}"),
                ));
            }
        }
    } else {
        None
    };

    // 使用并发控制处理实例；每项任务返回 (结果, 最终成功时的资源变化量)。
    let config_ref = config.clone();
    let task_results: Vec<(Value, i64, i64, i64)> = stream::iter(instances.into_iter())
        .map(|instance| {
            let state = state.clone();
            let client = client.clone();
            let config = config_ref.clone();
            async move {
                let first =
                    update_single_instance(&state, &instance, &config, client.as_deref()).await;
                let mut result = first;
                // 如果是可重试错误，自动重试一次
                if !result["success"].as_bool().unwrap_or(false) {
                    let error_text = result["error"].as_str().unwrap_or("");
                    if is_retryable_error(error_text) {
                        tracing::info!(
                            "[BatchConfig] Retrying instance {} due to: {error_text}",
                            instance.name
                        );
                        result = update_single_instance(
                            &state,
                            &instance,
                            &config,
                            client.as_deref(),
                        )
                        .await;
                    }
                }
                // 资源变化量只在最终成功时累计一次（TS 在首尝成功或重试转败为胜
                // 时各计一次，等价于“最终成功”各一次）。
                let deltas = if result["success"].as_bool().unwrap_or(false) {
                    (
                        config
                            .get("cpu")
                            .and_then(Value::as_i64)
                            .map(|c| c - instance.cpu as i64)
                            .unwrap_or(0),
                        config
                            .get("memory")
                            .and_then(Value::as_i64)
                            .map(|m| m - instance.memory as i64)
                            .unwrap_or(0),
                        config
                            .get("disk")
                            .and_then(Value::as_f64)
                            .map(|d| d.round() as i64 - instance.disk as i64)
                            .unwrap_or(0),
                    )
                } else {
                    (0, 0, 0)
                };
                (result, deltas.0, deltas.1, deltas.2)
            }
        })
        .buffer_unordered(BATCH_CONFIG_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    // 批量完成后，统一更新宿主机资源使用量（避免并发问题）
    let (total_cpu, total_memory, total_disk) = task_results.iter().fold(
        (0i64, 0i64, 0i64),
        |(c, m, d), (_, dc, dm, dd)| (c + dc, m + dm, d + dd),
    );
    if total_cpu != 0 || total_memory != 0 || total_disk != 0 {
        adjust_host_resources(&state, host_id, total_cpu, total_memory, total_disk).await?;
    }

    let results: Vec<Value> = task_results.iter().map(|(r, _, _, _)| r.clone()).collect();
    let success_count = results
        .iter()
        .filter(|r| r["success"].as_bool().unwrap_or(false))
        .count();
    let failed_items: Vec<Value> = results
        .iter()
        .filter(|r| !r["success"].as_bool().unwrap_or(false))
        .cloned()
        .collect();
    let failed_count = failed_items.len();

    // 记录操作日志
    create_log(
        &state,
        user.id,
        "instance",
        "instance.batch_config",
        &format!(
            "Batch updated {success_count} instances config on host \"{host_name}\", failed: {failed_count}"
        ),
        if failed_count > 0 { "partial" } else { "success" },
    )
    .await;

    // TS leaves `retryPayload` undefined when nothing failed, and
    // JSON.stringify drops undefined keys — omit it on the all-success path.
    let mut response = json!({
        "success": failed_count == 0,
        "totalCount": results.len(),
        "successCount": success_count,
        "failedCount": failed_count,
        "failedItems": failed_items,
    });
    if failed_count > 0 {
        response["retryPayload"] = json!({
            "instanceIds": response_failed_ids(&results),
            "config": Value::Object(config),
        });
    }

    Ok(Json(response))
}

// ===========================================================================
// per-instance update (port of updateSingleInstance)
// ===========================================================================

/// 判断配置是否需要同步到 Incus
fn has_incus_config(config: &Map<String, Value>) -> bool {
    [
        "cpu", "memory", "disk", "swapEnabled", "swapSize", "nested", "privileged",
        "limitsRead", "limitsWrite", "limitsReadIops", "limitsWriteIops",
        "limitsIngress", "limitsEgress", "limitsProcesses", "limitsCpuPriority",
        "bootAutostart", "bootAutostartPriority", "bootAutostartDelay",
        "bootHostShutdownTimeout",
    ]
    .iter()
    .any(|field| config.get(*field).is_some())
}

/// 判断是否有需要同步到 Incus 的高级配置
fn has_advanced_incus_config(config: &Map<String, Value>) -> bool {
    [
        "nested", "privileged", "limitsRead", "limitsWrite", "limitsReadIops",
        "limitsWriteIops", "limitsIngress", "limitsEgress", "limitsProcesses",
        "limitsCpuPriority", "bootAutostart", "bootAutostartPriority",
        "bootAutostartDelay", "bootHostShutdownTimeout",
    ]
    .iter()
    .any(|field| config.get(*field).is_some())
}

/// 判断是否有需要存储到数据库的高级配置
fn has_db_advanced_config(config: &Map<String, Value>) -> bool {
    [
        "limitsRead", "limitsWrite", "limitsReadIops", "limitsWriteIops",
        "limitsIngress", "limitsEgress", "limitsProcesses", "limitsCpuPriority",
        "bootAutostart", "bootAutostartPriority", "bootAutostartDelay",
        "bootHostShutdownTimeout",
    ]
    .iter()
    .any(|field| config.get(*field).is_some())
}

struct StorageOverrides {
    limits_read: Option<Option<String>>,
    limits_write: Option<Option<String>>,
    limits_read_iops: Option<Option<i64>>,
    limits_write_iops: Option<Option<i64>>,
}

fn resolve_storage_overrides(config: &Map<String, Value>) -> StorageOverrides {
    let mut overrides = StorageOverrides {
        limits_read: None,
        limits_write: None,
        limits_read_iops: None,
        limits_write_iops: None,
    };

    if config.get("limitsRead").is_some() {
        overrides.limits_read = get_str(config, "limitsRead");
        overrides.limits_read_iops = Some(None);
    } else if config.get("limitsReadIops").is_some() {
        overrides.limits_read = Some(None);
        overrides.limits_read_iops = get_i64(config, "limitsReadIops");
    }

    if config.get("limitsWrite").is_some() {
        overrides.limits_write = get_str(config, "limitsWrite");
        overrides.limits_write_iops = Some(None);
    } else if config.get("limitsWriteIops").is_some() {
        overrides.limits_write = Some(None);
        overrides.limits_write_iops = get_i64(config, "limitsWriteIops");
    }

    overrides
}

/// Inserts/deletes a key in a device map (None -> remove, mirroring the TS
/// `delete incusDevices[...]` semantics for explicit nulls).
fn set_device_key(device: &mut Map<String, Value>, key: &str, value: Option<String>) {
    match value {
        Some(v) => {
            device.insert(key.to_string(), json!(v));
        }
        None => {
            device.remove(key);
        }
    }
}

/// Runs an UPDATE with dynamically bound parameters. Explicit nulls become SQL
/// NULL literals (a text-typed bind cannot be compared against int/bigint/bool
/// columns without a cast).
async fn update_instance_row(
    state: &SharedAppState,
    instance_id: i32,
    sets: &[String],
    binds: &[String],
) -> Result<(), String> {
    if sets.is_empty() {
        return Ok(());
    }
    let sql = format!(
        "UPDATE instances SET {} WHERE id = {}",
        sets.join(", "),
        instance_id
    );
    let mut query = sqlx::query(&sql);
    for value in binds {
        query = query.bind(value);
    }
    query.execute(&state.db).await.map_err(|e| e.to_string())?;
    Ok(())
}

fn response_failed_ids(results: &[Value]) -> Vec<Value> {
    results
        .iter()
        .filter(|r| !r["success"].as_bool().unwrap_or(false))
        .map(|r| r["instanceId"].clone())
        .collect()
}

fn push_str_field(binds: &mut Vec<String>, sets: &mut Vec<String>, column: &str, v: Option<String>) {
    match v {
        Some(s) => {
            binds.push(s);
            sets.push(format!("{column} = ${}", binds.len()));
        }
        None => sets.push(format!("{column} = NULL")),
    }
}

fn push_int_field(binds: &mut Vec<String>, sets: &mut Vec<String>, column: &str, v: Option<i64>) {
    match v {
        Some(n) => {
            binds.push(n.to_string());
            sets.push(format!("{column} = ${}::int", binds.len()));
        }
        None => sets.push(format!("{column} = NULL")),
    }
}

fn push_bool_field(binds: &mut Vec<String>, sets: &mut Vec<String>, column: &str, v: Option<bool>) {
    match v {
        Some(b) => {
            binds.push(b.to_string());
            sets.push(format!("{column} = ${}::boolean", binds.len()));
        }
        None => sets.push(format!("{column} = NULL")),
    }
}

async fn update_single_instance(
    state: &SharedAppState,
    instance: &BatchInstanceRow,
    config: &Map<String, Value>,
    client: Option<&IncusClient>,
) -> Value {
    let result: Result<(), String> = async {
        if let Some(task_type) = get_active_task_for_instance(state, instance.id)
            .await
            .map_err(|e| e.to_string())?
        {
            return Err(format!("实例存在进行中的任务: {task_type}"));
        }

        let has_swap_config =
            config.get("swapEnabled").is_some() || config.get("swapSize").is_some();
        let instance_kind = if instance.package_instance_type.as_deref() == Some("vm") {
            "vm"
        } else {
            "container"
        };
        let current_swap_size = resolve_effective_swap_size(
            instance.swap_size.map(i64::from),
            instance.plan_swap_size.map(i64::from),
        );
        let next_swap_enabled = get_bool(config, "swapEnabled")
            .flatten()
            .unwrap_or(instance.swap_enabled);
        let next_swap_size = if let Some(raw) = get_i64(config, "swapSize") {
            raw.unwrap_or(0).max(0)
        } else {
            current_swap_size
        };
        let storage_overrides = resolve_storage_overrides(config);

        if has_swap_config && instance_kind == "vm" {
            return Err("虚拟机不支持批量 SWAP 配置".to_string());
        }

        if next_swap_enabled && next_swap_size <= 0 {
            return Err("启用 SWAP 前需要设置大于 0 的 SWAP 大小".to_string());
        }

        // 1. 更新资源配置（CPU、内存、磁盘）到 Incus
        if let Some(client) = client {
            if config.get("cpu").is_some()
                || config.get("memory").is_some()
                || config.get("disk").is_some()
            {
                patch_instance_resources(
                    client,
                    &instance.incus_id,
                    InstanceResourcePatch {
                        cpu: get_i64(config, "cpu").flatten(),
                        memory: get_i64(config, "memory").flatten(),
                        disk: get_f64(config, "disk").flatten().map(|d| d.round() as i64),
                    },
                )
                .await
                .map_err(|e| e.to_string())?;
            }
        }

        // 2. 更新高级配置到 Incus
        if let Some(client) = client {
            if has_advanced_incus_config(config) || has_swap_config {
                let mut incus_config: Map<String, Value> = Map::new();
                let needs_device_config = config.get("limitsRead").is_some()
                    || config.get("limitsReadIops").is_some()
                    || config.get("limitsWrite").is_some()
                    || config.get("limitsWriteIops").is_some()
                    || config.get("limitsIngress").is_some()
                    || config.get("limitsEgress").is_some();
                let mut incus_devices: Option<Map<String, Value>> = None;

                if has_swap_config {
                    incus_config.insert(
                        "limits.memory.swap".to_string(),
                        json!(resolve_incus_swap_value(next_swap_enabled, Some(next_swap_size))),
                    );
                }

                // 容器权限
                if let Some(v) = get_bool(config, "nested") {
                    incus_config.insert(
                        "security.nesting".to_string(),
                        json!(if v.unwrap_or(false) { "true" } else { "false" }),
                    );
                }
                if let Some(v) = get_bool(config, "privileged") {
                    incus_config.insert(
                        "security.privileged".to_string(),
                        json!(if v.unwrap_or(false) { "true" } else { "false" }),
                    );
                }

                // 进程限制
                if let Some(v) = get_i64(config, "limitsProcesses") {
                    match v {
                        Some(n) => {
                            incus_config
                                .insert("limits.processes".to_string(), json!(n.to_string()));
                        }
                        None => {
                            incus_config.insert("limits.processes".to_string(), Value::Null);
                        }
                    }
                }

                // CPU 优先级直接使用 Incus 原生 0-10 语义
                if let Some(v) = get_i64(config, "limitsCpuPriority") {
                    match v {
                        Some(n) => {
                            incus_config
                                .insert("limits.cpu.priority".to_string(), json!(n.to_string()));
                        }
                        None => {
                            incus_config.insert("limits.cpu.priority".to_string(), Value::Null);
                        }
                    }
                }

                // 启动设置
                if let Some(v) = get_bool(config, "bootAutostart") {
                    match v {
                        Some(b) => {
                            incus_config.insert(
                                "boot.autostart".to_string(),
                                json!(if b { "true" } else { "false" }),
                            );
                        }
                        None => {
                            incus_config.insert("boot.autostart".to_string(), Value::Null);
                        }
                    }
                }
                if let Some(v) = get_i64(config, "bootAutostartPriority") {
                    match v {
                        Some(n) => {
                            incus_config.insert(
                                "boot.autostart.priority".to_string(),
                                json!(n.to_string()),
                            );
                        }
                        None => {
                            incus_config
                                .insert("boot.autostart.priority".to_string(), Value::Null);
                        }
                    }
                }
                if let Some(v) = get_i64(config, "bootAutostartDelay") {
                    match v {
                        Some(n) => {
                            incus_config.insert(
                                "boot.autostart.delay".to_string(),
                                json!(n.to_string()),
                            );
                        }
                        None => {
                            incus_config.insert("boot.autostart.delay".to_string(), Value::Null);
                        }
                    }
                }
                if let Some(v) = get_i64(config, "bootHostShutdownTimeout") {
                    match v {
                        Some(n) => {
                            incus_config.insert(
                                "boot.host_shutdown_timeout".to_string(),
                                json!(n.to_string()),
                            );
                        }
                        None => {
                            incus_config
                                .insert("boot.host_shutdown_timeout".to_string(), Value::Null);
                        }
                    }
                }

                if needs_device_config {
                    // 复制完整的设备列表，然后修改需要修改的设备
                    let current_instance = get_instance(client, &instance.incus_id)
                        .await
                        .map_err(|e| e.to_string())?;
                    incus_devices = Some(current_instance.devices);
                }

                // 存储 I/O 限制 (应用到 root 设备)
                if config.get("limitsRead").is_some()
                    || config.get("limitsReadIops").is_some()
                    || config.get("limitsWrite").is_some()
                    || config.get("limitsWriteIops").is_some()
                {
                    let devices = incus_devices.get_or_insert_with(Map::new);
                    if !devices.contains_key("root") {
                        devices.insert(
                            "root".to_string(),
                            json!({ "path": "/", "pool": "default", "type": "disk" }),
                        );
                    }
                    let root_obj = devices.get_mut("root").unwrap().as_object_mut().unwrap();

                    if config.get("limitsRead").is_some() {
                        set_device_key(
                            root_obj,
                            "limits.read",
                            get_str(config, "limitsRead").flatten(),
                        );
                    } else if config.get("limitsReadIops").is_some() {
                        set_device_key(
                            root_obj,
                            "limits.read",
                            get_i64(config, "limitsReadIops")
                                .flatten()
                                .map(|v| format!("{v}iops")),
                        );
                    }

                    if config.get("limitsWrite").is_some() {
                        set_device_key(
                            root_obj,
                            "limits.write",
                            get_str(config, "limitsWrite").flatten(),
                        );
                    } else if config.get("limitsWriteIops").is_some() {
                        set_device_key(
                            root_obj,
                            "limits.write",
                            get_i64(config, "limitsWriteIops")
                                .flatten()
                                .map(|v| format!("{v}iops")),
                        );
                    }
                }

                // 网络限制 (应用到 eth0 设备)
                if config.get("limitsIngress").is_some() || config.get("limitsEgress").is_some() {
                    // 确保 eth0 设备存在
                    let devices = incus_devices.get_or_insert_with(Map::new);
                    if !devices.contains_key("eth0") {
                        devices.insert(
                            "eth0".to_string(),
                            json!({ "type": "nic", "name": "eth0", "network": "incusbr0" }),
                        );
                    }
                    let eth0_obj = devices.get_mut("eth0").unwrap().as_object_mut().unwrap();

                    if config.get("limitsIngress").is_some() {
                        set_device_key(
                            eth0_obj,
                            "limits.ingress",
                            get_str(config, "limitsIngress").flatten(),
                        );
                    }
                    if config.get("limitsEgress").is_some() {
                        set_device_key(
                            eth0_obj,
                            "limits.egress",
                            get_str(config, "limitsEgress").flatten(),
                        );
                    }
                }

                // 应用更新到 Incus
                let mut updates: Map<String, Value> = Map::new();
                if !incus_config.is_empty() {
                    updates.insert("config".to_string(), Value::Object(incus_config));
                }
                if let Some(devices) = incus_devices {
                    if !devices.is_empty() {
                        updates.insert("devices".to_string(), Value::Object(devices));
                    }
                }

                if !updates.is_empty() {
                    update_instance(client, &instance.incus_id, &updates)
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }

        // 3. 更新数据库中的资源配置
        if config.get("cpu").is_some()
            || config.get("memory").is_some()
            || config.get("disk").is_some()
            || config.get("monthlyTrafficLimit").is_some()
        {
            let traffic_limit: Option<Option<i64>> = if config.get("monthlyTrafficLimit").is_some()
            {
                match config.get("monthlyTrafficLimit") {
                    Some(Value::Null) => Some(None),
                    Some(Value::String(s)) if s.is_empty() => Some(None),
                    Some(Value::String(s)) => Some(Some(js_bigint_from_string(s)?)),
                    _ => return Err("Cannot convert monthlyTrafficLimit to a BigInt".to_string()),
                }
            } else {
                None
            };

            let mut sets: Vec<String> = Vec::new();
            let mut binds: Vec<String> = Vec::new();
            if let Some(v) = get_i64(config, "cpu") {
                push_int_field(&mut binds, &mut sets, "cpu", v);
            }
            if let Some(v) = get_i64(config, "memory") {
                push_int_field(&mut binds, &mut sets, "memory", v);
            }
            if let Some(v) = get_f64(config, "disk") {
                push_int_field(&mut binds, &mut sets, "disk", v.map(|d| d.round() as i64));
            }
            if let Some(v) = traffic_limit {
                match v {
                    Some(n) => {
                        binds.push(n.to_string());
                        sets.push(format!(
                            "monthly_traffic_limit = ${}::bigint",
                            binds.len()
                        ));
                    }
                    None => sets.push("monthly_traffic_limit = NULL".to_string()),
                }
            }
            update_instance_row(&state, instance.id, &sets, &binds).await?;
            // 注意：宿主机资源使用量在批量处理完成后统一更新，避免并发问题
        }

        // 4. 更新数据库中的配额限制
        if config.get("portLimit").is_some()
            || config.get("snapshotLimit").is_some()
            || config.get("backupLimit").is_some()
            || config.get("siteLimit").is_some()
        {
            let mut sets: Vec<String> = Vec::new();
            let mut binds: Vec<String> = Vec::new();
            for (key, column) in [
                ("portLimit", "port_limit"),
                ("snapshotLimit", "snapshot_limit"),
                ("backupLimit", "backup_limit"),
                ("siteLimit", "site_limit"),
            ] {
                if let Some(v) = get_i64(config, key) {
                    push_int_field(&mut binds, &mut sets, column, v);
                }
            }
            update_instance_row(&state, instance.id, &sets, &binds).await?;
        }

        // 5. 更新数据库中的 SWAP 配置
        if has_swap_config {
            let mut sets: Vec<String> = Vec::new();
            let mut binds: Vec<String> = Vec::new();
            if let Some(v) = get_bool(config, "swapEnabled") {
                push_bool_field(&mut binds, &mut sets, "swap_enabled", v);
            }
            if config.get("swapSize").is_some() {
                push_int_field(
                    &mut binds,
                    &mut sets,
                    "swap_size",
                    get_i64(config, "swapSize").flatten(),
                );
            } else if get_bool(config, "swapEnabled").flatten() == Some(true) {
                push_int_field(&mut binds, &mut sets, "swap_size", Some(next_swap_size));
            }
            update_instance_row(&state, instance.id, &sets, &binds).await?;
        }

        // 6. 更新数据库中的高级配置
        if has_db_advanced_config(config) {
            let mut sets: Vec<String> = Vec::new();
            let mut binds: Vec<String> = Vec::new();
            if let Some(v) = storage_overrides.limits_read.clone() {
                push_str_field(&mut binds, &mut sets, "limits_read", v);
            }
            if let Some(v) = storage_overrides.limits_write.clone() {
                push_str_field(&mut binds, &mut sets, "limits_write", v);
            }
            if let Some(v) = storage_overrides.limits_read_iops {
                push_int_field(&mut binds, &mut sets, "limits_read_iops", v);
            }
            if let Some(v) = storage_overrides.limits_write_iops {
                push_int_field(&mut binds, &mut sets, "limits_write_iops", v);
            }
            if let Some(v) = get_str(config, "limitsIngress") {
                push_str_field(&mut binds, &mut sets, "limits_ingress", v);
            }
            if let Some(v) = get_str(config, "limitsEgress") {
                push_str_field(&mut binds, &mut sets, "limits_egress", v);
            }
            if let Some(v) = get_i64(config, "limitsProcesses") {
                push_int_field(&mut binds, &mut sets, "limits_processes", v);
            }
            if let Some(v) = get_i64(config, "limitsCpuPriority") {
                push_int_field(&mut binds, &mut sets, "limits_cpu_priority", v);
            }
            if let Some(v) = get_bool(config, "bootAutostart") {
                push_bool_field(&mut binds, &mut sets, "boot_autostart", v);
            }
            if let Some(v) = get_i64(config, "bootAutostartPriority") {
                push_int_field(&mut binds, &mut sets, "boot_autostart_priority", v);
            }
            if let Some(v) = get_i64(config, "bootAutostartDelay") {
                push_int_field(&mut binds, &mut sets, "boot_autostart_delay", v);
            }
            if let Some(v) = get_i64(config, "bootHostShutdownTimeout") {
                push_int_field(&mut binds, &mut sets, "boot_host_shutdown_timeout", v);
            }
            update_instance_row(&state, instance.id, &sets, &binds).await?;
        }

        Ok(())
    }
    .await;

    match result {
        Ok(()) => json!({
            "instanceId": instance.id,
            "incusId": instance.incus_id,
            "name": instance.name,
            "success": true,
        }),
        Err(message) => {
            tracing::error!(
                "[BatchConfig] Failed to update instance {}: {message}",
                instance.name
            );
            json!({
                "instanceId": instance.id,
                "incusId": instance.incus_id,
                "name": instance.name,
                "success": false,
                "error": message,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// batch_config shares the /api/hosts prefix with routes::hosts; app.rs
    /// merges the two routers. Assert the merge stays conflict-free (axum
    /// panics on overlapping route patterns).
    #[test]
    fn merged_hosts_router_builds_without_conflicts() {
        let _router = crate::routes::hosts::router().merge(router());
    }
}
