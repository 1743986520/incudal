//! 签到系统路由 — port of server/src/routes/checkin.ts (+ db/checkin.ts,
//! db/redeem-codes.ts system-code consumption). Mounted at /api/checkin.
//!
//! Daily check-in is hard-disabled upstream (isDailyCheckinEnabled() ===
//! false). Redeem accepts system codes (h- prefix) only, applies resources
//! directly to a free instance under a per-instance distributed lock with
//! optimistic version claim, advisory-lock-guarded code consumption, and the
//! TS compensation ladder (disk growth is irreversible once applied remotely).

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
use crate::db::{advisory_lock_namespace, try_advisory_transaction_lock};
use crate::error::{code, ApiError};
use crate::libs::incus::incus_instances::patch_instance_resources;
use crate::libs::instance_common::{
    create_log_with_instance, get_host_for_incus, get_incus_client_for_host, iso,
};
use crate::libs::resource_pool::{
    add_points, add_to_resource_pool, adjust_host_resources, has_checked_in_today,
    randomize_reward, release_lock, acquire_lock, extend_lock, update_instance_resources,
};
use crate::state::SharedAppState;

const CODE_TYPE_NAMES: &[(&str, &str)] = &[
    ("c", "CPU"), ("r", "Memory"), ("d", "Disk"), ("t", "Traffic"), ("p", "Points"),
];
const CODE_TYPE_UNITS: &[(&str, &str)] = &[("c", "%"), ("r", "MB"), ("d", "MB"), ("t", "GB"), ("p", "")];

fn type_name_en(t: &str) -> &str {
    CODE_TYPE_NAMES.iter().find(|(k, _)| *k == t).map(|(_, v)| *v).unwrap_or(t)
}
fn type_unit(t: &str) -> &'static str {
    CODE_TYPE_UNITS.iter().find(|(k, _)| *k == t).map(|(_, v)| *v).unwrap_or("")
}

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/status", get(status))
        .route("/checkin", post(checkin))
        .route("/redeem", post(redeem))
        .route("/instances", get(instances))
        .route("/records", get(records))
        .route("/redeems", get(redeems))
}

// ===========================================================================
// GET /status
// ===========================================================================

async fn status(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    let stats: Option<(bool, i32)> = sqlx::query_as(
        "SELECT self_only_mode, consecutive_others_use FROM checkin_stats WHERE user_id = $1",
    )
    .bind(user.0.id)
    .fetch_optional(&state.db)
    .await?;
    let (instance_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instances WHERE user_id = $1 AND status::text NOT IN ('deleted','error')",
    )
    .bind(user.0.id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(json!({
        "hasCheckedIn": has_checked_in_today(&state.db, user.0.id).await?,
        "hasInstances": instance_count > 0,
        "selfOnlyMode": stats.as_ref().map(|s| s.0).unwrap_or(false),
        "consecutiveOthersUse": stats.as_ref().map(|s| s.1).unwrap_or(0),
    })))
}

// ===========================================================================
// POST /checkin — 上线开关关闭中
// ===========================================================================

async fn checkin(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    // isDailyCheckinEnabled() === false（TS 同步硬编码）
    create_log_with_instance(
        &state,
        user.0.id,
        "checkin",
        "checkin.disabled",
        "Daily check-in is temporarily disabled",
        "failed",
        None,
    )
    .await;
    Err(ApiError::new(code::FEATURE_DISABLED, StatusCode::FORBIDDEN)
        .with_details("签到功能暂时下线，后续改版后再开放"))
}

// ===========================================================================
// POST /redeem — 系统兑换码应用到实例
// ===========================================================================

#[derive(Deserialize)]
struct RedeemBody {
    #[serde(rename = "redeemCode")]
    redeem_code: Option<String>,
    instance_id: Option<serde_json::Value>,
}

#[derive(Debug, FromRow)]
struct SystemCodeRow {
    id: i32,
    host_id: i32,
    code_type: String,
    code_value: i32,
    max_uses: i32,
    used_count: i32,
    enabled: bool,
    expires_at: Option<DateTime<Utc>>,
    batch_id: Option<String>,
}

fn bare(status: StatusCode, message: impl Into<String>) -> ApiError {
    ApiError::bare(status, message)
}

async fn redeem(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    body: Option<Json<RedeemBody>>,
) -> Result<Response, ApiError> {
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let redeem_code = body
        .redeem_code
        .as_deref()
        .map(str::trim)
        .filter(|c| (5..=30).contains(&c.len()))
        .ok_or_else(|| ApiError::validation("redeemCode must be between 5 and 30 characters"))?;
    let instance_id = body
        .instance_id
        .as_ref()
        .and_then(Value::as_i64)
        .filter(|id| *id >= 1)
        .ok_or_else(|| ApiError::validation("instanceId must be >= 1"))? as i32;

    // 仅支持系统码（h- 前缀）
    if !redeem_code.starts_with("h-") {
        return Err(ApiError::bad_request(code::REDEEM_CODE_INVALID_FORMAT));
    }

    let system_code = sqlx::query_as::<_, SystemCodeRow>(
        "SELECT id, host_id, code_type::text AS code_type, code_value, max_uses, used_count, \
                enabled, expires_at, batch_id FROM redeem_codes WHERE code = $1",
    )
    .bind(redeem_code)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found(code::REDEEM_CODE_NOT_FOUND))?;

    if !system_code.enabled {
        return Err(ApiError::bad_request(code::REDEEM_CODE_DISABLED));
    }
    if system_code
        .expires_at
        .map(|e| e < Utc::now())
        .unwrap_or(false)
    {
        return Err(ApiError::bad_request(code::REDEEM_CODE_EXPIRED));
    }
    if system_code.used_count >= system_code.max_uses {
        return Err(ApiError::bad_request(code::REDEEM_CODE_EXHAUSTED));
    }

    let (used_code,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM redeem_code_usages WHERE redeem_code_id = $1 AND user_id = $2",
    )
    .bind(system_code.id)
    .bind(user.0.id)
    .fetch_one(&state.db)
    .await?;
    if used_code > 0 {
        return Err(ApiError::bad_request(code::REDEEM_CODE_ALREADY_USED_BY_USER));
    }
    if let Some(batch_id) = &system_code.batch_id {
        let (used_batch,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM redeem_code_usages WHERE user_id = $1 AND batch_id = $2",
        )
        .bind(user.0.id)
        .bind(batch_id)
        .fetch_one(&state.db)
        .await?;
        if used_batch > 0 {
            return Err(ApiError::bad_request(code::REDEEM_CODE_BATCH_LIMIT));
        }
    }

    let code_type = system_code.code_type.clone();
    let code_value = system_code.code_value;

    // 目标实例
    let instance = crate::libs::instance_common::get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    if !matches!(instance.status.as_str(), "running" | "stopped") {
        return Err(ApiError::bad_request(code::INSTANCE_STATUS_INVALID));
    }
    if instance.host_id != system_code.host_id {
        return Err(ApiError::bad_request(code::REDEEM_CODE_HOST_MISMATCH));
    }

    // 同一实例兑换串行化（分布式锁 + 心跳）
    let lock_key = format!("redeem:instance:{instance_id}");
    let Some(lock_owner) = acquire_lock(&state.db, &lock_key, 120_000, 5_000).await? else {
        return Err(ApiError::with_message(
            "REDEEM_INSTANCE_BUSY",
            StatusCode::CONFLICT,
            "Instance is being modified, please retry",
        ));
    };
    let heartbeat_state = state.clone();
    let hb_key = lock_key.clone();
    let hb_owner = lock_owner.clone();
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            extend_lock(&heartbeat_state.db, &hb_key, &hb_owner, 120_000).await;
        }
    });

    let result = redeem_locked(
        &state,
        &user.0,
        instance_id,
        &system_code,
        &code_type,
        code_value,
        redeem_code,
    )
    .await;

    heartbeat.abort();
    release_lock(&state.db, &lock_key, &lock_owner).await;

    match result {
        Ok(response) => Ok(response.into_response()),
        Err(err) => Err(err),
    }
}

#[allow(clippy::too_many_arguments)]
async fn redeem_locked(
    state: &SharedAppState,
    user: &crate::auth::AuthUser,
    instance_id: i32,
    system_code: &SystemCodeRow,
    code_type: &str,
    code_value: i32,
    trimmed_code: &str,
) -> Result<Json<Value>, ApiError> {
    // 取鎖後重讀實例（基準值最新）
    let instance = crate::libs::instance_common::get_instance_by_id(state, instance_id)
        .await?
        .filter(|i| i.user_id == user.id)
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;

    let actual_added = code_value;
    let mut host_adjusted = false;
    let mut remote_applied = false;
    let mut database_applied = false;
    let mut code_consumed = false;

    let outcome: Result<Value, String> = async {
        // 乐观锁 claim（version + status guard）
        let claimed = sqlx::query(
            "UPDATE instances SET version = version + 1 \
             WHERE id = $1 AND user_id = $2 AND version = $3 AND status::text IN ('running','stopped')",
        )
        .bind(instance_id)
        .bind(user.id)
        .bind(sqlx::query_scalar::<_, i32>("SELECT version FROM instances WHERE id = $1")
            .bind(instance_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| e.to_string())?)
        .execute(&state.db)
        .await
        .map_err(|e| e.to_string())?;
        if claimed.rows_affected() != 1 {
            return Err("REDEEM_INSTANCE_BUSY".into());
        }

        // 兑换码消费（advisory lock + 原子计数）
        consume_system_code(state, system_code, user.id, instance_id)
            .await
            .map_err(|e| e.to_string())?;
        code_consumed = true;

        match code_type {
            "c" | "r" | "d" => {
                let host = crate::libs::instance_common::get_host_for_incus(state, instance.host_id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "REDEEM_HOST_NOT_FOUND".to_string())?;
                let new_value = if code_type == "c" {
                    instance.cpu + code_value
                } else if code_type == "r" {
                    instance.memory + code_value
                } else {
                    instance.disk + code_value
                };
                adjust_host_resources(
                    state,
                    instance.host_id,
                    if code_type == "c" { Some(actual_added as i64) } else { None },
                    if code_type == "r" { Some(actual_added as i64) } else { None },
                    if code_type == "d" { Some(actual_added as i64) } else { None },
                )
                .await
                .map_err(|e| e.to_string())?;
                host_adjusted = true;

                let client = get_incus_client_for_host(state, &host)
                    .await
                    .map_err(|e| e.error)?;
                let patch = crate::libs::incus::incus_instances::InstanceResourcePatch {
                    cpu: if code_type == "c" { Some(new_value as i64) } else { None },
                    memory: if code_type == "r" { Some(new_value as i64) } else { None },
                    disk: if code_type == "d" { Some(new_value as i64) } else { None },
                };
                patch_instance_resources(&client, &instance.incus_id, patch)
                    .await
                    .map_err(|e| format!("REDEEM_APPLY_FAILED: {e}"))?;
                remote_applied = true;

                update_instance_resources(
                    state,
                    instance_id,
                    if code_type == "c" { Some(new_value) } else { None },
                    if code_type == "r" { Some(new_value) } else { None },
                    if code_type == "d" { Some(new_value) } else { None },
                    None,
                )
                .await
                .map_err(|e| e.to_string())?;
                database_applied = true;
            }
            "t" => {
                let traffic_bytes = (code_value as i64) * 1024 * 1024 * 1024;
                let current_limit: Option<i64> = sqlx::query_scalar(
                    "SELECT monthly_traffic_limit FROM instances WHERE id = $1",
                )
                .bind(instance_id)
                .fetch_one(&state.db)
                .await
                .map_err(|e| e.to_string())?;
                let new_limit = current_limit.map(|l| l + traffic_bytes);
                update_instance_resources(state, instance_id, None, None, None, Some(new_limit))
                    .await
                    .map_err(|e| e.to_string())?;
                database_applied = true;
            }
            "p" => {
                add_points(&state.db, user.id, code_value as i64, "checkin", None, Some("兑换码奖励"))
                    .await
                    .map_err(|e| e.to_string())?;
                database_applied = true;
            }
            _ => {}
        }

        create_log_with_instance(
            state,
            user.id,
            "checkin",
            "redeem.success",
            &format!(
                "Redeemed system code {trimmed_code} for instance \"{}\": {} +{actual_added}{}",
                instance.name,
                type_name_en(code_type),
                type_unit(code_type),
            ),
            "success",
            Some(instance_id),
        )
        .await;

        if code_type != "p" {
            let log = sqlx::query(
                "INSERT INTO resource_pool_logs (user_id, action, resource_type, amount, instance_id, remark) \
                 VALUES ($1, 'system_redeem', $2::\"RedeemCodeType\", $3, $4, $5)",
            )
            .bind(user.id)
            .bind(code_type)
            .bind(actual_added)
            .bind(instance_id)
            .bind(format!("系统兑换码 {trimmed_code} 应用到 {}", instance.name));
            if let Err(err) = log.execute(&state.db).await {
                tracing::warn!("兑换成功，但资源日志写入失败: {err}");
            }
        }

        Ok(json!({
            "message": "Redeem successful",
            "codeType": code_type,
            "codeValue": code_value,
            "actualAdded": actual_added,
            "instanceId": instance_id,
            "instanceName": instance.name,
            "isSystemCode": true,
            "toResourcePool": false,
        }))
    }
    .await;

    match outcome {
        Ok(response) => Ok(Json(response)),
        Err(message) => {
            // 补偿阶梯（与 TS 相同，含磁盘不可逆逻辑）
            let compensation: Result<(), sqlx::Error> = async {
                match code_type {
                    "c" => {
                        if remote_applied {
                            if let Ok(Some(host)) =
                                crate::libs::instance_common::get_host_for_incus(state, instance.host_id).await
                            {
                                if let Ok(client) = get_incus_client_for_host(state, &host).await {
                                    let _ = patch_instance_resources(
                                        &client, &instance.incus_id,
                                        crate::libs::incus::incus_instances::InstanceResourcePatch {
                                            cpu: Some(instance.cpu as i64), memory: None, disk: None,
                                        },
                                    ).await;
                                }
                            }
                        }
                        if database_applied {
                            update_instance_resources(state, instance_id, Some(instance.cpu), None, None, None).await?;
                        }
                        if host_adjusted {
                            adjust_host_resources(state, instance.host_id, Some(-(actual_added as i64)), None, None).await?;
                        }
                    }
                    "r" => {
                        if remote_applied {
                            if let Ok(Some(host)) =
                                crate::libs::instance_common::get_host_for_incus(state, instance.host_id).await
                            {
                                if let Ok(client) = get_incus_client_for_host(state, &host).await {
                                    let _ = patch_instance_resources(
                                        &client, &instance.incus_id,
                                        crate::libs::incus::incus_instances::InstanceResourcePatch {
                                            cpu: None, memory: Some(instance.memory as i64), disk: None,
                                        },
                                    ).await;
                                }
                            }
                        }
                        if database_applied {
                            update_instance_resources(state, instance_id, None, Some(instance.memory), None, None).await?;
                        }
                        if host_adjusted {
                            adjust_host_resources(state, instance.host_id, None, Some(-(actual_added as i64)), None).await?;
                        }
                    }
                    "d" => {
                        if !remote_applied {
                            if database_applied {
                                update_instance_resources(state, instance_id, None, None, Some(instance.disk), None).await?;
                            }
                            if host_adjusted {
                                adjust_host_resources(state, instance.host_id, None, None, Some(-(actual_added as i64))).await?;
                            }
                        } else if !database_applied {
                            // 磁盘扩容在常见 Incus 存储驱动上不可逆：补齐本地而非尝试收缩
                            update_instance_resources(state, instance_id, None, None, Some(instance.disk + code_value), None).await?;
                            database_applied = true;
                        }
                    }
                    "t" if database_applied => {
                        let current_limit: Option<i64> = sqlx::query_scalar(
                            "SELECT monthly_traffic_limit FROM instances WHERE id = $1",
                        )
                        .bind(instance_id)
                        .fetch_one(&state.db).await?;
                        update_instance_resources(state, instance_id, None, None, None,
                            Some(current_limit)).await?;
                    }
                    "p" if database_applied => {
                        add_points(&state.db, user.id, -(code_value as i64), "checkin", None, Some("兑换码发放失败回滚")).await?;
                    }
                    _ => {}
                }
                let keep_consumed = code_type == "d" && remote_applied && database_applied;
                if code_consumed && !keep_consumed {
                    release_system_code(state, system_code.id, user.id, instance_id).await?;
                }
                Ok(())
            }
            .await;
            if let Err(comp_err) = compensation {
                tracing::error!("兑换码发放补偿失败: {comp_err}");
            }

            match message.as_str() {
                "REDEEM_HOST_NOT_FOUND" => Err(ApiError::not_found(code::HOST_NOT_FOUND)),
                "REDEEM_INSTANCE_BUSY" => Err(ApiError::with_message(
                    "REDEEM_INSTANCE_BUSY",
                    StatusCode::CONFLICT,
                    "Instance is being modified, please retry",
                )),
                "REDEEM_CODE_EXHAUSTED" => Err(ApiError::bad_request(code::REDEEM_CODE_EXHAUSTED)),
                "REDEEM_CODE_ALREADY_USED_BY_USER" => {
                    Err(ApiError::bad_request(code::REDEEM_CODE_ALREADY_USED_BY_USER))
                }
                "REDEEM_CODE_BATCH_LIMIT" => Err(ApiError::bad_request(code::REDEEM_CODE_BATCH_LIMIT)),
                _ => {
                    create_log_with_instance(
                        state,
                        user.id,
                        "checkin",
                        "redeem.failed",
                        &format!("Failed to redeem code {trimmed_code}: {message}"),
                        "failed",
                        Some(instance_id),
                    )
                    .await;
                    Err(ApiError::new(code::INTERNAL_ERROR, StatusCode::INTERNAL_SERVER_ERROR)
                        .with_details(message))
                }
            }
        }
    }
}

/// db useSystemRedeemCode: advisory-locked tx with per-user/batch checks and
/// atomic counter increment + usage row.
async fn consume_system_code(
    state: &SharedAppState,
    system_code: &SystemCodeRow,
    user_id: i32,
    instance_id: i32,
) -> Result<(), String> {
    const RETRY_LIMIT: usize = 10;
    for _ in 0..RETRY_LIMIT {
        let mut tx = state.db.begin().await.map_err(|e| e.to_string())?;
        let locked = try_advisory_transaction_lock(
            &mut tx,
            advisory_lock_namespace::REDEEM_CODE,
            system_code.id as i64,
        )
        .await
        .map_err(|e| e.to_string())?;
        if !locked {
            let _ = tx.rollback().await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            continue;
        }

        let used: Option<i32> = sqlx::query_scalar(
            "SELECT id FROM redeem_code_usages WHERE redeem_code_id = $1 AND user_id = $2",
        )
        .bind(system_code.id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        if used.is_some() {
            let _ = tx.rollback().await;
            return Err("REDEEM_CODE_ALREADY_USED_BY_USER".into());
        }
        if let Some(batch) = &system_code.batch_id {
            let used_batch: Option<i32> = sqlx::query_scalar(
                "SELECT id FROM redeem_code_usages WHERE user_id = $1 AND batch_id = $2",
            )
            .bind(user_id)
            .bind(batch)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
            if used_batch.is_some() {
                let _ = tx.rollback().await;
                return Err("REDEEM_CODE_BATCH_LIMIT".into());
            }
        }

        let updated = sqlx::query(
            "UPDATE redeem_codes SET used_count = used_count + 1 \
             WHERE id = $1 AND used_count < max_uses",
        )
        .bind(system_code.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        if updated.rows_affected() != 1 {
            let _ = tx.rollback().await;
            return Err("REDEEM_CODE_EXHAUSTED".into());
        }
        sqlx::query(
            "INSERT INTO redeem_code_usages (redeem_code_id, user_id, instance_id, batch_id) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(system_code.id)
        .bind(user_id)
        .bind(instance_id)
        .bind(&system_code.batch_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(());
    }
    Err("REDEEM_CODE_BUSY".into())
}

async fn release_system_code(
    state: &SharedAppState,
    redeem_code_id: i32,
    user_id: i32,
    instance_id: i32,
) -> Result<(), sqlx::Error> {
    let mut tx = state.db.begin().await?;
    let usage: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM redeem_code_usages \
         WHERE redeem_code_id = $1 AND user_id = $2 AND instance_id = $3",
    )
    .bind(redeem_code_id)
    .bind(user_id)
    .bind(instance_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(usage_id) = usage {
        sqlx::query("DELETE FROM redeem_code_usages WHERE id = $1")
            .bind(usage_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE redeem_codes SET used_count = GREATEST(used_count - 1, 0) WHERE id = $1")
            .bind(redeem_code_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

// ===========================================================================
// GET /instances — 可兑换实例（免费 package 计费 + 无方案）
// ===========================================================================

async fn instances(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    #[derive(Debug, FromRow)]
    struct RedeemInstanceRow {
        id: i32,
        name: String,
        status: String,
        cpu: i32,
        memory: i32,
        disk: i32,
        monthly_traffic_limit: Option<i64>,
        pkg_id: Option<i32>,
        pkg_name: Option<String>,
        pkg_cpu_max: Option<i32>,
        pkg_memory_max: Option<i32>,
        pkg_disk_max: Option<i32>,
        pkg_traffic_limit: Option<i64>,
        host_id: Option<i32>,
        host_name: Option<String>,
        host_location: Option<String>,
        host_country: Option<String>,
    }
    let rows = sqlx::query_as::<_, RedeemInstanceRow>(
        "SELECT i.id, i.name, i.status::text AS status, i.cpu, i.memory, i.disk,                 i.monthly_traffic_limit,                 p.id AS pkg_id, p.name AS pkg_name, p.cpu_max AS pkg_cpu_max,                 p.memory_max AS pkg_memory_max, p.disk_max AS pkg_disk_max,                 p.monthly_traffic_limit AS pkg_traffic_limit,                 h.id AS host_id, h.name AS host_name, h.location AS host_location,                 h.country_code AS host_country          FROM instances i          LEFT JOIN packages p ON p.id = i.package_id          JOIN hosts h ON h.id = i.host_id          WHERE i.user_id = $1 AND i.status::text IN ('running','stopped')            AND i.billing_mode::text = 'package' AND i.package_plan_id IS NULL          ORDER BY i.name ASC",
    )
    .bind(user.0.id)
    .fetch_all(&state.db)
    .await?;

    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "status": r.status,
                "cpu": r.cpu,
                "memory": r.memory,
                "disk": r.disk,
                "monthlyTrafficLimit": r.monthly_traffic_limit.map(|v| Value::String(v.to_string())).unwrap_or(Value::Null),
                "package": r.pkg_id.map(|pid| json!({
                    "id": pid,
                    "name": r.pkg_name,
                    "cpuMax": r.pkg_cpu_max,
                    "memoryMax": r.pkg_memory_max,
                    "diskMax": r.pkg_disk_max,
                    "monthlyTrafficLimit": r.pkg_traffic_limit.map(|v| Value::String(v.to_string())).unwrap_or(Value::Null),
                })).unwrap_or(Value::Null),
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

// ===========================================================================
// GET /records & /redeems
// ===========================================================================

#[derive(Deserialize)]
struct PageQuery {
    limit: Option<String>,
    offset: Option<String>,
}

fn page_params(query: &PageQuery) -> (i64, i64) {
    let limit = query
        .limit
        .as_deref()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| (1..=100).contains(v))
        .unwrap_or(20);
    let offset = query
        .offset
        .as_deref()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(0);
    (limit, offset)
}

async fn records(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let (limit, offset) = page_params(&query);
    let rows: Vec<(i32, String, i32, Option<i32>, Option<DateTime<Utc>>, DateTime<Utc>)> =
        sqlx::query_as(
            "SELECT id, redeem_code, code_value, used_by, used_at, created_at \
             FROM checkin_records WHERE user_id = $1 \
             ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(user.0.id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;
    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM checkin_records WHERE user_id = $1",
    )
    .bind(user.0.id)
    .fetch_one(&state.db)
    .await?;

    let records: Vec<Value> = rows
        .iter()
        .map(|(id, redeem_code, value, _used_by, used_at, created_at)| {
            json!({
                "id": id,
                "redeemCode": redeem_code,
                "codeValue": value,
                "usedAt": used_at.map(iso).unwrap_or(Value::Null),
                "createdAt": iso(*created_at),
            })
        })
        .collect();
    Ok(Json(json!({ "records": records, "total": total })))
}

async fn redeems(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let (limit, offset) = page_params(&query);
    let rows: Vec<(String, String, i32, Option<String>, Option<String>, Option<i32>, Option<String>, DateTime<Utc>)> =
        sqlx::query_as(
            "SELECT rc.code, rc.code_type::text, rc.code_value, \
                    creator.username AS creator_name, inst.name AS instance_name, \
                    inst.id AS instance_id, NULL, u.used_at \
             FROM redeem_code_usages u \
             JOIN redeem_codes rc ON rc.id = u.redeem_code_id \
             LEFT JOIN users creator ON creator.id = rc.created_by_id \
             LEFT JOIN instances inst ON inst.id = u.instance_id \
             WHERE u.user_id = $1 \
             ORDER BY u.used_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(user.0.id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;
    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM redeem_code_usages WHERE user_id = $1",
    )
    .bind(user.0.id)
    .fetch_one(&state.db)
    .await?;

    let records: Vec<Value> = rows
        .iter()
        .map(|(code, code_type, value, creator, instance_name, instance_id, _n, used_at)| {
            json!({
                "code": code,
                "codeType": code_type,
                "codeValue": value,
                "createdBy": creator,
                "instance": instance_id.map(|iid| json!({
                    "id": iid,
                    "name": instance_name,
                })).unwrap_or(Value::Null),
                "usedAt": iso(*used_at),
            })
        })
        .collect();
    Ok(Json(json!({ "records": records, "total": total })))
}
