//! IP 地址管理路由 — port of server/src/routes/ip-addresses.ts
//! (+ db/ip-addresses.ts + db/ipv6-subnets.ts semantics).
//!
//! Mounted at /api upstream with paths under /instances/:id/... — merged into
//! the /api/instances router. All endpoints use `fastify.authenticateUser` →
//! UserOnlyAuth; inner permission checks (admin/owner/host-owner) mirror the
//! TS exactly even though authenticateUser rejects admins at the door.
//!
//! NOTE: id params use JS parseInt semantics ("12abc" → 12).

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::UserOnlyAuth;
use crate::error::{code, ApiError};
use crate::libs::incus::ip_calculator as ipcalc;
use crate::libs::incus::network_payload_builder::{
    is_valid_ipv6_subnet_loose, sync_instance_network, Ipv6Config,
};
use crate::libs::instance_common::{
    create_log_with_instance, get_host_for_incus, get_incus_client_for_host,
    get_instance_with_permission, iso,
};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route(
            "/{instanceId}/ips",
            get(list_ips).post(add_ip),
        )
        .route(
            "/{instanceId}/ips/{ipId}",
            axum::routing::delete(delete_ip),
        )
        .route(
            "/{instanceId}/ips/{ipId}/custom",
            axum::routing::put(set_custom_ip),
        )
        .route("/{instanceId}/subnet", post(allocate_subnet))
        .route(
            "/{instanceId}/subnet/{subnetId}",
            axum::routing::delete(delete_subnet),
        )
        .route("/{instanceId}/subnets", get(list_subnets))
}

/// JS parseInt-style leading-integer parse.
fn parse_int(raw: &str) -> Option<i32> {
    let s = raw.trim_start();
    let bytes = s.as_bytes();
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
    s[..end].parse().ok()
}

fn invalid_params() -> ApiError {
    ApiError::bad_request(code::INVALID_PARAMS)
}

fn bare(status: axum::http::StatusCode, message: impl Into<String>) -> ApiError {
    ApiError::bare(status, message)
}

fn with_code(status: axum::http::StatusCode, code_str: &str, message: impl Into<String>) -> ApiError {
    ApiError::with_message(code_str, status, message)
}

#[derive(Debug, FromRow)]
struct IpRow {
    id: i32,
    address: String,
    #[sqlx(rename = "type")]
    ip_type: String,
    is_primary: bool,
    is_custom: bool,
    device: String,
    instance_id: i32,
    created_at: DateTime<Utc>,
}

const IP_COLUMNS: &str =
    "id, address, type, is_primary, is_custom, device, instance_id, created_at";

async fn ip_exists(state: &SharedAppState, address: &str) -> Result<bool, ApiError> {
    // db.isIpAddressExists: ip_addresses (inet6, non-deleted instance) OR
    // instances.ipv6 (non-deleted).
    let (a,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ip_addresses ipa \
         JOIN instances i ON i.id = ipa.instance_id \
         WHERE ipa.address = $1 AND ipa.type = 'inet6' AND i.status != 'deleted'",
    )
    .bind(address)
    .fetch_one(&state.db)
    .await?;
    if a > 0 {
        return Ok(true);
    }
    let (b,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instances WHERE ipv6 = $1 AND status != 'deleted'",
    )
    .bind(address)
    .fetch_one(&state.db)
    .await?;
    Ok(b > 0)
}

async fn get_ips(state: &SharedAppState, instance_id: i32) -> Result<Vec<IpRow>, ApiError> {
    Ok(sqlx::query_as::<_, IpRow>(&format!(
        "SELECT {IP_COLUMNS} FROM ip_addresses WHERE instance_id = $1 \
         ORDER BY is_primary DESC, created_at ASC"
    ))
    .bind(instance_id)
    .fetch_all(&state.db)
    .await?)
}

// ===========================================================================
// GET /instances/:instanceId/ips
// ===========================================================================

async fn list_ips(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id).ok_or_else(invalid_params)?;
    let _instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    let ips = get_ips(&state, instance_id).await?;
    let ip_addresses: Vec<Value> = ips
        .iter()
        .map(|ip| {
            json!({
                "id": ip.id,
                "address": ip.address,
                "type": ip.ip_type,
                "isPrimary": ip.is_primary,
                "isCustom": ip.is_custom,
                "device": ip.device,
                "createdAt": iso(ip.created_at),
            })
        })
        .collect();
    Ok(Json(json!({ "ipAddresses": ip_addresses })))
}

// ===========================================================================
// POST /instances/:instanceId/ips
// ===========================================================================

#[derive(Deserialize)]
struct AddIpBody {
    #[serde(rename = "customAddress")]
    custom_address: Option<String>,
}

async fn add_ip(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(instance_id): Path<String>,
    body: Option<Json<AddIpBody>>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id).ok_or_else(invalid_params)?;
    let custom_address = body.and_then(|Json(b)| b.custom_address);

    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    if !matches!(instance.status.as_str(), "running" | "stopped") {
        return Err(ApiError::bad_request(code::INSTANCE_STATUS_INVALID));
    }
    if instance.network_mode == "nat" {
        return Err(bare(
            axum::http::StatusCode::BAD_REQUEST,
            "NAT mode does not support additional IPs",
        ));
    }

    let host = get_host_for_incus(&state, instance.host_id)
        .await?
        .ok_or_else(|| bare(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Host not found"))?;

    let ipv6_subnet = host.ipv6_subnet.clone().ok_or_else(|| {
        bare(
            axum::http::StatusCode::BAD_REQUEST,
            "Host does not have IPv6 subnet configured",
        )
    })?;

    // ==== 校验自定义地址（在创建记录之前） ====
    let (new_ipv6, is_custom) = match custom_address.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(trimmed) => {
            if !ipcalc::is_strict_valid_ipv6(trimmed) {
                return Err(with_code(
                    axum::http::StatusCode::BAD_REQUEST,
                    "INVALID_IPV6_FORMAT",
                    "Invalid IPv6 address format",
                ));
            }
            if !ipcalc::is_ipv6_in_subnet(trimmed, &ipv6_subnet) {
                return Err(with_code(
                    axum::http::StatusCode::BAD_REQUEST,
                    "IPV6_NOT_IN_SUBNET",
                    format!("IPv6 address must be within host subnet range ({ipv6_subnet})"),
                ));
            }
            if ip_exists(&state, trimmed).await? {
                return Err(with_code(
                    axum::http::StatusCode::CONFLICT,
                    "IPV6_ALREADY_EXISTS",
                    "IPv6 address already in use",
                ));
            }
            (trimmed.to_string(), true)
        }
        None => {
            let max_attempts = 50;
            let mut chosen: Option<String> = None;
            for _ in 0..max_attempts {
                let candidate = ipcalc::generate_random_ipv6(&ipv6_subnet)
                    .map_err(|e| ApiError::internal(e))?;
                if !ip_exists(&state, &candidate).await? {
                    chosen = Some(candidate);
                    break;
                }
            }
            let chosen = chosen.ok_or_else(|| {
                with_code(
                    axum::http::StatusCode::CONFLICT,
                    "IPV6_POOL_EXHAUSTED",
                    format!("无法找到可用的 IPv6 地址，已尝试 {max_attempts} 次随机生成"),
                )
            })?;
            (chosen, false)
        }
    };

    let device_name = "eth1";

    let ip_record: (i32,) = sqlx::query_as(
        "INSERT INTO ip_addresses (address, type, is_primary, is_custom, device, host_id, instance_id) \
         VALUES ($1, 'inet6', false, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&new_ipv6)
    .bind(is_custom)
    .bind(device_name)
    .bind(instance.host_id)
    .bind(instance_id)
    .fetch_one(&state.db)
    .await?;

    // sync eth1 配置；失败回滚 IP 记录后以 500 冒泡（TS throw error）
    let sync_result = async {
        if matches!(instance.status.as_str(), "running" | "stopped") {
            let client = get_incus_client_for_host(&state, &host).await?;
            let ipv6_records: Vec<IpRow> = get_ips(&state, instance_id)
                .await?
                .into_iter()
                .filter(|ip| ip.ip_type == "inet6")
                .collect();
            let primary_ip = ipv6_records
                .iter()
                .find(|ip| ip.is_primary)
                .ok_or_else(|| ApiError::internal("未找到主 IPv6 地址"))?;
            let extra_ips: Vec<String> = ipv6_records
                .iter()
                .filter(|ip| !ip.is_primary)
                .map(|ip| ip.address.clone())
                .collect();
            let config = Ipv6Config {
                primary_ip: primary_ip.address.clone(),
                extra_ips: if extra_ips.is_empty() { None } else { Some(extra_ips) },
                subnet: None,
            };
            sync_instance_network(
                &client,
                &instance.incus_id,
                &config,
                host.ipv6_parent_interface.as_deref().unwrap_or("eth0"),
                instance.status == "running",
            )
            .await
            .map_err(|e| ApiError::internal(format!("{e}")))?;
        }
        Ok::<(), ApiError>(())
    }
    .await;

    if let Err(err) = sync_result {
        let _ = sqlx::query("DELETE FROM ip_addresses WHERE id = $1")
            .bind(ip_record.0)
            .execute(&state.db)
            .await;
        return Err(err);
    }

    create_log_with_instance(
        &state,
        user.0.id,
        "instance",
        "ip.add",
        &format!("Added IP {new_ipv6} to instance \"{}\"", instance.name),
        "success",
        Some(instance_id),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "ipAddress": {
            "id": ip_record.0,
            "address": new_ipv6,
            "type": "inet6",
            "isPrimary": false,
            "device": device_name,
        }
    })))
}

// ===========================================================================
// DELETE /instances/:instanceId/ips/:ipId
// ===========================================================================

async fn delete_ip(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((instance_id, ip_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id).ok_or_else(invalid_params)?;
    let ip_id = parse_int(&ip_id).ok_or_else(invalid_params)?;

    let ip_record = sqlx::query_as::<_, IpRow>(&format!(
        "SELECT {IP_COLUMNS} FROM ip_addresses WHERE id = $1"
    ))
    .bind(ip_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| bare(axum::http::StatusCode::NOT_FOUND, "IP address not found"))?;

    if ip_record.instance_id != instance_id {
        return Err(bare(
            axum::http::StatusCode::BAD_REQUEST,
            "IP does not belong to this instance",
        ));
    }

    // getIpAddressById include instance → permission re-check
    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    if ip_record.is_primary {
        return Err(bare(
            axum::http::StatusCode::BAD_REQUEST,
            "Cannot remove primary IP address",
        ));
    }

    // 从 eth1 移除；停止状态下次启动自动应用；Incus 失败仅告警继续删除
    if matches!(instance.status.as_str(), "running" | "stopped") {
        let sync = async {
            let host = get_host_for_incus(&state, instance.host_id)
                .await?
                .ok_or_else(|| ApiError::internal("host missing"))?;
            let client = get_incus_client_for_host(&state, &host).await?;
            let ipv6_records: Vec<IpRow> = get_ips(&state, instance_id)
                .await?
                .into_iter()
                .filter(|ip| ip.ip_type == "inet6" && ip.id != ip_id)
                .collect();
            if let Some(primary_ip) = ipv6_records.iter().find(|ip| ip.is_primary) {
                let extra_ips: Vec<String> = ipv6_records
                    .iter()
                    .filter(|ip| !ip.is_primary)
                    .map(|ip| ip.address.clone())
                    .collect();
                let config = Ipv6Config {
                    primary_ip: primary_ip.address.clone(),
                    extra_ips: if extra_ips.is_empty() { None } else { Some(extra_ips) },
                    subnet: None,
                };
                sync_instance_network(
                    &client,
                    &instance.incus_id,
                    &config,
                    host.ipv6_parent_interface.as_deref().unwrap_or("eth0"),
                    instance.status == "running",
                )
                .await
                .map_err(|e| ApiError::internal(format!("{e}")))?;
            }
            Ok::<(), ApiError>(())
        }
        .await;
        if let Err(err) = sync {
            tracing::warn!("Failed to remove IP {} from eth1: {err:?}", ip_record.address);
        }
    }

    sqlx::query("DELETE FROM ip_addresses WHERE id = $1")
        .bind(ip_id)
        .execute(&state.db)
        .await?;

    create_log_with_instance(
        &state,
        user.0.id,
        "instance",
        "ip.remove",
        &format!("Removed IP {} from instance \"{}\"", ip_record.address, instance.name),
        "success",
        Some(instance_id),
    )
    .await;

    Ok(Json(json!({ "success": true })))
}

// ===========================================================================
// PUT /instances/:instanceId/ips/:ipId/custom
// ===========================================================================

#[derive(Deserialize)]
struct CustomIpBody {
    address: Option<String>,
}

async fn set_custom_ip(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((instance_id, ip_id)): Path<(String, String)>,
    body: Option<Json<CustomIpBody>>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id).ok_or_else(invalid_params)?;
    let ip_id = parse_int(&ip_id).ok_or_else(invalid_params)?;
    let Json(body) = body.ok_or_else(invalid_params)?;
    let address = body.address.ok_or_else(invalid_params)?;

    if !ipcalc::is_strict_valid_ipv6(&address) {
        return Err(with_code(
            axum::http::StatusCode::BAD_REQUEST,
            "INVALID_IPV6_FORMAT",
            "Invalid IPv6 address format",
        ));
    }

    let ip_record = sqlx::query_as::<_, IpRow>(&format!(
        "SELECT {IP_COLUMNS} FROM ip_addresses WHERE id = $1"
    ))
    .bind(ip_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| bare(axum::http::StatusCode::NOT_FOUND, "IP address not found"))?;

    if ip_record.instance_id != instance_id {
        return Err(bare(
            axum::http::StatusCode::BAD_REQUEST,
            "IP does not belong to this instance",
        ));
    }

    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;
    let host = get_host_for_incus(&state, instance.host_id)
        .await?
        .ok_or_else(|| bare(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Host not found"))?;

    let ipv6_subnet = host.ipv6_subnet.clone().ok_or_else(|| {
        bare(
            axum::http::StatusCode::BAD_REQUEST,
            "Host does not have IPv6 subnet configured",
        )
    })?;
    if !ipcalc::is_ipv6_in_subnet(&address, &ipv6_subnet) {
        return Err(with_code(
            axum::http::StatusCode::BAD_REQUEST,
            "IPV6_NOT_IN_SUBNET",
            format!("IPv6 address must be within host subnet range ({ipv6_subnet})"),
        ));
    }

    if address != ip_record.address && ip_exists(&state, &address).await? {
        return Err(with_code(
            axum::http::StatusCode::CONFLICT,
            "IPV6_ALREADY_EXISTS",
            "IPv6 address already exists",
        ));
    }

    let old_address = ip_record.address.clone();

    sqlx::query("UPDATE ip_addresses SET address = $1, is_custom = true WHERE id = $2")
        .bind(&address)
        .bind(ip_id)
        .execute(&state.db)
        .await?;

    // 同步 Incus；失败仅告警
    if matches!(instance.status.as_str(), "running" | "stopped") {
        let sync = async {
            let client = get_incus_client_for_host(&state, &host).await?;
            let ipv6_records: Vec<IpRow> = get_ips(&state, instance_id)
                .await?
                .into_iter()
                .filter(|ip| ip.ip_type == "inet6")
                .collect();
            if let Some(primary_ip) = ipv6_records.iter().find(|ip| ip.is_primary) {
                let extra_ips: Vec<String> = ipv6_records
                    .iter()
                    .filter(|ip| !ip.is_primary)
                    .map(|ip| ip.address.clone())
                    .collect();
                let config = Ipv6Config {
                    primary_ip: primary_ip.address.clone(),
                    extra_ips: if extra_ips.is_empty() { None } else { Some(extra_ips) },
                    subnet: None,
                };
                sync_instance_network(
                    &client,
                    &instance.incus_id,
                    &config,
                    host.ipv6_parent_interface.as_deref().unwrap_or("eth0"),
                    instance.status == "running",
                )
                .await
                .map_err(|e| ApiError::internal(format!("{e}")))?;
            }
            Ok::<(), ApiError>(())
        }
        .await;
        if let Err(err) = sync {
            tracing::warn!("Failed to update custom IP in Incus: {err:?}");
        }
    }

    create_log_with_instance(
        &state,
        user.0.id,
        "instance",
        "ip.custom",
        &format!(
            "Set custom IPv6 {address} (was {old_address}) for instance \"{}\"",
            instance.name
        ),
        "success",
        Some(instance_id),
    )
    .await;

    Ok(Json(json!({ "success": true, "address": address })))
}

// ===========================================================================
// IPv6 网段
// ===========================================================================

#[derive(Debug, FromRow)]
struct SubnetRow {
    id: i32,
    cidr: String,
    primary_ip: String,
    device: String,
    instance_id: i32,
    created_at: DateTime<Utc>,
}

const SUBNET_COLUMNS: &str = "id, cidr, primary_ip, device, instance_id, created_at";

async fn subnet_exists(state: &SharedAppState, cidr: &str) -> Result<bool, ApiError> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM ipv6_subnets WHERE cidr = $1")
            .bind(cidr)
            .fetch_one(&state.db)
            .await?;
    Ok(count > 0)
}

#[derive(Deserialize)]
struct AllocateSubnetBody {
    cidr: Option<String>,
    prefix: Option<i64>,
    #[serde(rename = "primaryIp")]
    primary_ip: Option<String>,
}

async fn allocate_subnet(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(instance_id): Path<String>,
    body: Option<Json<AllocateSubnetBody>>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id).ok_or_else(invalid_params)?;
    let Json(body) = body.ok_or_else(invalid_params)?;

    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    if instance.network_mode == "nat" {
        return Err(bare(
            axum::http::StatusCode::BAD_REQUEST,
            "NAT mode does not support IPv6 subnet",
        ));
    }

    let host = get_host_for_incus(&state, instance.host_id)
        .await?
        .ok_or_else(|| bare(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Host not found"))?;

    // 确定 CIDR
    let cidr = if let Some(input_cidr) = body.cidr {
        if !is_valid_ipv6_subnet_loose(&input_cidr) {
            return Err(bare(
                axum::http::StatusCode::BAD_REQUEST,
                "Invalid IPv6 subnet CIDR format",
            ));
        }
        input_cidr
    } else if let Some(prefix) = body.prefix {
        if ![112, 120, 124].contains(&prefix) {
            return Err(bare(
                axum::http::StatusCode::BAD_REQUEST,
                "Prefix must be 112, 120, or 124",
            ));
        }
        let host_subnet = host.ipv6_subnet.clone().ok_or_else(|| {
            bare(
                axum::http::StatusCode::BAD_REQUEST,
                "Host does not have IPv6 subnet configured",
            )
        })?;
        let mut chosen: Option<String> = None;
        for _ in 0..20 {
            let candidate =
                ipcalc::generate_random_subnet(&host_subnet, prefix as u32)
                    .map_err(ApiError::internal)?;
            if !subnet_exists(&state, &candidate).await? {
                chosen = Some(candidate);
                break;
            }
        }
        chosen.ok_or_else(|| {
            bare(
                axum::http::StatusCode::CONFLICT,
                "Unable to allocate subnet, pool may be exhausted",
            )
        })?
    } else {
        return Err(bare(
            axum::http::StatusCode::BAD_REQUEST,
            "Either cidr or prefix must be provided",
        ));
    };

    if subnet_exists(&state, &cidr).await? {
        return Err(bare(
            axum::http::StatusCode::CONFLICT,
            "IPv6 subnet already allocated",
        ));
    }

    let ipv6_records: Vec<IpRow> = get_ips(&state, instance_id)
        .await?
        .into_iter()
        .filter(|ip| ip.ip_type == "inet6")
        .collect();
    let primary_ip_record = ipv6_records
        .iter()
        .find(|ip| ip.is_primary)
        .ok_or_else(|| {
            bare(
                axum::http::StatusCode::BAD_REQUEST,
                "Instance does not have a primary IPv6 address",
            )
        })?;

    // 网段内的主 IP（用户可指定，否则使用网段地址）
    let subnet_primary_ip = body
        .primary_ip
        .unwrap_or_else(|| cidr.split('/').next().unwrap_or(&cidr).to_string());

    let subnet: SubnetRow = sqlx::query_as::<_, SubnetRow>(&format!(
        "INSERT INTO ipv6_subnets (cidr, primary_ip, device, instance_id) \
         VALUES ($1, $2, 'eth1', $3) RETURNING {SUBNET_COLUMNS}"
    ))
    .bind(&cidr)
    .bind(&subnet_primary_ip)
    .bind(instance_id)
    .fetch_one(&state.db)
    .await?;

    // 同步 Incus；失败回滚网段记录并冒泡
    let sync_result = async {
        if matches!(instance.status.as_str(), "running" | "stopped") {
            let client = get_incus_client_for_host(&state, &host).await?;
            let extra_ips: Vec<String> = ipv6_records
                .iter()
                .filter(|ip| !ip.is_primary)
                .map(|ip| ip.address.clone())
                .collect();
            let config = Ipv6Config {
                primary_ip: primary_ip_record.address.clone(),
                extra_ips: if extra_ips.is_empty() { None } else { Some(extra_ips) },
                subnet: Some(cidr.clone()),
            };
            sync_instance_network(
                &client,
                &instance.incus_id,
                &config,
                host.ipv6_parent_interface.as_deref().unwrap_or("eth0"),
                instance.status == "running",
            )
            .await
            .map_err(|e| ApiError::internal(format!("{e}")))?;
        }
        Ok::<(), ApiError>(())
    }
    .await;

    if let Err(err) = sync_result {
        let _ = sqlx::query("DELETE FROM ipv6_subnets WHERE id = $1")
            .bind(subnet.id)
            .execute(&state.db)
            .await;
        return Err(err);
    }

    create_log_with_instance(
        &state,
        user.0.id,
        "instance",
        "subnet.allocate",
        &format!("Allocated IPv6 subnet {cidr} to instance \"{}\"", instance.name),
        "success",
        Some(instance_id),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "subnet": {
            "id": subnet.id,
            "cidr": subnet.cidr,
            "primaryIp": subnet.primary_ip,
            "device": subnet.device,
        }
    })))
}

async fn delete_subnet(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((instance_id, subnet_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id).ok_or_else(invalid_params)?;
    let subnet_id = parse_int(&subnet_id).ok_or_else(invalid_params)?;

    let instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    let subnets = sqlx::query_as::<_, SubnetRow>(&format!(
        "SELECT {SUBNET_COLUMNS} FROM ipv6_subnets WHERE instance_id = $1"
    ))
    .bind(instance_id)
    .fetch_all(&state.db)
    .await?;
    let subnet = subnets
        .iter()
        .find(|s| s.id == subnet_id)
        .ok_or_else(|| bare(axum::http::StatusCode::NOT_FOUND, "Subnet not found"))?;

    // 同步 Incus（不含 subnet → 移除 ipv6.routes）；失败仅告警
    if let Ok(Some(host)) = get_host_for_incus(&state, instance.host_id).await {
        if matches!(instance.status.as_str(), "running" | "stopped") {
            let sync = async {
                let client = get_incus_client_for_host(&state, &host).await?;
                let ipv6_records: Vec<IpRow> = get_ips(&state, instance_id)
                    .await?
                    .into_iter()
                    .filter(|ip| ip.ip_type == "inet6")
                    .collect();
                if let Some(primary_ip) = ipv6_records.iter().find(|ip| ip.is_primary) {
                    let extra_ips: Vec<String> = ipv6_records
                        .iter()
                        .filter(|ip| !ip.is_primary)
                        .map(|ip| ip.address.clone())
                        .collect();
                    let config = Ipv6Config {
                        primary_ip: primary_ip.address.clone(),
                        extra_ips: if extra_ips.is_empty() { None } else { Some(extra_ips) },
                        subnet: None,
                    };
                    sync_instance_network(
                        &client,
                        &instance.incus_id,
                        &config,
                        host.ipv6_parent_interface.as_deref().unwrap_or("eth0"),
                        instance.status == "running",
                    )
                    .await
                    .map_err(|e| ApiError::internal(format!("{e}")))?;
                }
                Ok::<(), ApiError>(())
            }
            .await;
            if let Err(err) = sync {
                tracing::warn!("Failed to remove subnet from Incus: {err:?}");
            }
        }
    }

    sqlx::query("DELETE FROM ipv6_subnets WHERE id = $1")
        .bind(subnet_id)
        .execute(&state.db)
        .await?;

    create_log_with_instance(
        &state,
        user.0.id,
        "instance",
        "subnet.remove",
        &format!(
            "Removed IPv6 subnet {} from instance \"{}\"",
            subnet.cidr, instance.name
        ),
        "success",
        Some(instance_id),
    )
    .await;

    Ok(Json(json!({ "success": true })))
}

async fn list_subnets(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id).ok_or_else(invalid_params)?;
    let _instance = get_instance_with_permission(&state, &user.0, instance_id).await?;

    let subnets = sqlx::query_as::<_, SubnetRow>(&format!(
        "SELECT {SUBNET_COLUMNS} FROM ipv6_subnets WHERE instance_id = $1"
    ))
    .bind(instance_id)
    .fetch_all(&state.db)
    .await?;

    let items: Vec<Value> = subnets
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "cidr": s.cidr,
                "primaryIp": s.primary_ip,
                "device": s.device,
                "createdAt": iso(s.created_at),
            })
        })
        .collect();
    Ok(Json(json!({ "subnets": items })))
}
