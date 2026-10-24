//! 反代站点管理路由 — port of server/src/routes/proxy-sites.ts
//! (+ db/proxy-sites.ts: isValidDomain / isDomainUsed (hostId,domain unique) /
//! CRUD helpers).
//!
//! Mounted at /api upstream with paths under /instances/:id/sites — merged
//! into the /api/instances router. GET list/certificate use
//! `fastify.authenticate` (AuthUser, view-permission for owner/hostOwner/
//! admin); mutations use `fastify.authenticateUser` (UserOnlyAuth) and are
//! owner-only (instance.user_id === user.id).
//!
//! DNS check uses getaddrinfo (std ToSocketAddrs) instead of Node
//! dns.resolve4/6 — same resolved set in practice, but /etc/hosts entries
//! also match. Certificate inspection does a real TLS connect (SNI, cert
//! validation skipped like rejectUnauthorized:false) and parses the X.509.

use std::net::ToSocketAddrs;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::{AuthUser, UserOnlyAuth};
use crate::error::{code, ApiError};
use crate::libs::host_caddy::CaddyClient;
use crate::libs::incus::network_address::get_dns_record_type;
use crate::libs::instance_common::{
    create_log_with_instance, ensure_instance_not_suspended, get_instance_by_id,
    get_instance_with_permission, iso,
};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/{id}/sites", get(list_sites).post(add_site))
        .route("/{id}/sites/{siteId}", axum::routing::patch(update_site).delete(delete_site))
        .route("/{id}/sites/{siteId}/check-dns", axum::routing::post(check_dns))
        .route("/{id}/sites/{siteId}/refresh", axum::routing::post(refresh_site))
        .route("/{id}/sites/{siteId}/toggle", axum::routing::post(toggle_site))
        .route("/{id}/sites/{siteId}/certificate", get(certificate))
}

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

fn bare(status: axum::http::StatusCode, message: impl Into<String>) -> ApiError {
    ApiError::bare(status, message)
}

/// db isValidDomain: no wildcard, basic domain regex.
fn is_valid_domain(domain: &str) -> bool {
    if domain.starts_with('*') {
        return false;
    }
    static RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")
            .expect("valid regex")
    });
    RE.is_match(domain)
}

#[derive(Debug, FromRow)]
struct SiteRow {
    id: i32,
    instance_id: i32,
    host_id: i32,
    domain: String,
    target_port: i32,
    https_enabled: bool,
    remark: Option<String>,
    status: String,
    enabled: bool,
    error: Option<String>,
    created_at: DateTime<Utc>,
}

const SITE_COLUMNS: &str =
    "id, instance_id, host_id, domain, target_port, https_enabled, remark, \
     status::text AS status, enabled, error, created_at";

async fn get_site(state: &SharedAppState, site_id: i32) -> Result<Option<SiteRow>, ApiError> {
    Ok(sqlx::query_as::<_, SiteRow>(&format!(
        "SELECT {SITE_COLUMNS} FROM proxy_sites WHERE id = $1"
    ))
    .bind(site_id)
    .fetch_optional(&state.db)
    .await?)
}

async fn get_sites(state: &SharedAppState, instance_id: i32) -> Result<Vec<SiteRow>, ApiError> {
    Ok(sqlx::query_as::<_, SiteRow>(&format!(
        "SELECT {SITE_COLUMNS} FROM proxy_sites WHERE instance_id = $1 ORDER BY created_at ASC"
    ))
    .bind(instance_id)
    .fetch_all(&state.db)
    .await?)
}

async fn is_domain_used(
    state: &SharedAppState,
    host_id: i32,
    domain: &str,
) -> Result<bool, ApiError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM proxy_sites WHERE host_id = $1 AND domain = $2",
    )
    .bind(host_id)
    .bind(domain)
    .fetch_one(&state.db)
    .await?;
    Ok(count > 0)
}

/// Host columns needed here (caddy config + public IP + site_limit inheritance
/// comes from packages).
#[derive(Debug, FromRow)]
struct HostInfo {
    id: i32,
    caddy_enabled: bool,
    caddy_username: Option<String>,
    caddy_password: Option<String>,
    caddy_port: i32,
    nat_public_ip: Option<String>,
    ip_address: Option<String>,
}

async fn get_host_info(state: &SharedAppState, host_id: i32) -> Result<Option<HostInfo>, ApiError> {
    Ok(sqlx::query_as::<_, HostInfo>(
        "SELECT id, caddy_enabled, caddy_username, caddy_password, caddy_port, \
         nat_public_ip, ip_address FROM hosts WHERE id = $1",
    )
    .bind(host_id)
    .fetch_optional(&state.db)
    .await?)
}

fn caddy_client(host: &HostInfo) -> Result<CaddyClient, ApiError> {
    let target = host
        .nat_public_ip
        .as_deref()
        .or(host.ip_address.as_deref())
        .unwrap_or_default();
    CaddyClient::new(
        target,
        host.caddy_port as i64,
        host.caddy_username.as_deref().unwrap_or_default(),
        host.caddy_password.as_deref().unwrap_or_default(),
    )
    .map_err(|e| ApiError::internal(e))
}

/// instance.site_limit ?? package.site_limit ?? 10 (0 = unlimited).
async fn site_limit(state: &SharedAppState, instance: &crate::libs::instance_common::InstanceRow) -> i32 {
    if let Some(limit) = instance.site_limit {
        return limit;
    }
    if let Some(package_id) = instance.package_id {
        let pkg: Option<(Option<i32>,)> = sqlx::query_as(
            "SELECT site_limit FROM packages WHERE id = $1",
        )
        .bind(package_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
        if let Some((Some(limit),)) = pkg {
            return limit;
        }
    }
    10
}

fn suspended_check(instance: &crate::libs::instance_common::InstanceRow) -> Result<(), ApiError> {
    ensure_instance_not_suspended(instance)
}

fn site_json(s: &SiteRow) -> Value {
    json!({
        "id": s.id,
        "domain": s.domain,
        "targetPort": s.target_port,
        "httpsEnabled": s.https_enabled,
        "remark": s.remark,
        "status": s.status,
        "enabled": s.enabled,
        "error": s.error,
        "createdAt": iso(s.created_at),
    })
}

// ===========================================================================
// GET /instances/:id/sites — 列表（查看权限：所有者/宿主所有者/管理员）
// ===========================================================================

async fn list_sites(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;
    let instance = get_instance_with_permission(&state, &user, instance_id).await?;

    let host = get_host_info(&state, instance.host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;

    let sites = get_sites(&state, instance_id).await?;
    let limit = site_limit(&state, &instance).await;

    let dns_value = host.nat_public_ip.clone().or(host.ip_address.clone());
    Ok(Json(json!({
        "sites": sites.iter().map(site_json).collect::<Vec<_>>(),
        "caddyEnabled": host.caddy_enabled,
        "dnsRecordType": dns_value.as_deref().map(get_dns_record_type).map(|t| t.as_str()),
        "dnsRecordValue": dns_value,
        "siteQuota": { "used": sites.len(), "limit": limit },
        // 增删改仅实例所有者；管理员/宿主所有者只读
        "canManageSites": user.role != "admin" && instance.user_id == user.id,
    })))
}

// ===========================================================================
// POST /instances/:id/sites — 添加（owner-only）
// ===========================================================================

#[derive(Deserialize)]
struct AddSiteBody {
    domain: Option<String>,
    #[serde(rename = "targetPort")]
    target_port: Option<i64>,
    #[serde(rename = "httpsEnabled")]
    https_enabled: Option<bool>,
    remark: Option<String>,
}

async fn add_site(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
    body: Option<Json<AddSiteBody>>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let domain = body
        .domain
        .filter(|d| d.chars().count() >= 4)
        .ok_or_else(|| ApiError::validation("domain must NOT have fewer than 4 characters"))?;
    let target_port = body
        .target_port
        .filter(|p| (1..=65535).contains(p))
        .ok_or_else(|| ApiError::validation("targetPort must be >= 1 and <= 65535"))?;
    let https_enabled = body.https_enabled.unwrap_or(true);
    if let Some(r) = &body.remark {
        if r.chars().count() > 100 {
            return Err(ApiError::validation("remark must NOT have more than 100 characters"));
        }
    }

    let normalized_domain = domain.trim().to_lowercase();
    if !is_valid_domain(&normalized_domain) {
        return Err(bare(
            axum::http::StatusCode::BAD_REQUEST,
            "域名格式无效（不支持泛域名）",
        ));
    }

    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    suspended_check(&instance)?;

    if instance.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let host = get_host_info(&state, instance.host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;

    if !host.caddy_enabled {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "请先在宿主机安装 Caddy"));
    }

    let (current,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM proxy_sites WHERE instance_id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.db)
    .await?;
    let limit = site_limit(&state, &instance).await;
    if limit != 0 && current >= limit as i64 {
        return Err(ApiError::with_message(
            "SITE_LIMIT_EXCEEDED",
            axum::http::StatusCode::BAD_REQUEST,
            format!("已达到站点数量上限 ({limit})"),
        ));
    }

    if is_domain_used(&state, host.id, &normalized_domain).await? {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "该域名已被使用"));
    }

    // 实例需要有内网 IP —— instance_common InstanceRow 没有 ipv4 字段，
    // 单独查询（与 TS instance.ipv4 一致）。
    let ipv4: Option<String> = sqlx::query_scalar("SELECT ipv4 FROM instances WHERE id = $1")
        .bind(instance_id)
        .fetch_one(&state.db)
        .await?;
    if ipv4.is_none() {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "实例未分配 IPv4 地址"));
    }

    let site: (i32,) = sqlx::query_as(
        "INSERT INTO proxy_sites \
         (instance_id, host_id, domain, target_port, https_enabled, remark, status, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', true) RETURNING id",
    )
    .bind(instance_id)
    .bind(host.id)
    .bind(&normalized_domain)
    .bind(target_port as i32)
    .bind(https_enabled)
    .bind(body.remark.as_deref().map(str::trim).filter(|r| !r.is_empty()))
    .fetch_one(&state.db)
    .await?;

    let dns_record_value = host.nat_public_ip.or(host.ip_address).unwrap_or_default();
    let dns_record_type = if dns_record_value.is_empty() {
        "A".to_string()
    } else {
        get_dns_record_type(&dns_record_value).as_str().to_string()
    };

    create_log_with_instance(
        &state,
        user.0.id,
        "proxy",
        "site.create",
        &format!("Created proxy site \"{normalized_domain}\" (pending DNS)"),
        "success",
        Some(instance_id),
    )
    .await;

    Ok(Json(json!({
        "site": {
            "id": site.0,
            "domain": normalized_domain,
            "targetPort": target_port,
            "httpsEnabled": https_enabled,
            "status": "pending",
        },
        "dnsHint": {
            "type": dns_record_type,
            "host": normalized_domain,
            "value": dns_record_value,
        },
        "message": "站点已创建，请配置 DNS 后点击“检测 DNS”激活",
    })))
}

// ===========================================================================
// DELETE /instances/:id/sites/:siteId
// ===========================================================================

async fn delete_site(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((id, site_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;
    let site_id = parse_int(&site_id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;

    let site = get_site(&state, site_id)
        .await?
        .ok_or_else(|| bare(axum::http::StatusCode::NOT_FOUND, "站点不存在"))?;
    if site.instance_id != instance_id {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "站点不属于该实例"));
    }

    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    suspended_check(&instance)?;
    if instance.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let host = get_host_info(&state, site.host_id).await?;
    if let Some(host) = &host {
        if host.caddy_enabled && host.caddy_username.is_some() && host.caddy_password.is_some() {
            if let Ok(client) = caddy_client(host) {
                if let Err(err) = client.delete_site(&site.domain).await {
                    tracing::error!("Failed to remove site from Caddy: {err}");
                    // 继续删除数据库记录
                }
            }
        }
    }

    sqlx::query("DELETE FROM proxy_sites WHERE id = $1")
        .bind(site_id)
        .execute(&state.db)
        .await?;

    create_log_with_instance(
        &state,
        user.0.id,
        "proxy",
        "site.delete",
        &format!("Deleted proxy site \"{}\"", site.domain),
        "success",
        Some(instance_id),
    )
    .await;

    Ok(Json(json!({ "message": "站点已删除" })))
}

// ===========================================================================
// POST /instances/:id/sites/:siteId/check-dns
// ===========================================================================

async fn check_dns(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((id, site_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;
    let site_id = parse_int(&site_id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;

    let site = get_site(&state, site_id).await?;
    let site = match site {
        Some(s) if s.instance_id == instance_id => s,
        _ => return Err(bare(axum::http::StatusCode::NOT_FOUND, "站点不存在")),
    };

    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    suspended_check(&instance)?;
    if instance.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let host = get_host_info(&state, site.host_id)
        .await?
        .ok_or_else(|| ApiError::internal("host missing"))?;
    let expected_ip = host
        .nat_public_ip
        .clone()
        .or(host.ip_address.clone())
        .ok_or_else(|| bare(axum::http::StatusCode::BAD_REQUEST, "宿主机未配置公网 IP"))?;

    // DNS 解析（getaddrinfo：A + AAAA 合并）
    let domain = site.domain.clone();
    let resolved: Vec<String> = tokio::task::spawn_blocking(move || {
        (domain.as_str(), 0)
            .to_socket_addrs()
            .map(|iter| iter.map(|a| a.ip().to_string()).collect())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();

    if resolved.is_empty() {
        return Ok(Json(json!({
            "dnsResolved": false,
            "expectedIp": expected_ip,
            "resolvedIps": [],
            "error": "DNS 未解析，请检查域名配置",
            "status": site.status,
        })));
    }

    let ip_matches = resolved.iter().any(|ip| ip == &expected_ip);
    if !ip_matches {
        return Ok(Json(json!({
            "dnsResolved": true,
            "ipMatches": false,
            "expectedIp": expected_ip,
            "resolvedIps": resolved,
            "error": format!("DNS 解析到 {}，但期望的是 {expected_ip}", resolved.join(", ")),
            "status": site.status,
        })));
    }

    // DNS 正确；pending 站点自动激活
    if site.status == "pending" {
        let activation = async {
            if !host.caddy_enabled
                || host.caddy_username.is_none()
                || host.caddy_password.is_none()
            {
                return Err("Caddy 未启用".to_string());
            }
            let instance_ip: Option<String> =
                sqlx::query_scalar("SELECT ipv4 FROM instances WHERE id = $1")
                    .bind(instance_id)
                    .fetch_one(&state.db)
                    .await
                    .map_err(|e| e.to_string())?;
            let instance_ip = instance_ip.ok_or_else(|| "实例未分配 IP".to_string())?;

            let client = caddy_client(&host).map_err(|e| e.error)?;
            // 先删除可能残留的旧配置
            let _ = client.delete_site(&site.domain).await;
            client
                .add_site(&site.domain, &instance_ip, site.target_port as i64, site.https_enabled)
                .await?;
            Ok::<(), String>(())
        }
        .await;

        match activation {
            Ok(()) => {
                sqlx::query(
                    "UPDATE proxy_sites SET status = 'active', error = NULL WHERE id = $1",
                )
                .bind(site.id)
                .execute(&state.db)
                .await?;
                create_log_with_instance(
                    &state,
                    user.0.id,
                    "proxy",
                    "site.activate",
                    &format!("Activated proxy site \"{}\" after DNS verification", site.domain),
                    "success",
                    Some(instance_id),
                )
                .await;
                Ok(Json(json!({
                    "dnsResolved": true,
                    "ipMatches": true,
                    "expectedIp": expected_ip,
                    "resolvedIps": resolved,
                    "activated": true,
                    "status": "active",
                    "message": "DNS 验证通过，站点已激活",
                })))
            }
            Err(message) => {
                sqlx::query("UPDATE proxy_sites SET status = 'error', error = $2 WHERE id = $1")
                    .bind(site.id)
                    .bind(&message)
                    .execute(&state.db)
                    .await?;
                tracing::error!("Failed to activate site after DNS check: {message}");
                Ok(Json(json!({
                    "dnsResolved": true,
                    "ipMatches": true,
                    "expectedIp": expected_ip,
                    "resolvedIps": resolved,
                    "activated": false,
                    "status": "error",
                    "error": format!("激活失败: {message}"),
                })))
            }
        }
    } else {
        let message = if site.status == "active" {
            "站点已激活"
        } else {
            "请点击刷新重试配置"
        };
        Ok(Json(json!({
            "dnsResolved": true,
            "ipMatches": true,
            "expectedIp": expected_ip,
            "resolvedIps": resolved,
            "status": site.status,
            "message": message,
        })))
    }
}

// ===========================================================================
// POST /instances/:id/sites/:siteId/refresh
// ===========================================================================

async fn refresh_site(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((id, site_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let instance_id = parse_int(&id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;
    let site_id = parse_int(&site_id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;

    let site = get_site(&state, site_id).await?;
    let site = match site {
        Some(s) if s.instance_id == instance_id => s,
        _ => return Err(bare(axum::http::StatusCode::NOT_FOUND, "站点不存在")),
    };

    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    suspended_check(&instance)?;
    if instance.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    if !site.enabled {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "站点已禁用，请先启用"));
    }

    let host = get_host_info(&state, site.host_id)
        .await?
        .ok_or_else(|| ApiError::internal("host missing"))?;
    if !host.caddy_enabled || host.caddy_username.is_none() || host.caddy_password.is_none() {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "Caddy 未启用"));
    }
    if host.nat_public_ip.is_none() && host.ip_address.is_none() {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "宿主机未配置公网 IP"));
    }
    let instance_ip: Option<String> = sqlx::query_scalar("SELECT ipv4 FROM instances WHERE id = $1")
        .bind(instance_id)
        .fetch_one(&state.db)
        .await?;
    let Some(instance_ip) = instance_ip else {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "实例未分配 IP"));
    };

    let result = async {
        let client = caddy_client(&host).map_err(|e| e.error)?;
        let _ = client.delete_site(&site.domain).await;
        client
            .add_site(&site.domain, &instance_ip, site.target_port as i64, site.https_enabled)
            .await?;
        Ok::<(), String>(())
    }
    .await;

    match result {
        Ok(()) => {
            sqlx::query("UPDATE proxy_sites SET status = 'active', error = NULL WHERE id = $1")
                .bind(site.id)
                .execute(&state.db)
                .await?;
            create_log_with_instance(
                &state,
                user.0.id,
                "proxy",
                "site.refresh",
                &format!("Refreshed proxy site \"{}\"", site.domain),
                "success",
                Some(instance_id),
            )
            .await;
            Ok(Json(json!({ "message": "站点配置已刷新", "status": "active" })).into_response())
        }
        Err(message) => {
            sqlx::query("UPDATE proxy_sites SET status = 'error', error = $2 WHERE id = $1")
                .bind(site.id)
                .bind(&message)
                .execute(&state.db)
                .await?;
            create_log_with_instance(
                &state,
                user.0.id,
                "proxy",
                "site.refresh",
                &format!("Failed to refresh proxy site \"{}\": {message}", site.domain),
                "failed",
                Some(instance_id),
            )
            .await;
            Err(bare(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("配置失败: {message}"),
            ))
        }
    }
}

// ===========================================================================
// PATCH /instances/:id/sites/:siteId
// ===========================================================================

#[derive(Deserialize)]
struct UpdateSiteBody {
    #[serde(rename = "targetPort")]
    target_port: Option<i64>,
    #[serde(rename = "httpsEnabled")]
    https_enabled: Option<bool>,
    remark: Option<String>,
}

async fn update_site(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((id, site_id)): Path<(String, String)>,
    body: Option<Json<UpdateSiteBody>>,
) -> Result<Response, ApiError> {
    let instance_id = parse_int(&id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;
    let site_id = parse_int(&site_id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;

    if let Some(p) = body.target_port {
        if !(1..=65535).contains(&p) {
            return Err(ApiError::validation("targetPort must be >= 1 and <= 65535"));
        }
    }
    if let Some(r) = &body.remark {
        if r.chars().count() > 100 {
            return Err(ApiError::validation("remark must NOT have more than 100 characters"));
        }
    }

    if body.target_port.is_none() && body.https_enabled.is_none() && body.remark.is_none() {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "请提供要修改的字段"));
    }

    let site = get_site(&state, site_id).await?;
    let site = match site {
        Some(s) if s.instance_id == instance_id => s,
        _ => return Err(bare(axum::http::StatusCode::NOT_FOUND, "站点不存在")),
    };

    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    suspended_check(&instance)?;
    if instance.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    if !site.enabled {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "请先启用站点"));
    }

    let new_target_port = body.target_port.unwrap_or(site.target_port as i64);
    let new_https_enabled = body.https_enabled.unwrap_or(site.https_enabled);
    let new_remark = match &body.remark {
        Some(r) => {
            let t = r.trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
        }
        None => site.remark.clone(),
    };

    let only_remark_changed = new_target_port == site.target_port as i64
        && new_https_enabled == site.https_enabled
        && new_remark != site.remark;
    if only_remark_changed {
        sqlx::query("UPDATE proxy_sites SET remark = $2 WHERE id = $1")
            .bind(site.id)
            .bind(&new_remark)
            .execute(&state.db)
            .await?;
        create_log_with_instance(
            &state,
            user.0.id,
            "proxy",
            "site.update",
            &format!("Updated proxy site \"{}\" remark", site.domain),
            "success",
            Some(instance_id),
        )
        .await;
        return Ok(Json(json!({
            "message": "站点备注已更新",
            "site": {
                "id": site.id,
                "domain": site.domain,
                "targetPort": site.target_port,
                "httpsEnabled": site.https_enabled,
                "remark": new_remark,
                "status": site.status,
            }
        }))
        .into_response());
    }

    if new_target_port == site.target_port as i64
        && new_https_enabled == site.https_enabled
        && new_remark == site.remark
    {
        return Ok(Json(json!({
            "message": "配置无变化",
            "site": {
                "id": site.id,
                "domain": site.domain,
                "targetPort": site.target_port,
                "httpsEnabled": site.https_enabled,
                "remark": site.remark,
                "status": site.status,
            }
        }))
        .into_response());
    }

    let host = get_host_info(&state, site.host_id)
        .await?
        .ok_or_else(|| ApiError::internal("host missing"))?;
    if !host.caddy_enabled || host.caddy_username.is_none() || host.caddy_password.is_none() {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "Caddy 未启用"));
    }
    if host.nat_public_ip.is_none() && host.ip_address.is_none() {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "宿主机未配置公网 IP"));
    }
    let instance_ip: Option<String> = sqlx::query_scalar("SELECT ipv4 FROM instances WHERE id = $1")
        .bind(instance_id)
        .fetch_one(&state.db)
        .await?;
    let Some(instance_ip) = instance_ip else {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "实例未分配 IP"));
    };

    if new_target_port == site.target_port as i64 && new_https_enabled == site.https_enabled {
        return Ok(Json(json!({
            "message": "配置无变化",
            "site": {
                "id": site.id,
                "domain": site.domain,
                "targetPort": site.target_port,
                "httpsEnabled": site.https_enabled,
                "remark": site.remark,
                "status": site.status,
            }
        }))
        .into_response());
    }

    let result = async {
        let client = caddy_client(&host).map_err(|e| e.error)?;
        client.delete_site(&site.domain).await?;
        client
            .add_site(&site.domain, &instance_ip, new_target_port, new_https_enabled)
            .await?;
        Ok::<(), String>(())
    }
    .await;

    match result {
        Ok(()) => {
            sqlx::query(
                "UPDATE proxy_sites SET target_port = $2, https_enabled = $3, remark = $4, \
                 status = 'active', error = NULL WHERE id = $1",
            )
            .bind(site.id)
            .bind(new_target_port as i32)
            .bind(new_https_enabled)
            .bind(&new_remark)
            .execute(&state.db)
            .await?;
            create_log_with_instance(
                &state,
                user.0.id,
                "proxy",
                "site.update",
                &format!(
                    "Updated proxy site \"{}\": port={new_target_port}, https={new_https_enabled}",
                    site.domain
                ),
                "success",
                Some(instance_id),
            )
            .await;
            Ok(Json(json!({
                "message": "站点配置已更新",
                "site": {
                    "id": site.id,
                    "domain": site.domain,
                    "targetPort": new_target_port,
                    "httpsEnabled": new_https_enabled,
                    "remark": new_remark,
                    "status": "active",
                }
            }))
            .into_response())
        }
        Err(message) => {
            sqlx::query("UPDATE proxy_sites SET status = 'error', error = $2 WHERE id = $1")
                .bind(site.id)
                .bind(&message)
                .execute(&state.db)
                .await?;
            tracing::error!("Failed to update site configuration: {message}");
            Err(bare(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("更新失败: {message}"),
            ))
        }
    }
}

// ===========================================================================
// POST /instances/:id/sites/:siteId/toggle
// ===========================================================================

async fn toggle_site(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((id, site_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;
    let site_id = parse_int(&site_id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;

    let site = get_site(&state, site_id).await?;
    let site = match site {
        Some(s) if s.instance_id == instance_id => s,
        _ => return Err(bare(axum::http::StatusCode::NOT_FOUND, "站点不存在")),
    };

    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    suspended_check(&instance)?;
    if instance.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let host = get_host_info(&state, site.host_id)
        .await?
        .ok_or_else(|| ApiError::internal("host missing"))?;
    if !host.caddy_enabled || host.caddy_username.is_none() || host.caddy_password.is_none() {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "Caddy 未启用"));
    }
    if host.nat_public_ip.is_none() && host.ip_address.is_none() {
        return Err(bare(axum::http::StatusCode::BAD_REQUEST, "宿主机未配置公网 IP"));
    }

    let new_enabled = !site.enabled;

    // 启用分支需要实例 IP；提前查询（禁用分支忽略）。
    let instance_ip: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT ipv4 FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?
    .flatten();

    let result: Result<(), String> = if new_enabled {
        let Some(instance_ip) = instance_ip else {
            return Err(bare(axum::http::StatusCode::BAD_REQUEST, "实例未分配 IP"));
        };
        async {
            let client = caddy_client(&host).map_err(|e| e.error)?;
            let _ = client.delete_site(&site.domain).await;
            client
                .add_site(&site.domain, &instance_ip, site.target_port as i64, site.https_enabled)
                .await?;
            Ok::<(), String>(())
        }
        .await
    } else {
        async {
            let client = caddy_client(&host).map_err(|e| e.error)?;
            client.delete_site(&site.domain).await?;
            Ok::<(), String>(())
        }
        .await
    };

    match result {
        Ok(()) => {
            let new_status = if new_enabled { "active" } else { "pending" };
            sqlx::query(
                "UPDATE proxy_sites SET status = $2::\"ProxySiteStatus\", error = NULL, \
                 enabled = $3 WHERE id = $1",
            )
            .bind(site.id)
            .bind(new_status)
            .bind(new_enabled)
            .execute(&state.db)
            .await?;
            create_log_with_instance(
                &state,
                user.0.id,
                "proxy",
                if new_enabled { "site.enable" } else { "site.disable" },
                &format!(
                    "{} proxy site \"{}\"",
                    if new_enabled { "Enabled" } else { "Disabled" },
                    site.domain
                ),
                "success",
                Some(instance_id),
            )
            .await;
            Ok(Json(json!({
                "message": if new_enabled { "站点已启用" } else { "站点已禁用" },
                "enabled": new_enabled,
                "status": new_status,
            })))
        }
        Err(message) => {
            tracing::error!("Failed to {} site: {message}", if new_enabled { "enable" } else { "disable" });
            Err(bare(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("操作失败: {message}"),
            ))
        }
    }
}

// ===========================================================================
// GET /instances/:id/sites/:siteId/certificate — 查看权限
// ===========================================================================

async fn certificate(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, site_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;
    let site_id = parse_int(&site_id).ok_or_else(|| ApiError::bad_request(code::INVALID_ID))?;

    let site = get_site(&state, site_id).await?;
    let site = match site {
        Some(s) if s.instance_id == instance_id => s,
        _ => return Err(bare(axum::http::StatusCode::NOT_FOUND, "站点不存在")),
    };

    // 查看权限：所有者/宿主所有者/管理员
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    crate::libs::instance_common::get_instance_with_permission(&state, &user, instance_id).await?;
    let _ = instance;

    if !site.https_enabled {
        return Ok(Json(json!({
            "httpsEnabled": false,
            "status": "disabled",
            "message": "HTTPS 未启用",
        })));
    }
    if site.status == "pending" {
        return Ok(Json(json!({
            "httpsEnabled": true,
            "status": "pending",
            "hint": "站点待激活，请先配置 DNS 并点击“检测 DNS”",
        })));
    }

    match tls_certificate_info(&site.domain).await {
        Ok(info) => Ok(Json(json!({
            "httpsEnabled": true,
            "status": "valid",
            "certificate": info,
        }))),
        Err(message) => {
            let lower = message.to_lowercase();
            let (status, hint) = if lower.contains("enotfound")
                || lower.contains("getaddrinfo")
                || lower.contains("dns")
                || lower.contains("failed to lookup")
            {
                ("dns_error", "DNS 未解析，请检查域名是否正确指向服务器")
            } else if lower.contains("econnrefused") || lower.contains("connection refused") {
                ("connection_refused", "连接被拒绝，请检查服务器 443 端口是否开放")
            } else if lower.contains("timeout") || message.contains("超时") {
                ("timeout", "连接超时，请检查网络连接")
            } else if lower.contains("handshake") || lower.contains("ssl") || lower.contains("tls") {
                ("cert_pending", "证书正在申请中，请稍后重试")
            } else if lower.contains("certificate") || lower.contains("self signed") {
                ("cert_pending", "证书正在申请中，请稍后重试")
            } else if lower.contains("econnreset") || lower.contains("connection reset") {
                ("cert_pending", "证书可能正在申请中，请稍后重试")
            } else {
                ("error", "")
            };
            Ok(Json(json!({
                "httpsEnabled": true,
                "status": status,
                "error": message,
                "hint": hint,
            })))
        }
    }
}

/// TLS connect to host:443 with SNI, skip cert validation (TS
/// rejectUnauthorized:false), and parse the leaf certificate.
async fn tls_certificate_info(domain: &str) -> Result<Value, String> {
    use tokio_rustls::rustls::pki_types::ServerName;

    // Resolve first so DNS errors are distinguishable from connect errors.
    let addr = tokio::net::lookup_host((domain, 443))
        .await
        .map_err(|e| format!("getaddrinfo ENOTFOUND {domain}: {e}"))?
        .next()
        .ok_or_else(|| format!("getaddrinfo ENOTFOUND {domain}"))?;

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| "连接超时".to_string())?
    .map_err(|e| e.to_string())?;

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Allow self-signed / invalid certs like rejectUnauthorized:false.
    config
        .dangerous()
        .set_certificate_verifier(std::sync::Arc::new(NoVerify));
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));

    let server_name = ServerName::try_from(domain.to_string())
        .map_err(|_| "invalid server name".to_string())?;
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "连接超时".to_string())?
    .map_err(|e| e.to_string())?;

    let cert_der = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .cloned()
        .ok_or_else(|| "无法获取证书信息".to_string())?;

    let (_rem, parsed) = x509_parser::parse_x509_certificate(&cert_der)
        .map_err(|e| format!("certificate parse error: {e}"))?;

    let valid_from: chrono::DateTime<chrono::Utc> =
        std::time::SystemTime::from(parsed.validity().not_before.to_datetime()).into();
    let valid_to: chrono::DateTime<chrono::Utc> =
        std::time::SystemTime::from(parsed.validity().not_after.to_datetime()).into();
    let now = chrono::Utc::now();
    let valid = now >= valid_from && now <= valid_to;
    let days_remaining = (valid_to - now).num_days();

    let issuer = parsed
        .issuer()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .next()
        .unwrap_or_default()
        .to_string();
    let issuer_org = parsed
        .issuer()
        .iter_organization()
        .filter_map(|o| o.as_str().ok())
        .next()
        .unwrap_or_default()
        .to_string();
    let issuer_display = if issuer_org.is_empty() {
        issuer
    } else if issuer.is_empty() {
        issuer_org
    } else {
        format!("{issuer_org} - {issuer}")
    };
    let subject = parsed
        .subject()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .next()
        .unwrap_or(domain)
        .to_string();

    Ok(json!({
        "valid": valid,
        "issuer": if issuer_display.is_empty() { "Unknown".to_string() } else { issuer_display },
        "subject": subject,
        "validFrom": valid_from.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "validTo": valid_to.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "daysRemaining": days_remaining,
    }))
}

#[derive(Debug)]
struct NoVerify;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::ED25519,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
