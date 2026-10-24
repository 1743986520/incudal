//! 宿主机管理路由 — port of server/src/routes/hosts.ts (mounted at /api/hosts).
//!
//! The TS file is 8.6k lines with ~68 endpoints; every handler below mirrors
//! the TS decorator (authenticate / authenticateAdmin), status codes, error
//! codes and body shapes. DB helpers from db/hosts.ts, db/host-addresses.ts,
//! db/storage-pools.ts, db/package-hosts.ts and the imported lib helpers are
//! private functions here or live under src/libs/host_*.rs.
//!
//! Reported deviations (see PORTING notes at the bottom):
//! - email/Telegram/external-channel fan-out is stubbed with warnings
//!   (lib/notifier external channels, lib/mailer, lib/release-notifier);
//!   inbox messages ARE created.
//! - hourly billing close/pause release the prepaid balance and flip the
//!   account status but do not run the per-second settlement math
//!   (settleInTransaction belongs to the hourly-billing module port).
//! - SSH keypair generation (create-for-user + forceGenerateSshKey) fails like
//!   the ssh-keys route (no rsa crate).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde_json::{json, Map, Value};
use sha2::Digest;

use crate::auth::{AdminAuth, AuthUser};
use crate::error::{code, ApiError};
use crate::libs::host_address_registry as registry;
use crate::libs::host_agent_credentials as agent_creds;
use crate::libs::host_audit::{
    analyze_audit_data, build_connection_audit_command, build_process_audit_command,
    build_startup_audit_command, builtin_audit_rules, connection_json, find_builtin_audit_rule,
    parse_connections, parse_processes, parse_startup_items, process_json, startup_item_json,
    AuditIgnoreDefinition, AuditRuleDefinition,
};
use crate::libs::incus::incus_backups::delete_backup;
use crate::libs::incus::incus_config_vm::generate_vm_config;
use crate::libs::incus::incus_snapshots::delete_snapshot;
use crate::libs::host_billing as billing;
use crate::libs::host_caddy::CaddyClient;
use crate::libs::host_network_policy::normalize_network_policy_input;
use crate::libs::incus::incus_client::{IncusClient, IncusClientOptions, IncusError};
use crate::libs::crypto as crypto_lib;
use crate::libs::incus::incus_config_container::{generate_random_password, IncusConfigParams};
use crate::libs::incus::incus_config_generator::generate_incus_config;
use crate::libs::incus::incus_instances::{
    build_instance_config, create_instance, delete_instance,
    ensure_instance_deleted, exec_with_output, get_instance, get_instance_state, list_instances,
    remove_device, restart_instance, start_instance, stop_instance, BusyRetryOptions,
    BuildInstanceConfigOptions, IncusExecCommand,
};
use crate::libs::incus::incus_pool::PoolHost;
use crate::libs::incus::incus_storage::{
    create_storage_pool, delete_storage_pool, get_storage_pool, get_storage_pool_resources,
    list_storage_pools, update_storage_pool, CreateStoragePoolOptions,
    UpdateStoragePoolOptions,
};
use crate::libs::incus::incus_tls::{
    assert_allowed_host_url, capture_incus_server_certificate, certificate_fingerprint,
    normalize_certificate_pem, panel_certificate_paths, resolve_incus_target,
};
use crate::libs::incus::incus_utils::map_instance_status;
use crate::libs::incus::ip_calculator::{generate_random_ipv4, generate_random_ipv6};
use crate::libs::incus::managed_instance_provision::{
    persist_resolved_instance_network_addresses, provision_managed_instance_async,
    resolve_instance_network_addresses, InstanceNetworkSyncTarget,
    ManagedInstanceProvisionConfig,
};
use crate::libs::incus::network_address::get_dns_record_type;
use crate::libs::incus::network_payload_builder::NetworkMode;
use crate::libs::validators;
use crate::response::num;
use crate::routes::users::{create_inbox_notification, create_log};
use crate::state::SharedAppState;

// ===========================================================================
// router (paths relative to /api/hosts)
// ===========================================================================

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list_hosts).post(create_host))
        .route("/install.sh", get(install_script_generic))
        .route("/install.sh/{token}", get(install_script_with_token))
        .route("/cert/{token}", get(cert_download))
        .route("/tls-bootstrap/{token}", post(tls_bootstrap))
        .route("/caddy-script/{token}", get(caddy_script_download))
        .route(
            "/{id}",
            get(host_detail).patch(host_update).delete(host_delete),
        )
        .route("/{id}/verify", post(host_verify))
        .route("/{id}/regenerate-install", post(host_regenerate_install))
        .route("/{id}/test", post(host_test))
        .route(
            "/{id}/images",
            get(host_images_get).put(host_images_put),
        )
        .route("/{id}/maintenance", post(host_maintenance))
        .route("/{id}/sync", post(host_sync))
        .route("/{id}/extend-all", post(host_extend_all))
        .route("/{id}/takeover-official", post(host_takeover_official))
        .route("/{id}/plans", get(host_plans))
        .route("/{id}/recalculate-resources", post(host_recalculate_resources))
        .route("/{id}/users/lookup", get(host_users_lookup))
        .route(
            "/{id}/storage-pools",
            get(storage_pools_list).post(storage_pool_create),
        )
        .route(
            "/{id}/storage-pools/{pool_name}",
            delete(storage_pool_delete).patch(storage_pool_update),
        )
        .route("/{id}/caddy", get(caddy_status))
        .route("/{id}/caddy/generate", post(caddy_generate))
        .route("/{id}/caddy/reset", post(caddy_reset))
        .route("/{id}/caddy/confirm", post(caddy_confirm))
        .route("/{id}/caddy/test", post(caddy_test))
        .route("/{id}/caddy/sites", get(caddy_sites))
        .route(
            "/{id}/instances/batch-delete-preview",
            post(batch_delete_preview),
        )
        .route("/{id}/instances/batch", delete(batch_delete_instances))
        .route("/{id}/instances/sync-status", post(batch_sync_status))
        .route("/{id}/instances/suspend", post(batch_suspend))
        .route("/{id}/instances/unsuspend", post(batch_unsuspend))
        .route("/{id}/instances/migrate", post(batch_migrate))
        .route("/{id}/instances/create-for-user", post(create_for_user))
        .route("/{id}/instances/gift-days", post(gift_days))
        .route(
            "/{id}/instances/{instance_id}/renewal-price",
            patch(update_renewal_price),
        )
        .route("/{id}/ops/discover", post(ops_discover))
        .route("/{id}/ops/baseline-sync", post(ops_baseline_sync))
        .route("/{id}/ops/network-repair", post(ops_network_repair))
        .route(
            "/{id}/ops/instances/{instance_id}/preview",
            post(ops_instance_preview),
        )
        .route(
            "/{id}/ops/instances/{instance_id}/ssh-keys",
            get(ops_instance_ssh_keys),
        )
        .route(
            "/{id}/ops/instances/{instance_id}/init-commands",
            get(ops_instance_init_commands),
        )
        .route(
            "/{id}/ops/instances/{instance_id}/sync",
            post(ops_instance_sync),
        )
        .route(
            "/{id}/ops/instances/{instance_id}/restart",
            post(ops_instance_restart),
        )
        .route(
            "/{id}/ops/instances/{instance_id}/dangerous-action",
            post(ops_instance_dangerous_action),
        )
        .route(
            "/{id}/ops/instances/{instance_id}/audit/scan",
            post(audit_scan),
        )
        .route(
            "/{id}/ops/instances/{instance_id}/audit/kill-process",
            post(audit_kill_process),
        )
        .route(
            "/{id}/ops/audit/rules",
            get(audit_rules_list).post(audit_rules_create),
        )
        .route(
            "/{id}/ops/audit/rules/{rule_id}",
            patch(audit_rule_update).delete(audit_rule_delete),
        )
        .route(
            "/{id}/ops/audit/builtin-rules/{rule_id}",
            patch(audit_builtin_rule_override).delete(audit_builtin_rule_reset),
        )
        .route(
            "/{id}/ops/audit/ignores",
            get(audit_ignores_list).post(audit_ignores_create),
        )
        .route(
            "/{id}/ops/audit/ignores/{ignore_id}",
            delete(audit_ignores_delete),
        )
        .route("/{id}/ops/audit/history", get(audit_history))
}

// ===========================================================================
// small shared helpers
// ===========================================================================

/// TS `Date` fields serialize as ISO strings through Fastify's JSON encoder.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn iso_opt(value: Option<DateTime<Utc>>) -> Value {
    match value {
        Some(v) => json!(iso(v)),
        None => Value::Null,
    }
}

/// TS `Number(request.params.id)` + isNaN check: NaN -> 400 INVALID_ID;
/// integral values -> i32; non-integral/out-of-range would fail Prisma Int
/// validation -> 500.
fn js_number_id(raw: &str) -> Result<i32, ApiError> {
    let t = raw.trim();
    let v: f64 = if t.is_empty() {
        f64::NAN
    } else {
        t.parse::<f64>().unwrap_or(f64::NAN)
    };
    if v.is_nan() {
        return Err(ApiError::bad_request(code::INVALID_ID));
    }
    if v.fract() != 0.0 || !v.is_finite() || !(i32::MIN as f64..=i32::MAX as f64).contains(&v) {
        return Err(ApiError::internal(format!(
            "Prisma Int argument out of range: {v}"
        )));
    }
    Ok(v as i32)
}

/// TS parseInt(str, 10) semantics (leading digits; "12abc" -> 12).
fn js_parse_int(raw: &str) -> Option<i32> {
    let t = raw.trim_start();
    let end = t
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(t.len());
    if end == 0 {
        return None;
    }
    t[..end].parse::<i64>().ok().and_then(|v| {
        if (i32::MIN as i64..=i32::MAX as i64).contains(&v) {
            Some(v as i32)
        } else {
            Some(i32::MAX)
        }
    })
}

/// parseStringArray (lib/json-validation.ts): tags JSON -> string list.
fn parse_string_array(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// lib/security.ts normalizeHostAddress: strips brackets from IPv6 literals.
fn normalize_host_address(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    trimmed.to_string()
}

fn is_valid_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
                && !(p.len() > 1 && p.starts_with('0'))
        })
}

fn is_valid_ipv6_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
        && matches!(value.parse::<std::net::IpAddr>(), Ok(std::net::IpAddr::V6(_)))
}

/// lib/security.ts validateUrl: URL parseable + http(s) prefix.
fn validate_url(url: &str, field_name: &str) -> Result<String, String> {
    if url.is_empty() {
        return Err(format!("{field_name} cannot be empty"));
    }
    let trimmed = url.trim();
    if reqwest::Url::parse(trimmed).is_err() {
        return Err(format!("{field_name} format is invalid"));
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err(format!("{field_name} must start with http:// or https://"));
    }
    Ok(trimmed.to_string())
}

/// lib/security.ts validateIpAddress (normalizes brackets, accepts v4/v6).
fn validate_ip_address(ip: &str, field_name: &str) -> Result<String, String> {
    if ip.is_empty() {
        return Err(format!("{field_name} cannot be empty"));
    }
    let trimmed = normalize_host_address(ip);
    if !is_valid_ipv4(&trimmed) && !is_valid_ipv6_address(&trimmed) {
        return Err(format!("{field_name} format is invalid"));
    }
    Ok(trimmed)
}

/// lib/security.ts validateIpOrDomain.
fn validate_ip_or_domain(input: &str, field_name: &str) -> Result<String, String> {
    if input.is_empty() {
        return Err(format!("{field_name} cannot be empty"));
    }
    let trimmed = normalize_host_address(input);
    if trimmed.len() > 253 {
        return Err(format!("{field_name} cannot exceed 253 characters"));
    }
    if is_valid_ipv4(&trimmed) || is_valid_ipv6_address(&trimmed) {
        return Ok(trimmed);
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    let domain_ok = (!trimmed.starts_with('-')
        && !trimmed.starts_with('.')
        && !trimmed.ends_with('-')
        && !trimmed.ends_with('.'))
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if domain_ok {
        for label in labels {
            if label.len() > 63 {
                return Err(format!(
                    "{field_name} format is invalid: domain label cannot exceed 63 characters"
                ));
            }
        }
        return Ok(trimmed);
    }
    Err(format!("{field_name} format is invalid"))
}

/// lib/external-url.ts getSafeHttpUrl.
fn get_safe_http_url(value: Option<&str>) -> Option<String> {
    let Some(value) = value else {
        return None;
    };
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c.is_control())
        || reqwest::Url::parse(trimmed).is_err()
    {
        return None;
    }
    let parsed = reqwest::Url::parse(trimmed).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    Some(parsed.to_string())
}

/// lib/external-url.ts validateOptionalHttpUrl (null/empty clears).
fn validate_optional_http_url(value: Option<&Value>, field_name: &str) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.trim().is_empty() {
                return Ok(None);
            }
            if s.trim().chars().any(|c| c.is_control()) {
                return Err(format!("{field_name} contains invalid control characters"));
            }
            let parsed = reqwest::Url::parse(s.trim())
                .map_err(|_| format!("{field_name} format is invalid"))?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(format!("{field_name} must use http:// or https://"));
            }
            Ok(Some(parsed.to_string()))
        }
        Some(_) => Err(format!("{field_name} must be a string")),
    }
}

/// lib/architecture.ts normalizeArchitecture.
fn normalize_architecture(value: Option<&str>) -> &'static str {
    let normalized = value.map(|v| v.trim().to_lowercase());
    match normalized.as_deref() {
        Some("aarch64") | Some("arm64") => "aarch64",
        Some("x86_64") | Some("amd64") | Some("x64") | Some("x86") => "x86_64",
        _ => "x86_64",
    }
}

/// JS Number(x) for body integers arriving as JSON (fastify coerces).
fn body_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else {
                n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)
            }
        }
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        Some(Value::Bool(_)) | Some(Value::Null) | Some(Value::Array(_)) | Some(Value::Object(_)) | None => None,
    }
}

/// randomUUID().
fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// caddy generateRandomString: random alnum via crypto.randomBytes modulo.
fn caddy_random_string(length: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    use rand::RngCore;
    let mut out = String::with_capacity(length);
    let mut buf = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    for b in buf {
        out.push(CHARS[(b as usize) % CHARS.len()] as char);
    }
    out
}

/// generateCaddyScriptToken: base64url(`hostId:expireAt:hmac_sha256`).
fn generate_caddy_script_token(jwt_secret: &str, host_id: i32) -> String {
    let expire_at = Utc::now().timestamp_millis() + 30 * 60 * 1000;
    let payload = format!("{host_id}:{expire_at}");
    let signature = hmac_sha256_hex(jwt_secret.as_bytes(), payload.as_bytes());
    let decoded = format!("{payload}:{signature}");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded.as_bytes())
}

/// Minimal HMAC-SHA256 (RFC 2104) for the caddy script tokens (crypto.createHmac).
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut key = key.to_vec();
    if key.len() > BLOCK {
        key = sha2::Sha256::digest(&key).to_vec();
    }
    key.resize(BLOCK, 0);
    let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
    let mut inner_data = ipad;
    inner_data.extend_from_slice(message);
    let inner = sha2::Sha256::digest(&inner_data);
    let mut outer_data = opad;
    outer_data.extend_from_slice(&inner);
    hex::encode(sha2::Sha256::digest(&outer_data))
}

/// verifyCaddyScriptToken -> hostId.
fn verify_caddy_script_token(jwt_secret: &str, token: &str) -> Option<i32> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let parts: Vec<&str> = decoded.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let host_id: i32 = parts[0].parse().ok()?;
    let expire_at: i64 = parts[1].parse().ok()?;
    if host_id <= 0 {
        return None;
    }
    if Utc::now().timestamp_millis() > expire_at {
        return None;
    }
    let payload = format!("{}:{}", parts[0], parts[1]);
    let expected = hmac_sha256_hex(jwt_secret.as_bytes(), payload.as_bytes());
    // timingSafeEqual equivalent: constant-time comparison of equal-length hex.
    if expected.len() != parts[2].len() {
        return None;
    }
    let diff: u8 = expected
        .bytes()
        .zip(parts[2].bytes())
        .fold(0, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return None;
    }
    Some(host_id)
}

/// derivePanelUrl: PUBLIC_URL > first FRONTEND_URL entry; production refuses
/// header-derived URLs (mirrors the TS guard).
fn derive_panel_url(state: &SharedAppState) -> Result<String, ApiError> {
    let configured = std::env::var("PUBLIC_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("FRONTEND_URL")
                .ok()
                .and_then(|v| v.split(',').next().map(|s| s.trim().to_string()))
                .filter(|v| !v.is_empty())
        });
    if let Some(configured) = configured {
        let parsed = reqwest::Url::parse(&configured)
            .map_err(|_| ApiError::internal("PUBLIC_URL/FRONTEND_URL is not a valid URL"))?;
        if (parsed.scheme() != "http" && parsed.scheme() != "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(ApiError::internal(
                "PUBLIC_URL/FRONTEND_URL must be an absolute HTTP(S) URL without credentials",
            ));
        }
        let mut origin = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or_default());
        if let Some(port) = parsed.port() {
            origin = format!("{origin}:{port}");
        }
        return Ok(origin);
    }
    if crate::config::runtime_is_production() {
        return Err(ApiError::internal(
            "PUBLIC_URL or FRONTEND_URL is required to generate host install scripts",
        ));
    }
    // Local development: TS uses request.protocol/hostname (localhost:port of
    // the API server); the panel URL convention stays the configured default.
    Ok(format!("http://localhost:{}", state.config.port))
}

fn shell_double_quote(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

fn inject_install_variable(script: &str, name: &str, value: &str) -> String {
    let pattern = format!("(?m)^{name}=\"\"");
    let replacement = format!("{name}=\"{}\"", shell_double_quote(value));
    once_cell_regex_replace(&pattern, script, &replacement)
}

fn once_cell_regex_replace(pattern: &str, text: &str, replacement: &str) -> String {
    match regex::Regex::new(pattern) {
        Ok(re) => re.replace(text, replacement).into_owned(),
        Err(_) => text.to_string(),
    }
}

const HOST_INSTALL_OS: &[&str] = &["ubuntu", "debian", "rocky", "alpine"];

/// Template root: PANEL_TEMPLATES_DIR > <repo>/server/templates (the Rust crate
/// is a sibling of the TS server in this repository).
fn template_root() -> String {
    if let Ok(dir) = std::env::var("PANEL_TEMPLATES_DIR") {
        if !dir.is_empty() {
            return dir;
        }
    }
    concat!(env!("CARGO_MANIFEST_DIR"), "/../server/templates").to_string()
}

fn read_host_install_template(stage: &str, os: Option<&str>) -> Result<String, String> {
    let template_root = template_root();
    if stage == "bootstrap" {
        return std::fs::read_to_string(format!("{template_root}/install.sh"))
            .map_err(|e| format!("read install.sh failed: {e}"));
    }
    let Some(os) = os else {
        return Err("Unsupported installer platform".to_string());
    };
    if !HOST_INSTALL_OS.contains(&os) {
        return Err("Unsupported installer platform".to_string());
    }
    let module_names = [
        format!("platform/{os}.sh"),
        "prelude.sh".to_string(),
        "storage.sh".to_string(),
        "network.sh".to_string(),
        "system.sh".to_string(),
        "pps.sh".to_string(),
        "incus.sh".to_string(),
        "agent.sh".to_string(),
        "firewall.sh".to_string(),
        "uninstall.sh".to_string(),
        "guardian.sh".to_string(),
        "main.sh".to_string(),
    ];
    let mut out = String::new();
    for module in module_names {
        let content = std::fs::read_to_string(format!("{template_root}/install/{module}"))
            .map_err(|e| format!("read install/{module} failed: {e}"))?;
        out.push_str(&content);
        out.push('\n');
    }
    Ok(out)
}

fn resolve_host_install_stage(stage: Option<&str>) -> Result<&'static str, String> {
    match stage {
        None | Some("") | Some("bootstrap") => Ok("bootstrap"),
        Some("platform") => Ok("platform"),
        Some(_) => Err("Unsupported installer stage".to_string()),
    }
}

fn build_host_install_command(panel_url: &str, install_token: &str) -> String {
    let script_url = format!("{panel_url}/api/hosts/install.sh/{install_token}");
    let quoted_script_url = format!("'{}'", script_url.replace('\'', "'\"'\"'"));
    format!(
        "incudal_as_root() {{ if [ \"$(id -u)\" = 0 ]; then \"$@\"; else sudo \"$@\"; fi; }}; \
         if ! command -v curl >/dev/null 2>&1 || ! command -v bash >/dev/null 2>&1; then \
         if command -v apk >/dev/null 2>&1; then incudal_as_root apk add --no-cache bash curl ca-certificates; \
         elif command -v apt-get >/dev/null 2>&1; then incudal_as_root apt-get update && incudal_as_root apt-get install -y bash curl ca-certificates; \
         elif command -v dnf >/dev/null 2>&1; then incudal_as_root dnf install -y bash curl ca-certificates; \
         else echo 'Unsupported package manager' >&2; exit 1; fi; fi && \
         curl --fail --show-error --location {quoted_script_url} -o incudal.sh && incudal_as_root bash incudal.sh"
    )
}

fn text_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

fn no_store_text(status: StatusCode, body: String) -> Response {
    let mut response = text_response(status, body);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    response
}

// ===========================================================================
// host row + db helpers (port of db/hosts.ts and friends)
// ===========================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HostRow {
    pub id: i32,
    pub user_id: i32,
    pub name: String,
    pub url: String,
    pub location: Option<String>,
    pub country_code: String,
    pub architecture: String,
    #[sqlx(rename = "status")]
    pub status: String,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub server_certificate: Option<String>,
    pub server_fingerprint: Option<String>,
    pub allow_private_network: bool,
    pub nat_public_ip: Option<String>,
    pub nat_public_ipv6: Option<String>,
    pub nat_bind_ip: Option<String>,
    pub nat_bind_ipv6: Option<String>,
    pub nat_port_start: Option<i32>,
    pub nat_port_end: Option<i32>,
    pub cpu_used: i32,
    pub memory_used: i32,
    pub disk_used: i32,
    pub tags: Option<Value>,
    pub nat_ports_used_count: i32,
    pub cpu_allowance_max: i32,
    pub memory_max: i32,
    #[sqlx(rename = "instance_type")]
    pub instance_type: String,
    pub ip_address: Option<String>,
    pub storage_driver: String,
    pub storage_type: String,
    pub storage_path: Option<String>,
    pub storage_size: i32,
    pub ipv6_mode: i32,
    pub ipv6_subnet: Option<String>,
    pub ipv6_gateway: Option<String>,
    pub ipv6_parent_interface: Option<String>,
    pub enable_api: bool,
    pub sysctl_config: Option<String>,
    pub install_token: Option<String>,
    pub install_token_expire: Option<DateTime<Utc>>,
    pub is_installed: bool,
    pub cert_download_count: i32,
    pub cert_download_expire: Option<DateTime<Utc>>,
    pub caddy_enabled: bool,
    pub caddy_username: Option<String>,
    pub caddy_password: Option<String>,
    pub caddy_port: i32,
    pub transfer_enabled: bool,
    pub hourly_billing_enabled: bool,
    pub traffic_reset_day: i32,
    pub announcement: Option<String>,
    pub notify_purchase: bool,
    pub notify_renew: bool,
    pub notify_destroy: bool,
    pub enable_resource_pool: bool,
    pub probe_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const HOST_COLUMNS: &str = "id, user_id, name, url, location, country_code, architecture, \
    status::text AS status, cert_path, key_path, server_certificate, server_fingerprint, \
    allow_private_network, nat_public_ip, nat_public_ipv6, nat_bind_ip, nat_bind_ipv6, \
    nat_port_start, nat_port_end, cpu_used, memory_used, disk_used, tags, nat_ports_used_count, \
    cpu_allowance_max, memory_max, instance_type::text AS instance_type, ip_address, \
    storage_driver, storage_type, storage_path, storage_size, ipv6_mode, ipv6_subnet, \
    ipv6_gateway, ipv6_parent_interface, enable_api, sysctl_config, install_token, \
    install_token_expire, is_installed, cert_download_count, cert_download_expire, \
    caddy_enabled, caddy_username, caddy_password, caddy_port, transfer_enabled, \
    hourly_billing_enabled, traffic_reset_day, announcement, notify_purchase, notify_renew, \
    notify_destroy, enable_resource_pool, probe_url, created_at, updated_at";

/// db.getHostById.
async fn get_host_by_id(state: &SharedAppState, id: i32) -> Result<Option<HostRow>, ApiError> {
    let row = sqlx::query_as::<_, HostRow>(&format!(
        "SELECT {HOST_COLUMNS} FROM hosts WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// db.getHostByUserAndName (unique (user_id, name)).
async fn get_host_by_user_and_name(
    state: &SharedAppState,
    user_id: i32,
    name: &str,
) -> Result<Option<HostRow>, ApiError> {
    let row = sqlx::query_as::<_, HostRow>(&format!(
        "SELECT {HOST_COLUMNS} FROM hosts WHERE user_id = $1 AND name = $2"
    ))
    .bind(user_id)
    .bind(name)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// db.getHostByInstallToken + extra columns used by install/cert endpoints.
async fn get_host_by_install_token(
    state: &SharedAppState,
    token: &str,
) -> Result<Option<(i32, String, bool, Option<DateTime<Utc>>)>, ApiError> {
    let row: Option<(i32, String, bool, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id, name, is_installed, install_token_expire FROM hosts WHERE install_token = $1",
    )
    .bind(token)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// db.getInstanceCountByHost (status != deleted).
async fn get_instance_count_by_host(state: &SharedAppState, host_id: i32) -> Result<i64, ApiError> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM instances WHERE host_id = $1 AND status <> 'deleted'")
            .bind(host_id)
            .fetch_one(&state.db)
            .await?;
    Ok(count)
}

/// db.updateHostStatus.
async fn update_host_status(state: &SharedAppState, host_id: i32, status: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE hosts SET status = $2::\"HostStatus\" WHERE id = $1")
        .bind(host_id)
        .bind(status)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// db.calculateHostResourcesFromInstances (host-resource-usage statuses).
async fn calculate_host_resources_from_instances(
    state: &SharedAppState,
    host_id: i32,
) -> Result<(i64, i64, i64), ApiError> {
    let row: (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT COALESCE(SUM(cpu), 0), COALESCE(SUM(memory), 0), COALESCE(SUM(disk), 0) \
         FROM instances WHERE host_id = $1 \
         AND status IN ('creating','running','stopped','suspended')",
    )
    .bind(host_id)
    .fetch_one(&state.db)
    .await?;
    Ok((row.0.unwrap_or(0), row.1.unwrap_or(0), row.2.unwrap_or(0)))
}

/// The reserved-port aggregate shared by sync/recalculate/batch endpoints:
/// SUM(port_limit) over allocated NAT modes.
async fn reserved_nat_ports(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    host_id: i32,
) -> Result<i64, ApiError> {
    let row: (Option<i64>,) = sqlx::query_as(
        "SELECT COALESCE(SUM(port_limit), 0) FROM instances WHERE host_id = $1 \
         AND status IN ('creating','running','stopped','suspended') \
         AND network_mode IN ('nat','nat_ipv6','nat_ipv6_nat','ipv6_nat','ipv6_only')",
    )
    .bind(host_id)
    .fetch_one(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(row.0.unwrap_or(0))
}

/// db.updateHostResources (subset the routes use).
struct HostResourceUpdate<'a> {
    cpu_used: Option<i64>,
    memory_used: Option<i64>,
    disk_used: Option<i64>,
    cpu_allowance_max: Option<i64>,
    memory_max: Option<i64>,
    instance_type: Option<&'a str>,
    architecture: Option<&'a str>,
}

async fn update_host_resources(
    state: &SharedAppState,
    host_id: i32,
    update: HostResourceUpdate<'_>,
) -> Result<(), ApiError> {
    let mut sets: Vec<String> = Vec::new();
    let mut idx = 2usize;
    let mut q = sqlx::query("UPDATE hosts SET");
    if update.cpu_used.is_some() {
        sets.push(format!(" cpu_used = ${idx}"));
        idx += 1;
    }
    if update.memory_used.is_some() {
        sets.push(format!(" memory_used = ${idx}"));
        idx += 1;
    }
    if update.disk_used.is_some() {
        sets.push(format!(" disk_used = ${idx}"));
        idx += 1;
    }
    if update.cpu_allowance_max.is_some() {
        sets.push(format!(" cpu_allowance_max = ${idx}"));
        idx += 1;
    }
    if update.memory_max.is_some() {
        sets.push(format!(" memory_max = ${idx}"));
        idx += 1;
    }
    if update.instance_type.is_some() {
        sets.push(format!(" instance_type = ${idx}::\"InstanceType\""));
        idx += 1;
    }
    if update.architecture.is_some() {
        sets.push(format!(" architecture = ${idx}"));
        idx += 1;
    }
    if sets.is_empty() {
        return Ok(());
    }
    let sql = format!(
        "UPDATE hosts SET{} WHERE id = $1",
        sets.join(",")
    );
    q = sqlx::query(&sql).bind(host_id);
    if let Some(v) = update.cpu_used {
        q = q.bind(v as i32);
    }
    if let Some(v) = update.memory_used {
        q = q.bind(v as i32);
    }
    if let Some(v) = update.disk_used {
        q = q.bind(v as i32);
    }
    if let Some(v) = update.cpu_allowance_max {
        q = q.bind(v as i32);
    }
    if let Some(v) = update.memory_max {
        q = q.bind(v as i32);
    }
    if let Some(v) = update.instance_type {
        q = q.bind(v);
    }
    if let Some(v) = update.architecture {
        q = q.bind(v);
    }
    q.execute(&state.db).await?;
    Ok(())
}

/// db.rollbackResources: atomic decrement with lower bound 0 (Serializable tx
/// in the TS; the counters update runs in its own short transaction here).
async fn rollback_resources(
    state: &SharedAppState,
    host_id: i32,
    cpu: i64,
    memory: i64,
    disk: i64,
    port_count: i64,
) -> Result<(), ApiError> {
    let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
    sqlx::query(
        "UPDATE hosts SET \
         cpu_used = GREATEST(0, cpu_used - $2), \
         memory_used = GREATEST(0, memory_used - $3), \
         disk_used = GREATEST(0, disk_used - $4), \
         nat_ports_used_count = GREATEST(0, nat_ports_used_count - $5) \
         WHERE id = $1",
    )
    .bind(host_id)
    .bind(cpu as i32)
    .bind(memory as i32)
    .bind(disk as i32)
    .bind(port_count as i32)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    tx.commit().await.map_err(ApiError::from_sql)?;
    Ok(())
}

/// db.adjustHostResources (atomic increments used by migrate).
async fn adjust_host_resources(
    state: &SharedAppState,
    host_id: i32,
    cpu: i64,
    memory: i64,
    disk: i64,
) -> Result<(), ApiError> {
    if cpu == 0 && memory == 0 && disk == 0 {
        return Ok(());
    }
    sqlx::query(
        "UPDATE hosts SET cpu_used = cpu_used + $2, memory_used = memory_used + $3, \
         disk_used = disk_used + $4 WHERE id = $1",
    )
    .bind(host_id)
    .bind(cpu as i32)
    .bind(memory as i32)
    .bind(disk as i32)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// db.deleteHost: port mappings, then instances (cascade), then the host.
async fn delete_host_record(state: &SharedAppState, host_id: i32) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM port_mappings WHERE host_id = $1")
        .bind(host_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM instances WHERE host_id = $1")
        .bind(host_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM hosts WHERE id = $1")
        .bind(host_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// db.getInstancesByHost -> the (id, name, status) triple the detail view uses.
async fn get_instances_by_host(
    state: &SharedAppState,
    host_id: i32,
) -> Result<Vec<(i32, String, String)>, ApiError> {
    let rows: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT id, name, status::text AS status FROM instances \
         WHERE host_id = $1 AND status <> 'deleted' ORDER BY id ASC",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// db.getInstanceById (subset of fields used by ops endpoints).
#[derive(Debug, Clone, sqlx::FromRow)]
struct InstanceRow {
    pub id: i32,
    pub incus_id: String,
    pub name: String,
    pub user_id: i32,
    pub host_id: i32,
    pub package_id: Option<i32>,
    pub package_plan_id: Option<i32>,
    #[sqlx(rename = "billing_mode")]
    pub billing_mode: String,
    pub status: String,
    pub cpu: i32,
    pub memory: i32,
    pub disk: i32,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    #[sqlx(rename = "network_mode")]
    pub network_mode: String,
    pub port_limit: Option<i32>,
    #[sqlx(rename = "suspend_reason")]
    pub suspend_reason: Option<String>,
    pub billing_price: Option<Decimal>,
    pub billing_cycle: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub suspended_at: Option<DateTime<Utc>>,
    pub suspended_by: Option<i32>,
    pub image: Option<String>,
    pub storage_pool_name: Option<String>,
    pub version: i32,
    pub user_username: Option<String>,
    pub user_email: Option<String>,
}

const INSTANCE_SELECT: &str = "SELECT i.id, i.incus_id, i.name, i.user_id, i.host_id, \
    i.package_id, i.package_plan_id, i.billing_mode::text AS billing_mode, \
    i.status::text AS status, i.cpu, i.memory, i.disk, i.ipv4, i.ipv6, \
    i.network_mode::text AS network_mode, i.port_limit, i.suspend_reason, \
    i.billing_price, i.billing_cycle, i.expires_at, i.suspended_at, i.suspended_by, \
    i.image, i.storage_pool_name, i.version, u.username AS user_username, u.email AS user_email \
    FROM instances i LEFT JOIN users u ON u.id = i.user_id";

async fn get_instance_by_id(state: &SharedAppState, id: i32) -> Result<Option<InstanceRow>, ApiError> {
    let row = sqlx::query_as::<_, InstanceRow>(&format!(
        "{INSTANCE_SELECT} WHERE i.id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// db.updateInstanceStatus (deleted -> unconditional; otherwise guard on the
/// current status like the TS updateMany where-clause).
async fn update_instance_status(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    id: i32,
    status: &str,
) -> Result<(), ApiError> {
    if status == "deleted" {
        sqlx::query("UPDATE instances SET status = 'deleted'::\"InstanceStatus\" WHERE id = $1")
            .bind(id)
            .execute(exec)
            .await
            .map_err(ApiError::from_sql)?;
    } else {
        sqlx::query(
            "UPDATE instances SET status = $2::\"InstanceStatus\" WHERE id = $1 AND status <> 'deleted'",
        )
        .bind(id)
        .bind(status)
        .execute(exec)
        .await
        .map_err(ApiError::from_sql)?;
    }
    Ok(())
}

/// db.hasPendingTransfer.
async fn has_pending_transfer(state: &SharedAppState, instance_id: i32) -> Result<bool, ApiError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instance_transfers WHERE instance_id = $1 AND status IN ('pending','processing')",
    )
    .bind(instance_id)
    .fetch_one(&state.db)
    .await?;
    Ok(count > 0)
}

/// db.isIpAddressExistsOnHost (ipv4 on the given host, excluding deleted).
async fn is_ipv4_exists_on_host(state: &SharedAppState, address: &str, host_id: i32) -> Result<bool, ApiError> {
    let in_ip: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM ip_addresses WHERE address = $1 AND type = 'inet4' \
         AND host_id = $2 AND instance_id IN (SELECT id FROM instances WHERE status <> 'deleted') LIMIT 1",
    )
    .bind(address)
    .bind(host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    if in_ip.is_some() {
        return Ok(true);
    }
    let in_instance: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM instances WHERE ipv4 = $1 AND host_id = $2 AND status <> 'deleted' LIMIT 1",
    )
    .bind(address)
    .bind(host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(in_instance.is_some())
}

/// db.isIpAddressExists (global ipv6 check).
async fn is_ipv6_exists(state: &SharedAppState, address: &str) -> Result<bool, ApiError> {
    let in_ip: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM ip_addresses WHERE address = $1 AND type = 'inet6' \
         AND instance_id IN (SELECT id FROM instances WHERE status <> 'deleted') LIMIT 1",
    )
    .bind(address)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    if in_ip.is_some() {
        return Ok(true);
    }
    let in_instance: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM instances WHERE ipv6 = $1 AND status <> 'deleted' LIMIT 1",
    )
    .bind(address)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(in_instance.is_some())
}

/// build PoolHost from a host row exactly like lib/incus calls in TS.
fn pool_host_from(host: &HostRow) -> PoolHost {
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

/// getIncusClient via the shared pool.
async fn get_incus_client(
    state: &SharedAppState,
    host: &HostRow,
) -> Result<std::sync::Arc<IncusClient>, ApiError> {
    state
        .incus_pool
        .get_incus_client(&pool_host_from(host))
        .await
        .map_err(|e| ApiError::internal(format!("{e}")))
}

/// Ownership guard shared by most endpoints (getAuthorizedOpsHost inline form).
/// Returns Ok(true) when the host exists and the user may access it; otherwise
/// the matching ApiError.
fn host_access_error(host: &HostRow, user: &AuthUser) -> Option<ApiError> {
    if host.user_id != user.id && user.role != "admin" {
        return Some(ApiError::forbidden(code::FORBIDDEN));
    }
    None
}

// ===========================================================================
// notifications (inbox messages with the TS EVENT_TEMPLATES text; the external
// channel fan-out of lib/notifier.ts is not ported)
// ===========================================================================

async fn send_notification(
    state: &SharedAppState,
    user_id: i32,
    event_type: &str,
    data: &Value,
) {
    let (title, message) = match event_type {
        "instance_deleted" => (
            "🗑️ 实例已删除".to_string(),
            {
                let mut msg = format!("实例「{}」已永久删除", data["instanceName"].as_str().unwrap_or(""));
                if let Some(host_name) = data["hostName"].as_str() {
                    msg = format!("{msg}\n原节点: {host_name}");
                }
                msg
            },
        ),
        "instance_deleted_by_host_owner" => (
            "⚠️ 您的实例已被删除".to_string(),
            {
                let mut msg = format!("实例「{}」已被删除", data["instanceName"].as_str().unwrap_or(""));
                if let Some(host_name) = data["hostName"].as_str() {
                    msg = format!("{msg}\n节点: {host_name}");
                }
                if let Some(reason) = data["deleteReason"].as_str() {
                    msg = format!("{msg}\n原因: {reason}");
                }
                msg
            },
        ),
        "instance_suspended" => (
            "🚫 您的实例已被封停".to_string(),
            {
                let mut msg = format!("实例「{}」已被封停", data["instanceName"].as_str().unwrap_or(""));
                if let Some(host_name) = data["hostName"].as_str() {
                    msg = format!("{msg}\n节点: {host_name}");
                }
                if let Some(reason) = data["suspendReason"].as_str() {
                    if !reason.is_empty() {
                        msg = format!("{msg}\n原因: {reason}");
                    }
                }
                msg.push_str("\n封停期间，实例无法启动、重启、重装等操作");
                msg.push_str("\n如有疑问，请发送工单");
                msg
            },
        ),
        "instance_unsuspended" => (
            "✅ 您的实例已解除封停".to_string(),
            {
                let mut msg = format!("实例「{}」已解除封停", data["instanceName"].as_str().unwrap_or(""));
                if let Some(host_name) = data["hostName"].as_str() {
                    msg = format!("{msg}\n节点: {host_name}");
                }
                msg.push_str("\n您现在可以正常使用该实例");
                msg
            },
        ),
        "quota_warning" => (
            "⚠️ 配额即将用尽".to_string(),
            {
                let mut msg = format!("您的{}配额即将用尽", data["quotaType"].as_str().unwrap_or(""));
                msg = format!(
                    "{msg}\n使用: {} / {}",
                    num_for_message(&data["currentUsed"]),
                    num_for_message(&data["maxLimit"])
                );
                if let Some(percent) = data["usagePercent"].as_i64() {
                    msg = format!("{msg} ({percent}%)");
                }
                msg.push_str("\n请前往个人设置添加配额");
                msg
            },
        ),
        "instances_batch_extended" => (
            "🎁 管理员已为您的实例赠送时长".to_string(),
            {
                let mut msg = format!(
                    "您在节点「{}」的付费实例已免费延期",
                    data["hostName"].as_str().unwrap_or("")
                );
                if let Some(days) = data["days"].as_i64() {
                    msg = format!("{msg}\n延期时长: {days} 天");
                }
                msg.push_str("\n请前往面板查看最新到期时间");
                msg
            },
        ),
        "instance_renewal_price_updated" => (
            "💰 实例续费价格已调整".to_string(),
            {
                let mut msg = format!(
                    "实例「{}」的续费价格已调整",
                    data["instanceName"].as_str().unwrap_or("")
                );
                if let (Some(old_price), Some(new_price)) =
                    (data["oldPrice"].as_f64(), data["newPrice"].as_f64())
                {
                    msg = format!("{msg}\n原价格: ¥{old_price:.2}/月");
                    msg = format!("{msg}\n新价格: ¥{new_price:.2}/月");
                }
                msg.push_str("\n\n该价格将于下次续费时生效，本月不受影响。");
                if let Some(host_name) = data["hostName"].as_str() {
                    msg = format!("{msg}\n节点: {host_name}");
                }
                msg
            },
        ),
        _ => {
            tracing::warn!("[Notifier] Unknown event type: {event_type}");
            return;
        }
    };

    create_inbox_notification(state, user_id, event_type, &title, &message, data.clone()).await;
    // External notification channels (telegram/discord/email/webhook) are not
    // ported; the TS ignores their failures as well.
    tracing::warn!("[Notifier] external channel fan-out not ported; inbox message only ({event_type})");
}

fn num_for_message(value: &Value) -> String {
    match value {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => String::new(),
    }
}

/// sendReleaseNotification (global channel fan-out) is not ported.
fn send_release_notification(package_id: i32, cpu: i64, memory: i64, source: &str) {
    tracing::warn!(
        "[ReleaseNotifier] not ported; skipped (packageId={package_id}, cpu={cpu}, memory={memory}, source={source})"
    );
}

/// db/logs createLog with an explicit instanceId option.
async fn create_log_with_instance(
    state: &SharedAppState,
    user_id: i32,
    module: &str,
    action: &str,
    content: &str,
    result: &str,
    instance_id: i32,
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
        tracing::warn!("create_log failed (ignored): {err}");
    }
}

/// createLog with a nullable user (system logs).
async fn create_system_log(
    state: &SharedAppState,
    user_id: Option<i32>,
    module: &str,
    action: &str,
    content: &str,
    result: &str,
) {
    let insert = sqlx::query(
        "INSERT INTO logs (user_id, module, action, content, result) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(module)
    .bind(action)
    .bind(content)
    .bind(result)
    .execute(&state.db)
    .await;
    if let Err(err) = insert {
        tracing::warn!("create_log failed (ignored): {err}");
    }
}

/// Incus error message formatting matching `err instanceof Error ? err.message : String(err)`.
fn incus_error_message(err: &IncusError) -> String {
    format!("{err}")
}

/// extractHostPublicIpv6FromResources: first global inet6 address on any NIC
/// that is not link-local/unique-local.
fn extract_host_public_ipv6_from_resources(resources: &Value) -> Option<String> {
    let cards = resources.pointer("/network/cards")?.as_array()?;
    let starts_ok = |ip: &str| !(ip.starts_with("fe80:") || ip.starts_with("fd") || ip.starts_with("fc"));
    for card in cards {
        if let Some(addresses) = card.get("addresses").and_then(Value::as_array) {
            for addr in addresses {
                let family = addr.get("family").and_then(Value::as_str).unwrap_or("");
                let scope = addr.get("scope").and_then(Value::as_str).unwrap_or("");
                let address = addr.get("address").and_then(Value::as_str).unwrap_or("");
                if family == "inet6" && scope == "global" && !address.is_empty() && starts_ok(address) {
                    return Some(address.to_string());
                }
            }
        }
        if let Some(ports) = card.get("ports").and_then(Value::as_array) {
            for port in ports {
                if let Some(addresses) = port.get("addresses").and_then(Value::as_array) {
                    for addr in addresses {
                        let family = addr.get("family").and_then(Value::as_str).unwrap_or("");
                        let scope = addr.get("scope").and_then(Value::as_str).unwrap_or("");
                        let address = addr.get("address").and_then(Value::as_str).unwrap_or("");
                        if family == "inet6" && scope == "global" && !address.is_empty() && starts_ok(address)
                        {
                            return Some(address.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// getResources() disk-total computation shared by create/verify/sync/baseline.
fn extract_disk_total_bytes(resources: &Value) -> i64 {
    let mut disk_total_bytes = 0i64;
    if let Some(disks) = resources
        .pointer("/storage/disks")
        .and_then(Value::as_array)
    {
        if !disks.is_empty() {
            disk_total_bytes = disks
                .iter()
                .map(|d| d.get("size").and_then(Value::as_i64).unwrap_or(0))
                .sum();
        }
    }
    if disk_total_bytes == 0 {
        if let Some(pools) = resources
            .pointer("/storage/pools")
            .and_then(Value::as_object)
        {
            for pool in pools.values() {
                disk_total_bytes += pool
                    .pointer("/space/total")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
            }
        }
    }
    if disk_total_bytes == 0 {
        disk_total_bytes = 1024 * 1024 * 1024 * 1024; // default 1TB
    }
    disk_total_bytes
}

fn resources_architecture(server_info: &Value) -> &'static str {
    let kernel = server_info
        .pointer("/environment/kernel_architecture")
        .and_then(Value::as_str);
    let first_arch = server_info
        .pointer("/environment/architectures/0")
        .and_then(Value::as_str);
    normalize_architecture(kernel.or(first_arch))
}

// ===========================================================================
// hourly billing close/pause (services/hourly-billing-scheduler.ts subset)
// ===========================================================================
//
// DEVIATION: the TS runs settleInTransaction (per-second usage settlement,
// debt records, suspension) inside a serializable tx. That math belongs to the
// hourly-billing module port (roadmap); here we perform the unconditional tail
// of closeHourlyBilling/pauseHourlyBilling: prepaid-balance release with an
// hourly_release balance log, account status flip, counters. `suspended` is
// approximated from the account's outstanding/status.

struct HourlyPauseOutcome {
    suspended: bool,
}

async fn close_hourly_billing(state: &SharedAppState, instance_id: i32) -> Result<(), ApiError> {
    tracing::warn!(
        "[HourlyBilling] settlement math not ported; closing account #{instance_id} with prepaid release only"
    );
    let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;

    let account: Option<(i32, Decimal, String, i32)> = sqlx::query_as(
        "SELECT a.id, a.prepaid_balance, a.status::text AS status, a.version \
         FROM hourly_billing_accounts a WHERE a.instance_id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;

    let Some((account_id, prepaid, status, _version)) = account else {
        return Ok(());
    };
    if status == "closed" {
        return Ok(());
    }

    if prepaid > Decimal::ZERO {
        let user_id: (i32,) = sqlx::query_as(
            "SELECT user_id FROM instances WHERE id = $1",
        )
        .bind(instance_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
        let (balance_before,): (Decimal,) = sqlx::query_as("SELECT balance FROM users WHERE id = $1")
            .bind(user_id.0)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
        let balance_after = balance_before + prepaid;
        sqlx::query(
            "UPDATE users SET balance = balance + $2, hourly_reserved_balance = hourly_reserved_balance - $2 \
             WHERE id = $1",
        )
        .bind(user_id.0)
        .bind(prepaid)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
        sqlx::query(
            "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, instance_id, remark) \
             VALUES ($1, 'hourly_release'::\"BalanceLogType\", $2, $3, $4, $5, $6)",
        )
        .bind(user_id.0)
        .bind(prepaid)
        .bind(balance_before)
        .bind(balance_after)
        .bind(instance_id)
        .bind(format!(
            "按小时计费实例销毁，退回冻结预付款：{}",
            prepaid.normalize()
        ))
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
    }

    sqlx::query(
        "UPDATE hourly_billing_accounts SET status = 'closed', next_settlement_at = NULL, \
         prepaid_balance = 0, total_released = total_released + $2, version = version + 1 WHERE id = $1",
    )
    .bind(account_id)
    .bind(prepaid)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    tx.commit().await.map_err(ApiError::from_sql)?;
    Ok(())
}

async fn pause_hourly_billing(state: &SharedAppState, instance_id: i32) -> Result<HourlyPauseOutcome, ApiError> {
    tracing::warn!(
        "[HourlyBilling] settlement math not ported; pausing account #{instance_id} with prepaid release only"
    );
    let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;

    let account: Option<(i32, Decimal, String, Decimal)> = sqlx::query_as(
        "SELECT id, prepaid_balance, status::text AS status, outstanding_amount \
         FROM hourly_billing_accounts WHERE instance_id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;

    let Some((account_id, prepaid, status, outstanding)) = account else {
        return Ok(HourlyPauseOutcome { suspended: false });
    };
    if status == "closed" {
        return Ok(HourlyPauseOutcome { suspended: false });
    }
    // A suspended/outstanding account must keep its debt state (the resume path
    // requires the debt-payment flow), mirroring the TS early return.
    if status == "suspended" || outstanding > Decimal::ZERO {
        return Ok(HourlyPauseOutcome { suspended: true });
    }

    if prepaid > Decimal::ZERO {
        let (user_id,): (i32,) = sqlx::query_as("SELECT user_id FROM instances WHERE id = $1")
            .bind(instance_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
        let (balance_before,): (Decimal,) = sqlx::query_as("SELECT balance FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
        let balance_after = balance_before + prepaid;
        sqlx::query(
            "UPDATE users SET balance = balance + $2, hourly_reserved_balance = hourly_reserved_balance - $2 \
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(prepaid)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
        sqlx::query(
            "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, instance_id, remark) \
             VALUES ($1, 'hourly_release'::\"BalanceLogType\", $2, $3, $4, $5, $6)",
        )
        .bind(user_id)
        .bind(prepaid)
        .bind(balance_before)
        .bind(balance_after)
        .bind(instance_id)
        .bind(format!(
            "按小时计费实例停止，退回冻结预付款：{}",
            prepaid.normalize()
        ))
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
    }

    sqlx::query(
        "UPDATE hourly_billing_accounts SET status = 'paused', next_settlement_at = NULL, \
         prepaid_balance = 0, total_released = total_released + $2, version = version + 1 WHERE id = $1",
    )
    .bind(account_id)
    .bind(prepaid)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    tx.commit().await.map_err(ApiError::from_sql)?;
    Ok(HourlyPauseOutcome { suspended: false })
}

// ===========================================================================
// claimInstanceForDelete (routes/instances/helpers.ts)
// ===========================================================================

async fn claim_instance_for_delete(
    state: &SharedAppState,
    instance_id: i32,
    current_status: &str,
    deletion_billing_pending: bool,
    deletion_billing_mode: Option<&str>,
) -> Result<bool, ApiError> {
    let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
    let locked = crate::db::try_advisory_transaction_lock(
        &mut tx,
        crate::db::advisory_lock_namespace::INSTANCE_OPERATION,
        instance_id as i64,
    )
    .await
    .map_err(ApiError::from_sql)?;
    if !locked {
        return Ok(false);
    }
    let active_restore: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM restore_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING') LIMIT 1",
    )
    .bind(instance_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    let active_upload: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM backup_upload_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING') LIMIT 1",
    )
    .bind(instance_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    let active_task: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM instance_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING') LIMIT 1",
    )
    .bind(instance_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    if active_restore.is_some() || active_upload.is_some() || active_task.is_some() {
        return Ok(false);
    }
    let result = sqlx::query(
        "UPDATE instances SET status = 'deleted'::\"InstanceStatus\", deletion_billing_pending = $3, \
         deletion_remote_deleted = false, deletion_billing_mode = $4, deletion_refundable_value = NULL, \
         deletion_fee_waiver = false WHERE id = $1 AND status = $2::\"InstanceStatus\"",
    )
    .bind(instance_id)
    .bind(current_status)
    .bind(deletion_billing_pending)
    .bind(deletion_billing_mode)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    tx.commit().await.map_err(ApiError::from_sql)?;
    Ok(result.rows_affected() == 1)
}

/// getActiveTaskForInstance.
async fn get_active_task_for_instance(
    state: &SharedAppState,
    instance_id: i32,
) -> Result<Option<(i32, String, String)>, ApiError> {
    let row: Option<(i32, String, String)> = sqlx::query_as(
        "SELECT id, task_type::text AS task_type, status::text AS status FROM instance_tasks \
         WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING') ORDER BY created_at DESC LIMIT 1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(row)
}

// ===========================================================================
// GET / — 获取宿主机列表
// ===========================================================================

async fn list_hosts(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let is_admin = user.role == "admin";
    let mine = params.get("mine").map(|s| s.as_str()).unwrap_or("");
    let scope = params.get("scope").map(|s| s.as_str()).unwrap_or("");
    let search = params.get("search").map(|s| s.as_str()).unwrap_or("");
    let filter_user_id = params.get("userId");

    if !is_admin && mine != "true" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let mut query_user_id: Option<i32> = None;
    let mut owner_role: Option<&str> = None;
    let mut include_owner = false;

    if is_admin && scope == "hosted" {
        owner_role = Some("user");
        include_owner = true;
        if let Some(filter) = filter_user_id {
            if let Ok(filter_uid) = filter.trim().parse::<i32>() {
                if filter_uid != user.id {
                    query_user_id = Some(filter_uid);
                }
            }
        }
    } else if is_admin && scope == "official" {
        owner_role = Some("admin");
    } else if is_admin && scope == "mine" {
        query_user_id = Some(user.id);
    } else if !is_admin {
        query_user_id = Some(user.id);
    }

    // parsePagination-like page/pageSize (invalid/0/negative -> defaults).
    let page: i64 = params
        .get("page")
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(1);
    let page_size: i64 = params
        .get("pageSize")
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(20);

    // Conditions are appended in a fixed bind order: search, userId, ownerRole.
    let mut conditions: Vec<String> = Vec::new();
    let mut param_idx = 0usize;
    let mut search_pattern: Option<String> = None;
    if !search.is_empty() {
        param_idx += 1;
        search_pattern = Some(format!("%{}%", search.to_lowercase()));
        conditions.push(format!(
            "(LOWER(h.name) LIKE ${param_idx} OR LOWER(COALESCE(h.location, '')) LIKE ${param_idx} OR LOWER(h.url) LIKE ${param_idx})"
        ));
    }
    if query_user_id.is_some() {
        param_idx += 1;
        conditions.push(format!("h.user_id = ${param_idx}"));
    }
    if owner_role.is_some() {
        param_idx += 1;
        conditions.push(format!("u.role = ${param_idx}"));
    }

    let list_sql = "SELECT h.id, h.name, h.url, h.location, h.country_code, h.architecture, \
        h.status::text AS status, h.nat_public_ip, h.nat_public_ipv6, h.nat_bind_ip, \
        h.nat_bind_ipv6, h.nat_port_start, h.nat_port_end, h.nat_ports_used_count, \
        h.cpu_used, h.memory_used, h.disk_used, h.cpu_allowance_max, h.memory_max, \
        h.instance_type::text AS instance_type, h.storage_size, h.tags, \
        u.id AS owner_id, u.username AS owner_username, u.email AS owner_email, \
        u.avatar_style AS owner_avatar_style, u.avatar_badge_id AS owner_avatar_badge_id \
        FROM hosts h JOIN users u ON u.id = h.user_id";
    let mut sql = String::from(list_sql);
    let mut count_sql = String::from(
        "SELECT COUNT(*) FROM hosts h JOIN users u ON u.id = h.user_id",
    );
    if !conditions.is_empty() {
        let joined = format!(" WHERE {}", conditions.join(" AND "));
        sql.push_str(&joined);
        count_sql.push_str(&joined);
    }
    sql.push_str(&format!(
        " ORDER BY h.name ASC LIMIT {page_size} OFFSET {}",
        (page - 1) * page_size
    ));

    let mut q = sqlx::query_as::<_, HostListRow>(&sql);
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(pattern) = &search_pattern {
        q = q.bind(pattern);
        cq = cq.bind(pattern);
    }
    if let Some(uid) = query_user_id {
        q = q.bind(uid);
        cq = cq.bind(uid);
    }
    if let Some(role) = owner_role {
        q = q.bind(role);
        cq = cq.bind(role);
    }

    let hosts = q.fetch_all(&state.db).await?;
    let total = cq.fetch_one(&state.db).await?;

    // instance counts in one aggregate (TS does per-host queries).
    let ids: Vec<i32> = hosts.iter().map(|h| h.id).collect();
    let mut count_map: HashMap<i32, i64> = HashMap::new();
    if !ids.is_empty() {
        let rows: Vec<(i32, i64)> = sqlx::query_as(
            "SELECT host_id, COUNT(*) FROM instances \
             WHERE host_id = ANY($1) AND status <> 'deleted' GROUP BY host_id",
        )
        .bind(&ids)
        .fetch_all(&state.db)
        .await?;
        for (host_id, count) in rows {
            count_map.insert(host_id, count);
        }
    }

    let items: Vec<Value> = hosts
        .iter()
        .map(|h| {
            let view = host_row_from_list(h);
            let instance_count = count_map.get(&h.id).copied().unwrap_or(0);
            let mut body = json!({
                "id": view.id,
                "name": view.name,
                "url": view.url,
                "status": view.status,
                "maintenance": view.status == "maintenance",
                "location": view.location,
                "countryCode": if view.country_code.is_empty() { "us".to_string() } else { view.country_code.clone() },
                "architecture": if view.architecture.is_empty() { "x86_64".to_string() } else { view.architecture.clone() },
                "tags": parse_string_array(view.tags.as_ref()),
                "resources": {
                    "cpuUsed": view.cpu_used,
                    "memoryUsed": view.memory_used,
                    "diskTotal": view.storage_size.map(|s| s as i64 * 1024).unwrap_or(0),
                    "diskUsed": view.disk_used,
                },
                "cpuAllowanceMax": view.cpu_allowance_max.unwrap_or(0),
                "memoryMax": view.memory_max.unwrap_or(0),
                "instanceType": view.instance_type.clone().unwrap_or_else(|| "container".to_string()),
                "instanceCount": instance_count,
                "natConfig": {
                    "publicIp": view.nat_public_ip,
                    "publicIpv6": view.nat_public_ipv6,
                    "bindIp": view.nat_bind_ip,
                    "bindIpv6": view.nat_bind_ipv6,
                    "portRangeStart": view.nat_port_start,
                    "portRangeEnd": view.nat_port_end,
                    "portsUsedCount": view.nat_ports_used_count.unwrap_or(0),
                },
            });
            if include_owner && h.owner_username.is_some() {
                body["owner"] = json!({
                    "id": h.owner_id,
                    "username": h.owner_username,
                    "email": h.owner_email,
                    "avatarStyle": h.owner_avatar_style,
                    "avatarBadgeId": h.owner_avatar_badge_id,
                });
            }
            body
        })
        .collect();

    let total_pages = if total > 0 { (total + page_size - 1) / page_size } else { 0 };
    Ok(Json(json!({
        "hosts": items,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "totalPages": total_pages,
    })))
}

#[derive(Debug, sqlx::FromRow)]
struct HostListRow {
    pub id: i32,
    pub name: String,
    pub url: String,
    pub location: Option<String>,
    pub country_code: String,
    pub architecture: String,
    pub status: String,
    pub nat_public_ip: Option<String>,
    pub nat_public_ipv6: Option<String>,
    pub nat_bind_ip: Option<String>,
    pub nat_bind_ipv6: Option<String>,
    pub nat_port_start: Option<i32>,
    pub nat_port_end: Option<i32>,
    pub nat_ports_used_count: Option<i32>,
    pub cpu_used: i32,
    pub memory_used: i32,
    pub disk_used: i32,
    pub cpu_allowance_max: Option<i32>,
    pub memory_max: Option<i32>,
    pub instance_type: Option<String>,
    pub storage_size: Option<i32>,
    pub tags: Option<Value>,
    pub owner_id: Option<i32>,
    pub owner_username: Option<String>,
    pub owner_email: Option<String>,
    pub owner_avatar_style: Option<String>,
    pub owner_avatar_badge_id: Option<String>,
}

struct HostListView {
    id: i32,
    name: String,
    url: String,
    location: Option<String>,
    country_code: String,
    architecture: String,
    status: String,
    nat_public_ip: Option<String>,
    nat_public_ipv6: Option<String>,
    nat_bind_ip: Option<String>,
    nat_bind_ipv6: Option<String>,
    nat_port_start: Option<i32>,
    nat_port_end: Option<i32>,
    nat_ports_used_count: Option<i32>,
    cpu_used: i32,
    memory_used: i32,
    disk_used: i32,
    cpu_allowance_max: Option<i32>,
    memory_max: Option<i32>,
    instance_type: Option<String>,
    storage_size: Option<i32>,
    tags: Option<Value>,
}

fn host_row_from_list(row: &HostListRow) -> HostListView {
    HostListView {
        id: row.id,
        name: row.name.clone(),
        url: row.url.clone(),
        location: row.location.clone(),
        country_code: row.country_code.clone(),
        architecture: row.architecture.clone(),
        status: row.status.clone(),
        nat_public_ip: row.nat_public_ip.clone(),
        nat_public_ipv6: row.nat_public_ipv6.clone(),
        nat_bind_ip: row.nat_bind_ip.clone(),
        nat_bind_ipv6: row.nat_bind_ipv6.clone(),
        nat_port_start: row.nat_port_start,
        nat_port_end: row.nat_port_end,
        nat_ports_used_count: row.nat_ports_used_count,
        cpu_used: row.cpu_used,
        memory_used: row.memory_used,
        disk_used: row.disk_used,
        cpu_allowance_max: row.cpu_allowance_max,
        memory_max: row.memory_max,
        instance_type: row.instance_type.clone(),
        storage_size: row.storage_size,
        tags: row.tags.clone(),
    }
}

// ===========================================================================
// GET/PUT /{id}/ops/agent-monitoring
// ===========================================================================

async fn ops_agent_monitoring_get(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let config: Option<(i32, i32, bool, i32, i32, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT host_id, id, enabled, interval_seconds, batch_size, last_requested_at \
         FROM host_agent_audit_configs WHERE host_id = $1",
    )
    .bind(host_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(Json(json!({
        "config": match config {
            Some((host_id, id, enabled, interval_seconds, batch_size, last_requested_at)) => json!({
                "hostId": host_id,
                "id": id,
                "enabled": enabled,
                "intervalSeconds": interval_seconds,
                "batchSize": batch_size,
                "lastRequestedAt": iso_opt(last_requested_at),
                "createdAt": Value::Null,
                "updatedAt": Value::Null,
            }),
            None => json!({
                "hostId": host_id,
                "enabled": false,
                "intervalSeconds": 300,
                "batchSize": 8,
                "lastRequestedAt": Value::Null,
            }),
        }
    })))
}

async fn ops_agent_monitoring_put(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    // Math.max(60, Math.min(86400, Number(...) || 300))
    let interval_seconds = body
        .get("intervalSeconds")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        .max(60.0)
        .min(86400.0) as i64;
    let interval_seconds = if body.get("intervalSeconds").and_then(Value::as_f64).unwrap_or(0.0) == 0.0 {
        300
    } else {
        interval_seconds
    };
    let batch_size_raw = body.get("batchSize").and_then(Value::as_f64).unwrap_or(0.0);
    let batch_size = if batch_size_raw == 0.0 {
        8i64
    } else {
        batch_size_raw.max(1.0).min(32.0) as i64
    };
    let enabled = body.get("enabled") == Some(&Value::Bool(true));

    let row: (i32, i32, bool, i64, i64, Option<DateTime<Utc>>, DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO host_agent_audit_configs (host_id, enabled, interval_seconds, batch_size, updated_by_id) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (host_id) DO UPDATE SET enabled = $2, interval_seconds = $3, batch_size = $4, updated_by_id = $5 \
         RETURNING host_id, id, enabled, interval_seconds, batch_size, last_requested_at, created_at, updated_at",
    )
    .bind(host_id)
    .bind(enabled)
    .bind(interval_seconds as i32)
    .bind(batch_size as i32)
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    create_log(
        &state,
        user.id,
        "host",
        "host.ops.agent_monitoring.update",
        &format!(
            "Updated Agent monitoring on host \"{}\": enabled={}, interval={}s, batch={}",
            host.name, row.2, interval_seconds, batch_size
        ),
        "success",
    )
    .await;

    Ok(Json(json!({
        "config": {
            "hostId": row.0,
            "id": row.1,
            "enabled": row.2,
            "intervalSeconds": row.3,
            "batchSize": row.4,
            "lastRequestedAt": iso_opt(row.5),
            "createdAt": iso(row.6),
            "updatedAt": iso(row.7),
        }
    })))
}

// ===========================================================================
// GET/POST /{id}/ops/network-policies, PATCH/DELETE /{id}/ops/network-policies/{policyId}
// ===========================================================================

async fn ops_policies_list(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let policies: Vec<(i32, i32, i32, String, String, String, Value, Value, bool, i32, String, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, host_id, created_by_id, name, policy_type, target_mode, target_instance_ids, config, \
         enabled, revision, apply_status, apply_error, applied_at, created_at, updated_at \
         FROM host_network_policies WHERE host_id = $1 ORDER BY updated_at DESC",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    let instances: Vec<(i32, String, String, String)> = sqlx::query_as(
        "SELECT id, name, incus_id, status::text AS status FROM instances \
         WHERE host_id = $1 AND status <> 'deleted' ORDER BY name ASC",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    let policies_json: Vec<Value> = policies
        .iter()
        .map(|(id, host_id, created_by_id, name, policy_type, target_mode, target_ids, config, enabled, revision, apply_status, apply_error, applied_at, created_at, updated_at)| {
            json!({
                "id": id, "hostId": host_id, "createdById": created_by_id, "name": name,
                "policyType": policy_type, "targetMode": target_mode,
                "targetInstanceIds": target_ids, "config": config, "enabled": enabled,
                "revision": revision, "applyStatus": apply_status, "applyError": apply_error,
                "appliedAt": iso_opt(*applied_at), "createdAt": iso(*created_at), "updatedAt": iso(*updated_at),
            })
        })
        .collect();
    let instances_json: Vec<Value> = instances
        .iter()
        .map(|(id, name, incus_id, status)| json!({ "id": id, "name": name, "incusId": incus_id, "status": status }))
        .collect();
    Ok(Json(json!({ "policies": policies_json, "instances": instances_json })))
}

async fn ops_policies_create(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let name: String = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .chars()
        .take(100)
        .collect();
    if name.is_empty() {
        return Ok(bare_bad_request("请填写策略名称"));
    }
    let normalized = match normalize_network_policy_input(
        body.get("policyType"),
        body.get("targetMode"),
        body.get("targetInstanceIds"),
        body.get("config"),
    ) {
        Ok(v) => v,
        Err(message) => return Ok(bare_bad_request(message)),
    };
    let target_ids = json!(normalized.target_instance_ids);
    let valid_target_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instances WHERE host_id = $1 AND id = ANY($2) AND status <> 'deleted'",
    )
    .bind(host_id)
    .bind(&normalized.target_instance_ids)
    .fetch_one(&state.db)
    .await?;
    if normalized.target_mode == "selected"
        && valid_target_count.0 != normalized.target_instance_ids.len() as i64
    {
        return Ok(bare_bad_request("部分目标实例不属于当前节点"));
    }
    let enabled = body.get("enabled") == Some(&Value::Bool(true));
    let policy: (i32, i32, i32, String, String, String, Value, Value, bool, i32, String, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO host_network_policies \
         (host_id, created_by_id, name, policy_type, target_mode, target_instance_ids, config, enabled, apply_status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING id, host_id, created_by_id, name, policy_type, target_mode, target_instance_ids, config, \
                   enabled, revision, apply_status, apply_error, applied_at, created_at, updated_at",
    )
    .bind(host_id)
    .bind(user.id)
    .bind(&name)
    .bind(&normalized.policy_type)
    .bind(&normalized.target_mode)
    .bind(&target_ids)
    .bind(&normalized.config)
    .bind(enabled)
    .bind(if enabled { "pending" } else { "disabled" })
    .fetch_one(&state.db)
    .await?;

    create_log(
        &state,
        user.id,
        "host",
        "host.ops.network_policy.create",
        &format!(
            "Created {} policy \"{}\" on host \"{}\"",
            normalized.policy_type, name, host.name
        ),
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "policy": policy_row_json(&policy) })),
    )
        .into_response())
}

#[allow(clippy::type_complexity)]
fn policy_row_json(
    row: &(i32, i32, i32, String, String, String, Value, Value, bool, i32, String, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>, DateTime<Utc>),
) -> Value {
    json!({
        "id": row.0, "hostId": row.1, "createdById": row.2, "name": row.3,
        "policyType": row.4, "targetMode": row.5, "targetInstanceIds": row.6,
        "config": row.7, "enabled": row.8, "revision": row.9,
        "applyStatus": row.10, "applyError": row.11, "appliedAt": iso_opt(row.12),
        "createdAt": iso(row.13), "updatedAt": iso(row.14),
    })
}

/// Display for ApiError (message text) so `format!("{err}")` matches the TS
/// `err.message` usage in logs and result strings.
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

/// ApiError variant for TS `reply.code(400).send({ error })` bodies.
fn bare_err(message: impl Into<String>) -> ApiError {
    ApiError::bare(StatusCode::BAD_REQUEST, message)
}

fn decimal_to_f64(value: Decimal) -> f64 {
    use rust_decimal::prelude::ToPrimitive;
    value.to_f64().unwrap_or(0.0)
}

/// `?` conversions inside handlers returning Result<_, ApiError>.
impl From<IncusError> for ApiError {
    fn from(err: IncusError) -> Self {
        ApiError::internal(incus_error_message(&err))
    }
}

/// Bare `{ error }` 400 used by TS handlers that send raw error objects.
fn bare_bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": message.into() })),
    )
        .into_response()
}

async fn ops_policy_update(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, policy_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let policy_id = js_number_id(&policy_id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let existing: Option<(i32, String, String, Value, Value, Value, bool)> = sqlx::query_as(
        "SELECT id, name, policy_type, target_mode, target_instance_ids, config, enabled \
         FROM host_network_policies WHERE id = $1 AND host_id = $2",
    )
    .bind(policy_id)
    .bind(host_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(existing) = existing else {
        return Err(ApiError::with_message(
            "POLICY_NOT_FOUND",
            StatusCode::NOT_FOUND,
            "网络策略不存在",
        ));
    };
    let merged_target_mode = body
        .get("targetMode")
        .cloned()
        .unwrap_or_else(|| json!(existing.3));
    let merged_target_ids = body
        .get("targetInstanceIds")
        .cloned()
        .unwrap_or_else(|| existing.4.clone());
    let merged_config = body.get("config").cloned().unwrap_or_else(|| existing.5.clone());
    let normalized = match normalize_network_policy_input(
        Some(&json!(existing.2)),
        Some(&merged_target_mode),
        Some(&merged_target_ids),
        Some(&merged_config),
    ) {
        Ok(v) => v,
        Err(message) => return Err(ApiError::with_message("POLICY_INVALID", StatusCode::BAD_REQUEST, message)),
    };
    let name: String = body
        .get("name")
        .and_then(Value::as_str)
        .map(|n| n.trim().chars().take(100).collect::<String>())
        .filter(|n| !n.is_empty())
        .unwrap_or(existing.1.clone());
    let enabled = match body.get("enabled") {
        Some(v) => v.as_bool().unwrap_or(false),
        None => existing.6,
    };
    let row: (i32, i32, i32, String, String, String, Value, Value, bool, i32, String, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "UPDATE host_network_policies SET name = $2, target_mode = $3, target_instance_ids = $4, \
         config = $5, enabled = $6, revision = revision + 1, apply_status = $7, apply_error = NULL \
         WHERE id = $1 \
         RETURNING id, host_id, created_by_id, name, policy_type, target_mode, target_instance_ids, config, \
                   enabled, revision, apply_status, apply_error, applied_at, created_at, updated_at",
    )
    .bind(policy_id)
    .bind(&name)
    .bind(&normalized.target_mode)
    .bind(json!(normalized.target_instance_ids))
    .bind(&normalized.config)
    .bind(enabled)
    .bind(if enabled { "pending" } else { "disabled" })
    .fetch_one(&state.db)
    .await?;

    create_log(
        &state,
        user.id,
        "host",
        "host.ops.network_policy.update",
        &format!(
            "Updated network policy \"{}\" on host \"{}\"",
            row.3, host.name
        ),
        "success",
    )
    .await;
    Ok(Json(json!({ "policy": policy_row_json(&row) })))
}

async fn ops_policy_delete(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, policy_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let policy_id = js_number_id(&policy_id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT name FROM host_network_policies WHERE id = $1 AND host_id = $2")
            .bind(policy_id)
            .bind(host_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((name,)) = existing else {
        return Err(ApiError::with_message(
            "POLICY_NOT_FOUND",
            StatusCode::NOT_FOUND,
            "网络策略不存在",
        ));
    };
    sqlx::query("DELETE FROM host_network_policies WHERE id = $1")
        .bind(policy_id)
        .execute(&state.db)
        .await?;
    create_log(
        &state,
        user.id,
        "host",
        "host.ops.network_policy.delete",
        &format!("Deleted network policy \"{name}\" on host \"{}\"", host.name),
        "warning",
    )
    .await;
    Ok(Json(json!({ "success": true })))
}

// ===========================================================================
// Shared db helpers for the remaining endpoints
// ===========================================================================

/// js `Math.min(Math.max(Number(x||d), lo), hi)` for query params.
fn clamp_int_query(raw: Option<&String>, default_value: i64, min: i64, max: i64) -> i64 {
    let parsed = raw
        .and_then(|v| v.trim().parse::<f64>().ok())
        .unwrap_or(f64::NAN);
    if parsed.is_nan() {
        return default_value;
    }
    parsed.max(min as f64).min(max as f64) as i64
}

/// db.parsePagination(query, { defaultPageSize, maxPageSize }).
fn parse_pagination(params: &HashMap<String, String>, default_page_size: i64, max_page_size: Option<i64>) -> (i64, i64) {
    let page = params
        .get("page")
        .and_then(|v| js_parse_int(v))
        .filter(|v| *v >= 1)
        .unwrap_or(1) as i64;
    let mut page_size: i64 = params
        .get("pageSize")
        .and_then(|v| js_parse_int(v))
        .filter(|v| *v >= 1)
        .map(|v| v as i64)
        .unwrap_or(default_page_size);
    if let Some(max) = max_page_size {
        if page_size > max {
            page_size = max;
        }
    }
    (page, page_size)
}

/// db.suspendInstance -> suspendInstanceManually (instance-operation lock).
async fn suspend_instance_manually(
    state: &SharedAppState,
    instance_id: i32,
    operator_id: i32,
    reason: &str,
) -> Result<(), ApiError> {
    let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
    crate::db::advisory_transaction_lock(
        &mut tx,
        crate::db::advisory_lock_namespace::INSTANCE_OPERATION,
        instance_id as i64,
    )
    .await
    .map_err(ApiError::from_sql)?;
    let current: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT status::text AS status, suspend_reason FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    if let Some((status, suspend_reason)) = current {
        if status == "deleted" && suspend_reason.as_deref() == Some("expired") {
            return Err(ApiError::internal("实例正在删除，无法封停"));
        }
    }
    sqlx::query(
        "UPDATE instances SET status = 'suspended'::\"InstanceStatus\", suspended_at = now(), \
         suspended_by = $2, suspend_reason = $3, version = version + 1 WHERE id = $1",
    )
    .bind(instance_id)
    .bind(operator_id)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    tx.commit().await.map_err(ApiError::from_sql)?;
    Ok(())
}

/// db.unsuspendInstance.
async fn unsuspend_instance(state: &SharedAppState, instance_id: i32) -> Result<(), ApiError> {
    let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
    crate::db::advisory_transaction_lock(
        &mut tx,
        crate::db::advisory_lock_namespace::INSTANCE_OPERATION,
        instance_id as i64,
    )
    .await
    .map_err(ApiError::from_sql)?;
    let current: Option<(String,)> =
        sqlx::query_as("SELECT status::text AS status FROM instances WHERE id = $1")
            .bind(instance_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    match current {
        Some((status,)) if status == "suspended" => {}
        _ => return Err(ApiError::internal("实例未被封停或正在删除")),
    }
    sqlx::query(
        "UPDATE instances SET status = 'stopped'::\"InstanceStatus\", suspended_at = NULL, \
         suspended_by = NULL, suspend_reason = NULL, version = version + 1 WHERE id = $1",
    )
    .bind(instance_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    tx.commit().await.map_err(ApiError::from_sql)?;
    Ok(())
}

/// db.getSSHKeysByUserId (first public_key wins, ordered like the TS findMany).
async fn get_ssh_keys_by_user_id(
    state: &SharedAppState,
    user_id: i32,
) -> Result<Vec<(i32, String, String)>, ApiError> {
    let rows: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT id, name, fingerprint FROM ssh_keys WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

/// db.getEnabledCommandsByDistro.
async fn get_enabled_commands_by_distro(
    state: &SharedAppState,
    user_id: i32,
    distro: &str,
) -> Result<Vec<(i32, String, String, Value, Option<String>)>, ApiError> {
    let rows: Vec<(i32, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, command, distros, description FROM custom_init_commands \
         WHERE user_id = $1 AND enabled = true ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for (id, name, command, distros_raw, description) in rows {
        let distros: Vec<String> = serde_json::from_str(&distros_raw).unwrap_or_default();
        if distros.iter().any(|d| d == "all" || d == distro) {
            out.push((id, name, command, json!(distros), description));
        }
    }
    Ok(out)
}

/// db.validateCommandsOwnership.
async fn validate_commands_ownership(
    state: &SharedAppState,
    command_ids: &[i64],
    user_id: i32,
) -> Result<bool, ApiError> {
    if command_ids.is_empty() {
        return Ok(true);
    }
    let ids: Vec<i32> = command_ids.iter().map(|v| *v as i32).collect();
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM custom_init_commands WHERE id = ANY($1) AND user_id = $2 AND enabled = true",
    )
    .bind(&ids)
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(count == ids.len() as i64)
}

/// db.getSSHKeyById (owner check included in the caller).
async fn get_ssh_key_by_id(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<(i32, i32)>, ApiError> {
    let row: Option<(i32, i32)> =
        sqlx::query_as("SELECT id, user_id FROM ssh_keys WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    Ok(row)
}

/// db.getHostPackages.
async fn get_host_packages(state: &SharedAppState, host_id: i32) -> Result<Vec<i32>, ApiError> {
    let rows: Vec<(i32,)> =
        sqlx::query_as("SELECT package_id FROM package_hosts WHERE host_id = $1")
            .bind(host_id)
            .fetch_all(&state.db)
            .await?;
    Ok(rows.into_iter().map(|(p,)| p).collect())
}

/// db.getPackageHostIds.
async fn get_package_host_ids(
    state: &SharedAppState,
    package_id: i32,
) -> Result<Vec<i32>, ApiError> {
    let rows: Vec<(i32,)> =
        sqlx::query_as("SELECT host_id FROM package_hosts WHERE package_id = $1")
            .bind(package_id)
            .fetch_all(&state.db)
            .await?;
    Ok(rows.into_iter().map(|(h,)| h).collect())
}

/// db.getIncompatiblePackagesByHostTypeChange.
async fn get_incompatible_packages_by_host_type_change(
    state: &SharedAppState,
    host_id: i32,
    new_instance_type: &str,
) -> Result<Vec<Value>, ApiError> {
    if new_instance_type == "both" {
        return Ok(Vec::new());
    }
    let rows: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT p.id, p.name, p.instance_type::text AS instance_type \
         FROM package_hosts ph JOIN packages p ON p.id = ph.package_id WHERE ph.host_id = $1",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(_, _, instance_type)| instance_type != new_instance_type && instance_type != "both")
        .map(|(id, name, instance_type)| json!({ "id": id, "name": name, "instanceType": instance_type }))
        .collect())
}

/// db.getProxySitesByInstanceId.
async fn get_proxy_sites_by_instance_id(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    instance_id: i32,
) -> Result<Vec<(i32, String, i32, bool, String, bool, Option<String>)>, ApiError> {
    let rows: Vec<(i32, String, i32, bool, String, bool, Option<String>)> = sqlx::query_as(
        "SELECT id, domain, target_port, https_enabled, status::text AS status, enabled, error \
         FROM proxy_sites WHERE instance_id = $1",
    )
    .bind(instance_id)
    .fetch_all(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(rows)
}

/// db.deleteProxySite.
async fn delete_proxy_site(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    id: i32,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM proxy_sites WHERE id = $1")
        .bind(id)
        .execute(exec)
        .await
        .map_err(ApiError::from_sql)?;
    Ok(())
}

/// db.getProxySitesByHostId (with instance info joined like the TS include).
async fn get_proxy_sites_by_host_id(
    state: &SharedAppState,
    host_id: i32,
) -> Result<Vec<Value>, ApiError> {
    let rows: Vec<(i32, String, i32, bool, String, bool, Option<String>, Option<DateTime<Utc>>, Option<i32>, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT ps.id, ps.domain, ps.target_port, ps.https_enabled, ps.status::text AS status, \
         ps.enabled, ps.error, ps.created_at, i.id, i.name, i.ipv4, i.status::text AS instance_status \
         FROM proxy_sites ps \
         LEFT JOIN instances i ON i.id = ps.instance_id \
         WHERE ps.host_id = $1 ORDER BY ps.created_at DESC",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, domain, target_port, https_enabled, status, enabled, error, created_at, instance_id, instance_name, instance_ipv4, instance_status)| {
            json!({
                "id": id,
                "domain": domain,
                "targetPort": target_port,
                "httpsEnabled": https_enabled,
                "status": status,
                "enabled": enabled,
                "error": error,
                "createdAt": iso_opt(created_at),
                "instance": instance_id.map(|iid| json!({
                    "id": iid,
                    "name": instance_name,
                    "ipv4": instance_ipv4,
                    "status": instance_status,
                })),
            })
        })
        .collect())
}

/// db.getProxySiteCountByHost.
async fn get_proxy_site_count_by_host(state: &SharedAppState, host_id: i32) -> Result<i64, ApiError> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxy_sites WHERE host_id = $1")
        .bind(host_id)
        .fetch_one(&state.db)
        .await?;
    Ok(count)
}

/// db.getPortMappings.
async fn get_port_mappings(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    instance_id: i32,
) -> Result<Vec<(i32, String, i32)>, ApiError> {
    let rows: Vec<(i32, String, i32)> = sqlx::query_as(
        "SELECT id, protocol::text AS protocol, public_port FROM port_mappings WHERE instance_id = $1",
    )
    .bind(instance_id)
    .fetch_all(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(rows)
}

async fn delete_port_mapping(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    id: i32,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM port_mappings WHERE id = $1")
        .bind(id)
        .execute(exec)
        .await
        .map_err(ApiError::from_sql)?;
    Ok(())
}

/// db.getSnapshotsByInstanceId.
async fn get_snapshots_by_instance_id(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    instance_id: i32,
) -> Result<Vec<(i32, String)>, ApiError> {
    let rows: Vec<(i32, String)> = sqlx::query_as(
        "SELECT id, incus_name FROM snapshots WHERE instance_id = $1 ORDER BY created_at DESC",
    )
    .bind(instance_id)
    .fetch_all(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(rows)
}

async fn delete_snapshot_record(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    id: i32,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM snapshots WHERE id = $1")
        .bind(id)
        .execute(exec)
        .await
        .map_err(ApiError::from_sql)?;
    Ok(())
}

/// db.getBackupsByInstanceId.
async fn get_backups_by_instance_id(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    instance_id: i32,
) -> Result<Vec<(i32, String)>, ApiError> {
    let rows: Vec<(i32, String)> = sqlx::query_as(
        "SELECT id, incus_name FROM backups WHERE instance_id = $1 ORDER BY created_at DESC",
    )
    .bind(instance_id)
    .fetch_all(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(rows)
}

async fn delete_backup_record(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    id: i32,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM backups WHERE id = $1")
        .bind(id)
        .execute(exec)
        .await
        .map_err(ApiError::from_sql)?;
    Ok(())
}

/// db.reassignInstanceBillingRecords.
async fn reassign_instance_billing_records(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    source_instance_id: i32,
    target_instance_id: i32,
) -> Result<i64, ApiError> {
    if source_instance_id == target_instance_id {
        return Ok(0);
    }
    let result = sqlx::query(
        "UPDATE instance_billing_records SET instance_id = $2 WHERE instance_id = $1",
    )
    .bind(source_instance_id)
    .bind(target_instance_id)
    .execute(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(result.rows_affected() as i64)
}

/// db.getInstanceAffBinding -> (affCodeId, supersedesOfficialCoupon).
async fn get_instance_aff_binding(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    instance_id: i32,
) -> Result<Option<(i32, bool)>, ApiError> {
    let row: Option<(i32, bool)> = sqlx::query_as(
        "SELECT ab.aff_code_id, ab.supersedes_official_coupon FROM aff_bindings ab \
         WHERE ab.instance_id = $1",
    )
    .bind(instance_id)
    .fetch_optional(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(row)
}

/// db.createAffBinding.
async fn create_aff_binding(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    instance_id: i32,
    aff_code_id: i32,
    supersedes_official_coupon: bool,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO aff_bindings (instance_id, aff_code_id, supersedes_official_coupon) \
         VALUES ($1, $2, $3)",
    )
    .bind(instance_id)
    .bind(aff_code_id)
    .bind(supersedes_official_coupon)
    .execute(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(())
}

/// lib/traffic-multiplier.ts resolveInstanceTrafficLimitForHost (bigint bytes).
async fn resolve_instance_traffic_limit_for_host(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    package_id: Option<i32>,
    host_id: i32,
    base_traffic_limit: Option<i64>,
) -> Result<Option<i64>, ApiError> {
    let Some(package_id) = package_id else {
        return Ok(base_traffic_limit);
    };
    let binding: Option<(Option<Decimal>,)> = sqlx::query_as(
        "SELECT traffic_multiplier FROM package_hosts WHERE package_id = $1 AND host_id = $2",
    )
    .bind(package_id)
    .bind(host_id)
    .fetch_optional(exec)
    .await
    .map_err(ApiError::from_sql)?;
    let multiplier: f64 = match binding.and_then(|(m,)| m) {
        None => 1.0,
        Some(m) => {
            let v = decimal_to_f64(m);
            if !v.is_finite() || !(0.001..=100.0).contains(&v) {
                return Err(ApiError::internal(
                    "Traffic multiplier must be at least 0.001 and no more than 100",
                ));
            }
            (v * 1000.0).round() / 1000.0
        }
    };
    let scaled = match base_traffic_limit {
        None => None,
        Some(limit) => Some((limit as f64 * multiplier * 1000.0).round() as i64 / 1000),
    };
    Ok(scaled)
}

/// db.getUserQuota (host_limit/host_used only, null when absent).
async fn get_user_quota(
    state: &SharedAppState,
    user_id: i32,
) -> Result<Option<(i64, i64)>, ApiError> {
    let row: Option<(i32, i32)> = sqlx::query_as(
        "SELECT host_limit, host_used FROM user_quotas WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|(l, u)| (l as i64, u as i64)))
}

/// getSystemConfigBoolean (local mirror; hosting keys are not sensitive).
async fn get_system_config_boolean(
    state: &SharedAppState,
    key: &str,
    default_value: bool,
) -> Result<bool, ApiError> {
    let value: Option<(String,)> =
        sqlx::query_as("SELECT value FROM system_configs WHERE key = $1")
            .bind(key)
            .fetch_optional(&state.db)
            .await?;
    Ok(match value {
        None => default_value,
        Some((v,)) => v == "true" || v == "1",
    })
}

/// checkHostingAccess (lib/hosting-access.ts).
async fn check_hosting_access(
    state: &SharedAppState,
    user_id: i32,
) -> Result<Result<(), String>, ApiError> {
    let user: Option<(String, bool)> = sqlx::query_as(
        "SELECT role::text AS role, has_created_host_before FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((role, has_created_host_before)) = user else {
        return Ok(Err("用户不存在".to_string()));
    };
    if role == "admin" {
        return Ok(Ok(()));
    }
    let feature_enabled = get_system_config_boolean(&state.clone(), "hosting_feature_enabled", true).await?;
    let (instance_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM instances WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    let hidden_by_system_setting = !feature_enabled && !has_created_host_before;
    if hidden_by_system_setting {
        return Ok(Err("托管功能暂未向未创建过节点的用户开放".to_string()));
    }
    if instance_count >= 1 {
        return Ok(Ok(()));
    }
    Ok(Err(format!(
        "不满足托管准入条件：需要至少拥有过 1 台实例（当前 {instance_count} 台）"
    )))
}

// ===========================================================================
// images db helpers (port of db/images.ts)
// ===========================================================================

const LOW_MEMORY_ALLOWED_DISTROS: &[&str] = &["alpine", "debian"];
const LOW_MEMORY_THRESHOLD: i64 = 128;

#[derive(Debug, Clone, sqlx::FromRow)]
struct SystemImageRow {
    pub id: i32,
    pub name: String,
    #[sqlx(rename = "remote_alias")]
    pub remote_alias: String,
    pub os_type: String,
    pub architecture: String,
    #[sqlx(rename = "instance_type")]
    pub instance_type: String,
    pub icon: String,
    pub sort_order: i32,
    pub hidden: bool,
}

fn image_instance_type(image: &SystemImageRow) -> &'static str {
    match image.instance_type.as_str() {
        "container" => "container",
        "vm" => "vm",
        _ => "both",
    }
}

fn host_instance_type(instance_type: Option<&str>) -> &'static str {
    match instance_type {
        Some("container") => "container",
        Some("vm") => "vm",
        _ => "container",
    }
}

fn is_image_compatible_with_target_type(image_type: &str, target_type: &str) -> bool {
    if target_type == "both" {
        return true;
    }
    image_type == "both" || image_type == target_type
}

fn is_image_compatible_with_low_memory(image: &SystemImageRow, memory: Option<i64>) -> bool {
    let Some(memory) = memory else {
        return true;
    };
    if memory > LOW_MEMORY_THRESHOLD {
        return true;
    }
    LOW_MEMORY_ALLOWED_DISTROS.contains(&image.icon.to_lowercase().as_str())
}

async fn get_system_image_by_alias(
    state: &SharedAppState,
    remote_alias: &str,
) -> Result<Option<SystemImageRow>, ApiError> {
    let row = sqlx::query_as::<_, SystemImageRow>(
        "SELECT id, name, remote_alias, os_type, architecture, instance_type::text AS instance_type, \
         icon, sort_order, hidden FROM system_images WHERE remote_alias = $1",
    )
    .bind(remote_alias)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// db.isValidSystemImage.
async fn is_valid_system_image(state: &SharedAppState, remote_alias: &str) -> Result<bool, ApiError> {
    Ok(get_system_image_by_alias(state, remote_alias)
        .await?
        .map(|i| !i.hidden)
        .unwrap_or(false))
}

/// db.isImageCompatibleWithInstanceType.
async fn is_image_compatible_with_instance_type(
    state: &SharedAppState,
    remote_alias: &str,
    instance_type: &str,
) -> Result<bool, ApiError> {
    let Some(image) = get_system_image_by_alias(state, remote_alias).await? else {
        return Ok(false);
    };
    if image.hidden {
        return Ok(false);
    }
    Ok(is_image_compatible_with_target_type(
        image_instance_type(&image),
        instance_type,
    ))
}

/// db.isImageCompatibleWithMemory.
async fn is_image_compatible_with_memory(
    state: &SharedAppState,
    remote_alias: &str,
    memory: i64,
) -> Result<bool, ApiError> {
    let Some(image) = get_system_image_by_alias(state, remote_alias).await? else {
        return Ok(false);
    };
    if image.hidden {
        return Ok(false);
    }
    Ok(is_image_compatible_with_low_memory(&image, Some(memory)))
}

/// db.getHostImageSelectionState.
async fn get_host_image_selection_state(
    state: &SharedAppState,
    host_id: i32,
) -> Result<Option<Value>, ApiError> {
    let host: Option<(i32, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, architecture, instance_type::text AS instance_type \
         FROM hosts WHERE id = $1",
    )
    .bind(host_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((id, name, architecture_raw, instance_type_raw)) = host else {
        return Ok(None);
    };
    let host_architecture = normalize_architecture(Some(&architecture_raw));
    let host_type = host_instance_type(instance_type_raw.as_deref());
    let raw_allowed: Vec<i32> = sqlx::query_scalar(
        "SELECT image_id FROM host_allowed_images WHERE host_id = $1 ORDER BY id ASC",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    let images: Vec<SystemImageRow> = sqlx::query_as(
        "SELECT id, name, remote_alias, os_type, architecture, instance_type::text AS instance_type, \
         icon, sort_order, hidden FROM system_images \
         WHERE hidden = false AND architecture = $1 ORDER BY sort_order ASC, id ASC",
    )
    .bind(host_architecture)
    .fetch_all(&state.db)
    .await?;
    let compatible: Vec<&SystemImageRow> = images
        .iter()
        .filter(|i| is_image_compatible_with_target_type(image_instance_type(i), host_type))
        .collect();
    let compatible_ids: std::collections::HashSet<i32> =
        compatible.iter().map(|i| i.id).collect();
    let image_json: Vec<Value> = compatible
        .iter()
        .map(|i| {
            json!({
                "id": i.id, "name": i.name, "remoteAlias": i.remote_alias,
                "osType": i.os_type, "architecture": i.architecture,
                "instanceType": i.instance_type, "icon": i.icon,
                "sortOrder": i.sort_order, "hidden": i.hidden,
            })
        })
        .collect();
    Ok(Some(json!({
        "hostId": id,
        "hostName": name,
        "architecture": host_architecture,
        "instanceType": host_type,
        "useDefault": raw_allowed.is_empty(),
        "allowedImageIds": raw_allowed
            .into_iter()
            .filter(|image_id| compatible_ids.contains(image_id))
            .collect::<Vec<i32>>(),
        "images": image_json,
    })))
}

/// db.saveHostAllowedImages -> selection state or Err(INVALID_IMAGE_FOR_HOST:id).
async fn save_host_allowed_images(
    state: &SharedAppState,
    host_id: i32,
    use_default: bool,
    image_ids: &[i64],
) -> Result<Option<Value>, ApiError> {
    let selection_state = get_host_image_selection_state(state, host_id).await?;
    let Some(selection) = selection_state else {
        return Ok(None);
    };
    let allowed: std::collections::HashSet<i32> = selection["images"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v["id"].as_i64().map(|v| v as i32)).collect())
        .unwrap_or_default();
    for image_id in image_ids {
        if !allowed.contains(&(*image_id as i32)) {
            return Err(ApiError::internal(format!(
                "INVALID_IMAGE_FOR_HOST:{image_id}"
            )));
        }
    }
    let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
    sqlx::query("DELETE FROM host_allowed_images WHERE host_id = $1")
        .bind(host_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
    if !use_default && !image_ids.is_empty() {
        let ids: Vec<i32> = image_ids.iter().map(|v| *v as i32).collect();
        sqlx::query(
            "INSERT INTO host_allowed_images (host_id, image_id) \
             SELECT $1, x FROM unnest($2::int[]) AS x WHERE NOT EXISTS (\
             SELECT 1 FROM host_allowed_images h WHERE h.host_id = $1 AND h.image_id = x)",
        )
        .bind(host_id)
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
    }
    tx.commit().await.map_err(ApiError::from_sql)?;
    get_host_image_selection_state(state, host_id).await
}

/// db.getSystemImageAvailabilityForHost -> Ok(json) or Err(reason).
async fn get_system_image_availability_for_host(
    state: &SharedAppState,
    remote_alias: &str,
    host_id: i32,
    options_instance_type: Option<&str>,
    memory: Option<i64>,
) -> Result<Result<Value, String>, ApiError> {
    let host: Option<(i32, String, Option<String>)> = sqlx::query_as(
        "SELECT id, architecture, instance_type::text AS instance_type FROM hosts WHERE id = $1",
    )
    .bind(host_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((id, architecture_raw, host_type_raw)) = host else {
        return Ok(Err("host_not_found".to_string()));
    };
    let Some(image) = get_system_image_by_alias(state, remote_alias).await? else {
        return Ok(Err("image_not_found".to_string()));
    };
    if image.hidden {
        return Ok(Err("image_not_found".to_string()));
    }
    let host_architecture = normalize_architecture(Some(&architecture_raw));
    let image_architecture = normalize_architecture(Some(&image.architecture));
    if image_architecture != host_architecture {
        return Ok(Err("architecture_mismatch".to_string()));
    }
    let host_type = host_instance_type(host_type_raw.as_deref());
    let image_type = image_instance_type(&image);
    if !is_image_compatible_with_target_type(image_type, host_type) {
        return Ok(Err("host_instance_type_mismatch".to_string()));
    }
    if let Some(target) = options_instance_type {
        if !is_image_compatible_with_target_type(image_type, target) {
            return Ok(Err("instance_type_mismatch".to_string()));
        }
    }
    if !is_image_compatible_with_low_memory(&image, memory) {
        return Ok(Err("memory_incompatible".to_string()));
    }
    let allowed: Vec<i32> = sqlx::query_scalar(
        "SELECT image_id FROM host_allowed_images WHERE host_id = $1",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    if !allowed.is_empty() && !allowed.contains(&image.id) {
        return Ok(Err("not_allowed".to_string()));
    }
    Ok(Ok(json!({
        "hostId": id,
        "imageId": image.id,
        "architecture": host_architecture,
        "useDefault": allowed.is_empty(),
    })))
}

// ===========================================================================
// storage pools db helpers (port of db/storage-pools.ts)
// ===========================================================================

/// db.getStoragePoolsByHostId / getSystemDiskPoolsByHostId.
async fn get_storage_pools(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    host_id: i32,
    instance_data_only: bool,
) -> Result<Vec<(i32, String, String, String, Option<String>, Option<Value>)>, ApiError> {
    let filter = if instance_data_only {
        " AND purpose = 'instance_data'::\"StoragePurpose\""
    } else {
        ""
    };
    let rows: Vec<(i32, String, String, String, Option<String>, Option<Value>)> = sqlx::query_as(
        &format!(
            "SELECT id, name, driver, purpose::text AS purpose, description, config \
             FROM storage_pools WHERE host_id = $1{filter} ORDER BY created_at ASC"
        ),
    )
    .bind(host_id)
    .fetch_all(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(rows)
}

/// db.createStoragePool record.
#[allow(clippy::too_many_arguments)]
async fn create_storage_pool_record(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    host_id: i32,
    name: &str,
    driver: &str,
    purpose: &str,
    description: Option<&str>,
    config: &Value,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO storage_pools (host_id, name, driver, purpose, description, config) \
         VALUES ($1, $2, $3, $4::\"StoragePurpose\", $5, $6)",
    )
    .bind(host_id)
    .bind(name)
    .bind(driver)
    .bind(purpose)
    .bind(description)
    .bind(config)
    .execute(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(())
}

/// db.deleteStoragePool.
async fn delete_storage_pool_records(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    host_id: i32,
    name: &str,
) -> Result<u64, ApiError> {
    let result = sqlx::query("DELETE FROM storage_pools WHERE host_id = $1 AND name = $2")
        .bind(host_id)
        .bind(name)
        .execute(exec)
        .await
        .map_err(ApiError::from_sql)?;
    Ok(result.rows_affected())
}

/// db.updateStoragePool (description/purpose subset).
async fn update_storage_pool_record(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    host_id: i32,
    name: &str,
    description: Option<Option<String>>,
    purpose: Option<&str>,
) -> Result<(), ApiError> {
    let mut sets: Vec<String> = Vec::new();
    let mut idx = 3usize;
    if description.is_some() {
        sets.push(format!(" description = ${idx}"));
        idx += 1;
    }
    if purpose.is_some() {
        sets.push(format!(" purpose = ${idx}::\"StoragePurpose\""));
    }
    if sets.is_empty() {
        return Ok(());
    }
    let sql = format!(
        "UPDATE storage_pools SET{} WHERE host_id = $1 AND name = $2",
        sets.join(",")
    );
    let mut q = sqlx::query(&sql).bind(host_id).bind(name);
    if let Some(desc) = description {
        q = q.bind(desc);
    }
    if let Some(purpose) = purpose {
        q = q.bind(purpose);
    }
    q.execute(exec).await.map_err(ApiError::from_sql)?;
    Ok(())
}

/// db.resolveStoragePoolForNewInstance: package-bound pool -> random instance_data pool -> null.
async fn resolve_storage_pool_for_new_instance(
    exec: &mut sqlx::PgConnection,
    host_id: i32,
    package_id: Option<i32>,
) -> Result<Option<String>, ApiError> {
    if let Some(package_id) = package_id {
        let bound: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT storage_pool_name FROM package_hosts WHERE package_id = $1 AND host_id = $2",
        )
        .bind(package_id)
        .bind(host_id)
        .fetch_optional(&mut *exec)
        .await
        .map_err(ApiError::from_sql)?;
        if let Some((Some(pool),)) = bound {
            if !pool.is_empty() {
                return Ok(Some(pool));
            }
        }
    }
    let pools = get_storage_pools(&mut *exec, host_id, true).await?;
    if pools.is_empty() {
        return Ok(None);
    }
    let index = (rand::random::<u64>() % pools.len() as u64) as usize;
    Ok(Some(pools[index].1.clone()))
}

/// db.hostHasInstanceDataPool.
async fn host_has_instance_data_pool(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    host_id: i32,
) -> Result<bool, ApiError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM storage_pools WHERE host_id = $1 AND purpose = 'instance_data'::\"StoragePurpose\"",
    )
    .bind(host_id)
    .fetch_one(exec)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(count > 0)
}

/// Executor-based calculateHostResourcesFromInstances (used inside FOR UPDATE tx).
async fn calc_resources_exec(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    host_id: i32,
) -> Result<(i64, i64, i64), ApiError> {
    let row: (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT COALESCE(SUM(cpu), 0), COALESCE(SUM(memory), 0), COALESCE(SUM(disk), 0) \
         FROM instances WHERE host_id = $1 \
         AND status IN ('creating','running','stopped','suspended')",
    )
    .bind(host_id)
    .fetch_one(exec)
    .await?;
    Ok((row.0.unwrap_or(0), row.1.unwrap_or(0), row.2.unwrap_or(0)))
}

/// db.selectAvailableHost (non-locking precheck used by create-for-user).
async fn select_available_host(
    state: &SharedAppState,
    package_host_ids: &[i32],
    node_selectors: &[String],
    cpu: i64,
    memory: i64,
    disk: i64,
    host_id: i32,
    owner_id: i32,
) -> Result<Option<HostRow>, ApiError> {
    let _ = disk;
    if host_id != 0 && !package_host_ids.is_empty() && !package_host_ids.contains(&(host_id as i32)) {
        return Ok(None);
    }
    let rows: Vec<HostRow> = if host_id != 0 {
        sqlx::query_as::<_, HostRow>(&format!(
            "SELECT {HOST_COLUMNS} FROM hosts WHERE status = 'online'::\"HostStatus\" AND id = $1 \
             ORDER BY memory_used ASC, cpu_used ASC"
        ))
        .bind(host_id)
        .fetch_all(&state.db)
        .await?
    } else if !package_host_ids.is_empty() {
        sqlx::query_as::<_, HostRow>(&format!(
            "SELECT {HOST_COLUMNS} FROM hosts WHERE status = 'online'::\"HostStatus\" AND id = ANY($1) \
             ORDER BY memory_used ASC, cpu_used ASC"
        ))
        .bind(&package_host_ids)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, HostRow>(&format!(
            "SELECT {HOST_COLUMNS} FROM hosts WHERE status = 'online'::\"HostStatus\" AND user_id = $1 \
             ORDER BY memory_used ASC, cpu_used ASC"
        ))
        .bind(owner_id)
        .fetch_all(&state.db)
        .await?
    };
    for host in rows {
        if !host_has_instance_data_pool(&state.db, host.id).await? {
            continue;
        }
        if !node_selectors.is_empty() {
            let host_tags = parse_string_array(host.tags.as_ref());
            if !node_selectors.iter().all(|tag| host_tags.contains(tag)) {
                continue;
            }
        }
        let (cpu_used, memory_used, _disk_used) =
            calculate_host_resources_from_instances(&state, host.id).await?;
        let cpu_allowance_max = host.cpu_allowance_max as i64;
        if cpu_allowance_max <= 0 || cpu_used + cpu > cpu_allowance_max {
            continue;
        }
        let memory_max = host.memory_max as i64;
        if memory_max <= 0 || memory_used + memory > memory_max {
            continue;
        }
        return Ok(Some(host));
    }
    Ok(None)
}

/// db.selectAndReserveHostWithLock: FOR UPDATE row locks + resource reservation.
#[allow(clippy::too_many_arguments)]
async fn select_and_reserve_host_with_lock(
    tx: &mut sqlx::PgConnection,
    package_host_ids: &[i32],
    node_selectors: &[String],
    cpu: i64,
    memory: i64,
    disk: i64,
    host_id: i32,
    owner_id: i32,
    port_count: i64,
) -> Result<Option<HostRow>, ApiError> {
    let _ = disk;
    if host_id != 0 && !package_host_ids.is_empty() && !package_host_ids.contains(&(host_id as i32)) {
        return Ok(None);
    }
    let rows: Vec<HostRow> = if host_id != 0 {
        sqlx::query_as::<_, HostRow>(&format!(
            "SELECT {HOST_COLUMNS} FROM hosts WHERE status = 'online'::\"HostStatus\" AND id = $1 \
             ORDER BY memory_used ASC, cpu_used ASC FOR UPDATE"
        ))
        .bind(host_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?
    } else if !package_host_ids.is_empty() {
        sqlx::query_as::<_, HostRow>(&format!(
            "SELECT {HOST_COLUMNS} FROM hosts WHERE status = 'online'::\"HostStatus\" AND id = ANY($1) \
             ORDER BY memory_used ASC, cpu_used ASC FOR UPDATE"
        ))
        .bind(&package_host_ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?
    } else {
        sqlx::query_as::<_, HostRow>(&format!(
            "SELECT {HOST_COLUMNS} FROM hosts WHERE status = 'online'::\"HostStatus\" AND user_id = $1 \
             ORDER BY memory_used ASC, cpu_used ASC FOR UPDATE"
        ))
        .bind(owner_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?
    };
    for host in rows {
        if !host_has_instance_data_pool(&mut *tx, host.id).await? {
            continue;
        }
        if !node_selectors.is_empty() {
            let host_tags = parse_string_array(host.tags.as_ref());
            if !node_selectors.iter().all(|tag| host_tags.contains(tag)) {
                continue;
            }
        }
        let (cpu_used, memory_used, _disk_used) =
            calc_resources_exec(&mut *tx, host.id).await?;
        let cpu_allowance_max = host.cpu_allowance_max as i64;
        if cpu_allowance_max <= 0 || cpu_used + cpu > cpu_allowance_max {
            continue;
        }
        let memory_max = host.memory_max as i64;
        if memory_max <= 0 || memory_used + memory > memory_max {
            continue;
        }
        if port_count > 0 {
            let nat_ports_total = match (host.nat_port_start, host.nat_port_end) {
                (Some(start), Some(end)) => (end - start) as i64 + 1,
                _ => 0,
            };
            if host.nat_ports_used_count as i64 + port_count > nat_ports_total {
                continue;
            }
        }
        sqlx::query(
            "UPDATE hosts SET cpu_used = $2, memory_used = $3, disk_used = $4 \
             WHERE id = $1",
        )
        .bind(host.id)
        .bind((cpu_used + cpu) as i32)
        .bind((memory_used + memory) as i32)
        .bind((_disk_used + disk) as i32)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
        if port_count > 0 {
            sqlx::query("UPDATE hosts SET nat_ports_used_count = $2 WHERE id = $1")
                .bind(host.id)
                .bind(host.nat_ports_used_count + port_count as i32)
                .execute(&mut *tx)
                .await
                .map_err(ApiError::from_sql)?;
        }
        let mut reserved = host.clone();
        reserved.cpu_used = (cpu_used + cpu) as i32;
        reserved.memory_used = (memory_used + memory) as i32;
        reserved.disk_used = (_disk_used + disk) as i32;
        return Ok(Some(reserved));
    }
    Ok(None)
}

/// generateUniqueOwnedName (takeover-official).
async fn generate_unique_owned_name(
    exec: &mut sqlx::PgConnection,
    model: &str,
    user_id: i32,
    base_name: &str,
) -> Result<String, ApiError> {
    const MAX_OWNED_NAME_LENGTH: usize = 64;
    let normalized = base_name.trim();
    let sql = if model == "host" {
        "SELECT id FROM hosts WHERE user_id = $1 AND name = $2 LIMIT 1"
    } else {
        "SELECT id FROM packages WHERE user_id = $1 AND name = $2 LIMIT 1"
    };
    let truncate = |suffix: &str| -> String {
        if suffix.is_empty() {
            let taken: String = normalized.chars().take(MAX_OWNED_NAME_LENGTH).collect();
            return taken;
        }
        let suffix_len = suffix.chars().count();
        let base_max = std::cmp::max(1, MAX_OWNED_NAME_LENGTH.saturating_sub(suffix_len));
        let base: String = normalized.chars().take(base_max).collect();
        format!("{base}{suffix}")
    };
    let current = truncate("");
    let taken = sqlx::query_scalar::<_, i32>(sql)
        .bind(user_id)
        .bind(&current)
        .fetch_optional(&mut *exec)
        .await
        .map_err(ApiError::from_sql)?;
    if taken.is_none() {
        return Ok(current);
    }
    let mut suffix = 1usize;
    loop {
        let suffix_text = if suffix == 1 {
            "-official".to_string()
        } else {
            format!("-official-{suffix}")
        };
        let candidate = truncate(&suffix_text);
        let taken = sqlx::query_scalar::<_, i32>(sql)
            .bind(user_id)
            .bind(&candidate)
            .fetch_optional(&mut *exec)
            .await
            .map_err(ApiError::from_sql)?;
        if taken.is_none() {
            return Ok(candidate);
        }
        suffix += 1;
    }
}

/// db.createInstanceTask (P2002 partial-unique-index -> conflict).
struct CreatedTask {
    id: i32,
    status: String,
}

async fn create_instance_task(
    state: &SharedAppState,
    instance_id: i32,
    host_id: i32,
    user_id: i32,
    task_type: &str,
    image_alias: Option<&str>,
    ssh_key_id: Option<i32>,
    custom_init_command_ids: Option<Vec<i64>>,
) -> Result<CreatedTask, Result<(i32, String, String), ApiError>> {
    let result = sqlx::query_as::<_, (i32, String)>(
        "INSERT INTO instance_tasks (instance_id, host_id, user_id, task_type, image_alias, ssh_key_id, custom_init_command_ids, status) \
         VALUES ($1, $2, $3, $4::\"InstanceTaskType\", $5, $6, $7, 'PENDING'::\"InstanceTaskStatus\") \
         RETURNING id, status::text AS status",
    )
    .bind(instance_id)
    .bind(host_id)
    .bind(user_id)
    .bind(task_type)
    .bind(image_alias)
    .bind(ssh_key_id)
    .bind(custom_init_command_ids.map(|ids| json!(ids)))
    .fetch_one(&state.db)
    .await;
    match result {
        Ok((id, status)) => Ok(CreatedTask { id, status }),
        Err(err) => {
            // Unique violation -> race with another active task.
            if err.as_database_error().map(|e| e.code().as_deref() == Some("23505")).unwrap_or(false) {
                if let Some(active) = get_active_task_for_instance(state, instance_id)
                    .await
                    .map_err(|e| Err(e))?
                {
                    return Err(Ok((active.0, active.1, active.2)));
                }
            }
            Err(Err(ApiError::from_sql(err)))
        }
    }
}

/// issueHostAgentInstallToken: rotate credentials + one-time install token.
struct IssuedAgentInstallToken {
    agent_id: String,
    install_token: String,
}

async fn issue_host_agent_install_token(
    state: &SharedAppState,
    host_id: i32,
    enabled: bool,
) -> Result<IssuedAgentInstallToken, ApiError> {
    let rotated = agent_creds::new_agent_credentials(&state.config.encryption_key);
    let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT agent_id FROM host_agents WHERE host_id = $1")
            .bind(host_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    if let Some((existing_agent_id,)) = existing {
        sqlx::query("DELETE FROM host_agent_nonces WHERE agent_id = $1")
            .bind(&existing_agent_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    }
    // Unique agent_id: retry generation like generateUniqueAgentId.
    let mut agent_id = rotated.agent_id.clone();
    for _ in 0..8 {
        let exists: Option<i32> = sqlx::query_scalar("SELECT id FROM host_agents WHERE agent_id = $1")
            .bind(&agent_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
        if exists.is_none() {
            break;
        }
        agent_id = agent_creds::generate_agent_id();
    }
    let install_token = agent_creds::generate_agent_install_token();
    let token_hash = agent_creds::hash_agent_install_token(&install_token);
    let expires_at = Utc::now() + chrono::Duration::milliseconds(agent_creds::AGENT_INSTALL_TOKEN_TTL_MS);
    sqlx::query(
        "INSERT INTO host_agents (host_id, agent_id, secret_hash, secret_encrypted, install_token_hash, \
         install_token_expires_at, install_token_used_at, enabled, status, capabilities, last_report) \
         VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, 'offline', '[]', '{}') \
         ON CONFLICT (host_id) DO UPDATE SET agent_id = $2, secret_hash = $3, secret_encrypted = $4, \
         install_token_hash = $5, install_token_expires_at = $6, install_token_used_at = NULL, \
         enabled = $7, status = 'offline', version = NULL, capabilities = '[]', \
         last_report = '{}', last_seen_at = NULL",
    )
    .bind(host_id)
    .bind(&agent_id)
    .bind(&rotated.secret_hash)
    .bind(&rotated.secret_encrypted)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(enabled)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    tx.commit().await.map_err(ApiError::from_sql)?;
    Ok(IssuedAgentInstallToken {
        agent_id,
        install_token,
    })
}

/// lib/instance-network-sync.ts persistResolvedInstanceNetworkAddresses, with
/// the change flags computed locally (the Rust lib helper returns no flags and
/// skips lastSyncedAt, so this wrapper fills both gaps).
async fn persist_network_addresses(
    state: &SharedAppState,
    instance: &InstanceNetworkSyncTarget,
    old_ipv4: Option<String>,
    old_ipv6: Option<String>,
    incus_devices: Option<&Value>,
    incus_expanded_devices: Option<&Value>,
    incus_state: Option<&Value>,
    update_last_synced_at: bool,
) -> Result<(bool, Option<String>, Option<String>, bool, Option<String>, Option<String>), ApiError> {
    let resolved = resolve_instance_network_addresses(
        instance,
        incus_devices,
        incus_expanded_devices,
        incus_state,
    );
    let new_ipv4 = resolved.ipv4.clone();
    let new_ipv6 = resolved.ipv6.clone();
    let ipv4_changed = old_ipv4 != new_ipv4;
    let ipv6_changed = old_ipv6 != new_ipv6;
    persist_resolved_instance_network_addresses(&state.db, instance, &resolved)
        .await
        .map_err(|e| ApiError::internal(e))?;
    if update_last_synced_at {
        sqlx::query("UPDATE instances SET last_synced_at = now() WHERE id = $1 AND status <> 'deleted'")
            .bind(instance.id as i32)
            .execute(&state.db)
            .await
            .map_err(ApiError::from_sql)?;
    }
    Ok((ipv4_changed, old_ipv4, new_ipv4, ipv6_changed, old_ipv6, new_ipv6))
}

// ===========================================================================
// audit helpers (routes/hosts.ts module scope)
// ===========================================================================

fn normalize_audit_severity_value(value: Option<&Value>) -> String {
    match value.and_then(Value::as_str) {
        Some(s @ ("info" | "low" | "medium" | "high")) => s.to_string(),
        _ => "medium".to_string(),
    }
}

fn normalize_audit_match_type(value: Option<&Value>) -> String {
    match value.and_then(Value::as_str) {
        Some(s @ ("contains" | "regex" | "exact")) => s.to_string(),
        _ => "contains".to_string(),
    }
}

fn normalize_audit_target_types(value: Option<&Value>) -> Vec<String> {
    let items: Vec<String> = value
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|i| i.as_str())
                .filter(|s| matches!(*s, "process" | "network" | "startup"))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let mut unique: Vec<String> = Vec::new();
    for item in items {
        if !unique.contains(&item) {
            unique.push(item);
        }
    }
    if unique.is_empty() {
        vec!["process".to_string()]
    } else {
        unique
    }
}

fn normalize_audit_finding_target(value: Option<&Value>) -> Option<String> {
    match value.and_then(Value::as_str) {
        Some(s @ ("process" | "network" | "startup" | "capability")) => Some(s.to_string()),
        _ => None,
    }
}

/// validateAuditRegex: reject catastrophic-backtracking constructs for regex
/// rules and verify the pattern compiles.
fn validate_audit_regex(match_type: &str, pattern: &str) -> Result<(), ()> {
    if match_type != "regex" {
        return Ok(());
    }
    if pattern.len() > 200
        || regex::Regex::new(r"\\[1-9]").unwrap().is_match(pattern)
        || regex::Regex::new(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")
            .unwrap()
            .is_match(pattern)
        || regex::Regex::new(r"(?:\.\*|\.\+).*(?:\.\*|\.\+)")
            .unwrap()
            .is_match(pattern)
    {
        return Err(());
    }
    regex::Regex::new(pattern).map(|_| ()).map_err(|_| ())
}

/// applyBuiltinAuditRuleOverride (AuditRuleDefinition + override row).
fn apply_builtin_audit_rule_override(
    rule: &AuditRuleDefinition,
    override_row: Option<&AuditBuiltinOverrideRow>,
) -> AuditRuleDefinition {
    let Some(ov) = override_row else {
        return rule.clone();
    };
    let mut applied = rule.clone();
    applied.severity = normalize_audit_severity_value(Some(&json!(ov.severity)));
    if !ov.category.is_empty() {
        applied.category = ov.category.clone();
    }
    if !ov.name.is_empty() {
        applied.name = ov.name.clone();
    }
    if let Some(description) = &ov.description {
        applied.description = Some(description.clone());
    }
    applied.target_types = normalize_audit_target_types(Some(&ov.target_types));
    applied.match_type = normalize_audit_match_type(Some(&json!(ov.match_type)));
    if !ov.pattern.is_empty() {
        applied.pattern_text = ov.pattern.clone();
    }
    applied.case_sensitive = ov.case_sensitive;
    applied.enabled = ov.enabled;
    if let Some(recommendation) = &ov.recommendation {
        applied.recommendation = Some(recommendation.clone());
    }
    applied
}

/// The persisted builtin-override row (instance_audit_builtin_rule_overrides).
#[derive(Debug, Clone, sqlx::FromRow)]
struct AuditBuiltinOverrideRow {
    pub id: i32,
    #[sqlx(rename = "builtin_rule_id")]
    pub builtin_rule_id: String,
    #[sqlx(rename = "created_by_id")]
    pub created_by_id: i32,
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub category: String,
    #[sqlx(rename = "target_types")]
    pub target_types: Value,
    #[sqlx(rename = "match_type")]
    pub match_type: String,
    pub pattern: String,
    #[sqlx(rename = "case_sensitive")]
    pub case_sensitive: bool,
    pub recommendation: Option<String>,
    pub enabled: bool,
    #[sqlx(rename = "created_at")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updated_at")]
    pub updated_at: DateTime<Utc>,
}

const AUDIT_OVERRIDE_COLUMNS: &str =
    "id, builtin_rule_id, created_by_id, name, description, severity, category, target_types, \
     match_type, pattern, case_sensitive, recommendation, enabled, created_at, updated_at";

/// toCustomAuditRuleDefinition.
fn to_custom_audit_rule_definition(
    id: i32,
    name: &str,
    description: Option<&str>,
    severity: &str,
    category: &str,
    target_types: &Value,
    match_type: &str,
    pattern: &str,
    case_sensitive: bool,
    enabled: bool,
    recommendation: Option<&str>,
) -> AuditRuleDefinition {
    AuditRuleDefinition {
        id: format!("custom:{id}"),
        severity: severity.to_string(),
        category: if category.is_empty() {
            "custom".to_string()
        } else {
            category.to_string()
        },
        name: name.to_string(),
        description: description.map(String::from),
        target_types: normalize_audit_target_types(Some(target_types)),
        match_type: match_type.to_string(),
        pattern_text: pattern.to_string(),
        case_sensitive,
        source: "custom",
        enabled,
        recommendation: recommendation.map(String::from),
    }
}

/// toAuditRuleResponse for builtin rules (with original + override).
fn builtin_rule_response(
    applied: &AuditRuleDefinition,
    original: &AuditRuleDefinition,
    override_row: Option<&AuditBuiltinOverrideRow>,
    _host_id: i32,
) -> Value {
    json!({
        "id": applied.id,
        "severity": applied.severity,
        "category": applied.category,
        "name": applied.name,
        "description": applied.description,
        "targetTypes": applied.target_types,
        "matchType": applied.match_type,
        "pattern": applied.pattern_text,
        "caseSensitive": applied.case_sensitive,
        "enabled": applied.enabled,
        "recommendation": applied.recommendation,
        "source": "builtin",
        "readOnly": true,
        "scope": "builtin",
        "originalName": original.name,
        "originalSeverity": original.severity,
        "originalCategory": original.category,
        "originalTargetTypes": original.target_types,
        "originalMatchType": original.match_type,
        "originalPattern": original.pattern_text,
        "originalCaseSensitive": original.case_sensitive,
        "originalRecommendation": original.recommendation,
        "overridden": override_row.is_some(),
        "overrideId": override_row.map(|o| o.id),
        "overrideUpdatedAt": override_row.map(|o| iso(o.updated_at)),
    })
}

/// toAuditRuleResponse for custom rules (raw prisma row + scope).
fn custom_rule_response(row: &AuditCustomRuleRow, host_id: i32) -> Value {
    let scope = if row.host_id.is_none() {
        "global"
    } else if row.host_id == Some(host_id) {
        "host"
    } else {
        "global"
    };
    json!({
        "id": row.id,
        "ruleId": format!("custom:{}", row.id),
        "source": "custom",
        "readOnly": false,
        "scope": scope,
        "hostId": row.host_id,
        "name": row.name,
        "description": row.description,
        "severity": row.severity,
        "category": row.category,
        "targetTypes": normalize_audit_target_types(Some(&row.target_types)),
        "matchType": row.match_type,
        "pattern": row.pattern,
        "caseSensitive": row.case_sensitive,
        "recommendation": row.recommendation,
        "enabled": row.enabled,
        "createdAt": iso(row.created_at),
        "updatedAt": iso(row.updated_at),
    })
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct AuditCustomRuleRow {
    pub id: i32,
    #[sqlx(rename = "host_id")]
    pub host_id: Option<i32>,
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub category: String,
    #[sqlx(rename = "target_types")]
    pub target_types: Value,
    #[sqlx(rename = "match_type")]
    pub match_type: String,
    pub pattern: String,
    #[sqlx(rename = "case_sensitive")]
    pub case_sensitive: bool,
    pub recommendation: Option<String>,
    pub enabled: bool,
    #[sqlx(rename = "created_at")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updated_at")]
    pub updated_at: DateTime<Utc>,
}

const AUDIT_RULE_COLUMNS: &str =
    "id, host_id, name, description, severity, category, target_types, match_type, pattern, \
     case_sensitive, recommendation, enabled, created_at, updated_at";

/// getAuditRuleDefinitions (scan-time rules: builtin+overrides, enabled custom).
async fn get_audit_rule_definitions(
    state: &SharedAppState,
    host_id: i32,
) -> Result<Vec<AuditRuleDefinition>, ApiError> {
    let custom_rows: Vec<(i32, String, Option<String>, String, String, Value, String, String, bool, bool, Option<String>)> = sqlx::query_as(
        "SELECT id, name, description, severity, category, target_types, match_type, pattern, \
         case_sensitive, enabled, recommendation FROM instance_audit_rules \
         WHERE enabled = true AND (host_id IS NULL OR host_id = $1) ORDER BY host_id ASC NULLS FIRST, id ASC",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    let overrides: Vec<AuditBuiltinOverrideRow> = sqlx::query_as::<_, AuditBuiltinOverrideRow>(
        &format!(
            "SELECT {AUDIT_OVERRIDE_COLUMNS} FROM instance_audit_builtin_rule_overrides WHERE host_id = $1"
        ),
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    let override_map: HashMap<String, AuditBuiltinOverrideRow> = overrides
        .into_iter()
        .map(|o| (o.builtin_rule_id.clone(), o))
        .collect();
    let mut rules: Vec<AuditRuleDefinition> = builtin_audit_rules()
        .into_iter()
        .map(|rule| {
            let ov = override_map.get(&rule.id);
            apply_builtin_audit_rule_override(&rule, ov)
        })
        .filter(|rule| rule.enabled)
        .collect();
    for (id, name, description, severity, category, target_types, match_type, pattern, case_sensitive, enabled, recommendation) in custom_rows {
        rules.push(to_custom_audit_rule_definition(
            id,
            &name,
            description.as_deref(),
            &severity,
            &category,
            &target_types,
            &match_type,
            &pattern,
            case_sensitive,
            enabled,
            recommendation.as_deref(),
        ));
    }
    Ok(rules)
}

/// getAuditRuleResponses (management view).
async fn get_audit_rule_responses(state: &SharedAppState, host_id: i32) -> Result<Value, ApiError> {
    let custom_rows: Vec<AuditCustomRuleRow> = sqlx::query_as::<_, AuditCustomRuleRow>(&format!(
        "SELECT {AUDIT_RULE_COLUMNS} FROM instance_audit_rules \
         WHERE host_id IS NULL OR host_id = $1 ORDER BY host_id ASC NULLS FIRST, id DESC"
    ))
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    let overrides: Vec<AuditBuiltinOverrideRow> = sqlx::query_as::<_, AuditBuiltinOverrideRow>(
        &format!(
            "SELECT {AUDIT_OVERRIDE_COLUMNS} FROM instance_audit_builtin_rule_overrides WHERE host_id = $1"
        ),
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    let override_map: HashMap<String, AuditBuiltinOverrideRow> = overrides
        .into_iter()
        .map(|o| (o.builtin_rule_id.clone(), o))
        .collect();
    let builtin: Vec<Value> = builtin_audit_rules()
        .iter()
        .map(|rule| {
            let ov = override_map.get(&rule.id);
            let applied = apply_builtin_audit_rule_override(rule, ov);
            builtin_rule_response(&applied, rule, ov, host_id)
        })
        .collect();
    let custom: Vec<Value> = custom_rows
        .iter()
        .map(|row| custom_rule_response(row, host_id))
        .collect();
    Ok(json!({ "builtin": builtin, "custom": custom }))
}

/// getAuditIgnores for a scan.
async fn get_audit_ignores_for_scan(
    state: &SharedAppState,
    host_id: i32,
    instance_id: i32,
) -> Result<Vec<AuditIgnoreDefinition>, ApiError> {
    let rows: Vec<(i32, Option<String>, Option<String>, Option<String>, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id, rule_id, target_type, match_text, reason, expires_at FROM instance_audit_ignores \
         WHERE host_id = $1 AND enabled = true AND (instance_id IS NULL OR instance_id = $2)",
    )
    .bind(host_id)
    .bind(instance_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, rule_id, target_type, match_text, reason, expires_at)| {
            let _ = id;
            AuditIgnoreDefinition {
                rule_id,
                target_type: normalize_audit_finding_target(target_type.as_deref().map(|s| json!(s)).as_ref()),
                match_text,
                reason,
                expires_at: expires_at.map(|t| t.timestamp_millis()),
            }
        })
        .collect())
}

/// getAuthorizedOpsHost.
async fn get_authorized_ops_host(
    state: &SharedAppState,
    host_id: i32,
    user: &AuthUser,
) -> Result<HostRow, ApiError> {
    let host = get_host_by_id(state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if host.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    Ok(host)
}

// ===========================================================================
// POST / — 创建宿主机
// ===========================================================================

async fn create_host(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let get_str = |key: &str| body.get(key).and_then(Value::as_str).map(String::from);
    let name = get_str("name").unwrap_or_default();
    let url = get_str("url").unwrap_or_default();
    let location = get_str("location");
    let country_code = get_str("countryCode");
    let cert_path = get_str("certPath");
    let key_path = get_str("keyPath");
    let server_certificate = get_str("serverCertificate");
    let server_fingerprint = get_str("serverFingerprint");
    let ip_address = get_str("ipAddress");
    let storage_driver = get_str("storageDriver");
    let storage_type = get_str("storageType");
    let storage_path = get_str("storagePath");
    let storage_size = body_int(body.get("storageSize")).map(|v| v as i32);
    let ipv6_mode = body_int(body.get("ipv6Mode")).map(|v| v as i32);
    let ipv6_subnet = get_str("ipv6Subnet");
    let ipv6_gateway = get_str("ipv6Gateway");
    let ipv6_parent_interface = get_str("ipv6ParentInterface");
    let cpu_allowance_max = body_int(body.get("cpuAllowanceMax")).map(|v| v as i32);
    let memory_max = body_int(body.get("memoryMax")).map(|v| v as i32);
    let instance_type = get_str("instanceType");
    let tags: Vec<String> = body
        .get("tags")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let nat_config = body.get("natConfig");
    let nat = |key: &str| nat_config.and_then(|n| n.get(key)).and_then(Value::as_str).map(String::from);
    let nat_port_start = nat_config.and_then(|n| body_int(n.get("portRangeStart"))).map(|v| v as i32);
    let nat_port_end = nat_config.and_then(|n| body_int(n.get("portRangeEnd"))).map(|v| v as i32);

    // Fastify schema: name minLength 2; countryCode 2 chars (schema violations
    // produce 400 {statusCode:400, error:"Bad Request"} — approximated with a
    // bare 400 like the validators below).
    if name.chars().count() < 2 {
        return Ok(bare_bad_request(format!(
            "body/name must NOT have fewer than 2 characters"
        )));
    }
    if let Some(code_str) = &country_code {
        if code_str.chars().count() != 2 {
            return Ok(bare_bad_request(
                "body/countryCode must NOT have fewer or more than 2 characters",
            ));
        }
    }
    if let Some(driver) = &storage_driver {
        if driver != "zfs" && driver != "lvm" {
            return Ok(bare_bad_request("body/storageDriver must be equal to one of the allowed values"));
        }
    }
    if let Some(st) = &storage_type {
        if st != "loop" && st != "disk" {
            return Ok(bare_bad_request("body/storageType must be equal to one of the allowed values"));
        }
    }
    if let Some(it) = &instance_type {
        if it != "container" && it != "vm" && it != "both" {
            return Ok(bare_bad_request("body/instanceType must be equal to one of the allowed values"));
        }
    }

    if user.role != "admin" && (cert_path.is_some() || key_path.is_some()) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Certificate paths are server-managed; ordinary hosts must use initialization",
                "code": "HOST_CERT_PATH_FORBIDDEN",
            })),
        )
            .into_response());
    }

    let name_validation = validators::validate_identifier(&name, "Host name", 2, 64);
    if !name_validation.valid {
        return Ok(bare_bad_request(name_validation.message.unwrap_or_default()));
    }

    if user.role != "admin" {
        let prefix = format!("PEER{}", user.id);
        let pattern = format!("(?i)^{prefix}[-_]");
        let ok = regex::Regex::new(&pattern)
            .map(|re| re.is_match(&name))
            .unwrap_or(false);
        if !ok {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Node name must start with your user ID prefix: {prefix}-"),
                    "code": "INVALID_HOST_NAME_PREFIX",
                })),
            )
                .into_response());
        }
    }

    if get_host_by_user_and_name(&state, user.id, &name)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request(code::HOST_NAME_EXISTS));
    }

    if user.role != "admin" {
        match check_hosting_access(&state, user.id).await? {
            Ok(()) => {}
            Err(reason) => {
                return Ok((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": reason, "code": "HOSTING_ACCESS_DENIED" })),
                )
                    .into_response());
            }
        }
    }

    let url_validation = validate_url(&url, "Host URL").map_err(bare_err)?;
    let parsed_url = reqwest::Url::parse(&url_validation)
        .map_err(|_| bare_err("Host URL format is invalid"))?;
    let hostname = parsed_url
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    validate_ip_or_domain(&hostname, "Host address").map_err(bare_err)?;
    if let Err(err) = assert_allowed_host_url(&url_validation, user.role == "admin").await {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": incus_error_message(&err),
                "code": "HOST_URL_NOT_PUBLIC",
            })),
        )
            .into_response());
    }

    if let Some(location) = &location {
        let location_validation = validators::validate_name(location, "Location", 1, 100);
        if !location_validation.valid {
            return Ok(bare_bad_request(location_validation.message.unwrap_or_default()));
        }
    }

    let mut normalized_nat_public_ip: Option<String> = None;
    let mut normalized_nat_public_ipv6: Option<String> = None;
    let mut normalized_nat_bind_ip: Option<String> = None;
    let mut normalized_nat_bind_ipv6: Option<String> = None;
    let normalized_ipv6_subnet = ipv6_subnet
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let normalized_ipv6_parent_interface = ipv6_parent_interface
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(public_ip) = nat("publicIp") {
        normalized_nat_public_ip = Some(validate_ip_address(&public_ip, "NAT public IP").map_err(bare_err)?);
    }
    if let Some(bind_ip) = nat("bindIp") {
        normalized_nat_bind_ip = Some(validate_ip_address(&bind_ip, "NAT bind IP").map_err(bare_err)?);
    }
    if let Some(bind_ipv6) = nat("bindIpv6") {
        let normalized = validate_ip_address(&bind_ipv6, "NAT bind IPv6").map_err(bare_err)?;
        if !normalized.contains(':') {
            return Ok(bare_bad_request("Invalid NAT bind IPv6 address format"));
        }
        normalized_nat_bind_ipv6 = Some(normalized);
    }
    if let Some(public_ipv6) = nat("publicIpv6") {
        let normalized = validate_ip_address(&public_ipv6, "NAT public IPv6").map_err(bare_err)?;
        if !normalized.contains(':') {
            return Ok(bare_bad_request("Invalid NAT public IPv6 address format"));
        }
        normalized_nat_public_ipv6 = Some(normalized);
    }

    if let (Some(start), Some(end)) = (nat_port_start, nat_port_end) {
        if end < start {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Port range end must be greater than or equal to start",
                    "code": "INVALID_PORT_RANGE",
                })),
            )
                .into_response());
        }
    }

    let needs_initialization =
        user.role != "admin" || cert_path.as_deref().unwrap_or("").is_empty() || key_path.as_deref().unwrap_or("").is_empty();

    if let Some(max) = cpu_allowance_max {
        if max < 0 {
            return Err(ApiError::bad_request(code::HOST_INVALID_CPU_MAX));
        }
    }
    if let Some(max) = memory_max {
        if max < 0 || (max > 0 && max < 256) {
            return Err(ApiError::bad_request(code::HOST_INVALID_MEMORY_MAX));
        }
    }

    if needs_initialization {
        if let Some(driver) = &storage_driver {
            if driver != "zfs" && driver != "lvm" {
                return Ok(bare_bad_request(
                    "Invalid storage driver, must be zfs or lvm",
                ));
            }
        }
        if let Some(st) = &storage_type {
            if st != "loop" && st != "disk" {
                return Ok(bare_bad_request(
                    "Invalid storage type, must be loop or disk",
                ));
            }
        }
        if let Some(path) = &storage_path {
            if !regex::Regex::new(r"^/dev/[a-zA-Z0-9_-]+$")
                .unwrap()
                .is_match(path)
            {
                return Ok(bare_bad_request(
                    "Invalid storage path, must be a valid device path like /dev/sdb or /dev/nvme0n1",
                ));
            }
        }
        if let Some(size) = storage_size {
            if !(10..=10000).contains(&size) {
                return Ok(bare_bad_request(
                    "Storage size must be between 10 and 10000 GB",
                ));
            }
        }
        if let Some(mode) = ipv6_mode {
            if !(1..=3).contains(&mode) {
                return Err(ApiError::bad_request(code::HOST_INVALID_IPV6_MODE));
            }
        }
        if ipv6_mode == Some(1)
            && normalized_ipv6_subnet.is_some()
            && normalized_ipv6_parent_interface.is_none()
        {
            return Ok(bare_bad_request(
                "IPv6 subnet and parent interface must be provided together",
            ));
        }
        if ipv6_mode == Some(1)
            && normalized_ipv6_subnet.is_none()
            && normalized_ipv6_parent_interface.is_some()
        {
            return Ok(bare_bad_request(
                "IPv6 subnet and parent interface must be provided together",
            ));
        }
    }

    let install_token: Option<String> = if needs_initialization {
        Some(random_uuid())
    } else {
        None
    };
    let cert_download_expire: Option<DateTime<Utc>> = if needs_initialization {
        Some(Utc::now() + chrono::Duration::minutes(15))
    } else {
        None
    };

    // withHostAddressRegistryLock { prepare + tx(create + user flag + snapshot) }.
    let snapshot = match registry::prepare_host_address_snapshot_for_write(&state.db, &url, None).await {
        Ok(snapshot) => snapshot,
        Err(err) => {
            if err.error_code == code::HOST_ADDRESS_UNRESOLVABLE {
                registry::log_host_address_resolution_failure(
                    &state.db,
                    Some(user.id),
                    &format!("{name}(create)"),
                    &url,
                    "create",
                    &err,
                )
                .await;
            }
            return Ok((StatusCode::BAD_REQUEST, Json(err_to_json(&err))).into_response());
        }
    };

    let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
    registry::registry_lock_in_tx(&mut tx).await?;
    let created: i32 = sqlx::query_scalar::<_, i32>(
        "INSERT INTO hosts (user_id, name, url, location, country_code, architecture, status, tags, \
         cert_path, key_path, nat_public_ip, nat_public_ipv6, nat_bind_ip, nat_bind_ipv6, \
         nat_port_start, nat_port_end, ip_address, storage_driver, storage_type, storage_path, \
         storage_size, ipv6_mode, ipv6_subnet, ipv6_gateway, ipv6_parent_interface, enable_api, \
         sysctl_config, install_token, install_token_expire, is_installed, cert_download_count, \
         cert_download_expire, cpu_allowance_max, memory_max, instance_type) \
         VALUES ($1, $2, $3, $4, $5, $6, 'offline'::\"HostStatus\", $7, $8, $9, $10, $11, $12, $13, \
         $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, true, NULL, $25, $26, $27, 0, $28, \
         $29, $30, $31::\"InstanceType\") RETURNING id",
    )
    .bind(user.id)
    .bind(&name)
    .bind(&url)
    .bind(&location)
    .bind(country_code.as_deref().unwrap_or("us"))
    .bind("x86_64")
    .bind(json!(tags))
    .bind(if user.role == "admin" { cert_path.clone() } else { None })
    .bind(if user.role == "admin" { key_path.clone() } else { None })
    .bind(&normalized_nat_public_ip)
    .bind(&normalized_nat_public_ipv6)
    .bind(&normalized_nat_bind_ip)
    .bind(&normalized_nat_bind_ipv6)
    .bind(nat_port_start)
    .bind(nat_port_end)
    .bind(&ip_address)
    .bind(storage_driver.as_deref().unwrap_or("zfs"))
    .bind(storage_type.as_deref().unwrap_or("loop"))
    .bind(&storage_path)
    .bind(storage_size.unwrap_or(60))
    .bind(ipv6_mode.unwrap_or(1))
    .bind(&normalized_ipv6_subnet)
    .bind(&ipv6_gateway)
    .bind(&normalized_ipv6_parent_interface)
    .bind(&install_token)
    .bind(if needs_initialization {
        Some(Utc::now() + chrono::Duration::hours(24))
    } else {
        None
    })
    .bind(!needs_initialization)
    .bind(&cert_download_expire)
    .bind(cpu_allowance_max.unwrap_or(0))
    .bind(memory_max.unwrap_or(0))
    .bind(instance_type.as_deref().unwrap_or("container"))
    .fetch_one(&mut *tx)
    .await?;
    let host_id = created;

    if user.role != "admin" {
        sqlx::query("UPDATE users SET has_created_host_before = true WHERE id = $1")
            .bind(user.id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    }
    registry::persist_in_tx(&mut tx, host_id, &snapshot, "create")
        .await
        .map_err(ApiError::from_sql)?;
    tx.commit().await.map_err(ApiError::from_sql)?;

    // Admin import path: try to auto-connect and sync resources.
    let mut auto_connected = false;
    let mut resource_info: Option<Value> = None;
    let mut detected_architecture = "x86_64";

    if !needs_initialization && cert_path.is_some() && key_path.is_some() {
        let client = IncusClient::new(&IncusClientOptions {
            url: url.clone(),
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            ca_path: None,
            server_certificate: None,
            server_fingerprint: None,
            allow_private_network: user.role == "admin",
        });
        match client {
            Ok(client) => match async {
                let server_info = client.connect().await?;
                detected_architecture = resources_architecture(&server_info);
                let resources = client.get_resources().await?;
                Ok::<_, IncusError>((server_info, resources))
            }
            .await
            {
                Ok((_server_info, resources)) => {
                    let disk_total_bytes = extract_disk_total_bytes(&resources);
                    let cpu_total = resources
                        .pointer("/cpu/total")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let memory_total_mb =
                        (resources.pointer("/memory/total").and_then(Value::as_f64).unwrap_or(0.0) / 1024.0 / 1024.0).round() as i64;
                    let disk_total_mb = (disk_total_bytes as f64 / 1024.0 / 1024.0).round() as i64;
                    update_host_status(&state, host_id, "online").await?;
                    if cpu_allowance_max.is_some()
                        || memory_max.is_some()
                        || instance_type.is_some()
                        || detected_architecture != "x86_64"
                    {
                        update_host_resources(
                            &state,
                            host_id,
                            HostResourceUpdate {
                                cpu_used: None,
                                memory_used: None,
                                disk_used: None,
                                cpu_allowance_max: cpu_allowance_max.map(|v| v as i64),
                                memory_max: memory_max.map(|v| v as i64),
                                instance_type: instance_type.as_deref(),
                                architecture: Some(detected_architecture),
                            },
                        )
                        .await?;
                    }
                    client.close();
                    auto_connected = true;
                    resource_info = Some(json!({
                        "cpuTotal": cpu_total,
                        "memoryTotalGB": (memory_total_mb as f64 / 1024.0).round() as i64,
                        "diskTotalGB": (disk_total_mb as f64 / 1024.0).round() as i64,
                    }));
                }
                Err(err) => {
                    tracing::warn!("自动连接节点 {name} 失败: {}", incus_error_message(&err));
                }
            },
            Err(err) => {
                tracing::warn!("自动连接节点 {name} 失败: {}", incus_error_message(&err));
            }
        }
    } else if cpu_allowance_max.is_some() || memory_max.is_some() || instance_type.is_some() {
        update_host_resources(
            &state,
            host_id,
            HostResourceUpdate {
                cpu_used: None,
                memory_used: None,
                disk_used: None,
                cpu_allowance_max: cpu_allowance_max.map(|v| v as i64),
                memory_max: memory_max.map(|v| v as i64),
                instance_type: instance_type.as_deref(),
                architecture: None,
            },
        )
        .await?;
    }

    create_log(
        &state,
        user.id,
        "host",
        "host.create",
        &format!(
            "Created host \"{name}\" [url: {url}, location: {}, country: {}, storage: {}/{}, instanceType: {}]",
            location.as_deref().unwrap_or("N/A"),
            country_code.as_deref().unwrap_or("us"),
            storage_driver.as_deref().unwrap_or("zfs"),
            storage_type.as_deref().unwrap_or("loop"),
            storage_size.unwrap_or(60),
        ),
        "success",
    )
    .await;

    if let Ok(Some((host_limit, host_used))) = get_user_quota(&state, user.id).await {
        if host_limit > 0 {
            let usage_percent = (host_used as f64 / host_limit as f64) * 100.0;
            if usage_percent >= 80.0 {
                send_notification(
                    &state,
                    user.id,
                    "quota_warning",
                    &json!({
                        "instanceName": "",
                        "quotaType": "宿主机",
                        "currentUsed": host_used,
                        "maxLimit": host_limit,
                        "usagePercent": usage_percent.round() as i64,
                    }),
                )
                .await;
            }
        }
    }

    let mut install_command: Option<String> = None;
    if needs_initialization {
        if let Some(token) = &install_token {
            let panel_url = derive_panel_url(&state)?;
            install_command = Some(build_host_install_command(&panel_url, token));
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": if needs_initialization {
                "Host added, please run install script to complete initialization"
            } else if auto_connected {
                "Host added and connected"
            } else {
                "Host added, please test connection manually"
            },
            "host": {
                "id": host_id,
                "name": name,
                "url": url,
                "architecture": detected_architecture,
                "status": if auto_connected { "online" } else { "offline" },
                "location": location,
                "resources": resource_info,
            },
            "installCommand": install_command,
            "installToken": install_token,
        })),
    )
        .into_response())
}

/// HostAddressRegistryError -> { error, code, details? } body.
fn err_to_json(err: &registry::HostAddressRegistryError) -> Value {
    let mut body = json!({
        "error": crate::error::message(err.error_code).unwrap_or(err.error_code),
        "code": err.error_code,
    });
    if let Some(details) = &err.details {
        body["details"] = json!(details);
    }
    body
}

// ===========================================================================
// GET /install.sh — 通用安装脚本（无需鉴权）
// ===========================================================================

fn query_get<'a>(params: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    params.get(key).map(|s| s.as_str()).filter(|s| !s.is_empty())
}

async fn install_script_generic(
    State(state): State<SharedAppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let stage = match resolve_host_install_stage(query_get(&params, "stage")) {
        Ok(stage) => stage,
        Err(_) => return no_store_text(StatusCode::BAD_REQUEST, "# Error: Invalid installer request".into()),
    };
    let template = match read_host_install_template(stage, query_get(&params, "os")) {
        Ok(script) => script,
        Err(_) => return no_store_text(StatusCode::BAD_REQUEST, "# Error: Invalid installer request".into()),
    };
    let panel_url = match derive_panel_url(&state) {
        Ok(url) => url,
        Err(_) => return no_store_text(StatusCode::BAD_REQUEST, "# Error: Invalid installer request".into()),
    };
    let script = inject_install_variable(&template, "INJECT_PANEL_URL", &panel_url);
    no_store_text(StatusCode::OK, script)
}

// ===========================================================================
// GET /install.sh/:token — 基于 installToken 的安装脚本下载
// ===========================================================================

async fn install_script_with_token(
    State(state): State<SharedAppState>,
    Path(token): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if token.is_empty() || token.len() < 10 {
        return no_store_text(StatusCode::BAD_REQUEST, "# Error: Invalid token format".into());
    }
    let host = match get_host_by_install_token(&state, &token).await {
        Ok(Some(host)) => host,
        Ok(None) => return no_store_text(StatusCode::NOT_FOUND, "# Error: Invalid or expired token".into()),
        Err(_) => return no_store_text(StatusCode::INTERNAL_SERVER_ERROR, "# Error: Internal server error".into()),
    };
    let (host_id, host_name, is_installed, install_token_expire) = host;
    if is_installed {
        return no_store_text(StatusCode::FORBIDDEN, "# Error: Host already installed".into());
    }
    let Some(expire) = install_token_expire else {
        return no_store_text(StatusCode::FORBIDDEN, "# Error: Invalid install token".into());
    };
    if Utc::now() > expire {
        return no_store_text(
            StatusCode::FORBIDDEN,
            "# Error: Install token has expired (24 hours)".into(),
        );
    }
    let stage = match resolve_host_install_stage(query_get(&params, "stage")) {
        Ok(stage) => stage,
        Err(_) => return no_store_text(StatusCode::BAD_REQUEST, "# Error: Invalid installer stage".into()),
    };
    let template = match read_host_install_template(stage, query_get(&params, "os")) {
        Ok(script) => script,
        Err(_) => return no_store_text(StatusCode::BAD_REQUEST, "# Error: Unsupported installer platform".into()),
    };
    let panel_url = match derive_panel_url(&state) {
        Ok(url) => url,
        Err(_) => return no_store_text(StatusCode::INTERNAL_SERVER_ERROR, "# Error: Internal server error".into()),
    };
    let mut script = inject_install_variable(&template, "INJECT_PANEL_URL", &panel_url);
    script = inject_install_variable(&script, "INJECT_TOKEN", &token);

    if stage == "platform" {
        match issue_host_agent_install_token(&state, host_id, true).await {
            Ok(agent_install) => {
                script = inject_install_variable(&script, "INJECT_AGENT_INSTALL_TOKEN", &agent_install.install_token);
                script = inject_install_variable(&script, "INJECT_AGENT_ENABLED", "true");
                if let Ok(binary_url) = std::env::var("INCUDAL_AGENT_BINARY_URL") {
                    let binary_url = binary_url.trim().to_string();
                    if !binary_url.is_empty() {
                        script = inject_install_variable(&script, "INJECT_AGENT_BINARY_URL", &binary_url);
                        let sha = std::env::var("INCUDAL_AGENT_BINARY_SHA256")
                            .map(|v| v.trim().to_string())
                            .unwrap_or_default();
                        script = inject_install_variable(&script, "INJECT_AGENT_BINARY_SHA256", &sha);
                    }
                }
                create_system_log(
                    &state,
                    None,
                    "host",
                    "host.agent_install_token_issue",
                    &format!("为宿主机安装脚本生成 Agent 一次性安装 token: {host_name} (#{host_id})"),
                    "success",
                )
                .await;
            }
            Err(err) => {
                tracing::error!(hostId = host_id, "Failed to prepare Host Agent bootstrap credentials: {err}");
            }
        }
    }

    no_store_text(StatusCode::OK, script)
}

// ===========================================================================
// GET /cert/:token — 证书下载
// ===========================================================================

async fn cert_download(
    State(state): State<SharedAppState>,
    Path(token): Path<String>,
) -> Response {
    if token.is_empty() || token.len() < 10 {
        return no_store_text(StatusCode::BAD_REQUEST, "# Error: Invalid token format".into());
    }
    let host = match get_host_by_install_token(&state, &token).await {
        Ok(Some(host)) => host,
        Ok(None) => return no_store_text(StatusCode::NOT_FOUND, "# Error: Invalid or expired token".into()),
        Err(_) => return no_store_text(StatusCode::INTERNAL_SERVER_ERROR, "# Error: Internal server error".into()),
    };
    let (_, _host_name, is_installed, install_token_expire) = host;
    if is_installed {
        return no_store_text(StatusCode::FORBIDDEN, "# Error: Host already installed".into());
    }
    match install_token_expire {
        Some(expire) if expire >= Utc::now() => {}
        _ => return no_store_text(StatusCode::FORBIDDEN, "# Error: Install token has expired".into()),
    }
    let (cert_path, _key_path) = panel_certificate_paths();
    match std::fs::read_to_string(&cert_path) {
        Ok(cert_content) => no_store_text(StatusCode::OK, cert_content),
        Err(_) => no_store_text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "# Error: Certificate file not found".into(),
        ),
    }
}

// ===========================================================================
// POST /tls-bootstrap/:token — 安装脚本的一次性回传通道
// ===========================================================================

async fn tls_bootstrap(
    State(state): State<SharedAppState>,
    Path(token): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    if token.len() < 16 || body.get("certificate").and_then(Value::as_str).is_none() {
        return Ok(bare_bad_request("Invalid TLS bootstrap payload"));
    }
    let host = get_host_by_install_token(&state, &token).await?;
    let Some((host_id, _name, is_installed, install_token_expire)) = host else {
        return Ok(bare_bad_request("Invalid or expired install session"));
    };
    let valid_session = !is_installed
        && install_token_expire
            .map(|expire| expire >= Utc::now())
            .unwrap_or(false);
    if !valid_session {
        return Ok(bare_bad_request("Invalid or expired install session"));
    }

    let storage_pool = body.get("storagePool").filter(|v| v.is_object());
    let mut pool_name: Option<String> = None;
    let mut pool_driver: Option<String> = None;
    let mut pool_config: Option<Value> = None;
    if let Some(pool) = storage_pool {
        let name_ok = pool
            .get("name")
            .and_then(Value::as_str)
            .map(|s| regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$").unwrap().is_match(s))
            .unwrap_or(false);
        let driver_ok = pool
            .get("driver")
            .and_then(Value::as_str)
            .map(|s| matches!(s, "zfs" | "lvm" | "btrfs" | "dir"))
            .unwrap_or(false);
        let purpose_ok = pool.get("purpose").and_then(Value::as_str) == Some("instance_data");
        let empty = Map::new();
        let config = pool.get("config").and_then(Value::as_object).unwrap_or(&empty);
        let config_ok = config.iter().all(|(key, value)| {
            matches!(key.as_str(), "source" | "size")
                && value.is_string()
                && regex::Regex::new(r"^[A-Za-z0-9_./:+=@%~-]+$")
                    .unwrap()
                    .is_match(value.as_str().unwrap_or(""))
        });
        if !name_ok || !driver_ok || !purpose_ok || !config_ok {
            return Ok(bare_bad_request("Invalid storage pool bootstrap payload"));
        }
        pool_name = pool.get("name").and_then(Value::as_str).map(String::from);
        pool_driver = pool.get("driver").and_then(Value::as_str).map(String::from);
        pool_config = Some(Value::Object(config.clone()));
    }

    let certificate_b64 = body.get("certificate").and_then(Value::as_str).unwrap_or("");
    let bootstrap = async {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(certificate_b64)
            .map_err(|_| ())?;
        let certificate = String::from_utf8(decoded).map_err(|_| ())?;
        let normalized = normalize_certificate_pem(&certificate).map_err(|_| ())?;
        let fingerprint = certificate_fingerprint(&normalized).map_err(|_| ())?;
        let mut tx = state.db.begin().await.map_err(|_| ())?;
        sqlx::query(
            "UPDATE hosts SET server_certificate = $2, server_fingerprint = $3 WHERE id = $1",
        )
        .bind(host_id)
        .bind(&normalized)
        .bind(&fingerprint)
        .execute(&mut *tx)
        .await
        .map_err(|_| ())?;
        if let (Some(name), Some(driver)) = (&pool_name, &pool_driver) {
            sqlx::query(
                "INSERT INTO storage_pools (host_id, name, driver, purpose, config) \
                 VALUES ($1, $2, $3, 'instance_data'::\"StoragePurpose\", $4) \
                 ON CONFLICT (host_id, name) DO UPDATE SET driver = $3, \
                 purpose = 'instance_data'::\"StoragePurpose\", config = $4",
            )
            .bind(host_id)
            .bind(name)
            .bind(driver)
            .bind(pool_config.clone().unwrap_or_else(|| json!({})))
            .execute(&mut *tx)
            .await
            .map_err(|_| ())?;
        }
        tx.commit().await.map_err(|_| ())?;
        Ok::<String, ()>(fingerprint)
    };
    match bootstrap.await {
        Ok(fingerprint) => Ok((
            StatusCode::OK,
            Json(json!({
                "success": true,
                "fingerprint": fingerprint,
                "storagePool": pool_name,
            })),
        )
            .into_response()),
        Err(()) => Ok(bare_bad_request("Invalid Incus server certificate")),
    }
}

// ===========================================================================
// POST /:id/verify — 验证并连接宿主机
// ===========================================================================

async fn host_verify(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    if host.is_installed {
        return Ok(bare_bad_request("该宿主机已完成安装，无需再次验证"));
    }
    if let Some(expire) = host.install_token_expire {
        if Utc::now() > expire {
            return Ok(bare_bad_request("安装会话已过期，请删除宿主机后重新创建"));
        }
    }

    let (cert_path, key_path) = panel_certificate_paths();
    let (cert_pem, key_pem) = match (
        std::fs::read_to_string(&cert_path),
        std::fs::read_to_string(&key_path),
    ) {
        (Ok(cert), Ok(key)) => (cert, key),
        _ => {
            return Ok(bare_bad_request(
                "面板证书文件读取失败，请检查服务器配置",
            ));
        }
    };
    // The Rust IncusClient consumes the panel pair from disk paths; the TLS
    // trust anchor comes from the captured server certificate below.
    let _ = (cert_pem, key_pem);

    let verify_flow = async {
        let target = resolve_incus_target(&host.url, user.role == "admin").await?;
        let (captured_cert, captured_fp) = if let (Some(cert), Some(fp)) =
            (host.server_certificate.clone(), host.server_fingerprint.clone())
        {
            (cert, fp)
        } else {
            let (cert, fp, _target) =
                capture_incus_server_certificate(&host.url, user.role == "admin").await?;
            (cert, fp)
        };
        let client = IncusClient::new(&IncusClientOptions {
            url: target.url.clone(),
            cert_path: Some(cert_path.clone()),
            key_path: Some(key_path.clone()),
            ca_path: None,
            server_certificate: Some(captured_cert.clone()),
            server_fingerprint: Some(captured_fp.clone()),
            allow_private_network: user.role == "admin",
        })
        .map_err(|err| err)?;
        let server_info = client.connect().await?;
        let resources = client.get_resources().await?;
        client.close();
        Ok::<_, IncusError>((captured_cert, captured_fp, server_info, resources))
    };

    match verify_flow.await {
        Ok((captured_cert, captured_fp, server_info, resources)) => {
            let host_architecture = resources_architecture(&server_info);
            let disk_total_bytes = extract_disk_total_bytes(&resources);
            let cpu_total = resources
                .pointer("/cpu/total")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let memory_total_mb =
                (resources.pointer("/memory/total").and_then(Value::as_f64).unwrap_or(0.0) / 1024.0 / 1024.0).round() as i64;
            let disk_total_mb = (disk_total_bytes as f64 / 1024.0 / 1024.0).round() as i64;
            let detected_ipv6 = extract_host_public_ipv6_from_resources(&resources);

            let mut update_sql = "UPDATE hosts SET status = 'online'::\"HostStatus\", \
                 is_installed = true, install_token = NULL, install_token_expire = NULL, \
                 cert_download_count = 0, cert_download_expire = NULL, cert_path = $2, \
                 key_path = $3, server_certificate = $4, server_fingerprint = $5, \
                 allow_private_network = $6, architecture = $7"
                .to_string();
            let mut set_ipv6 = false;
            if let Some(_detected) = &detected_ipv6 {
                if host.nat_public_ipv6.is_none() {
                    update_sql.push_str(", nat_public_ipv6 = $8");
                    set_ipv6 = true;
                }
            }
            update_sql.push_str(" WHERE id = $1");
            let mut q = sqlx::query(&update_sql)
                .bind(host_id)
                .bind(&cert_path)
                .bind(&key_path)
                .bind(&captured_cert)
                .bind(&captured_fp)
                .bind(user.role == "admin")
                .bind(host_architecture);
            if set_ipv6 {
                q = q.bind(detected_ipv6.clone());
            } else {
                let _ = set_ipv6;
            }
            q.execute(&state.db).await?;

            create_log(
                &state,
                user.id,
                "host",
                "host.verify",
                &format!(
                    "Verified and connected host \"{}\" [arch: {}, CPU: {} cores, Memory: {}GB, Disk: {}GB]",
                    host.name,
                    host_architecture,
                    cpu_total,
                    memory_total_mb / 1024,
                    disk_total_mb / 1024
                ),
                "success",
            )
            .await;

            Ok((
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "message": "纳管成功",
                    "resources": {
                        "cpuTotal": cpu_total,
                        "memoryTotalGB": memory_total_mb / 1024,
                        "diskTotalGB": disk_total_mb / 1024,
                    },
                    "architecture": host_architecture,
                    "serverFingerprint": captured_fp,
                })),
            )
                .into_response())
        }
        Err(err) => {
            let error_message = incus_error_message(&err);
            if error_message.contains("ECONNREFUSED") {
                let host_port = reqwest::Url::parse(&host.url)
                    .ok()
                    .and_then(|u| u.port().map(|p| p.to_string()))
                    .unwrap_or_else(|| "8443".to_string());
                return Ok(bare_bad_request(format!(
                    "连接被拒绝：请检查宿主机防火墙是否放行 TCP {host_port} 端口，以及 Incus 服务是否正在运行"
                )));
            }
            if error_message.contains("ETIMEDOUT") || error_message.contains("ECONNRESET") {
                return Ok(bare_bad_request("连接超时：请检查网络连通性和防火墙设置"));
            }
            if error_message.contains("not authorized")
                || error_message.contains("certificate")
                || error_message.contains("unauthorized")
            {
                return Ok(bare_bad_request(
                    "认证失败：证书未正确导入，请确认安装脚本已正确执行并成功导入面板证书",
                ));
            }
            Ok(bare_bad_request(format!("连接失败：{error_message}")))
        }
    }
}

// ===========================================================================
// POST /:id/regenerate-install
// ===========================================================================

async fn host_regenerate_install(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let install_token = random_uuid();
    let install_token_expire = Utc::now() + chrono::Duration::hours(24);
    sqlx::query(
        "UPDATE hosts SET install_token = $2, install_token_expire = $3, is_installed = false, \
         cert_path = NULL, key_path = NULL WHERE id = $1",
    )
    .bind(host_id)
    .bind(&install_token)
    .bind(install_token_expire)
    .execute(&state.db)
    .await?;
    let panel_url = derive_panel_url(&state)?;
    let install_command = build_host_install_command(&panel_url, &install_token);
    create_log(
        &state,
        user.id,
        "host",
        "host.regenerate_install",
        &format!("Regenerated install command for host \"{}\"", host.name),
        "success",
    )
    .await;
    Ok(Json(json!({
        "success": true,
        "installCommand": install_command,
        "installToken": install_token,
        "message": "安装命令已重新生成，请在24小时内完成安装",
    })))
}

// ===========================================================================
// POST /:id/test — 测试宿主机连接
// ===========================================================================

async fn host_test(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    if host.cert_path.is_none() || host.key_path.is_none() {
        return Err(ApiError::bad_request(code::HOST_CERT_NOT_CONFIGURED));
    }

    let mut server_certificate = host.server_certificate.clone();
    let mut server_fingerprint = host.server_fingerprint.clone();
    let _ = (&server_certificate, &server_fingerprint);
    if server_certificate.is_none() {
        if user.role != "admin" {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "success": false,
                    "error": "该节点尚未建立 TLS 信任锚，请联系管理员执行受控迁移",
                    "code": "HOST_TLS_TRUST_MIGRATION_REQUIRED",
                })),
            )
                .into_response());
        }
        let (cert, fp, _target) = capture_incus_server_certificate(&host.url, true).await?;
        server_certificate = Some(cert.clone());
        server_fingerprint = Some(fp.clone());
        sqlx::query(
            "UPDATE hosts SET server_certificate = $2, server_fingerprint = $3, \
             allow_private_network = true WHERE id = $1",
        )
        .bind(host_id)
        .bind(&cert)
        .bind(&fp)
        .execute(&state.db)
        .await?;
        state.incus_pool.remove_incus_client(host_id as i64).await;
    }

    let test_flow = async {
        let client = IncusClient::new(&IncusClientOptions {
            url: host.url.clone(),
            cert_path: host.cert_path.clone(),
            key_path: host.key_path.clone(),
            ca_path: None,
            server_certificate: server_certificate.clone(),
            server_fingerprint: server_fingerprint.clone(),
            allow_private_network: host.allow_private_network || user.role == "admin",
        })?;
        let server_info = client.connect().await?;
        client.close();
        Ok::<_, IncusError>(server_info)
    };

    match test_flow.await {
        Ok(server_info) => {
            let host_architecture = resources_architecture(&server_info);
            update_host_status(&state, host_id, "online").await?;
            update_host_resources(
                &state,
                host_id,
                HostResourceUpdate {
                    cpu_used: None,
                    memory_used: None,
                    disk_used: None,
                    cpu_allowance_max: None,
                    memory_max: None,
                    instance_type: None,
                    architecture: Some(host_architecture),
                },
            )
            .await?;
            Ok((
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "message": "Connection successful",
                    "serverInfo": {
                        "apiVersion": server_info.get("api_version").cloned().unwrap_or(Value::Null),
                        "environment": server_info.pointer("/environment/server_name").cloned().unwrap_or(Value::Null),
                        "architecture": host_architecture,
                    },
                })),
            )
                .into_response())
        }
        Err(err) => Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": incus_error_message(&err),
            })),
        )
            .into_response()),
    }
}

// ===========================================================================
// GET /:id — 宿主机详情
// ===========================================================================

async fn host_detail(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instances = get_instances_by_host(&state, host_id).await?;

    let mut disk_total_mb: i64 = host.storage_size as i64 * 1024;
    if host.status == "online" && host.cert_path.is_some() && host.key_path.is_some() {
        let client = get_incus_client(&state, &host).await?;
        let system_pools = get_storage_pools(&state.db, host_id, true).await?;
        if !system_pools.is_empty() {
            let mut total_bytes: i64 = 0;
            for pool in &system_pools {
                if let Ok(pool_resources) = get_storage_pool_resources(&client, &pool.1).await {
                    if let Some(space) = &pool_resources.space {
                        total_bytes += space.total;
                    }
                }
            }
            if total_bytes > 0 {
                disk_total_mb = (total_bytes as f64 / 1024.0 / 1024.0).round() as i64;
            }
        }
    }

    Ok(Json(json!({
        "host": {
            "id": host.id,
            "name": host.name,
            "url": host.url,
            "status": host.status,
            "maintenance": host.status == "maintenance",
            "location": host.location,
            "countryCode": if host.country_code.is_empty() { "us".to_string() } else { host.country_code.clone() },
            "architecture": if host.architecture.is_empty() { "x86_64".to_string() } else { host.architecture.clone() },
            "certPath": host.cert_path.clone().unwrap_or_default(),
            "keyPath": host.key_path.clone().unwrap_or_default(),
            "resources": {
                "cpuUsed": host.cpu_used,
                "memoryUsed": host.memory_used,
                "diskTotal": disk_total_mb,
                "diskUsed": host.disk_used,
            },
            "cpuAllowanceMax": host.cpu_allowance_max,
            "memoryMax": host.memory_max,
            "instanceType": if host.instance_type.is_empty() { "container".to_string() } else { host.instance_type.clone() },
            "natConfig": {
                "publicIp": host.nat_public_ip,
                "publicIpv6": host.nat_public_ipv6,
                "bindIp": host.nat_bind_ip,
                "bindIpv6": host.nat_bind_ipv6,
                "portRangeStart": host.nat_port_start,
                "portRangeEnd": host.nat_port_end,
            },
            "ipAddress": host.ip_address,
            "storageDriver": host.storage_driver,
            "storageType": host.storage_type,
            "storagePath": host.storage_path,
            "storageSize": host.storage_size,
            "ipv6Mode": host.ipv6_mode,
            "ipv6Subnet": host.ipv6_subnet,
            "ipv6Gateway": host.ipv6_gateway,
            "ipv6ParentInterface": host.ipv6_parent_interface,
            "enableApi": host.enable_api,
            "sysctlConfig": host.sysctl_config,
            "transferEnabled": host.transfer_enabled,
            "trafficResetDay": host.traffic_reset_day,
            "notifyPurchase": host.notify_purchase,
            "notifyRenew": host.notify_renew,
            "notifyDestroy": host.notify_destroy,
            "enableResourcePool": host.enable_resource_pool,
            "announcement": host.announcement,
            "probeUrl": get_safe_http_url(host.probe_url.as_deref()),
            "instances": instances
                .iter()
                .map(|(iid, name, status)| json!({ "id": iid, "name": name, "status": status }))
                .collect::<Vec<_>>(),
        }
    })))
}

// ===========================================================================
// GET/PUT /:id/images — 节点镜像白名单
// ===========================================================================

fn image_selection_response(selection: &Value) -> Value {
    json!({
        "success": true,
        "host": {
            "id": selection["hostId"],
            "name": selection["hostName"],
            "architecture": selection["architecture"],
            "instanceType": selection["instanceType"],
        },
        "useDefault": selection["useDefault"],
        "allowedImageIds": selection["allowedImageIds"],
        "images": selection["images"],
    })
}

async fn host_images_get(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let selection = get_host_image_selection_state(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    Ok(Json(image_selection_response(&selection)))
}

async fn host_images_put(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let use_default = body.get("useDefault") == Some(&Value::Bool(true));
    let image_ids: Vec<i64> = body
        .get("imageIds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect())
        .unwrap_or_default();
    let selection = match save_host_allowed_images(&state, host_id, use_default, &image_ids).await {
        Ok(Some(selection)) => selection,
        Ok(None) => return Err(ApiError::not_found(code::HOST_NOT_FOUND)),
        Err(err) => {
            if err.error.starts_with("INVALID_IMAGE_FOR_HOST:") {
                return Err(ApiError::bad_request(code::IMAGE_INVALID_HOST_ID));
            }
            return Err(err);
        }
    };
    create_log(
        &state,
        user.id,
        "host",
        "host.image_policy",
        &if selection["useDefault"].as_bool().unwrap_or(false) {
            format!(
                "Reset image policy for host \"{}\" to default",
                selection["hostName"].as_str().unwrap_or("")
            )
        } else {
            format!(
                "Updated image policy for host \"{}\" with {} image(s)",
                selection["hostName"].as_str().unwrap_or(""),
                selection["allowedImageIds"].as_array().map(|a| a.len()).unwrap_or(0)
            )
        },
        "success",
    )
    .await;
    let mut response = image_selection_response(&selection);
    response["message"] = json!(if selection["useDefault"].as_bool().unwrap_or(false) {
        "Host image policy reset to default"
    } else {
        "Host image policy updated"
    });
    Ok(Json(response))
}

// ===========================================================================
// PATCH /:id — 更新宿主机配置
// ===========================================================================

async fn host_update(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let get_str = |key: &str| body.get(key).and_then(Value::as_str).map(String::from);
    let updates_name = get_str("name");
    let updates_url = get_str("url");
    let updates_location = get_str("location");
    let updates_country_code = get_str("countryCode");
    let updates_cert_path = get_str("certPath");
    let updates_key_path = get_str("keyPath");
    let cpu_allowance_max = body_int(body.get("cpuAllowanceMax")).map(|v| v as i32);
    let memory_max = body_int(body.get("memoryMax")).map(|v| v as i32);
    let instance_type = get_str("instanceType");
    let ipv6_parent_interface = get_str("ipv6ParentInterface");
    let ipv6_subnet = get_str("ipv6Subnet");
    let transfer_enabled = body.get("transferEnabled").and_then(Value::as_bool);
    let traffic_reset_day = body_int(body.get("trafficResetDay")).map(|v| v as i32);
    let notify_purchase = body.get("notifyPurchase").and_then(Value::as_bool);
    let notify_renew = body.get("notifyRenew").and_then(Value::as_bool);
    let notify_destroy = body.get("notifyDestroy").and_then(Value::as_bool);
    let enable_resource_pool = body.get("enableResourcePool").and_then(Value::as_bool);
    let announcement = body.get("announcement").cloned();
    let probe_url_raw = body.get("probeUrl").cloned();
    let nat_config = body.get("natConfig");

    if let Some(code_str) = &updates_country_code {
        if code_str.chars().count() != 2 {
            return Ok(bare_bad_request(
                "body/countryCode must NOT have fewer or more than 2 characters",
            ));
        }
    }
    if let Some(it) = &instance_type {
        if it != "container" && it != "vm" && it != "both" {
            return Ok(bare_bad_request("body/instanceType must be equal to one of the allowed values"));
        }
    }
    if let Some(day) = traffic_reset_day {
        if !(1..=28).contains(&day) {
            return Ok(bare_bad_request("body/trafficResetDay must be >= 1 and <= 28"));
        }
    }
    if let Some(a) = &announcement {
        if !a.is_null() && a.as_str().map(|s| s.chars().count() > 1000).unwrap_or(true) {
            return Ok(bare_bad_request("body/announcement must NOT have more than 1000 characters"));
        }
    }
    if let Some(p) = &probe_url_raw {
        if !p.is_null() && p.as_str().map(|s| s.chars().count() > 500).unwrap_or(true) {
            return Ok(bare_bad_request("body/probeUrl must NOT have more than 500 characters"));
        }
    }

    if user.role != "admin" && (updates_cert_path.is_some() || updates_key_path.is_some()) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Certificate paths are server-managed",
                "code": "HOST_CERT_PATH_FORBIDDEN",
            })),
        )
            .into_response());
    }

    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }

    if let Some(name) = &updates_name {
        let name_validation = validators::validate_identifier(name, "Host name", 2, 64);
        if !name_validation.valid {
            return Ok(bare_bad_request(name_validation.message.unwrap_or_default()));
        }
        if user.role != "admin" {
            let prefix = format!("PEER{}", user.id);
            let pattern = format!("(?i)^{prefix}[-_]");
            let ok = regex::Regex::new(&pattern)
                .map(|re| re.is_match(name))
                .unwrap_or(false);
            if !ok {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": format!("Node name must start with your user ID prefix: {prefix}-"),
                        "code": "INVALID_HOST_NAME_PREFIX",
                    })),
                )
                    .into_response());
            }
        }
        if let Some(duplicate) = get_host_by_user_and_name(&state, host.user_id, name).await? {
            if duplicate.id != host_id {
                return Err(ApiError::bad_request(code::HOST_NAME_EXISTS));
            }
        }
    }

    if let Some(url) = &updates_url {
        let url_validation = validate_url(url, "Host URL").map_err(bare_err)?;
        let parsed = reqwest::Url::parse(&url_validation)
            .map_err(|_| bare_err("Host URL format is invalid"))?;
        let hostname = parsed
            .host_str()
            .unwrap_or_default()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        validate_ip_or_domain(&hostname, "Host address").map_err(bare_err)?;
        if let Err(err) = assert_allowed_host_url(&url_validation, user.role == "admin").await {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": incus_error_message(&err),
                    "code": "HOST_URL_NOT_PUBLIC",
                })),
            )
                .into_response());
        }
    }

    let normalized_probe_url: Option<String> = match &probe_url_raw {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => validate_optional_http_url(Some(&json!(s)), "Probe URL")
            .map_err(bare_err)?,
        Some(_) => {
            return Ok(bare_bad_request("Probe URL must be a string"));
        }
    };

    if let Some(location) = &updates_location {
        if !location.is_empty() {
            let location_validation = validators::validate_name(location, "Location", 1, 100);
            if !location_validation.valid {
                return Ok(bare_bad_request(location_validation.message.unwrap_or_default()));
            }
        }
    }

    if let Some(max) = memory_max {
        if max > 0 && max < 256 {
            return Ok(bare_bad_request("内存最大值不能低于256MB"));
        }
    }

    let used_resources = calculate_host_resources_from_instances(&state, host_id).await?;
    if let Some(max) = cpu_allowance_max {
        if max > 0 && (max as i64) < used_resources.0 {
            return Err(ApiError::with_message(
                code::HOST_CPU_BELOW_USED,
                StatusCode::BAD_REQUEST,
                format!("当前已使用: {}%", used_resources.0),
            ));
        }
    }
    if let Some(max) = memory_max {
        if max > 0 && (max as i64) < used_resources.1 {
            return Err(ApiError::with_message(
                code::HOST_MEMORY_BELOW_USED,
                StatusCode::BAD_REQUEST,
                format!("当前已使用: {}MB", used_resources.1),
            ));
        }
    }

    let nat_key = |key: &str| -> Option<Option<String>> {
        nat_config
            .and_then(|n| n.get(key))
            .map(|v| v.as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
    };

    let mut normalized_nat_public_ip: Option<Option<String>> = None;
    let mut normalized_nat_bind_ip: Option<Option<String>> = None;
    let mut normalized_nat_bind_ipv6: Option<Option<String>> = None;
    let mut normalized_nat_public_ipv6: Option<Option<String>> = None;
    if let Some(value) = nat_key("publicIp") {
        if let Some(next) = &value {
            normalized_nat_public_ip = Some(Some(validate_ip_address(next, "NAT public IP").map_err(bare_err)?));
        } else {
            normalized_nat_public_ip = Some(None);
        }
    }
    if let Some(value) = nat_key("bindIp") {
        if let Some(next) = &value {
            normalized_nat_bind_ip = Some(Some(validate_ip_address(next, "NAT bind IP").map_err(bare_err)?));
        } else {
            normalized_nat_bind_ip = Some(None);
        }
    }
    if let Some(value) = nat_key("publicIpv6") {
        match &value {
            Some(next) => {
                let normalized =
                    validate_ip_address(next, "NAT public IPv6").map_err(bare_err)?;
                if !normalized.contains(':') {
                    return Ok(bare_bad_request("Invalid NAT public IPv6 address format"));
                }
                normalized_nat_public_ipv6 = Some(Some(normalized));
            }
            None => normalized_nat_public_ipv6 = Some(None),
        }
    }
    if let Some(value) = nat_key("bindIpv6") {
        match &value {
            Some(next) => {
                let normalized =
                    validate_ip_address(next, "NAT bind IPv6").map_err(bare_err)?;
                if !normalized.contains(':') {
                    return Ok(bare_bad_request("Invalid NAT bind IPv6 address format"));
                }
                normalized_nat_bind_ipv6 = Some(Some(normalized));
            }
            None => normalized_nat_bind_ipv6 = Some(None),
        }
    }

    let nat_port_start = nat_config.and_then(|n| body_int(n.get("portRangeStart"))).map(|v| v as i32);
    let nat_port_end = nat_config.and_then(|n| body_int(n.get("portRangeEnd"))).map(|v| v as i32);
    if let (Some(start), Some(end)) = (nat_port_start, nat_port_end) {
        if end < start {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Port range end must be greater than or equal to start",
                    "code": "INVALID_PORT_RANGE",
                })),
            )
                .into_response());
        }
    }

    let normalized_ipv6_parent_interface: Option<Option<String>> = ipv6_parent_interface
        .as_ref()
        .map(|s| Some(s.trim().to_string()).filter(|s| !s.is_empty()));
    let normalized_ipv6_subnet: Option<Option<String>> = ipv6_subnet
        .as_ref()
        .map(|s| Some(s.trim().to_string()).filter(|s| !s.is_empty()));

    let next_ipv6_mode = host.ipv6_mode;
    let next_ipv6_subnet = normalized_ipv6_subnet
        .clone()
        .unwrap_or_else(|| host.ipv6_subnet.clone());
    let next_ipv6_parent_interface = normalized_ipv6_parent_interface
        .clone()
        .unwrap_or_else(|| host.ipv6_parent_interface.clone());
    if next_ipv6_mode == 1 && (next_ipv6_subnet.is_none() || next_ipv6_parent_interface.is_none()) {
        return Err(ApiError::bad_request(code::HOST_IPV6_ROUTE_REQUIRES_CONFIG));
    }

    let update_result = (|| async {
        let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
        if updates_url.is_some() {
            let snapshot =
                registry::prepare_host_address_snapshot_for_write(&state.db, updates_url.as_deref().unwrap_or(""), Some(host_id))
                    .await
                    .map_err(RegistryErr::Registry)?;
            registry::registry_lock_in_tx(&mut tx).await?;
            apply_host_update(
                &state,
                &mut tx,
                host_id,
                &user,
                HostUpdateFields {
                    name: updates_name.clone(),
                    url: updates_url.clone(),
                    location: updates_location.clone(),
                    country_code: updates_country_code.clone(),
                    cert_path: updates_cert_path.clone(),
                    key_path: updates_key_path.clone(),
                    nat_public_ip: normalized_nat_public_ip,
                    nat_bind_ip: normalized_nat_bind_ip,
                    nat_bind_ipv6: normalized_nat_bind_ipv6,
                    nat_public_ipv6: normalized_nat_public_ipv6,
                    nat_port_start,
                    nat_port_end,
                    ipv6_parent_interface: normalized_ipv6_parent_interface,
                    ipv6_subnet: normalized_ipv6_subnet,
                    cpu_allowance_max,
                    memory_max,
                    instance_type: instance_type.clone(),
                    transfer_enabled,
                    traffic_reset_day,
                    notify_purchase,
                    notify_renew,
                    notify_destroy,
                    enable_resource_pool,
                    announcement: announcement.clone(),
                    probe_url: normalized_probe_url.clone(),
                },
            )
            .await?;
            registry::persist_in_tx(&mut tx, host_id, &snapshot, "update")
                .await
                .map_err(ApiError::from_sql)?;
        } else {
            apply_host_update(
                &state,
                &mut tx,
                host_id,
                &user,
                HostUpdateFields {
                    name: updates_name.clone(),
                    url: updates_url.clone(),
                    location: updates_location.clone(),
                    country_code: updates_country_code.clone(),
                    cert_path: updates_cert_path.clone(),
                    key_path: updates_key_path.clone(),
                    nat_public_ip: normalized_nat_public_ip,
                    nat_bind_ip: normalized_nat_bind_ip,
                    nat_bind_ipv6: normalized_nat_bind_ipv6,
                    nat_public_ipv6: normalized_nat_public_ipv6,
                    nat_port_start,
                    nat_port_end,
                    ipv6_parent_interface: normalized_ipv6_parent_interface,
                    ipv6_subnet: normalized_ipv6_subnet,
                    cpu_allowance_max,
                    memory_max,
                    instance_type: instance_type.clone(),
                    transfer_enabled,
                    traffic_reset_day,
                    notify_purchase,
                    notify_renew,
                    notify_destroy,
                    enable_resource_pool,
                    announcement: announcement.clone(),
                    probe_url: normalized_probe_url.clone(),
                },
            )
            .await?;
        }
        tx.commit().await.map_err(ApiError::from_sql)?;
        Ok::<(), RegistryErr>(())
    })()
    .await;

    if let Err(err) = update_result {
        return match err {
            RegistryErr::Registry(reg_err) => {
                if reg_err.error_code == code::HOST_ADDRESS_UNRESOLVABLE {
                    registry::log_host_address_resolution_failure(
                        &state.db,
                        Some(user.id),
                        &format!("{}(#{host_id})", host.name),
                        updates_url.as_deref().unwrap_or(&host.url),
                        "update",
                        &reg_err,
                    )
                    .await;
                }
                Ok((StatusCode::BAD_REQUEST, Json(err_to_json(&reg_err))).into_response())
            }
            RegistryErr::Api(api_err) => Err(api_err),
        };
    }

    let mut incompatible_packages: Vec<Value> = Vec::new();
    if let Some(next_type) = &instance_type {
        if next_type != &host.instance_type {
            incompatible_packages = get_incompatible_packages_by_host_type_change(&state, host_id, next_type).await?;
        }
    }

    if updates_cert_path.is_some() || updates_key_path.is_some() || updates_url.is_some() {
        state.incus_pool.remove_incus_client(host_id as i64).await;
    }

    let mut changes: Vec<String> = Vec::new();
    if let Some(name) = &updates_name {
        if !name.is_empty() {
            changes.push(format!("name -> \"{name}\""));
        }
    }
    if let Some(url) = &updates_url {
        if !url.is_empty() {
            changes.push(format!("url -> {url}"));
        }
    }
    if let Some(location) = &updates_location {
        if !location.is_empty() {
            changes.push(format!("location -> {location}"));
        }
    }
    if let Some(v) = cpu_allowance_max {
        changes.push(format!("cpuMax -> {v}%"));
    }
    if let Some(v) = memory_max {
        changes.push(format!("memoryMax -> {v}MB"));
    }
    if let Some(v) = &instance_type {
        changes.push(format!("instanceType -> {v}"));
    }
    if let Some(v) = nat_config.and_then(|n| n.get("publicIp")).and_then(Value::as_str) {
        if !v.is_empty() {
            changes.push(format!("natPublicIp -> {v}"));
        }
    }
    if let Some(v) = transfer_enabled {
        changes.push(format!("transferEnabled -> {v}"));
    }
    if let Some(v) = traffic_reset_day {
        changes.push(format!("trafficResetDay -> {v}"));
    }
    if let Some(v) = notify_purchase {
        changes.push(format!("notifyPurchase -> {v}"));
    }
    if let Some(v) = notify_renew {
        changes.push(format!("notifyRenew -> {v}"));
    }
    if let Some(v) = notify_destroy {
        changes.push(format!("notifyDestroy -> {v}"));
    }

    create_log(
        &state,
        user.id,
        "host",
        "host.update",
        &format!(
            "Updated host \"{}\" [{}]",
            host.name,
            if changes.is_empty() {
                "no major changes".to_string()
            } else {
                changes.join(", ")
            }
        ),
        "success",
    )
    .await;

    if !incompatible_packages.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(json!({
                "message": "Host config updated",
                "warnings": [{
                    "code": "INCOMPATIBLE_PACKAGES",
                    "message": "节点类型变更后，以下套餐可能无法使用该节点创建实例",
                    "packages": incompatible_packages,
                }],
            })),
        )
            .into_response());
    }

    Ok((StatusCode::OK, Json(json!({ "message": "Host config updated" }))).into_response())
}

/// Wrapper so the registry error and sql errors can share one Result.
enum RegistryErr {
    Registry(registry::HostAddressRegistryError),
    Api(ApiError),
}

impl From<ApiError> for RegistryErr {
    fn from(err: ApiError) -> Self {
        RegistryErr::Api(err)
    }
}

struct HostUpdateFields {
    name: Option<String>,
    url: Option<String>,
    location: Option<String>,
    country_code: Option<String>,
    cert_path: Option<String>,
    key_path: Option<String>,
    nat_public_ip: Option<Option<String>>,
    nat_bind_ip: Option<Option<String>>,
    nat_bind_ipv6: Option<Option<String>>,
    nat_public_ipv6: Option<Option<String>>,
    nat_port_start: Option<i32>,
    nat_port_end: Option<i32>,
    ipv6_parent_interface: Option<Option<String>>,
    ipv6_subnet: Option<Option<String>>,
    cpu_allowance_max: Option<i32>,
    memory_max: Option<i32>,
    instance_type: Option<String>,
    transfer_enabled: Option<bool>,
    traffic_reset_day: Option<i32>,
    notify_purchase: Option<bool>,
    notify_renew: Option<bool>,
    notify_destroy: Option<bool>,
    enable_resource_pool: Option<bool>,
    announcement: Option<Value>,
    probe_url: Option<String>,
}

/// db.updateHost + the follow-up tx.host.update calls in PATCH /:id.
#[allow(clippy::too_many_arguments)]
async fn apply_host_update(
    _state: &SharedAppState,
    tx: &mut sqlx::PgConnection,
    host_id: i32,
    user: &AuthUser,
    f: HostUpdateFields,
) -> Result<(), ApiError> {
    // Column updates are collected then bound in registration order; strings,
    // ints and bools keep separate bind pools keyed by `bind_order`.
    let mut sets: Vec<String> = Vec::new();
    let mut idx = 2usize;
    let mut binds: Vec<Option<String>> = Vec::new();
    let mut int_binds: Vec<i32> = Vec::new();
    let mut bool_binds: Vec<bool> = Vec::new();
    let mut bind_order: Vec<u8> = Vec::new();

    macro_rules! set_str {
        ($column:expr, $value:expr) => {{
            sets.push(format!(" {} = ${}", $column, idx));
            idx += 1;
            binds.push($value);
            bind_order.push(0u8);
        }};
    }
    macro_rules! set_int {
        ($column:expr, $value:expr) => {{
            sets.push(format!(" {} = ${}", $column, idx));
            idx += 1;
            int_binds.push($value);
            bind_order.push(1u8);
        }};
    }
    macro_rules! set_bool {
        ($column:expr, $value:expr) => {{
            sets.push(format!(" {} = ${}", $column, idx));
            idx += 1;
            bool_binds.push($value);
            bind_order.push(2u8);
        }};
    }

    if let Some(v) = &f.name {
        set_str!("name", Some(v.clone()));
    }
    if let Some(v) = &f.url {
        set_str!("url", Some(v.clone()));
    }
    if let Some(v) = &f.location {
        set_str!("location", Some(v.clone()));
    }
    if let Some(v) = &f.country_code {
        set_str!("country_code", Some(v.clone()));
    }
    if let Some(v) = &f.cert_path {
        if user.role == "admin" {
            set_str!("cert_path", Some(v.clone()));
        }
    }
    if let Some(v) = &f.key_path {
        if user.role == "admin" {
            set_str!("key_path", Some(v.clone()));
        }
    }
    if let Some(v) = f.nat_public_ip {
        set_str!("nat_public_ip", v);
    }
    if let Some(v) = f.nat_bind_ip {
        set_str!("nat_bind_ip", v);
    }
    if let Some(v) = f.nat_bind_ipv6 {
        set_str!("nat_bind_ipv6", v);
    }
    if let Some(v) = f.nat_port_start {
        set_int!("nat_port_start", v);
    }
    if let Some(v) = f.nat_port_end {
        set_int!("nat_port_end", v);
    }
    if let Some(v) = f.ipv6_parent_interface {
        set_str!("ipv6_parent_interface", v);
    }
    if let Some(v) = f.ipv6_subnet {
        set_str!("ipv6_subnet", v);
    }
    if let Some(v) = f.traffic_reset_day {
        set_int!("traffic_reset_day", v);
    }
    if let Some(v) = f.notify_purchase {
        set_bool!("notify_purchase", v);
    }
    if let Some(v) = f.notify_renew {
        set_bool!("notify_renew", v);
    }
    if let Some(v) = f.notify_destroy {
        set_bool!("notify_destroy", v);
    }

    if !sets.is_empty() {
        let sql = format!("UPDATE hosts SET{} WHERE id = $1", sets.join(","));
        let mut q = sqlx::query(&sql).bind(host_id);
        let mut str_iter = binds.iter();
        let mut int_iter = int_binds.iter();
        let mut bool_iter = bool_binds.iter();
        for kind in &bind_order {
            match kind {
                0 => {
                    if let Some(v) = str_iter.next() {
                        q = q.bind(v.clone());
                    }
                }
                1 => {
                    if let Some(v) = int_iter.next() {
                        q = q.bind(*v);
                    }
                }
                _ => {
                    if let Some(v) = bool_iter.next() {
                        q = q.bind(*v);
                    }
                }
            }
        }
        q.execute(&mut *tx).await.map_err(ApiError::from_sql)?;
    }

    if f.cpu_allowance_max.is_some() || f.memory_max.is_some() || f.instance_type.is_some() {
        let mut sets2: Vec<String> = Vec::new();
        let mut idx2 = 2usize;
        let mut int2: Vec<i32> = Vec::new();
        if let Some(v) = f.cpu_allowance_max {
            sets2.push(format!(" cpu_allowance_max = ${idx2}"));
            idx2 += 1;
            int2.push(v);
        }
        if let Some(v) = f.memory_max {
            sets2.push(format!(" memory_max = ${idx2}"));
            idx2 += 1;
            int2.push(v);
        }
        let mut instance_type_bind: Option<String> = None;
        if let Some(v) = &f.instance_type {
            sets2.push(format!(" instance_type = ${idx2}::\"InstanceType\""));
            instance_type_bind = Some(v.clone());
        }
        let sql2 = format!("UPDATE hosts SET{} WHERE id = $1", sets2.join(","));
        let mut q2 = sqlx::query(&sql2).bind(host_id);
        for v in int2 {
            q2 = q2.bind(v);
        }
        if let Some(v) = instance_type_bind {
            q2 = q2.bind(v);
        }
        q2.execute(&mut *tx).await.map_err(ApiError::from_sql)?;
    }

    if let Some(v) = f.transfer_enabled {
        sqlx::query("UPDATE hosts SET transfer_enabled = $2 WHERE id = $1")
            .bind(host_id)
            .bind(v)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    }
    if let Some(v) = f.enable_resource_pool {
        sqlx::query("UPDATE hosts SET enable_resource_pool = $2 WHERE id = $1")
            .bind(host_id)
            .bind(v)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    }
    if let Some(v) = &f.announcement {
        let value = if v.is_null() {
            None
        } else {
            v.as_str().filter(|s| !s.is_empty())
        };
        sqlx::query("UPDATE hosts SET announcement = $2 WHERE id = $1")
            .bind(host_id)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    }
    if f.probe_url.is_some() {
        sqlx::query("UPDATE hosts SET probe_url = $2 WHERE id = $1")
            .bind(host_id)
            .bind(&f.probe_url)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    }
    if let Some(v) = &f.nat_public_ipv6 {
        sqlx::query("UPDATE hosts SET nat_public_ipv6 = $2 WHERE id = $1")
            .bind(host_id)
            .bind(v)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    }
    Ok(())
}

// ===========================================================================
// POST /:id/maintenance
// ===========================================================================

async fn host_maintenance(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let enabled = body.get("enabled") == Some(&Value::Bool(true));
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let new_status = if enabled { "maintenance" } else { "online" };
    update_host_status(&state, host_id, new_status).await?;
    create_log(
        &state,
        user.id,
        "host",
        if enabled {
            "host.maintenance.enable"
        } else {
            "host.maintenance.disable"
        },
        &format!(
            "{} maintenance mode for host \"{}\"",
            if enabled { "Enabled" } else { "Disabled" },
            host.name
        ),
        "success",
    )
    .await;
    Ok(Json(json!({
        "message": if enabled { "Maintenance mode enabled" } else { "Maintenance mode disabled" },
    })))
}

// ===========================================================================
// POST /:id/sync — 同步宿主机资源使用情况
// ===========================================================================

async fn host_sync(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    match sync_host_resources(&state, &host).await {
        Ok((used, instance_count)) => Ok((
            StatusCode::OK,
            Json(json!({
                "message": "Sync completed",
                "instances": instance_count,
                "resources": {
                    "cpuUsed": used.0,
                    "memoryUsed": used.1,
                    "diskUsed": used.2,
                },
            })),
        )
            .into_response()),
        Err(err) => Ok(bare_500(err)),
    }
}

/// Shared body of sync + baseline-sync. Returns (used, instanceCount).
async fn sync_host_resources(
    state: &SharedAppState,
    host: &HostRow,
) -> Result<((i64, i64, i64), i64), ApiError> {
    let host_id = host.id;
    let client = get_incus_client(state, host).await?;
    let resources = client.get_resources().await.map_err(|e| ApiError::internal(incus_error_message(&e)))?;
    update_host_status(state, host_id, "online").await?;
    let detected_ipv6 = extract_host_public_ipv6_from_resources(&resources);
    if let Some(detected) = &detected_ipv6 {
        if host.nat_public_ipv6.is_none() {
            sqlx::query("UPDATE hosts SET nat_public_ipv6 = $2 WHERE id = $1")
                .bind(host_id)
                .bind(detected)
                .execute(&state.db)
                .await?;
        }
    }
    let used = calculate_host_resources_from_instances(&state, host_id).await?;
    update_host_resources(
        state,
        host_id,
        HostResourceUpdate {
            cpu_used: Some(used.0),
            memory_used: Some(used.1),
            disk_used: Some(used.2),
            cpu_allowance_max: None,
            memory_max: None,
            instance_type: None,
            architecture: None,
        },
    )
    .await?;
    let instance_count = get_instance_count_by_host(state, host_id).await?;
    Ok((used, instance_count))
}

/// TS `catch` of /:id/sync returns 500 with { error } (not the apiError shape).
fn bare_500(err: ApiError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.error })),
    )
        .into_response()
}

// ===========================================================================
// POST /:id/instances/batch-delete-preview
// ===========================================================================

async fn batch_delete_preview(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_ids: Vec<i32> = body
        .get("instanceIds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_i64().map(|v| v as i32)).collect())
        .unwrap_or_default();
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instances: Vec<(i32, String, i32, String)> = sqlx::query_as(
        "SELECT i.id, i.name, i.user_id, u.username FROM instances i \
         JOIN users u ON u.id = i.user_id \
         WHERE i.id = ANY($1) AND i.host_id = $2 AND i.status <> 'deleted'",
    )
    .bind(&instance_ids)
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;

    let mut previews: Vec<Value> = Vec::new();
    let mut total_refund = 0.0f64;
    for (instance_id, name, instance_user_id, username) in instances {
        let row: (Option<Decimal>, Option<i32>, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT billing_price, billing_cycle, expires_at FROM instances WHERE id = $1",
        )
        .bind(instance_id)
        .fetch_one(&state.db)
        .await?;
        let mut conn = state.db.acquire().await?;
        let quote = billing::calculate_instance_refund(
            &mut conn,
            (instance_id, row.0, row.1, row.2),
        )
        .await?;
        let is_own_instance = instance_user_id == host.user_id;
        total_refund += if !is_own_instance && quote.is_paid {
            quote.refundable_value
        } else {
            0.0
        };
        previews.push(json!({
            "id": instance_id,
            "name": name,
            "username": username,
            "userId": instance_user_id,
            "isOwnInstance": is_own_instance,
            "isPaid": quote.is_paid,
            "remainingDays": quote.remaining_days,
            "refundAmount": quote.refundable_value,
        }));
    }

    Ok(Json(json!({
        "instances": previews,
        "totalRefundAmount": billing::round_currency(total_refund),
    })))
}

// ===========================================================================
// DELETE /:id/instances/batch — 批量删除宿主机上的实例
// ===========================================================================

/// Broad instance row for the batch endpoints.
#[derive(Debug, Clone, sqlx::FromRow)]
struct BatchInstanceRow {
    pub id: i32,
    pub incus_id: String,
    pub name: String,
    pub user_id: i32,
    pub host_id: i32,
    pub package_id: Option<i32>,
    pub package_plan_id: Option<i32>,
    pub billing_mode: String,
    pub status: String,
    pub cpu: i32,
    pub memory: i32,
    pub disk: i32,
    pub network_mode: String,
    pub port_limit: Option<i32>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub suspend_reason: Option<String>,
}

const BATCH_INSTANCE_COLUMNS: &str =
    "id, incus_id, name, user_id, host_id, package_id, package_plan_id, \
     billing_mode::text AS billing_mode, status::text AS status, cpu, memory, disk, \
     network_mode::text AS network_mode, port_limit, ipv4, ipv6, suspend_reason";

async fn get_batch_instances(
    state: &SharedAppState,
    instance_ids: &[i32],
    host_id: i32,
    filter: &str,
) -> Result<Vec<BatchInstanceRow>, ApiError> {
    sqlx::query_as::<_, BatchInstanceRow>(&format!(
        "SELECT {BATCH_INSTANCE_COLUMNS} FROM instances \
         WHERE id = ANY($1) AND host_id = $2 AND {filter}"
    ))
    .bind(instance_ids)
    .bind(host_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from_sql)
}

async fn batch_delete_instances(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_ids: Vec<i32> = body
        .get("instanceIds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_i64().map(|v| v as i32)).collect())
        .unwrap_or_default();
    let reason = body.get("reason").and_then(Value::as_str).unwrap_or("").to_string();
    let database_only = body.get("databaseOnly") == Some(&Value::Bool(true));

    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }

    let instances = get_batch_instances(&state, &instance_ids, host_id, "status <> 'deleted'").await?;
    if instances.is_empty() {
        return Ok(bare_bad_request("没有找到可删除的实例"));
    }

    if database_only {
        let paid: Vec<i32> = instances
            .iter()
            .filter(|i| i.package_plan_id.is_some() || i.billing_mode == "hourly")
            .map(|i| i.id)
            .collect();
        if !paid.is_empty() {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "仅数据库删除不能处理付费实例；必须先确认宿主机上的 Incus 实例已删除",
                    "code": "REMOTE_DELETION_REQUIRED_FOR_REFUND",
                    "instanceIds": paid,
                })),
            )
                .into_response());
        }
    }

    let mut results: Vec<Value> = Vec::new();
    let mut total_refund = 0.0f64;
    let mut client: Option<Arc<IncusClient>> = None;
    if !database_only {
        client = get_incus_client(&state, &host).await.ok();
    }
    let mut deferred_notifications: Vec<(i32, Value)> = Vec::new();

    for instance in &instances {
        let mut deletion_claimed = false;
        let mut remote_deletion_confirmed = false;
        let mut requested_refund_amount = 0.0f64;
        let mut refund_amount = 0.0f64;
        match delete_batch_one(
            &state,
            &host,
            instance,
            database_only,
            client.as_deref(),
            &reason,
            &mut deletion_claimed,
            &mut remote_deletion_confirmed,
            &mut requested_refund_amount,
            &mut refund_amount,
            &mut deferred_notifications,
        )
        .await
        {
            Ok(()) => {
                total_refund += refund_amount;
                results.push(json!({
                    "id": instance.id,
                    "name": instance.name,
                    "success": true,
                    "refundAmount": if refund_amount > 0.0 { Some(refund_amount) } else { None },
                }));
                create_log(
                    &state,
                    user.id,
                    "instance",
                    "instance.batch_delete",
                    &format!(
                        "Batch deleted instance \"{}\" on host \"{}\"{}{}",
                        instance.name,
                        host.name,
                        if database_only { " (panel-only; host was not contacted)" } else { "" },
                        if refund_amount > 0.0 { format!(" (refund: ¥{refund_amount:.2})") } else { String::new() },
                    ),
                    "success",
                )
                .await;
            }
            Err(message) => {
                if deletion_claimed && !remote_deletion_confirmed {
                    let _ = sqlx::query(
                        "UPDATE instances SET status = $2::\"InstanceStatus\", version = version + 1, \
                         deletion_billing_pending = false, deletion_remote_deleted = false, \
                         deletion_billing_mode = NULL, deletion_refundable_value = NULL, \
                         deletion_fee_waiver = false \
                         WHERE id = $1 AND status = 'deleted'::\"InstanceStatus\" AND deletion_billing_pending = true",
                    )
                    .bind(instance.id)
                    .bind(&instance.status)
                    .execute(&state.db)
                    .await;
                }
                results.push(json!({
                    "id": instance.id,
                    "name": instance.name,
                    "success": false,
                    "error": message,
                }));
                tracing::error!("批量删除实例失败 ({}): {message}", instance.name);
            }
        }
    }

    // Release notifications per packageId (external fan-out not ported).
    let mut release_map: HashMap<i32, (i64, i64, i64)> = HashMap::new();
    for instance in &instances {
        let success = results
            .iter()
            .any(|r| r["id"].as_i64() == Some(instance.id as i64) && r["success"].as_bool() == Some(true));
        if success {
            if let Some(package_id) = instance.package_id {
                let entry = release_map.entry(package_id).or_insert((0, 0, 0));
                entry.0 += instance.cpu as i64;
                entry.1 += instance.memory as i64;
                entry.2 += 1;
            }
        }
    }
    for (package_id, released) in release_map {
        send_release_notification(
            package_id,
            released.0,
            released.1,
            &format!("节点所有者批量删除 {} 个实例", released.2),
        );
    }

    if let Ok(used) = calculate_host_resources_from_instances(&state, host_id).await {
        let reserved = reserved_nat_ports(&state.db, host_id).await.unwrap_or(0);
        let _ = update_host_resources(
            &state,
            host_id,
            HostResourceUpdate {
                cpu_used: Some(used.0),
                memory_used: Some(used.1),
                disk_used: Some(used.2),
                cpu_allowance_max: None,
                memory_max: None,
                instance_type: None,
                architecture: None,
            },
        )
        .await;
        let _ = sqlx::query("UPDATE hosts SET nat_ports_used_count = $2 WHERE id = $1")
            .bind(host_id)
            .bind(reserved as i32)
            .execute(&state.db)
            .await;
    }

    let success_count = results.iter().filter(|r| r["success"].as_bool() == Some(true)).count();
    let failed_count = results.len() - success_count;

    for (user_id, data) in deferred_notifications {
        let state = state.clone();
        tokio::spawn(async move {
            send_notification(&state, user_id, "instance_deleted_by_host_owner", &data).await;
        });
    }

    Ok(Json(json!({
        "message": format!(
            "成功删除 {success_count} 个实例{}{}",
            if failed_count > 0 { format!("，{failed_count} 个失败") } else { String::new() },
            if total_refund > 0.0 { format!("，共退款 ¥{total_refund:.2}") } else { String::new() }
        ),
        "results": results,
        "successCount": success_count,
        "failedCount": failed_count,
        "totalRefundAmount": billing::round_currency(total_refund),
    })).into_response())
}

/// One iteration of the TS batch-delete loop. `Err(message)` = per-instance
/// failure string, exactly like the TS try/catch.
#[allow(clippy::too_many_arguments)]
async fn delete_batch_one(
    state: &SharedAppState,
    host: &HostRow,
    instance: &BatchInstanceRow,
    database_only: bool,
    client: Option<&IncusClient>,
    reason: &str,
    deletion_claimed: &mut bool,
    remote_deletion_confirmed: &mut bool,
    requested_refund_amount: &mut f64,
    refund_amount: &mut f64,
    deferred_notifications: &mut Vec<(i32, Value)>,
) -> Result<(), String> {
    if has_pending_transfer(state, instance.id).await.map_err(|e| format!("{e}"))? {
        return Err("实例有待处理的转移请求".to_string());
    }
    let active_restore: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM restore_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING') LIMIT 1",
    )
    .bind(instance.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("{e}"))?;
    if active_restore.is_some() {
        return Err("实例有正在进行的恢复任务".to_string());
    }
    let active_upload: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM backup_upload_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING') LIMIT 1",
    )
    .bind(instance.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("{e}"))?;
    if active_upload.is_some() {
        return Err("实例有正在进行的上传任务".to_string());
    }

    let needs_privileged_refund = !database_only
        && instance.user_id != host.user_id
        && instance.package_plan_id.is_some()
        && instance.billing_mode != "hourly";
    let needs_hourly_closure = !database_only && instance.billing_mode == "hourly";
    if needs_privileged_refund || needs_hourly_closure {
        let claimed = claim_instance_for_delete(
            state,
            instance.id,
            &instance.status,
            true,
            Some(if needs_privileged_refund {
                "privileged_delete"
            } else {
                "hourly_close"
            }),
        )
        .await
        .map_err(|e| format!("{e}"))?;
        if !claimed {
            return Err("实例正在删除或已删除".to_string());
        }
        *deletion_claimed = true;

        if needs_privileged_refund {
            let billing_row: (Option<Decimal>, Option<i32>, Option<DateTime<Utc>>) = sqlx::query_as(
                "SELECT billing_price, billing_cycle, expires_at FROM instances WHERE id = $1",
            )
            .bind(instance.id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| format!("{e}"))?;
            let mut conn = state.db.acquire().await.map_err(|e| format!("{e}"))?;
            let quote = billing::calculate_instance_refund(
                &mut conn,
                (instance.id, billing_row.0, billing_row.1, billing_row.2),
            )
            .await
            .map_err(|e| format!("{e}"))?;
            *requested_refund_amount = if quote.is_paid { quote.refundable_value } else { 0.0 };
            sqlx::query("UPDATE instances SET deletion_refundable_value = $2 WHERE id = $1")
                .bind(instance.id)
                .bind(Decimal::from_f64_retain(*requested_refund_amount).unwrap_or_default())
                .execute(&state.db)
                .await
                .map_err(|e| format!("{e}"))?;
        }
    }

    if !database_only {
        let Some(client) = client else {
            return Err("Incus client unavailable".to_string());
        };
        ensure_instance_deleted(client, &instance.incus_id)
            .await
            .map_err(|e| incus_error_message(&e))?;
        *remote_deletion_confirmed = true;
        if *deletion_claimed {
            sqlx::query("UPDATE instances SET deletion_remote_deleted = true WHERE id = $1")
                .bind(instance.id)
                .execute(&state.db)
                .await
                .map_err(|e| format!("{e}"))?;
        }
    }

    if needs_hourly_closure {
        close_hourly_billing(state, instance.id).await.map_err(|e| format!("{e}"))?;
        billing::complete_hourly_deletion_billing(&state.db, instance.id)
            .await
            .map_err(|e| format!("{e}"))?;
    }

    if needs_privileged_refund {
        *refund_amount = billing::settle_privileged_deletion_billing(
            &state.db,
            instance.id,
            instance.user_id,
            instance.host_id,
            &instance.name,
            *requested_refund_amount,
            &format!("托管实例被批量删除退款：{}", instance.name),
        )
        .await
        .map_err(|e| format!("{e}"))?;
    }

    // 1. Proxy sites (Caddy remote in full mode; DB rows always).
    let proxy_sites = get_proxy_sites_by_instance_id(&state.db, instance.id)
        .await
        .map_err(|e| format!("{e}"))?;
    if !proxy_sites.is_empty() {
        if !database_only && host.caddy_enabled && host.caddy_username.is_some() && host.caddy_password.is_some() {
            if let Some(target_host) = host.nat_public_ip.clone().or_else(|| host.ip_address.clone()) {
                if let Ok(caddy_client) = CaddyClient::new(
                    &target_host,
                    host.caddy_port as i64,
                    host.caddy_username.as_deref().unwrap_or(""),
                    host.caddy_password.as_deref().unwrap_or(""),
                ) {
                    for site in &proxy_sites {
                        let _ = caddy_client.delete_site(&site.1).await;
                    }
                }
            }
        }
        for site in &proxy_sites {
            delete_proxy_site(&state.db, site.0).await.map_err(|e| format!("{e}"))?;
        }
    }

    // 2. Port mappings + Incus proxy devices.
    let mappings = get_port_mappings(&state.db, instance.id).await.map_err(|e| format!("{e}"))?;
    for (mapping_id, protocol, public_port) in mappings {
        if let Some(client) = client {
            let device_name = format!("proxy-{}-{}", protocol, public_port);
            let _ = remove_device(client, &instance.incus_id, &device_name).await;
        }
        delete_port_mapping(&state.db, mapping_id).await.map_err(|e| format!("{e}"))?;
    }

    // 3. Snapshots.
    let snapshots = get_snapshots_by_instance_id(&state.db, instance.id).await.map_err(|e| format!("{e}"))?;
    for (snapshot_id, incus_name) in snapshots {
        if let Some(client) = client {
            let _ = delete_snapshot(client, &instance.incus_id, &incus_name).await;
        }
        delete_snapshot_record(&state.db, snapshot_id).await.map_err(|e| format!("{e}"))?;
    }

    // 4. Backups.
    let backups = get_backups_by_instance_id(&state.db, instance.id).await.map_err(|e| format!("{e}"))?;
    for (backup_id, incus_name) in backups {
        if let Some(client) = client {
            let _ = delete_backup(client, &instance.incus_id, &incus_name).await;
        }
        delete_backup_record(&state.db, backup_id).await.map_err(|e| format!("{e}"))?;
    }

    // 5-5.4 policies / traffic / ip / task history / transfers (best effort).
    let _ = sqlx::query("DELETE FROM snapshot_policies WHERE instance_id = $1")
        .bind(instance.id)
        .execute(&state.db)
        .await;
    let _ = sqlx::query("DELETE FROM backup_policies WHERE instance_id = $1")
        .bind(instance.id)
        .execute(&state.db)
        .await;
    let _ = sqlx::query("DELETE FROM traffic_snapshots WHERE instance_id = $1")
        .bind(instance.id)
        .execute(&state.db)
        .await;
    let _ = sqlx::query("DELETE FROM daily_traffic WHERE instance_id = $1")
        .bind(instance.id)
        .execute(&state.db)
        .await;
    let _ = sqlx::query("DELETE FROM ip_addresses WHERE instance_id = $1")
        .bind(instance.id)
        .execute(&state.db)
        .await;
    let _ = sqlx::query("DELETE FROM ipv6_subnets WHERE instance_id = $1")
        .bind(instance.id)
        .execute(&state.db)
        .await;
    let _ = sqlx::query(
        "DELETE FROM restore_tasks WHERE instance_id = $1 AND status IN ('COMPLETED','FAILED')",
    )
    .bind(instance.id)
    .execute(&state.db)
    .await;
    let _ = sqlx::query(
        "DELETE FROM backup_upload_tasks WHERE instance_id = $1 AND status IN ('COMPLETED','FAILED')",
    )
    .bind(instance.id)
    .execute(&state.db)
    .await;
    let _ = sqlx::query(
        "UPDATE instance_transfers SET status = 'cancelled'::\"TransferStatus\", cancelled_at = now() \
         WHERE instance_id = $1 AND status = 'pending'::\"TransferStatus\"",
    )
    .bind(instance.id)
    .execute(&state.db)
    .await;

    // 8-9. status + resource release.
    update_instance_status(&state.db, instance.id, "deleted")
        .await
        .map_err(|e| format!("{e}"))?;
    let port_count = if matches!(
        instance.network_mode.as_str(),
        "nat" | "nat_ipv6" | "nat_ipv6_nat" | "ipv6_nat" | "ipv6_only"
    ) {
        instance.port_limit.unwrap_or(0) as i64
    } else {
        0
    };
    rollback_resources(
        state,
        instance.host_id,
        instance.cpu as i64,
        instance.memory as i64,
        instance.disk as i64,
        port_count,
    )
    .await
    .map_err(|e| format!("{e}"))?;

    // 10. notification.
    let delete_reason = reason.trim();
    let mut notification = json!({
        "instanceName": instance.name,
        "hostName": host.name,
    });
    let event_type = if !delete_reason.is_empty() {
        notification["deleteReason"] = json!(delete_reason);
        "instance_deleted_by_host_owner"
    } else {
        "instance_deleted"
    };
    if database_only {
        deferred_notifications.push((instance.user_id, notification));
    } else {
        send_notification(state, instance.user_id, event_type, &notification).await;
    }

    Ok(())
}

// ===========================================================================
// DELETE /:id — 删除宿主机
// ===========================================================================

async fn host_delete(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instance_count = get_instance_count_by_host(&state, host_id).await?;
    if instance_count > 0 {
        return Ok(bare_bad_request(format!(
            "该宿主机上还有 {instance_count} 个实例，请先删除或迁移实例"
        )));
    }
    state.incus_pool.remove_incus_client(host_id as i64).await;
    delete_host_record(&state, host_id).await?;
    create_log(
        &state,
        user.id,
        "host",
        "host.delete",
        &format!(
            "Deleted host \"{}\" [url: {}, location: {}]",
            host.name,
            host.url,
            host.location.as_deref().unwrap_or("N/A")
        ),
        "success",
    )
    .await;
    Ok(Json(json!({ "message": "Host deleted" })).into_response())
}

// ===========================================================================
// Storage pools CRUD
// ===========================================================================

async fn storage_pools_list(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let flow = async {
        let client = get_incus_client(&state, &host).await?;
        let pools = list_storage_pools(&client).await.map_err(ApiError::from)?;
        let db_pools = get_storage_pools(&state.db, host_id, false).await?;
        let purpose_map: HashMap<String, String> = db_pools
            .iter()
            .map(|p| (p.1.clone(), p.3.clone()))
            .collect();
        let mut pools_json: Vec<Value> = Vec::new();
        for pool in pools {
            let space = match get_storage_pool_resources(&client, &pool.name).await {
                Ok(resources) => json!(resources.space),
                Err(_) => Value::Null,
            };
            pools_json.push(json!({
                "name": pool.name,
                "driver": pool.driver,
                "status": pool.status.clone().unwrap_or_else(|| "Created".to_string()),
                "description": pool.description.clone().unwrap_or_default(),
                "purpose": purpose_map.get(&pool.name).cloned(),
                "config": pool.config.clone().unwrap_or_default(),
                "usedBy": pool.used_by.as_ref().map(|u| u.len()).unwrap_or(0),
                "space": space,
            }));
        }
        Ok::<_, ApiError>(pools_json)
    };
    match flow.await {
        Ok(pools) => Ok((StatusCode::OK, Json(json!({ "pools": pools }))).into_response()),
        Err(err) => Ok(bare_bad_request(format!("获取存储池列表失败: {err}"))),
    }
}

async fn storage_pool_create(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let name = body.get("name").and_then(Value::as_str).unwrap_or("").to_string();
    if name.is_empty() || name.chars().count() > 64 {
        return Ok(bare_bad_request("body/name must NOT have fewer than 1 characters"));
    }
    let driver = body.get("driver").and_then(Value::as_str).map(String::from);
    let source = body.get("source").and_then(Value::as_str).map(String::from);
    let size = body.get("size").and_then(Value::as_str).map(String::from);
    let zfs_pool_name = body.get("zfsPoolName").and_then(Value::as_str).map(String::from);
    let lvm_vg_name = body.get("lvmVgName").and_then(Value::as_str).map(String::from);
    let lvm_thinpool_name = body.get("lvmThinpoolName").and_then(Value::as_str).map(String::from);
    let lvm_use_thinpool = body.get("lvmUseThinpool").and_then(Value::as_bool);
    let description = body.get("description").and_then(Value::as_str).map(String::from);
    let purpose = body.get("purpose").and_then(Value::as_str).map(String::from);
    let use_existing = body.get("useExisting") == Some(&Value::Bool(true));
    let existing_source = body.get("existingSource").and_then(Value::as_str).map(String::from);

    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }

    let flow = async {
        let client = get_incus_client(&state, &host).await?;
        if use_existing {
            let existing: Option<i32> =
                sqlx::query_scalar("SELECT id FROM storage_pools WHERE host_id = $1 AND name = $2")
                    .bind(host_id)
                    .bind(&name)
                    .fetch_optional(&state.db)
                    .await
                    .map_err(ApiError::from)?;
            if existing.is_some() {
                return Err(ApiError::internal(format!("存储池 \"{name}\" 已在系统中关联")));
            }
            let pool_info = get_storage_pool(&client, &name).await.ok();
            if let Some(info) = pool_info {
                create_storage_pool_record(
                    &state.db,
                    host_id,
                    &name,
                    &info.driver,
                    purpose.as_deref().unwrap_or("instance_data"),
                    description.as_deref().or(info.description.as_deref()),
                    &json!(info.config.clone().unwrap_or_default()),
                )
                .await
                .map_err(ApiError::from)?;
                create_log(
                    &state,
                    user.id,
                    "host",
                    "storage.link",
                    &format!("Linked existing storage pool \"{name}\" ({}) on host \"{}\"", info.driver, host.name),
                    "success",
                )
                .await;
                return Ok(json!({ "message": "存储池关联成功", "name": name, "driver": info.driver }));
            }
            let Some(driver) = driver.clone() else {
                return Err(ApiError::internal(format!(
                    "存储池 \"{name}\" 在 Incus 中不存在。如需导入底层已有的存储池，请选择驱动类型并提供存储源名称。"
                )));
            };
            if (driver == "btrfs" || driver == "dir") && existing_source.is_none() {
                return Err(ApiError::internal(format!("{} 类型必须提供底层存储源路径", driver.to_uppercase())));
            }
            let source_value = existing_source.clone().unwrap_or_else(|| name.clone());
            let mut import_config = Map::new();
            import_config.insert("source".to_string(), json!(source_value));
            if driver == "lvm" {
                import_config.insert("lvm.use_thinpool".to_string(), json!("false"));
            }
            create_storage_pool(
                &client,
                &CreateStoragePoolOptions {
                    name: name.clone(),
                    driver: driver.clone(),
                    config: import_config.clone(),
                    description: None,
                },
            )
            .await
            .map_err(ApiError::from)?;
            let imported = get_storage_pool(&client, &name).await.map_err(ApiError::from)?;
            create_storage_pool_record(
                &state.db,
                host_id,
                &name,
                &driver,
                purpose.as_deref().unwrap_or("instance_data"),
                description.as_deref(),
                &json!(imported.config.clone().unwrap_or(import_config)),
            )
            .await
            .map_err(ApiError::from)?;
            create_log(
                &state,
                user.id,
                "host",
                "storage.import",
                &format!(
                    "Imported existing {} storage \"{}\" as pool \"{name}\" on host \"{}\"",
                    driver.to_uppercase(),
                    source_value,
                    host.name
                ),
                "success",
            )
            .await;
            return Ok(json!({
                "message": "存储池导入成功",
                "name": name,
                "driver": driver,
                "imported": true,
            }));
        }

        let Some(driver) = driver.clone() else {
            return Err(ApiError::internal("创建新存储池需要指定驱动类型"));
        };
        let mut config = Map::new();
        match driver.as_str() {
            "zfs" => {
                if let Some(source) = &source {
                    config.insert("source".to_string(), json!(source));
                } else if let Some(size) = &size {
                    config.insert("size".to_string(), json!(size));
                } else {
                    return Err(ApiError::internal("ZFS 需要指定 source（物理盘）或 size（Loop 文件）"));
                }
                if let Some(pool_name) = &zfs_pool_name {
                    config.insert("zfs.pool_name".to_string(), json!(pool_name));
                }
            }
            "lvm" => {
                if let Some(source) = &source {
                    config.insert("source".to_string(), json!(source));
                } else if let Some(size) = &size {
                    config.insert("size".to_string(), json!(size));
                } else {
                    return Err(ApiError::internal("LVM 需要指定 source（物理盘）或 size（Loop 文件）"));
                }
                if let Some(vg) = &lvm_vg_name {
                    config.insert("lvm.vg_name".to_string(), json!(vg));
                }
                if let Some(tp) = &lvm_thinpool_name {
                    config.insert("lvm.thinpool_name".to_string(), json!(tp));
                }
                config.insert(
                    "lvm.use_thinpool".to_string(),
                    json!(if lvm_use_thinpool != Some(false) { "true" } else { "false" }),
                );
            }
            "btrfs" => {
                if let Some(source) = &source {
                    config.insert("source".to_string(), json!(source));
                } else if let Some(size) = &size {
                    config.insert("size".to_string(), json!(size));
                } else {
                    return Err(ApiError::internal("Btrfs 需要指定 source（物理盘）或 size（Loop 文件）"));
                }
            }
            "dir" => {
                let Some(source) = &source else {
                    return Err(ApiError::internal("DIR 需要指定 source（目录路径）"));
                };
                config.insert("source".to_string(), json!(source));
            }
            _ => return Err(ApiError::internal("创建新存储池需要指定驱动类型")),
        }
        create_storage_pool(
            &client,
            &CreateStoragePoolOptions {
                name: name.clone(),
                driver: driver.clone(),
                config: config.clone(),
                description: None,
            },
        )
        .await
        .map_err(ApiError::from)?;
        create_storage_pool_record(
            &state.db,
            host_id,
            &name,
            &driver,
            purpose.as_deref().unwrap_or("instance_data"),
            description.as_deref(),
            &Value::Object(config),
        )
        .await
        .map_err(ApiError::from)?;
        create_log(
            &state,
            user.id,
            "host",
            "storage.create",
            &format!("Created storage pool \"{name}\" ({driver}) on host \"{}\"", host.name),
            "success",
        )
        .await;
        Ok(json!({ "message": "存储池创建成功", "name": name }))
    };

    match flow.await {
        Ok(payload) => Ok((StatusCode::CREATED, Json(payload)).into_response()),
        Err(err) => Ok(bare_bad_request(format!("创建存储池失败: {err}"))),
    }
}

async fn storage_pool_delete(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, pool_name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let flow = async {
        let client = get_incus_client(&state, &host).await?;
        delete_storage_pool(&client, &pool_name)
            .await
            .map_err(ApiError::from)?;
        delete_storage_pool_records(&state.db, host_id, &pool_name)
            .await
            .map_err(ApiError::from)?;
        create_log(
            &state,
            user.id,
            "host",
            "storage.delete",
            &format!("Deleted storage pool \"{pool_name}\" from host \"{}\"", host.name),
            "success",
        )
        .await;
        Ok::<_, ApiError>(())
    };
    match flow.await {
        Ok(()) => Ok((StatusCode::OK, Json(json!({ "message": "存储池删除成功" }))).into_response()),
        Err(err) => Ok(bare_bad_request(format!("删除存储池失败: {err}"))),
    }
}

async fn storage_pool_update(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, pool_name)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let size = body.get("size").and_then(Value::as_str).map(String::from);
    let description = body.get("description").and_then(Value::as_str).map(String::from);
    let purpose = body.get("purpose").and_then(Value::as_str).map(String::from);
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    if size.is_none() && description.is_none() && purpose.is_none() {
        return Ok(bare_bad_request("请提供要修改的内容"));
    }
    let flow = async {
        let client = get_incus_client(&state, &host).await?;
        let mut config = Map::new();
        if let Some(size) = &size {
            config.insert("size".to_string(), json!(size));
        }
        update_storage_pool(
            &client,
            &pool_name,
            &UpdateStoragePoolOptions {
                config: if config.is_empty() { None } else { Some(config) },
                description: description.clone(),
            },
        )
        .await
        .map_err(ApiError::from)?;
        if description.is_some() || purpose.is_some() {
            update_storage_pool_record(&state.db, host_id, &pool_name, Some(description), purpose.as_deref())
                .await
                .map_err(ApiError::from)?;
        }
        create_log(
            &state,
            user.id,
            "host",
            "storage.update",
            &format!("Updated storage pool \"{pool_name}\" on host \"{}\"", host.name),
            "success",
        )
        .await;
        Ok::<_, ApiError>(())
    };
    match flow.await {
        Ok(()) => Ok((StatusCode::OK, Json(json!({ "message": "存储池修改成功" }))).into_response()),
        Err(err) => Ok(bare_bad_request(format!("修改存储池失败: {err}"))),
    }
}

// ===========================================================================
// Caddy suite
// ===========================================================================

fn caddy_panel_url() -> String {
    std::env::var("FRONTEND_URL")
        .ok()
        .and_then(|v| v.split(',').next().map(|s| s.trim().to_string()))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://incudal.com".to_string())
}

async fn caddy_status(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let sites_count = get_proxy_site_count_by_host(&state, host_id).await?;
    Ok(Json(json!({
        "enabled": host.caddy_enabled,
        "username": host.caddy_username,
        "port": host.caddy_port,
        "hasPassword": host.caddy_password.is_some(),
        "natPublicIp": host.nat_public_ip.clone().or(host.ip_address.clone()),
        "sitesCount": sites_count,
    })).into_response())
}

fn build_caddy_install_command(host_id: i32, jwt_secret: &str, username: &str, password: &str, port: i32) -> String {
    let script_token = generate_caddy_script_token(jwt_secret, host_id);
    let panel_url = caddy_panel_url();
    format!(
        "curl -sSL \"{panel_url}/api/hosts/caddy-script/{script_token}\" | sudo bash -s -- --username \"{username}\" --password \"{password}\" --port {port}"
    )
}

async fn caddy_generate(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let mut username = host.caddy_username.clone();
    let mut password = host.caddy_password.clone();
    let port = if host.caddy_port != 0 { host.caddy_port } else { 8444 };
    let mut is_new_credentials = false;
    if username.is_none() || password.is_none() {
        username = Some(format!("caddy_{}", caddy_random_string(8)));
        password = Some(caddy_random_string(24));
        is_new_credentials = true;
        sqlx::query(
            "UPDATE hosts SET caddy_username = $2, caddy_password = $3, caddy_port = $4 WHERE id = $1",
        )
        .bind(host_id)
        .bind(&username)
        .bind(&password)
        .bind(port)
        .execute(&state.db)
        .await?;
        create_log(
            &state,
            user.id,
            "host",
            "caddy.generate",
            &format!("Generated Caddy credentials for host \"{}\"", host.name),
            "success",
        )
        .await;
    }
    let username = username.unwrap_or_default();
    let password = password.unwrap_or_default();
    let install_command =
        build_caddy_install_command(host_id, &state.config.jwt_secret, &username, &password, port);
    Ok(Json(json!({
        "installCommand": install_command,
        "username": username,
        "password": password,
        "port": port,
        "isNewCredentials": is_new_credentials,
    })))
}

async fn caddy_reset(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let username = format!("caddy_{}", caddy_random_string(8));
    let password = caddy_random_string(24);
    let port = if host.caddy_port != 0 { host.caddy_port } else { 8444 };
    sqlx::query(
        "UPDATE hosts SET caddy_username = $2, caddy_password = $3, caddy_port = $4, \
         caddy_enabled = false WHERE id = $1",
    )
    .bind(host_id)
    .bind(&username)
    .bind(&password)
    .bind(port)
    .execute(&state.db)
    .await?;
    let install_command =
        build_caddy_install_command(host_id, &state.config.jwt_secret, &username, &password, port);
    create_log(
        &state,
        user.id,
        "host",
        "caddy.reset",
        &format!("Reset Caddy credentials for host \"{}\"", host.name),
        "success",
    )
    .await;
    Ok(Json(json!({
        "installCommand": install_command,
        "username": username,
        "password": password,
        "port": port,
    })))
}

/// createCaddyClient equivalent; None when no public target is configured.
fn caddy_client_for_host(host: &HostRow) -> Result<CaddyClient, String> {
    let target = host
        .nat_public_ip
        .clone()
        .or_else(|| host.ip_address.clone())
        .ok_or_else(|| "宿主机未配置公网 IP".to_string())?;
    CaddyClient::new(
        &target,
        if host.caddy_port != 0 { host.caddy_port as i64 } else { 8444 },
        host.caddy_username.as_deref().unwrap_or(""),
        host.caddy_password.as_deref().unwrap_or(""),
    )
}

async fn caddy_confirm(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    if host.caddy_username.is_none() || host.caddy_password.is_none() {
        return Ok(bare_bad_request("请先生成安装命令"));
    }
    let client = match caddy_client_for_host(&host) {
        Ok(client) => client,
        Err(message) => return Ok(bare_bad_request(message)),
    };
    if !client.test_connection().await {
        return Ok(bare_bad_request("无法连接到 Caddy，请确认已执行安装命令"));
    }
    sqlx::query("UPDATE hosts SET caddy_enabled = true WHERE id = $1")
        .bind(host_id)
        .execute(&state.db)
        .await?;
    create_log(
        &state,
        user.id,
        "host",
        "caddy.confirm",
        &format!("Confirmed Caddy installation for host \"{}\"", host.name),
        "success",
    )
    .await;
    Ok((StatusCode::OK, Json(json!({ "message": "Caddy 已确认安装" }))).into_response())
}

async fn caddy_script_download(
    State(state): State<SharedAppState>,
    Path(token): Path<String>,
) -> Response {
    let Some(host_id) = verify_caddy_script_token(&state.config.jwt_secret, &token) else {
        return text_response(StatusCode::FORBIDDEN, "# Error: Invalid or expired token".into());
    };
    let exists: Option<i32> = sqlx::query_scalar("SELECT id FROM hosts WHERE id = $1")
        .bind(host_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
    if exists.is_none() {
        return text_response(StatusCode::NOT_FOUND, "# Error: Host not found".into());
    }
    match std::fs::read_to_string(format!("{}/caddy.sh", template_root())) {
        Ok(content) => text_response(StatusCode::OK, content),
        Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "# Error: Failed to read script".into()),
    }
}

async fn caddy_test(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    if !host.caddy_enabled || host.caddy_username.is_none() || host.caddy_password.is_none() {
        return Ok(bare_bad_request("Caddy 未启用"));
    }
    let client = match caddy_client_for_host(&host) {
        Ok(client) => client,
        Err(message) => return Ok(bare_bad_request(message)),
    };
    let connected = client.test_connection().await;
    let sites_count = if connected { client.get_sites().await.len() } else { 0 };
    let dns_target = host
        .nat_public_ip
        .clone()
        .or_else(|| host.ip_address.clone())
        .unwrap_or_default();
    Ok((
        StatusCode::OK,
        Json(json!({
            "connected": connected,
            "sitesCount": sites_count,
            "dnsRecordType": get_dns_record_type(&dns_target).as_str(),
            "dnsRecordValue": dns_target,
        })),
    )
        .into_response())
}

async fn caddy_sites(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let (page, page_size) = parse_pagination(&params, 10, Some(100));
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let all_sites = get_proxy_sites_by_host_id(&state, host_id).await?;
    let total = all_sites.len() as i64;
    let total_pages = if total > 0 { (total + page_size - 1) / page_size } else { 0 };
    let start = ((page - 1) * page_size) as usize;
    let paginated: Vec<Value> = all_sites
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .collect();
    Ok(Json(json!({
        "sites": paginated,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "totalPages": total_pages,
    })))
}

// ===========================================================================
// POST /:id/instances/sync-status — 批量同步实例状态
// ===========================================================================

async fn batch_sync_status(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_ids: Vec<i32> = body
        .get("instanceIds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_i64().map(|v| v as i32)).collect())
        .unwrap_or_default();
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instances =
        get_batch_instances(&state, &instance_ids, host_id, "status NOT IN ('deleted','creating')").await?;
    if instances.is_empty() {
        return Ok(bare_bad_request("没有找到可同步的实例"));
    }
    let client = match get_incus_client(&state, &host).await {
        Ok(client) => client,
        Err(err) => {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": format!("无法连接到节点: {}", err.error) })),
            )
                .into_response());
        }
    };

    let mut results: Vec<Value> = Vec::new();
    let mut synced_count = 0i64;
    let mut changed_count = 0i64;
    let mut ipv4_changed_count = 0i64;
    let mut ipv6_changed_count = 0i64;

    for instance in &instances {
        match sync_one_instance_status(&state, &host, &client, instance).await {
            Ok(InstanceSyncOutcome::Deleted(payload)) => {
                changed_count += 1;
                synced_count += 1;
                results.push(payload);
            }
            Ok(InstanceSyncOutcome::Synced {
                mut payload,
                status_changed,
                ipv4_changed,
                ipv6_changed,
            }) => {
                if status_changed {
                    changed_count += 1;
                }
                if ipv4_changed {
                    ipv4_changed_count += 1;
                }
                if ipv6_changed {
                    ipv6_changed_count += 1;
                }
                payload["id"] = json!(instance.id);
                payload["name"] = json!(instance.name);
                payload["success"] = json!(payload.get("error").is_none());
                results.push(payload);
                synced_count += 1;
            }
            Err(message) => {
                results.push(json!({
                    "id": instance.id,
                    "name": instance.name,
                    "success": false,
                    "error": message,
                }));
            }
        }
    }

    // Recompute host usage when instances were deleted remotely.
    let has_deleted = results
        .iter()
        .any(|r| r["to"].as_str() == Some("deleted"));
    if has_deleted {
        if let Ok(used) = calculate_host_resources_from_instances(&state, host_id).await {
            let reserved = reserved_nat_ports(&state.db, host_id).await.unwrap_or(0);
            let _ = update_host_resources(
                &state,
                host_id,
                HostResourceUpdate {
                    cpu_used: Some(used.0),
                    memory_used: Some(used.1),
                    disk_used: Some(used.2),
                    cpu_allowance_max: None,
                    memory_max: None,
                    instance_type: None,
                    architecture: None,
                },
            )
            .await;
            let _ = sqlx::query("UPDATE hosts SET nat_ports_used_count = $2 WHERE id = $1")
                .bind(host_id)
                .bind(reserved as i32)
                .execute(&state.db)
                .await;
        }
    }

    create_log(
        &state,
        user.id,
        "host",
        "host.sync_instance_status",
        &format!(
            "Synced {synced_count} instances on host \"{}\", {changed_count} status changed, {ipv4_changed_count} IPv4 changed, {ipv6_changed_count} IPv6 changed",
            host.name
        ),
        "success",
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(json!({
            "message": "同步完成",
            "results": results,
            "syncedCount": synced_count,
            "changedCount": changed_count,
            "ipv4ChangedCount": ipv4_changed_count,
            "ipv6ChangedCount": ipv6_changed_count,
            "failedCount": instances.len() as i64 - synced_count,
        })),
    )
        .into_response())
}

enum InstanceSyncOutcome {
    Deleted(Value),
    Synced {
        payload: Value,
        status_changed: bool,
        ipv4_changed: bool,
        ipv6_changed: bool,
    },
}

/// Sync one instance for batch_sync_status.
async fn sync_one_instance_status(
    state: &SharedAppState,
    host: &HostRow,
    client: &IncusClient,
    instance: &BatchInstanceRow,
) -> Result<InstanceSyncOutcome, String> {
    let state_result = async {
        let st = get_instance_state(client, &instance.incus_id).await?;
        let inst = get_instance(client, &instance.incus_id).await?;
        Ok::<_, IncusError>((st, inst))
    }
    .await;
    let (incus_state, incus_instance) = match state_result {
        Ok(v) => v,
        Err(err) => {
            let message = incus_error_message(&err);
            if message.contains("not found") || message.contains("Instance not found") {
                // Instance gone from Incus: mark deleted + rollback.
                if instance.billing_mode == "hourly" {
                    close_hourly_billing(state, instance.id).await.map_err(|e| format!("{e}"))?;
                }
                update_instance_status(&state.db, instance.id, "deleted")
                    .await
                    .map_err(|e| format!("{e}"))?;
                let port_count = if matches!(
                    instance.network_mode.as_str(),
                    "nat" | "nat_ipv6" | "nat_ipv6_nat" | "ipv6_nat" | "ipv6_only"
                ) {
                    instance.port_limit.unwrap_or(0) as i64
                } else {
                    0
                };
                rollback_resources(
                    state,
                    instance.host_id,
                    instance.cpu as i64,
                    instance.memory as i64,
                    instance.disk as i64,
                    port_count,
                )
                .await
                .map_err(|e| format!("{e}"))?;
                return Ok(InstanceSyncOutcome::Deleted(json!({
                    "from": instance.status,
                    "to": "deleted",
                })));
            }
            return Err(message);
        }
    };

    let raw_status = incus_state
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if raw_status.is_empty() {
        return Ok(InstanceSyncOutcome::Synced {
            payload: json!({ "error": "无法获取实例状态" }),
            status_changed: false,
            ipv4_changed: false,
            ipv6_changed: false,
        });
    }
    let incus_status = map_instance_status(raw_status);
    if incus_status == "unknown" {
        return Ok(InstanceSyncOutcome::Synced {
            payload: json!({ "error": format!("未知状态: {raw_status}") }),
            status_changed: false,
            ipv4_changed: false,
            ipv6_changed: false,
        });
    }

    let mut payload = json!({});
    let mut status_changed = false;
    if instance.status != incus_status {
        update_instance_status(&state.db, instance.id, incus_status)
            .await
            .map_err(|e| format!("{e}"))?;
        payload["from"] = json!(instance.status);
        payload["to"] = json!(incus_status);
        status_changed = true;
    }

    let target = InstanceNetworkSyncTarget {
        id: instance.id as i64,
        name: Some(instance.name.clone()),
        host_id: Some(host.id as i64),
        network_mode: Some(instance.network_mode.clone()),
        ipv4: instance.ipv4.clone(),
        ipv6: instance.ipv6.clone(),
    };
    let (ipv4_changed, _old_v4, new_v4, ipv6_changed, _old_v6, new_v6) = persist_network_addresses(
        state,
        &target,
        instance.ipv4.clone(),
        instance.ipv6.clone(),
        Some(&Value::Object(incus_instance.devices.clone())),
        Some(&Value::Object(incus_instance.expanded_devices.clone())),
        Some(&incus_state),
        true,
    )
    .await
    .map_err(|e| format!("{e}"))?;
    if ipv4_changed {
        payload["ipv4Changed"] = json!(true);
        payload["oldIpv4"] = json!(_old_v4);
        payload["newIpv4"] = json!(new_v4);
    }
    if ipv6_changed {
        payload["ipv6Changed"] = json!(true);
        payload["oldIpv6"] = json!(_old_v6);
        payload["newIpv6"] = json!(new_v6);
    }

    if ipv4_changed {
        if let Some(new_ipv4) = &new_v4 {
            let proxy_sites = get_proxy_sites_by_instance_id(&state.db, instance.id)
                .await
                .map_err(|e| format!("{e}"))?;
            if !proxy_sites.is_empty() && host.caddy_enabled && host.caddy_username.is_some() && host.caddy_password.is_some() {
                if let Some(caddy_target) = host.nat_public_ip.clone().or_else(|| host.ip_address.clone()) {
                    if let Ok(caddy_client) = CaddyClient::new(
                        &caddy_target,
                        if host.caddy_port != 0 { host.caddy_port as i64 } else { 8444 },
                        host.caddy_username.as_deref().unwrap_or(""),
                        host.caddy_password.as_deref().unwrap_or(""),
                    ) {
                        for site in &proxy_sites {
                            if site.4 == "active" && site.5 {
                                if caddy_client
                                    .add_site(&site.1, new_ipv4, site.2 as i64, site.3)
                                    .await
                                    .is_ok()
                                {
                                    payload["proxySitesUpdated"] = json!(payload["proxySitesUpdated"].as_i64().unwrap_or(0) + 1);
                                } else {
                                    tracing::error!("Failed to update proxy site \"{}\"", site.1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = status_changed;
    Ok(InstanceSyncOutcome::Synced {
        payload,
        status_changed,
        ipv4_changed,
        ipv6_changed,
    })
}

// ===========================================================================
// POST /:id/recalculate-resources
// ===========================================================================

async fn host_recalculate_resources(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let before = json!({
        "cpuUsed": host.cpu_used,
        "memoryUsed": host.memory_used,
        "diskUsed": host.disk_used,
        "natPortsUsedCount": host.nat_ports_used_count,
        "cpuAllowanceMax": host.cpu_allowance_max,
        "memoryMax": host.memory_max,
    });
    let used = calculate_host_resources_from_instances(&state, host_id).await?;
    let reserved = reserved_nat_ports(&state.db, host_id).await?;
    update_host_resources(
        &state,
        host_id,
        HostResourceUpdate {
            cpu_used: Some(used.0),
            memory_used: Some(used.1),
            disk_used: Some(used.2),
            cpu_allowance_max: None,
            memory_max: None,
            instance_type: None,
            architecture: None,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE hosts SET nat_ports_used_count = $2, cpu_allowance_max = $3, memory_max = $4 WHERE id = $1",
    )
    .bind(host_id)
    .bind(reserved as i32)
    .bind(used.0 as i32)
    .bind(used.1 as i32)
    .execute(&state.db)
    .await?;
    let after = json!({
        "cpuUsed": used.0,
        "memoryUsed": used.1,
        "diskUsed": used.2,
        "natPortsUsedCount": reserved,
        "cpuAllowanceMax": used.0,
        "memoryMax": used.1,
    });
    let diff = json!({
        "cpuUsed": used.0 - host.cpu_used as i64,
        "memoryUsed": used.1 - host.memory_used as i64,
        "diskUsed": used.2 - host.disk_used as i64,
        "natPortsUsedCount": reserved - host.nat_ports_used_count as i64,
        "cpuAllowanceMax": used.0 - host.cpu_allowance_max as i64,
        "memoryMax": used.1 - host.memory_max as i64,
    });
    let has_changes = diff.as_object().map(|m| m.values().any(|v| v.as_i64() != Some(0))).unwrap_or(false);
    create_log(
        &state,
        user.id,
        "host",
        "host.recalculate_resources",
        &format!(
            "Recalculated resources for host \"{}\": CPU {}→{}, Memory {}→{}, Disk {}→{}, Ports {}→{}, CPUMax {}→{}, MemMax {}→{}",
            host.name,
            host.cpu_used, used.0,
            host.memory_used, used.1,
            host.disk_used, used.2,
            host.nat_ports_used_count, reserved,
            host.cpu_allowance_max, used.0,
            host.memory_max, used.1,
        ),
        "success",
    )
    .await;
    Ok(Json(json!({
        "message": if has_changes { "资源校对完成，已修正差异" } else { "资源校对完成，无差异" },
        "hasChanges": has_changes,
        "before": before,
        "after": after,
        "diff": diff,
    })))
}

// ===========================================================================
// POST /:id/instances/suspend | /:id/instances/unsuspend
// ===========================================================================

async fn batch_suspend(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_ids: Vec<i32> = body
        .get("instanceIds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_i64().map(|v| v as i32)).collect())
        .unwrap_or_default();
    let reason = body.get("reason").and_then(Value::as_str).unwrap_or("").to_string();
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instances =
        get_batch_instances(&state, &instance_ids, host_id, "status NOT IN ('deleted','suspended')").await?;
    if instances.is_empty() {
        return Ok(bare_bad_request("没有找到可封停的实例"));
    }
    let client = get_incus_client(&state, &host).await.ok();

    let mut results: Vec<Value> = Vec::new();
    for instance in &instances {
        let outcome: Result<(), String> = async {
            if instance.status == "running" {
                match &client {
                    Some(client) => {
                        if let Err(stop_err) = stop_instance(
                            client,
                            &instance.incus_id,
                            true,
                            BusyRetryOptions {
                                allow_cancel_busy_update: false,
                                busy_update_cancel_after_ms: None,
                            },
                        )
                        .await
                        {
                            let message = incus_error_message(&stop_err);
                            tracing::error!("[BatchSuspend] Failed to stop instance {}: {message}", instance.id);
                            if instance.billing_mode == "hourly" {
                                return Err(
                                    "HOURLY_STOP_FAILED: 无法确认按小时计费实例已停止，未封停".to_string()
                                );
                            }
                        }
                    }
                    None => {
                        if instance.billing_mode == "hourly" {
                            return Err(
                                "HOURLY_STOP_FAILED: 宿主机连接不可用，未封停按小时计费实例".to_string()
                            );
                        }
                    }
                }
            }
            if instance.billing_mode == "hourly" {
                let pause = pause_hourly_billing(&state, instance.id).await.map_err(|e| format!("{e}"))?;
                if pause.suspended {
                    return Err(
                        "HOURLY_BALANCE_INSUFFICIENT: 按小时计费实例已有欠费，不能覆盖欠费封停状态".to_string(),
                    );
                }
            }
            suspend_instance_manually(&state, instance.id, user.id, &reason)
                .await
                .map_err(|e| format!("{e}"))?;
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => {
                create_log_with_instance(
                    &state,
                    user.id,
                    "instance",
                    "instance.suspend",
                    &format!(
                        "Batch suspended instance \"{}\"{}",
                        instance.name,
                        if reason.is_empty() { String::new() } else { format!(" (reason: {reason})") }
                    ),
                    "success",
                    instance.id,
                )
                .await;
                if instance.user_id != user.id {
                    send_notification(
                        &state,
                        instance.user_id,
                        "instance_suspended",
                        &json!({
                            "instanceName": instance.name,
                            "hostName": host.name,
                            "suspendReason": reason,
                        }),
                    )
                    .await;
                }
                results.push(json!({ "id": instance.id, "name": instance.name, "success": true }));
            }
            Err(message) => {
                tracing::error!("封停实例 {} 失败: {message}", instance.id);
                results.push(json!({ "id": instance.id, "name": instance.name, "success": false, "error": message }));
            }
        }
    }
    let success_count = results.iter().filter(|r| r["success"].as_bool() == Some(true)).count();
    let failed_count = results.len() - success_count;
    Ok(Json(json!({
        "message": "批量封停完成",
        "results": results,
        "successCount": success_count,
        "failedCount": failed_count,
    })).into_response())
}

async fn batch_unsuspend(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_ids: Vec<i32> = body
        .get("instanceIds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_i64().map(|v| v as i32)).collect())
        .unwrap_or_default();
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instances = get_batch_instances(&state, &instance_ids, host_id, "status = 'suspended'").await?;
    if instances.is_empty() {
        return Ok(bare_bad_request("没有找到可解封的实例"));
    }
    let mut results: Vec<Value> = Vec::new();
    for instance in &instances {
        if instance.billing_mode == "hourly" && instance.suspend_reason.as_deref() == Some("hourly_billing_insufficient_balance") {
            results.push(json!({
                "id": instance.id,
                "name": instance.name,
                "success": false,
                "error": "按小时计费欠款必须先由实例所有者结清",
            }));
            continue;
        }
        match unsuspend_instance(&state, instance.id).await {
            Ok(()) => {
                create_log_with_instance(
                    &state,
                    user.id,
                    "instance",
                    "instance.unsuspend",
                    &format!("Batch unsuspended instance \"{}\"", instance.name),
                    "success",
                    instance.id,
                )
                .await;
                if instance.user_id != user.id {
                    send_notification(
                        &state,
                        instance.user_id,
                        "instance_unsuspended",
                        &json!({
                            "instanceName": instance.name,
                            "hostName": host.name,
                        }),
                    )
                    .await;
                }
                results.push(json!({ "id": instance.id, "name": instance.name, "success": true }));
            }
            Err(err) => {
                results.push(json!({
                    "id": instance.id,
                    "name": instance.name,
                    "success": false,
                    "error": err.error,
                }));
            }
        }
    }
    let success_count = results.iter().filter(|r| r["success"].as_bool() == Some(true)).count();
    let failed_count = results.len() - success_count;
    Ok(Json(json!({
        "message": "批量解封完成",
        "results": results,
        "successCount": success_count,
        "failedCount": failed_count,
    })).into_response())
}

// ===========================================================================
// POST /:id/extend-all — 批量为付费实例免费延期（管理员）
// ===========================================================================

async fn host_extend_all(
    State(state): State<SharedAppState>,
    user: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let _ = user;
    let host_id = js_number_id(&id)?;
    let days = body_int(body.get("days")).unwrap_or(0);
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    let paid_instances: Vec<(i32, String, DateTime<Utc>, i32)> = sqlx::query_as(
        "SELECT id, name, expires_at, user_id FROM instances \
         WHERE host_id = $1 AND billing_mode = 'package'::\"InstanceBillingMode\" \
         AND package_plan_id IS NOT NULL AND status <> 'deleted' AND expires_at IS NOT NULL",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    if paid_instances.is_empty() {
        return Ok(Json(json!({
            "success": true,
            "message": "该节点下没有可延期的付费实例",
            "extendedCount": 0,
        })).into_response());
    }
    let days_ms = days * 24 * 60 * 60 * 1000;
    let mut extended_count = 0i64;
    let mut affected_users: Vec<i32> = Vec::new();
    for (instance_id, _name, expires_at, instance_user_id) in paid_instances {
        let new_expires_at = expires_at + chrono::Duration::milliseconds(days_ms);
        sqlx::query("UPDATE instances SET expires_at = $2 WHERE id = $1")
            .bind(instance_id)
            .bind(new_expires_at)
            .execute(&state.db)
            .await?;
        if !affected_users.contains(&instance_user_id) {
            affected_users.push(instance_user_id);
        }
        extended_count += 1;
    }
    create_log(
        &state,
        user.0.id,
        "host",
        "host.batch_extend",
        &format!(
            "Batch extended {extended_count} paid instances on host \"{}\" by {days} days",
            host.name
        ),
        "success",
    )
    .await;
    for user_id in affected_users {
        send_notification(
            &state,
            user_id,
            "instances_batch_extended",
            &json!({ "hostName": host.name, "days": days }),
        )
        .await;
    }
    Ok(Json(json!({
        "success": true,
        "message": format!("成功为 {extended_count} 个付费实例延期 {days} 天"),
        "extendedCount": extended_count,
    })).into_response())
}

// ===========================================================================
// POST /:id/takeover-official — 接管托管节点为自营（管理员）
// ===========================================================================

enum TakeoverError {
    HostNotFound,
    AlreadyOfficial,
    BindingConflict(Vec<String>),
    Sql(ApiError),
}

impl From<ApiError> for TakeoverError {
    fn from(err: ApiError) -> Self {
        TakeoverError::Sql(err)
    }
}

async fn host_takeover_official(
    State(state): State<SharedAppState>,
    user: AdminAuth,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let official_admin_id = user.0.id;

    let flow = async {
        let mut tx = state.db.begin().await.map_err(|e| TakeoverError::Sql(ApiError::from_sql(e)))?;
        let host: Option<(i32, String, i32, String, String)> = sqlx::query_as(
            "SELECT h.id, h.name, h.user_id, u.username, u.role::text AS role \
             FROM hosts h JOIN users u ON u.id = h.user_id WHERE h.id = $1",
        )
        .bind(host_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| TakeoverError::Sql(ApiError::from_sql(e)))?;
        let Some((hid, host_name, host_user_id, owner_username, owner_role)) = host else {
            return Err(TakeoverError::HostNotFound);
        };
        if owner_role == "admin" {
            return Err(TakeoverError::AlreadyOfficial);
        }
        let (instance_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM instances WHERE host_id = $1 AND status <> 'deleted'",
        )
        .bind(host_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| TakeoverError::Sql(ApiError::from_sql(e)))?;

        // Packages bound to this host with their owner + other bindings.
        let host_packages: Vec<(i32, String, i32, String)> = sqlx::query_as(
            "SELECT p.id, p.name, p.user_id, u.role::text AS role \
             FROM packages p \
             JOIN package_hosts ph ON ph.package_id = p.id \
             JOIN users u ON u.id = p.user_id \
             WHERE ph.host_id = $1",
        )
        .bind(host_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| TakeoverError::Sql(ApiError::from_sql(e)))?;

        let mut package_actions: Vec<(i32, String, i32, String, bool, bool)> = Vec::new();
        for (pkg_id, pkg_name, pkg_user_id, pkg_owner_role) in &host_packages {
            let other_bindings: Vec<(i32, String)> = sqlx::query_as(
                "SELECT ph.host_id, u.role::text AS role FROM package_hosts ph \
                 JOIN hosts h ON h.id = ph.host_id JOIN users u ON u.id = h.user_id \
                 WHERE ph.package_id = $1 AND ph.host_id <> $2",
            )
            .bind(pkg_id)
            .bind(host_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| TakeoverError::Sql(ApiError::from_sql(e)))?;
            let has_other_hosted = other_bindings.iter().any(|(_, role)| role != "admin");
            let can_transfer = pkg_owner_role != "admin"
                && *pkg_user_id == host_user_id
                && !has_other_hosted;
            package_actions.push((
                *pkg_id,
                pkg_name.clone(),
                *pkg_user_id,
                pkg_owner_role.clone(),
                can_transfer,
                !other_bindings.is_empty(),
            ));
        }

        let blocked: Vec<String> = package_actions
            .iter()
            .filter(|(_, _, _, role, can_transfer, has_others)| {
                role != "admin" && !can_transfer && !has_others
            })
            .map(|(_, name, _, _, _, _)| name.clone())
            .collect();
        if !blocked.is_empty() {
            return Err(TakeoverError::BindingConflict(blocked));
        }

        let new_host_name =
            generate_unique_owned_name(&mut tx, "host", official_admin_id, &host_name).await?;
        sqlx::query("UPDATE hosts SET user_id = $2, name = $3 WHERE id = $1")
            .bind(host_id)
            .bind(official_admin_id)
            .bind(&new_host_name)
            .execute(&mut *tx)
            .await
            .map_err(|e| TakeoverError::Sql(ApiError::from_sql(e)))?;

        let mut transferred: Vec<String> = Vec::new();
        let mut detached: Vec<String> = Vec::new();
        for (pkg_id, pkg_name, _, pkg_owner_role, can_transfer, has_others) in &package_actions {
            if pkg_owner_role == "admin" {
                continue;
            }
            if *can_transfer {
                let new_pkg_name =
                    generate_unique_owned_name(&mut tx, "package", official_admin_id, pkg_name).await?;
                sqlx::query(
                    "UPDATE packages SET user_id = $2, name = $3, release_channel_id = NULL WHERE id = $1",
                )
                .bind(pkg_id)
                .bind(official_admin_id)
                .bind(&new_pkg_name)
                .execute(&mut *tx)
                .await
                .map_err(|e| TakeoverError::Sql(ApiError::from_sql(e)))?;
                sqlx::query("UPDATE package_shares SET owner_id = $2 WHERE package_id = $1")
                    .bind(pkg_id)
                    .bind(official_admin_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| TakeoverError::Sql(ApiError::from_sql(e)))?;
                transferred.push(pkg_name.clone());
                continue;
            }
            if *has_others {
                sqlx::query("DELETE FROM package_hosts WHERE package_id = $1 AND host_id = $2")
                    .bind(pkg_id)
                    .bind(host_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| TakeoverError::Sql(ApiError::from_sql(e)))?;
                detached.push(pkg_name.clone());
            }
        }

        Ok(json!({
            "hostId": hid,
            "previousOwnerId": host_user_id,
            "previousOwnerUsername": owner_username,
            "instanceCount": instance_count,
            "transferredPackageCount": transferred.len(),
            "detachedPackageCount": detached.len(),
            "transferredPackageNames": transferred,
            "detachedPackageNames": detached,
            "hostRenamed": new_host_name != host_name,
            "oldHostName": host_name,
            "newHostName": new_host_name,
        }))
    };

    match flow.await {
        Ok(summary) => {
            create_log(
                &state,
                user.0.id,
                "host",
                "host.takeover_official",
                &format!(
                    "Take over hosted host #{} from user #{}: transferredPackages={}, detachedPackages={}, instances={}",
                    summary["hostId"].as_i64().unwrap_or(0),
                    summary["previousOwnerId"].as_i64().unwrap_or(0),
                    summary["transferredPackageCount"].as_i64().unwrap_or(0),
                    summary["detachedPackageCount"].as_i64().unwrap_or(0),
                    summary["instanceCount"].as_i64().unwrap_or(0),
                ),
                "success",
            )
            .await;
            Ok((StatusCode::OK, Json(json!({ "success": true, "summary": summary }))).into_response())
        }
        Err(TakeoverError::HostNotFound) => Err(ApiError::not_found(code::HOST_NOT_FOUND)),
        Err(TakeoverError::AlreadyOfficial) => Err(ApiError::bad_request(code::HOST_ALREADY_OFFICIAL)),
        Err(TakeoverError::BindingConflict(package_names)) => {
            let count = package_names.len();
            Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": crate::error::message(code::HOST_TAKEOVER_PACKAGE_BINDING_CONFLICT)
                        .unwrap_or(code::HOST_TAKEOVER_PACKAGE_BINDING_CONFLICT),
                    "code": code::HOST_TAKEOVER_PACKAGE_BINDING_CONFLICT,
                    "packageNames": package_names,
                    "count": count,
                })),
            )
                .into_response())
        }
        Err(TakeoverError::Sql(err)) => Err(err),
    }
}



// ===========================================================================
// GET /:id/plans — 节点绑定的套餐方案
// ===========================================================================

async fn host_plans(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let package_ids = get_host_packages(&state, host_id).await?;
    if package_ids.is_empty() {
        return Ok(Json(json!({ "plans": [] })));
    }
    let plans: Vec<(i32, String, i32, String, Decimal, i32)> = sqlx::query_as(
        "SELECT pl.id, pl.name, p.id, p.name, pl.price, pl.billing_cycle \
         FROM package_plans pl JOIN packages p ON p.id = pl.package_id \
         WHERE pl.package_id = ANY($1) AND p.active = true AND pl.is_active = true AND pl.is_sold_out = false \
         ORDER BY pl.sort_order ASC",
    )
    .bind(&package_ids)
    .fetch_all(&state.db)
    .await?;
    let plan_json: Vec<Value> = plans
        .into_iter()
        .map(|(plan_id, plan_name, pkg_id, pkg_name, price, billing_cycle)| {
            json!({
                "id": plan_id,
                "name": plan_name,
                "packageId": pkg_id,
                "packageName": pkg_name,
                "price": num(price),
                "billingCycle": billing_cycle,
            })
        })
        .collect();
    Ok(Json(json!({ "plans": plan_json })))
}

// ===========================================================================
// POST /:id/instances/migrate — 批量迁移实例到其他节点
// ===========================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
struct MigrateInstanceRow {
    pub id: i32,
    pub incus_id: String,
    pub name: String,
    pub user_id: i32,
    pub host_id: i32,
    pub package_id: Option<i32>,
    pub package_plan_id: Option<i32>,
    pub billing_mode: String,
    pub status: String,
    pub cpu: i32,
    pub memory: i32,
    pub disk: i32,
    pub network_mode: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub image: String,
    pub root_password: Option<String>,
    pub snapshotted_specs: Option<Value>,
    pub monthly_traffic_limit: Option<i64>,
    pub port_limit: Option<i32>,
    pub snapshot_limit: Option<i32>,
    pub backup_limit: Option<i32>,
    pub site_limit: Option<i32>,
    pub swap_enabled: bool,
    pub swap_size: Option<i32>,
    pub traffic_settled_bytes: i64,
    pub traffic_settled_cost: Option<Decimal>,
    pub next_traffic_billing_at: Option<DateTime<Utc>>,
    pub auto_renew: bool,
    pub limits_read: Option<String>,
    pub limits_write: Option<String>,
    pub limits_read_iops: Option<i32>,
    pub limits_write_iops: Option<i32>,
    pub limits_ingress: Option<String>,
    pub limits_egress: Option<String>,
    pub limits_processes: Option<i32>,
    pub limits_cpu_priority: Option<i32>,
    pub boot_autostart: Option<bool>,
    pub boot_autostart_priority: Option<i32>,
    pub boot_autostart_delay: Option<i32>,
    pub boot_host_shutdown_timeout: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub billing_price: Option<Decimal>,
    pub billing_cycle: Option<i32>,
    pub traffic_billing_mode: Option<String>,
    pub traffic_unit_price: Option<Decimal>,
}

const MIGRATE_INSTANCE_COLUMNS: &str =
    "id, incus_id, name, user_id, host_id, package_id, package_plan_id, \
     billing_mode::text AS billing_mode, status::text AS status, cpu, memory, disk, \
     network_mode::text AS network_mode, ipv4, ipv6, image, root_password, snapshotted_specs, \
     monthly_traffic_limit, port_limit, snapshot_limit, backup_limit, site_limit, \
     swap_enabled, swap_size, traffic_settled_bytes, traffic_settled_cost, next_traffic_billing_at, \
     auto_renew, limits_read, limits_write, limits_read_iops, limits_write_iops, \
     limits_ingress, limits_egress, limits_processes, limits_cpu_priority, \
     boot_autostart, boot_autostart_priority, boot_autostart_delay, boot_host_shutdown_timeout, \
     expires_at, billing_price, billing_cycle, traffic_billing_mode::text AS traffic_billing_mode, \
     traffic_unit_price";

fn nanoid_short() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(8);
    let mut buf = [0u8; 8];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut buf);
    for b in buf {
        out.push(CHARS[(b as usize) % CHARS.len()] as char);
    }
    out
}

async fn batch_migrate(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let source_host_id = js_number_id(&id)?;
    let instance_ids: Vec<i32> = body
        .get("instanceIds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_i64().map(|v| v as i32)).collect())
        .unwrap_or_default();
    let target_host_id = body_int(body.get("targetHostId")).unwrap_or(0) as i32;
    let target_image = body.get("targetImage").and_then(Value::as_str).unwrap_or("").to_string();
    let target_plan_id = body_int(body.get("targetPlanId")).map(|v| v as i32);
    let force = body.get("force") == Some(&Value::Bool(true));

    let source_host = get_host_by_id(&state, source_host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    let target_host = get_host_by_id(&state, target_host_id)
        .await?
        .ok_or_else(|| bare_err("目标节点不存在"))?;

    if user.role == "admin" {
        let target_owner_role: Option<(String,)> = sqlx::query_as(
            "SELECT u.role::text AS role FROM hosts h JOIN users u ON u.id = h.user_id WHERE h.id = $1",
        )
        .bind(target_host_id)
        .fetch_optional(&state.db)
        .await?;
        if target_owner_role.map(|(r,)| r) != Some("admin".to_string()) {
            return Ok(bare_bad_request("管理员迁移目标节点只能选择自营节点"));
        }
    } else {
        if source_host.user_id != user.id {
            return Err(ApiError::forbidden(code::FORBIDDEN));
        }
        if target_host.user_id != user.id {
            return Ok(bare_bad_request("目标节点不属于当前用户"));
        }
    }

    if source_host_id == target_host_id {
        return Ok(bare_bad_request("源节点和目标节点不能相同"));
    }
    if target_host.status != "online" {
        return Ok(bare_bad_request("目标节点不在线"));
    }
    if !is_valid_system_image(&state, &target_image).await? {
        return Ok(bare_bad_request("目标系统镜像不存在或已隐藏"));
    }

    let instances: Vec<MigrateInstanceRow> = sqlx::query_as(&format!(
        "SELECT {MIGRATE_INSTANCE_COLUMNS} FROM instances \
         WHERE id = ANY($1) AND host_id = $2 AND status <> 'deleted'"
    ))
    .bind(&instance_ids)
    .bind(source_host_id)
    .fetch_all(&state.db)
    .await?;
    if instances.is_empty() {
        return Ok(bare_bad_request("没有找到可迁移的实例"));
    }
    if instances.iter().any(|i| i.billing_mode == "hourly") {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "按小时计费实例暂不支持批量迁移，请先使用专用迁移流程",
                "code": "HOURLY_INSTANCE_MIGRATION_UNSUPPORTED",
            })),
        )
            .into_response());
    }

    let paid_count = instances
        .iter()
        .filter(|i| i.billing_mode == "package" && i.package_plan_id.is_some())
        .count();
    let mut target_plan: Option<(i32, i32, String, bool, bool, Decimal, i32, Option<String>, Option<Decimal>)> = None;
    if paid_count > 0 {
        let Some(plan_id) = target_plan_id else {
            return Ok(bare_bad_request("有付费实例需要迁移，请选择目标方案"));
        };
        let plan: Option<(i32, i32, String, bool, bool, Decimal, i32, Option<String>, Option<Decimal>)> = sqlx::query_as(
            "SELECT id, package_id, name, is_active, is_sold_out, price, billing_cycle, \
             traffic_billing_mode::text AS traffic_billing_mode, traffic_unit_price \
             FROM package_plans WHERE id = $1",
        )
        .bind(plan_id)
        .fetch_optional(&state.db)
        .await?;
        let Some(plan) = plan else {
            return Ok(bare_bad_request("目标方案不存在"));
        };
        if !plan.3 {
            return Ok(bare_bad_request("目标方案已下架"));
        }
        if plan.4 {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "目标方案已售罄", "code": "PLAN_SOLD_OUT" })),
            )
                .into_response());
        }
        let target_package_exists: Option<i32> =
            sqlx::query_scalar("SELECT id FROM packages WHERE id = $1")
                .bind(plan.1)
                .fetch_optional(&state.db)
                .await?;
        if target_package_exists.is_none() {
            return Ok(bare_bad_request("目标方案的套餐不存在"));
        }
        let package_host_ids = get_package_host_ids(&state, plan.1).await?;
        if !package_host_ids.contains(&target_host_id) {
            return Ok(bare_bad_request("目标方案的套餐未绑定目标节点"));
        }
        target_plan = Some(plan);
    }

    let mut source_client: Option<Arc<IncusClient>> = None;
    if !force {
        source_client = get_incus_client(&state, &source_host).await.ok();
        if source_client.is_none() {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "源节点无法连接，请选择“强制从面板迁移”",
                    "code": "SOURCE_HOST_UNAVAILABLE",
                })),
            )
                .into_response());
        }
    }
    let target_client = match get_incus_client(&state, &target_host).await {
        Ok(client) => client,
        Err(err) => {
            return Ok(bare_bad_request(format!("无法连接目标节点: {}", err.error)));
        }
    };

    let mut results: Vec<Value> = Vec::new();
    for instance in &instances {
        match migrate_one(
            &state,
            &user,
            &source_host,
            &target_host,
            &target_image,
            target_plan.as_ref(),
            force,
            source_client.as_deref(),
            &target_client,
            instance,
        )
        .await
        {
            Ok(new_instance_id) => {
                results.push(json!({
                    "id": instance.id,
                    "name": instance.name,
                    "success": true,
                    "newInstanceId": new_instance_id,
                }));
                create_log(
                    &state,
                    user.id,
                    "instance",
                    "instance.migrate",
                    &format!(
                        "Migrated instance \"{}\" from host \"{}\" to \"{}\"{}",
                        instance.name,
                        source_host.name,
                        target_host.name,
                        if force { " (panel-only; source host was not contacted)" } else { "" },
                    ),
                    "success",
                )
                .await;
            }
            Err(message) => {
                results.push(json!({
                    "id": instance.id,
                    "name": instance.name,
                    "success": false,
                    "error": message,
                }));
                tracing::error!("迁移实例失败 ({}): {message}", instance.name);
            }
        }
    }

    let success_count = results.iter().filter(|r| r["success"].as_bool() == Some(true)).count();
    let failed_count = results.len() - success_count;
    Ok((
        StatusCode::OK,
        Json(json!({
            "message": format!(
                "成功迁移 {success_count} 个实例{}",
                if failed_count > 0 { format!("，{failed_count} 个失败") } else { String::new() }
            ),
            "results": results,
            "successCount": success_count,
            "failedCount": failed_count,
        })),
    )
        .into_response())
}

/// One iteration of the TS migrate loop; Err = per-instance failure message.
#[allow(clippy::too_many_arguments)]
async fn migrate_one(
    state: &SharedAppState,
    user: &AuthUser,
    source_host: &HostRow,
    target_host: &HostRow,
    target_image: &str,
    target_plan: Option<&(i32, i32, String, bool, bool, Decimal, i32, Option<String>, Option<Decimal>)>,
    force: bool,
    source_client: Option<&IncusClient>,
    target_client: &IncusClient,
    instance: &MigrateInstanceRow,
) -> Result<i32, String> {
    if has_pending_transfer(state, instance.id).await.map_err(|e| format!("{e}"))? {
        return Err("实例有待处理的转移请求".to_string());
    }
    let active_restore: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM restore_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING') LIMIT 1",
    )
    .bind(instance.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("{e}"))?;
    if active_restore.is_some() {
        return Err("实例有正在进行的恢复任务".to_string());
    }
    let active_upload: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM backup_upload_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING') LIMIT 1",
    )
    .bind(instance.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("{e}"))?;
    if active_upload.is_some() {
        return Err("实例有正在进行的上传任务".to_string());
    }

    // SSH keys.
    let ssh_keys = get_ssh_keys_by_user_id(state, instance.user_id).await.map_err(|e| format!("{e}"))?;
    if ssh_keys.is_empty() {
        return Err("用户没有 SSH 密钥".to_string());
    }
    let ssh_key = ssh_keys[0].2.clone();

    // Decrypt old root password.
    let root_password = match &instance.root_password {
        Some(encrypted) => crypto_lib::decrypt_sensitive_data(&state.config.encryption_key, encrypted)
            .unwrap_or_else(|_| generate_random_password(16)),
        None => generate_random_password(16),
    };

    // Package info.
    let Some(package_id) = instance.package_id else {
        return Err("实例套餐不存在".to_string());
    };
    let package: Option<(String, String, bool, bool)> = sqlx::query_as::<_, (String, String, bool, bool)>(
        "SELECT name, instance_type::text AS instance_type, nested, privileged \
         FROM packages WHERE id = $1",
    )
    .bind(package_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("{e}"))?;
    let Some((pkg_name, pkg_instance_type, pkg_nested, pkg_privileged)) = package else {
        return Err("实例套餐不存在".to_string());
    };
    let instance_type = if pkg_instance_type == "vm" { "vm" } else { "container" };
    let effective_instance_type = if instance_type == "vm" {
        "virtual-machine"
    } else {
        "container"
    };
    if !is_image_compatible_with_instance_type(state, target_image, instance_type)
        .await
        .map_err(|e| format!("{e}"))?
    {
        return Err("目标系统与实例类型不兼容".to_string());
    }
    if !is_image_compatible_with_memory(state, target_image, instance.memory as i64)
        .await
        .map_err(|e| format!("{e}"))?
    {
        return Err("目标系统与实例内存不兼容".to_string());
    }
    let availability = get_system_image_availability_for_host(
        state,
        target_image,
        target_host.id,
        Some(instance_type),
        Some(instance.memory as i64),
    )
    .await
    .map_err(|e| format!("{e}"))?;
    if let Err(reason) = availability {
        return Err(format!("目标节点不可用该系统: {reason}"));
    }

    // cloud-init config (without static IP yet).
    #[allow(unused_variables)]
    let initial_config = generate_incus_config(&IncusConfigParams {
        instance_name: instance.name.clone(),
        image_alias: target_image.to_string(),
        root_password: root_password.clone(),
        ssh_key: Some(ssh_key.clone()),
        instance_type: Some(effective_instance_type.to_string()),
        network_mode: Some(instance.network_mode.clone()),
        network: None,
        extra_shell_commands: None,
        instance_id_seed: None,
    })
    .map_err(|e| e)?;
    let _ = &pkg_name;

    // New incusId + IP allocation.
    let new_incus_id = format!("u{}-{}", instance.user_id, nanoid_short());
    let mut static_ipv4: Option<String> = None;
    for _ in 0..50 {
        let candidate = generate_random_ipv4();
        if !is_ipv4_exists_on_host(state, &candidate, target_host.id).await.map_err(|e| format!("{e}"))? {
            static_ipv4 = Some(candidate);
            break;
        }
    }
    let Some(static_ipv4) = static_ipv4 else {
        return Err("无法分配 IPv4 地址".to_string());
    };
    let mut static_ipv6: Option<String> = None;
    if let Some(subnet) = &target_host.ipv6_subnet {
        for _ in 0..50 {
            let candidate = generate_random_ipv6(subnet).map_err(|e| e)?;
            if !is_ipv6_exists(state, &candidate).await.map_err(|e| format!("{e}"))? {
                static_ipv6 = Some(candidate);
                break;
            }
        }
    }

    // Rebuild cloud-init with the static network.
    let network_config = crate::libs::incus::incus_config_container::StaticNetworkConfig {
        ip_address: Some(format!("{static_ipv4}/22")),
        gateway: Some("10.10.0.1".to_string()),
        dns: Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]),
        ipv6_address: static_ipv6
            .as_ref()
            .map(|ip| {
                if effective_instance_type == "virtual-machine" {
                    ip.clone()
                } else {
                    format!("{ip}/128")
                }
            }),
        ipv6_gateway: if effective_instance_type == "virtual-machine" {
            static_ipv6.as_ref().map(|_| target_host.ipv6_gateway.clone().unwrap_or_default())
        } else {
            static_ipv6.as_ref().map(|_| "fe80::1".to_string())
        },
        ipv6_dns: None,
    };
    let final_config = if effective_instance_type == "virtual-machine" {
        generate_vm_config(&IncusConfigParams {
            instance_name: instance.name.clone(),
            image_alias: target_image.to_string(),
            root_password: root_password.clone(),
            ssh_key: Some(ssh_key.clone()),
            instance_type: Some("virtual-machine".to_string()),
            network_mode: Some(instance.network_mode.clone()),
            network: Some(network_config),
            extra_shell_commands: None,
            instance_id_seed: Some(new_incus_id.clone()),
        })
    } else {
        generate_incus_config(&IncusConfigParams {
            instance_name: instance.name.clone(),
            image_alias: target_image.to_string(),
            root_password: root_password.clone(),
            ssh_key: Some(ssh_key.clone()),
            instance_type: Some("container".to_string()),
            network_mode: Some(instance.network_mode.clone()),
            network: Some(network_config),
            extra_shell_commands: None,
            instance_id_seed: None,
        })
        .map_err(|e| e)?
    };

    // Storage pool on the target host.
    let selected_storage_pool = {
        let mut conn = state.db.acquire().await.map_err(|e| format!("{e}"))?;
        resolve_storage_pool_for_new_instance(&mut conn, target_host.id, instance.package_id)
            .await
            .map_err(|e| format!("{e}"))?
    };
    let Some(selected_storage_pool) = selected_storage_pool else {
        return Err("目标节点尚未创建可用的系统盘存储池，无法转移".to_string());
    };

    // Package IO/boot limits fallback (instance-level overrides win).
    let io_mode = "throughput";
    let pkg_io: Option<(String, String, String, i32, i32, String, String, i32, i32, Option<bool>, Option<i32>, Option<i32>, Option<i32>)> = sqlx::query_as(
        "SELECT io_limit_mode, limits_read, limits_write, limits_read_iops, limits_write_iops, \
         limits_ingress, limits_egress, limits_processes, limits_cpu_priority, \
         boot_autostart, boot_autostart_priority, boot_autostart_delay, boot_host_shutdown_timeout \
         FROM packages WHERE id = $1",
    )
    .bind(package_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("{e}"))?;
    let io_limit_mode = pkg_io.as_ref().map(|p| p.0.as_str()).unwrap_or("throughput");
    let _ = io_mode;
    let limits_read = instance
        .limits_read
        .clone()
        .or_else(|| pkg_io.as_ref().map(|p| p.1.clone()).filter(|_| io_limit_mode == "throughput"));
    let limits_write = instance
        .limits_write
        .clone()
        .or_else(|| pkg_io.as_ref().map(|p| p.2.clone()).filter(|_| io_limit_mode == "throughput"));
    let limits_read_iops = instance
        .limits_read_iops
        .map(|v| v as i64)
        .or_else(|| pkg_io.as_ref().and_then(|p| Some(p.3 as i64)).filter(|_| io_limit_mode == "iops"));
    let limits_write_iops = instance
        .limits_write_iops
        .map(|v| v as i64)
        .or_else(|| pkg_io.as_ref().and_then(|p| Some(p.4 as i64)).filter(|_| io_limit_mode == "iops"));
    let limits_ingress = instance.limits_ingress.clone().or_else(|| pkg_io.as_ref().map(|p| p.5.clone()));
    let limits_egress = instance.limits_egress.clone().or_else(|| pkg_io.as_ref().map(|p| p.6.clone()));
    let limits_processes = instance.limits_processes.map(|v| v as i64).or_else(|| pkg_io.as_ref().map(|p| p.7 as i64));
    let limits_cpu_priority = instance.limits_cpu_priority.map(|v| v as i64).or_else(|| pkg_io.as_ref().map(|p| p.8 as i64));
    let boot_autostart = instance.boot_autostart.or_else(|| pkg_io.as_ref().and_then(|p| p.9));
    let boot_autostart_priority = instance.boot_autostart_priority.map(|v| v as i64).or_else(|| pkg_io.as_ref().and_then(|p| p.10.map(|v| v as i64)));
    let boot_autostart_delay = instance.boot_autostart_delay.map(|v| v as i64).or_else(|| pkg_io.as_ref().and_then(|p| p.11.map(|v| v as i64)));
    let boot_host_shutdown_timeout = instance
        .boot_host_shutdown_timeout
        .map(|v| v as i64)
        .or_else(|| pkg_io.as_ref().and_then(|p| p.12.map(|v| v as i64)));

    let ipv6_config = static_ipv6
        .as_ref()
        .map(|ip| crate::libs::incus::network_payload_builder::Ipv6Config {
            primary_ip: ip.clone(),
            extra_ips: None,
            subnet: None,
        });
    let cloud_init_map: Map<String, Value> = match serde_json::to_value(final_config.config_payload) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    };
    let incus_config = build_instance_config(&BuildInstanceConfigOptions {
        name: new_incus_id.clone(),
        image: target_image.to_string(),
        cpu: instance.cpu as i64,
        memory: instance.memory as i64,
        disk: instance.disk as i64,
        swap_enabled: Some(instance.swap_enabled),
        swap_size: instance.swap_size.map(|v| v as i64),
        network_mode: NetworkMode::parse(&instance.network_mode),
        ssh_key: Some(String::new()),
        password: Some(String::new()),
        cloud_init_config: Some(cloud_init_map),
        nested: pkg_nested,
        privileged: pkg_privileged,
        instance_type: Some(instance_type.to_string()),
        storage_pool: Some(selected_storage_pool.clone()),
        ipv4_address: Some(static_ipv4.clone()),
        ipv6_address: static_ipv6.clone(),
        ipv6_gateway: target_host.ipv6_gateway.clone(),
        network_bridge: None,
        ipv6_config,
        host_interface: Some(target_host.ipv6_parent_interface.clone().unwrap_or_else(|| "eth0".to_string())),
        limits_read,
        limits_write,
        limits_read_iops,
        limits_write_iops,
        limits_ingress,
        limits_egress,
        limits_processes,
        limits_cpu_priority,
        boot_autostart,
        boot_autostart_priority,
        boot_autostart_delay,
        boot_host_shutdown_timeout,
    });

    // Create + start on the target host (outside any DB transaction).
    create_instance(target_client, &incus_config)
        .await
        .map_err(|e| incus_error_message(&e))?;
    start_instance(target_client, &new_incus_id)
        .await
        .map_err(|e| incus_error_message(&e))?;

    // AFF binding on the source instance.
    let aff_binding = get_instance_aff_binding(&state.db, instance.id)
        .await
        .map_err(|e| format!("{e}"))?;

    let is_paid_instance = instance.billing_mode == "package" && instance.package_plan_id.is_some();
    let final_package_id = if is_paid_instance {
        target_plan.map(|p| p.1).or(instance.package_id)
    } else {
        instance.package_id
    };
    let final_plan_id = if is_paid_instance {
        target_plan.map(|p| p.0).or(instance.package_plan_id)
    } else {
        instance.package_plan_id
    };
    let final_billing_price: Option<Decimal> = if is_paid_instance {
        match target_plan {
            Some(plan) => Some(plan.5 / Decimal::from(100)),
            None => instance.billing_price,
        }
    } else {
        instance.billing_price
    };
    let final_billing_cycle = if is_paid_instance {
        target_plan.map(|p| p.6).or(instance.billing_cycle)
    } else {
        instance.billing_cycle
    };
    let final_traffic_billing_mode = if is_paid_instance {
        target_plan.and_then(|p| p.7.clone()).or_else(|| instance.traffic_billing_mode.clone())
    } else {
        instance.traffic_billing_mode.clone()
    };
    let final_traffic_unit_price = if is_paid_instance {
        match target_plan.and_then(|p| p.8) {
            Some(price) => Some(price),
            None => instance.traffic_unit_price,
        }
    } else {
        instance.traffic_unit_price
    };
    let next_traffic_billing_at: Option<DateTime<Utc>> = if final_traffic_billing_mode.as_deref() == Some("usage") {
        Some(instance.next_traffic_billing_at.unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1)))
    } else {
        None
    };

    // DB transaction: create the new instance + move billing records.
    let new_instance_id: i32 = {
        let mut tx = state.db.begin().await.map_err(|e| format!("{e}"))?;
        let created: i32 = sqlx::query_scalar::<_, i32>(
            "INSERT INTO instances (incus_id, name, user_id, host_id, package_id, package_plan_id, \
             storage_pool_name, image, cpu, memory, disk, network_mode, snapshotted_specs, \
             root_password, status, ipv4, ipv6, monthly_traffic_limit, port_limit, snapshot_limit, \
             backup_limit, site_limit, expires_at, billing_price, billing_cycle, \
             traffic_billing_mode, traffic_unit_price, traffic_settled_bytes, traffic_settled_cost, \
             next_traffic_billing_at, auto_renew, limits_read, limits_write, limits_read_iops, \
             limits_write_iops, limits_ingress, limits_egress, limits_processes, limits_cpu_priority, \
             boot_autostart, boot_autostart_priority, boot_autostart_delay, boot_host_shutdown_timeout, ssh_port) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::\"NetworkMode\",$13,$14,'running'::\"InstanceStatus\",\
             $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25::\"TrafficBillingMode\",$26,$27,$28,$29,$30,\
             $31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,22) RETURNING id",
        )
        .bind(&new_incus_id)
        .bind(&instance.name)
        .bind(instance.user_id)
        .bind(target_host.id)
        .bind(final_package_id)
        .bind(final_plan_id)
        .bind(&selected_storage_pool)
        .bind(target_image)
        .bind(instance.cpu)
        .bind(instance.memory)
        .bind(instance.disk)
        .bind(&instance.network_mode)
        .bind(&instance.snapshotted_specs)
        .bind(crypto_lib::encrypt_sensitive_data(&state.config.encryption_key, &root_password))
        .bind(&static_ipv4)
        .bind(&static_ipv6)
        .bind(instance.monthly_traffic_limit)
        .bind(instance.port_limit)
        .bind(instance.snapshot_limit)
        .bind(instance.backup_limit)
        .bind(instance.site_limit)
        .bind(instance.expires_at)
        .bind(final_billing_price)
        .bind(final_billing_cycle)
        .bind(final_traffic_billing_mode)
        .bind(final_traffic_unit_price)
        .bind(instance.traffic_settled_bytes)
        .bind(instance.traffic_settled_cost)
        .bind(next_traffic_billing_at)
        .bind(instance.auto_renew)
        .bind(&instance.limits_read)
        .bind(&instance.limits_write)
        .bind(instance.limits_read_iops)
        .bind(instance.limits_write_iops)
        .bind(&instance.limits_ingress)
        .bind(&instance.limits_egress)
        .bind(instance.limits_processes)
        .bind(instance.limits_cpu_priority)
        .bind(instance.boot_autostart)
        .bind(instance.boot_autostart_priority)
        .bind(instance.boot_autostart_delay)
        .bind(instance.boot_host_shutdown_timeout)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("{e}"))?;
        let moved = reassign_instance_billing_records(&mut *tx, instance.id, created)
            .await
            .map_err(|e| format!("{e}"))?;
        if is_paid_instance && moved == 0 {
            tracing::warn!(
                oldInstanceId = instance.id,
                newInstanceId = created,
                "[Migrate] 付费实例迁移时未迁移到任何计费记录"
            );
        }
        tx.commit().await.map_err(|e| format!("{e}"))?;
        created
    };

    if let Some((aff_code_id, supersedes)) = aff_binding {
        create_aff_binding(&state.db, new_instance_id, aff_code_id, supersedes)
            .await
            .map_err(|e| format!("{e}"))?;
    }

    adjust_host_resources(state, target_host.id, instance.cpu as i64, instance.memory as i64, instance.disk as i64)
        .await
        .map_err(|e| format!("{e}"))?;

    // Delete the source instance (unless force).
    if !force {
        if let Some(source_client) = source_client {
            if instance.status == "running" {
                let _ = stop_instance(
                    source_client,
                    &instance.incus_id,
                    true,
                    BusyRetryOptions {
                        allow_cancel_busy_update: false,
                        busy_update_cancel_after_ms: None,
                    },
                )
                .await;
            }
            if let Err(err) = delete_instance(source_client, &instance.incus_id).await {
                tracing::warn!("删除源实例失败 ({}): {}", instance.incus_id, incus_error_message(&err));
            }
        }
    }

    update_instance_status(&state.db, instance.id, "deleted")
        .await
        .map_err(|e| format!("{e}"))?;
    rollback_resources(state, source_host.id, instance.cpu as i64, instance.memory as i64, instance.disk as i64, 0)
        .await
        .map_err(|e| format!("{e}"))?;

    create_inbox_notification(
        state,
        instance.user_id,
        "instance_migrated",
        "实例已迁移",
        &format!(
            "您的实例 {} 已被管理员迁移到新节点。\n\n新的连接信息：\n- IPv4: {}\n{}- 密码保持不变\n- SSH 密钥保持不变",
            instance.name,
            static_ipv4,
            match &static_ipv6 {
                Some(ip) => format!("- IPv6: {ip}\n"),
                None => String::new(),
            }
        ),
        json!({
            "oldHostId": source_host.id,
            "newHostId": target_host.id,
            "oldHostName": source_host.name,
            "newHostName": target_host.name,
            "instanceId": new_instance_id,
            "instanceName": instance.name,
        }),
    )
    .await;

    let _ = user;
    Ok(new_instance_id)
}

// ===========================================================================
// GET /:id/users/lookup
// ===========================================================================

async fn host_users_lookup(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let username = params.get("username").map(|s| s.trim()).unwrap_or("");
    if username.is_empty() {
        return Ok(bare_bad_request("Username is required"));
    }
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let target: Option<(i32, String, String)> = sqlx::query_as(
        "SELECT id, username, status::text AS status FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(&state.db)
    .await?;
    let Some((target_id, target_username, target_status)) = target else {
        return Err(ApiError::not_found(code::USER_NOT_FOUND));
    };
    let (ssh_key_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM ssh_keys WHERE user_id = $1")
            .bind(target_id)
            .fetch_one(&state.db)
            .await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "user": {
                "id": target_id,
                "username": target_username,
                "status": target_status,
                "hasSshKey": ssh_key_count > 0,
            },
        })),
    )
        .into_response())
}

// ===========================================================================
// POST /:id/instances/create-for-user
// ===========================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
struct PlanRow {
    pub id: i32,
    pub package_id: i32,
    pub name: String,
    pub is_active: bool,
    pub is_sold_out: bool,
    pub billing_mode: String,
    pub cpu: i32,
    pub memory: i32,
    pub disk: i32,
    pub port_limit: i32,
    pub snapshot_limit: i32,
    pub backup_limit: i32,
    pub site_limit: i32,
    pub swap_size: i32,
    pub traffic_limit: i64,
    pub traffic_limit_speed: String,
    pub traffic_billing_mode: String,
    pub traffic_unit_price: Decimal,
    pub price: Decimal,
    pub billing_cycle: i32,
}

/// billing.calculateCreateBilling (db/billing-operations.ts) for a paid plan:
/// price arrives in cents and is converted to yuan for `billing_price`.
struct CreateBilling {
    price: Decimal,
    billing_cycle: i32,
}

fn calculate_create_billing_local(plan: &PlanRow) -> Result<CreateBilling, ApiError> {
    let result = billing::calculate_create_billing((plan.price, plan.billing_cycle), Utc::now())?;
    Ok(CreateBilling {
        price: billing::dec_from_f64(result.price)?,
        billing_cycle: result.billing_cycle as i32,
    })
}

async fn fetch_plan_row(state: &SharedAppState, plan_id: i32) -> Result<Option<PlanRow>, ApiError> {
    let row: Option<PlanRow> = sqlx::query_as(
        "SELECT id, package_id, name, is_active, is_sold_out, billing_mode::text AS billing_mode, \
         cpu, memory, disk, port_limit, snapshot_limit, backup_limit, site_limit, swap_size, \
         traffic_limit, traffic_limit_speed, traffic_billing_mode::text AS traffic_billing_mode, \
         traffic_unit_price, price, billing_cycle FROM package_plans WHERE id = $1",
    )
    .bind(plan_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct PkgRow {
    pub user_id: i32,
    pub name: String,
    pub network_mode: String,
    pub instance_type: String,
    pub nested: bool,
    pub privileged: bool,
    pub active: bool,
    pub cpu_max: i32,
    pub memory_max: i32,
    pub disk_max: i32,
    pub port_limit: i32,
    pub monthly_traffic_limit: Option<i64>,
    pub io_limit_mode: String,
    pub limits_read: String,
    pub limits_write: String,
    pub limits_read_iops: i32,
    pub limits_write_iops: i32,
    pub limits_ingress: String,
    pub limits_egress: String,
    pub limits_processes: i32,
    pub limits_cpu_priority: i32,
    pub boot_autostart: bool,
    pub boot_autostart_priority: i32,
    pub boot_autostart_delay: i32,
    pub boot_host_shutdown_timeout: i32,
}

async fn create_for_user(
    State(state): State<SharedAppState>,
    operator: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let get_str = |key: &str| body.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    let username = get_str("username");
    let name = get_str("name");
    let package_id = body_int(body.get("packageId")).unwrap_or(0) as i32;
    let plan_id = body_int(body.get("planId")).map(|v| v as i32);
    let gift_days_raw = body_int(body.get("giftDays")).unwrap_or(30);
    let image = get_str("image");
    let cpu_opt = body_int(body.get("cpu")).map(|v| v as i32);
    let memory_opt = body_int(body.get("memory")).map(|v| v as i32);
    let disk_opt = body_int(body.get("disk")).map(|v| v as i32);
    let force_generate_ssh_key = body.get("forceGenerateSshKey") == Some(&Value::Bool(true));

    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    let is_admin = operator.role == "admin";
    if host.user_id != operator.id && !is_admin {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let name_validation = validators::validate_name(&name, "Instance name", 2, 64);
    if !name_validation.valid {
        return Ok(bare_bad_request(name_validation.message.unwrap_or_default()));
    }
    if username.chars().count() < 2 || username.chars().count() > 32 {
        return Ok(bare_bad_request("body/username must be between 2 and 32 characters"));
    }
    if image.is_empty() {
        return Ok(bare_bad_request("body/image must NOT have fewer than 1 characters"));
    }

    let target_user: Option<(i32, String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, username, email, status::text AS status FROM users WHERE username = $1",
    )
    .bind(username.trim())
    .fetch_optional(&state.db)
    .await?;
    let Some((target_user_id, target_username, _target_user_email, target_user_status)) = target_user
    else {
        return Ok(bare_bad_request(format!("用户 \"{username}\" 不存在")));
    };
    if target_user_id == operator.id && !is_admin {
        return Ok(bare_bad_request("不能给自己赠送实例，请使用当前节点的普通创建功能"));
    }
    if target_user_status != "active" {
        return Ok(bare_bad_request(format!("用户 \"{username}\" 状态异常，无法创建实例")));
    }

    let target_user_ssh_keys = get_ssh_keys_by_user_id(&state, target_user_id).await?;
    if target_user_ssh_keys.is_empty() && !force_generate_ssh_key {
        return Ok(bare_bad_request(format!(
            "用户 \"{username}\" 没有 SSH 密钥，请先让用户添加 SSH 密钥"
        )));
    }

    // Package + plan validation.
    let package: Option<PkgRow> = sqlx::query_as(
        "SELECT user_id, name, network_mode::text AS network_mode, instance_type::text AS instance_type, \
         nested, privileged, active, cpu_max, memory_max, disk_max, port_limit, monthly_traffic_limit, \
         io_limit_mode, limits_read, limits_write, limits_read_iops, limits_write_iops, \
         limits_ingress, limits_egress, limits_processes, limits_cpu_priority, \
         boot_autostart, boot_autostart_priority, boot_autostart_delay, boot_host_shutdown_timeout \
         FROM packages WHERE id = $1",
    )
    .bind(package_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(pkg) = package else {
        return Ok(bare_bad_request("套餐不存在或已禁用"));
    };
    let pkg_active = pkg.active;
    let pkg_active: bool = sqlx::query_scalar("SELECT active FROM packages WHERE id = $1")
        .bind(package_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(false);
    let _ = pkg_active;
    if !pkg_active {
        return Ok(bare_bad_request("套餐不存在或已禁用"));
    }
    let PkgRow {
        user_id: pkg_user_id,
        name: pkg_name,
        network_mode: pkg_network_mode,
        instance_type: pkg_instance_type,
        nested: pkg_nested,
        privileged: pkg_privileged,
        active: _pkg_active,
        cpu_max: pkg_cpu_max,
        memory_max: pkg_memory_max,
        disk_max: pkg_disk_max,
        port_limit: pkg_port_limit,
        monthly_traffic_limit: pkg_monthly_traffic_limit,
        io_limit_mode: pkg_io_limit_mode,
        limits_read: pkg_limits_read,
        limits_write: pkg_limits_write,
        limits_read_iops: pkg_limits_read_iops,
        limits_write_iops: pkg_limits_write_iops,
        limits_ingress: pkg_limits_ingress,
        limits_egress: pkg_limits_egress,
        limits_processes: pkg_limits_processes,
        limits_cpu_priority: pkg_limits_cpu_priority,
        boot_autostart: pkg_boot_autostart,
        boot_autostart_priority: pkg_boot_autostart_priority,
        boot_autostart_delay: pkg_boot_autostart_delay,
        boot_host_shutdown_timeout: pkg_boot_host_shutdown_timeout,
    } = pkg;

    if pkg_user_id != operator.id && !is_admin {
        return Ok(bare_bad_request("只能使用您自己的套餐为其他用户创建实例"));
    }
    let package_host_ids = get_package_host_ids(&state, package_id).await?;
    if !package_host_ids.is_empty() && !package_host_ids.contains(&host_id) {
        return Ok(bare_bad_request("该套餐未绑定到当前节点"));
    }
    if package_host_ids.is_empty() && host.user_id != pkg_user_id {
        return Ok(bare_bad_request("未绑定节点的套餐只能在套餐所有者的节点上创建实例"));
    }

    let node_selectors: Vec<String> = sqlx::query_scalar::<_, Value>(
        "SELECT node_selectors FROM packages WHERE id = $1",
    )
    .bind(package_id)
    .fetch_optional(&state.db)
    .await?
    .and_then(|v| serde_json::from_value(v).ok())
    .unwrap_or_default();

    let mut selected_plan: Option<PlanRow> = None;
    let mut billing: Option<CreateBilling> = None;
    let mut plan_traffic_speed: Option<String> = None;
    let paid_gift_days = plan_id.map(|_| gift_days_raw.clamp(1, 365));
    if let Some(plan_id) = plan_id {
        let plan = fetch_plan_row(&state, plan_id).await?;
        let Some(plan) = plan else {
            return Ok(bare_bad_request("方案不存在或不属于该套餐"));
        };
        if plan.package_id != package_id {
            return Ok(bare_bad_request("方案不存在或不属于该套餐"));
        }
        if !plan.is_active {
            return Ok(bare_bad_request("方案已下架"));
        }
        if plan.is_sold_out {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "方案已售罄", "code": "PLAN_SOLD_OUT" })),
            )
                .into_response());
        }
        if plan.billing_mode == "hourly" {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "按小时计费方案不能通过赠送实例入口创建，请由用户在套餐创建入口开通",
                    "code": "HOURLY_PLAN_REQUIRED",
                })),
            )
                .into_response());
        }
        plan_traffic_speed = if plan.traffic_billing_mode == "usage" {
            None
        } else {
            Some(plan.traffic_limit_speed.clone())
        };
        billing = Some(calculate_create_billing_local(&plan)?);
        selected_plan = Some(plan);
    }

    let requested_cpu = selected_plan.as_ref().map(|p| p.cpu).or(cpu_opt).unwrap_or(15);
    let requested_memory = selected_plan.as_ref().map(|p| p.memory).or(memory_opt).unwrap_or(128);
    let requested_disk = selected_plan.as_ref().map(|p| p.disk).or(disk_opt).unwrap_or(512);

    if !is_valid_system_image(&state, &image).await? {
        return Ok(bare_bad_request("镜像不存在"));
    }
    if !is_image_compatible_with_instance_type(&state, &image, &pkg_instance_type).await? {
        return Ok(bare_bad_request("镜像类型与套餐类型不兼容"));
    }
    if !is_image_compatible_with_memory(&state, &image, requested_memory as i64).await? {
        return Ok(bare_bad_request("128MB 内存只能使用 Alpine/Debian 镜像"));
    }

    // ensureHostStoragePoolOrReply equivalent: 503-style guard with inbox audit.
    if !host_has_instance_data_pool(&state.db, host_id).await? {
        return Ok(bare_bad_request("当前节点资源不足或不可用"));
    }

    let pre_check_host = select_available_host(
        &state,
        &package_host_ids,
        &node_selectors,
        requested_cpu as i64,
        requested_memory as i64,
        requested_disk as i64,
        host_id,
        pkg_user_id,
    )
    .await?;
    let Some(pre_check_host) = pre_check_host else {
        return Ok(bare_bad_request("当前节点资源不足或不可用"));
    };
    let host_instance_type = host_instance_type(Some(&pre_check_host.instance_type));
    if pkg_instance_type == "vm" && host_instance_type == "container" {
        return Ok(bare_bad_request("套餐要求虚拟机，但当前节点只支持容器"));
    }
    if pkg_instance_type == "container" && host_instance_type == "vm" {
        return Ok(bare_bad_request("套餐要求容器，但当前节点只支持虚拟机"));
    }
    match get_system_image_availability_for_host(
        &state,
        &image,
        pre_check_host.id,
        Some(&pkg_instance_type),
        Some(requested_memory as i64),
    )
    .await?
    {
        Ok(_) => {}
        Err(reason) => {
            return Ok(bare_bad_request(match reason.as_str() {
                "host_not_found" => "节点不存在",
                "image_not_found" => "镜像不存在",
                "memory_incompatible" => "128MB 内存只能使用 Alpine/Debian 镜像",
                "instance_type_mismatch" => "镜像类型与套餐类型不兼容",
                "host_instance_type_mismatch" => "套餐类型与宿主机不兼容",
                _ => "当前节点不可用该镜像",
            }));
        }
    }

    let network_mode = if pkg_network_mode.is_empty() {
        "nat".to_string()
    } else {
        pkg_network_mode.clone()
    };
    if pkg_instance_type == "vm" && matches!(network_mode.as_str(), "nat_ipv6_nat" | "ipv6_nat") {
        return Ok(bare_bad_request(
            "KVM packages do not support IPv4 NAT & IPv6 NAT or IPv6 NAT network modes",
        ));
    }

    // SSH key generation fails like the ssh-keys route (no rsa crate).
    let ssh_key = target_user_ssh_keys.first().map(|k| k.2.clone());
    if ssh_key.is_none() {
        return Ok(bare_bad_request(
            "SSH key generation is unavailable on this server; add an SSH key first",
        ));
    }
    let ssh_key = ssh_key.unwrap();

    let auto_password: String = {
        let uuid = random_uuid().replace('-', "");
        uuid.chars().take(16).collect()
    };
    let initial_config = generate_incus_config(&IncusConfigParams {
        instance_name: name.clone(),
        image_alias: image.clone(),
        root_password: auto_password.clone(),
        ssh_key: Some(ssh_key.clone()),
        instance_type: Some(if pkg_instance_type == "vm" {
            "virtual-machine".to_string()
        } else {
            "container".to_string()
        }),
        network_mode: Some(network_mode.clone()),
        network: None,
        extra_shell_commands: None,
        instance_id_seed: None,
    })
    .map_err(bare_err)?;
    let ssh_port = initial_config
        .meta_data
        .as_ref()
        .map(|m| m.ssh_port)
        .unwrap_or(22);

    let incus_id = format!("u{}-{}", target_user_id, random_uuid().replace('-', "").chars().take(8).collect::<String>());
    let package_traffic_limit: Option<i64> = pkg_monthly_traffic_limit;

    let paid_gift_expires_at: Option<DateTime<Utc>> = selected_plan
        .as_ref()
        .zip(paid_gift_days)
        .map(|(_, days)| Utc::now() + chrono::Duration::days(days as i64));

    // Serializable reservation transaction (selectAndReserveHostWithLock).
    let port_count = if matches!(
        network_mode.as_str(),
        "nat" | "nat_ipv6" | "nat_ipv6_nat" | "ipv6_nat" | "ipv6_only"
    ) {
        selected_plan
            .as_ref()
            .map(|p| p.port_limit as i64)
            .unwrap_or(pkg_port_limit as i64)
    } else {
        0
    };
    let snapshot_specs = json!({
        "packageId": package_id,
        "packageName": pkg_name,
        "planId": selected_plan.as_ref().map(|p| p.id),
        "planName": selected_plan.as_ref().map(|p| p.name.clone()),
        "cpuMax": pkg_cpu_max,
        "memoryMax": pkg_memory_max,
        "diskMax": pkg_disk_max,
        "networkMode": network_mode,
        "portLimit": selected_plan.as_ref().map(|p| p.port_limit).unwrap_or(pkg_port_limit),
        "nested": pkg_nested,
        "privileged": pkg_privileged,
        "nodeSelectors": node_selectors,
        "createdAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "hostOwnerGift": !is_admin,
        "adminGift": is_admin,
        "giftBy": operator.id,
        "giftByType": if is_admin { "admin" } else { "host_owner" },
        "isPaidInstance": selected_plan.is_some(),
        "chargedFirstMonth": false,
        "giftDays": paid_gift_days,
    });

    let reservation = (|| async {
        let mut tx = state.db.begin().await.map_err(ApiError::from_sql)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
        let reserved_host = select_and_reserve_host_with_lock(
            &mut tx,
            &package_host_ids,
            &node_selectors,
            requested_cpu as i64,
            requested_memory as i64,
            requested_disk as i64,
            host_id,
            pkg_user_id,
            port_count,
        )
        .await?
        .ok_or_else(|| ApiError::internal("HOST_RESOURCES_INSUFFICIENT"))?;
        let base_traffic_limit = selected_plan
            .as_ref()
            .map(|p| p.traffic_limit)
            .or(package_traffic_limit);
        let effective_monthly_traffic_limit = resolve_instance_traffic_limit_for_host(
            &mut *tx,
            Some(package_id),
            reserved_host.id,
            base_traffic_limit,
        )
        .await?;

        let (instance_quota_port, instance_quota_snapshot, instance_quota_backup, instance_quota_site, instance_quota_swap):
            (Option<i32>, Option<i32>, Option<i32>, Option<i32>, Option<i32>) = match &selected_plan {
                Some(plan) => (
                    Some(plan.port_limit),
                    Some(plan.snapshot_limit),
                    Some(plan.backup_limit),
                    Some(plan.site_limit),
                    if pkg_instance_type == "container" { Some(plan.swap_size) } else { None },
                ),
                None => (
                    Some(pkg_port_limit),
                    Some(0),
                    Some(0),
                    Some(0),
                    None,
                ),
            };

        let instance_id: i32 = sqlx::query_scalar(
            "INSERT INTO instances (incus_id, name, user_id, host_id, package_id, package_plan_id, \
             image, cpu, memory, disk, network_mode, snapshotted_specs, ssh_port, root_password, \
             status, monthly_traffic_limit, port_limit, snapshot_limit, backup_limit, site_limit, \
             swap_enabled, swap_size, limits_ingress, limits_egress, expires_at, billing_price, \
             billing_cycle, traffic_billing_mode, traffic_unit_price, next_traffic_billing_at, auto_renew) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::\"NetworkMode\",$12,$13,$14,\
             'creating'::\"InstanceStatus\",$15,$16,$17,$18,$19,false,$20,$21,$22,$23,$24,\
             $25,$26::\"TrafficBillingMode\",$27,$28,false) RETURNING id",
        )
        .bind(&incus_id)
        .bind(&name)
        .bind(target_user_id)
        .bind(reserved_host.id)
        .bind(package_id)
        .bind(selected_plan.as_ref().map(|p| p.id))
        .bind(&image)
        .bind(requested_cpu)
        .bind(requested_memory)
        .bind(requested_disk)
        .bind(&network_mode)
        .bind(&snapshot_specs)
        .bind(ssh_port as i32)
        .bind({
            let root_pw = initial_config
                .meta_data
                .as_ref()
                .map(|m| m.root_password.clone())
                .unwrap_or_else(|| auto_password.clone());
            crypto_lib::encrypt_sensitive_data(&state.config.encryption_key, &root_pw)
        })
        .bind(effective_monthly_traffic_limit)
        .bind(instance_quota_port)
        .bind(instance_quota_snapshot)
        .bind(instance_quota_backup)
        .bind(instance_quota_site)
        .bind(instance_quota_swap)
        .bind(plan_traffic_speed.clone())
        .bind(plan_traffic_speed.clone())
        .bind(paid_gift_expires_at)
        .bind(billing.as_ref().map(|b| b.price))
        .bind(billing.as_ref().map(|b| b.billing_cycle))
        .bind(
            selected_plan
                .as_ref()
                .map(|p| p.traffic_billing_mode.clone())
                .unwrap_or_else(|| "package".to_string()),
        )
        .bind(selected_plan.as_ref().map(|p| p.traffic_unit_price).unwrap_or(Decimal::ZERO))
        .bind(if selected_plan.as_ref().map(|p| p.traffic_billing_mode.as_str()) == Some("usage") {
            Some(Utc::now() + chrono::Duration::hours(1))
        } else {
            None
        })
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;

        if let (Some(plan), Some(expires_at)) = (selected_plan.as_ref(), paid_gift_expires_at) {
            let days = paid_gift_days.unwrap_or(0);
            if days > 0 {
                sqlx::query(
                    "INSERT INTO instance_billing_records (instance_id, user_id, type, amount, months, \
                     period_start, period_end, balance_log_id, remark) \
                     VALUES ($1, $2, 'newPurchase'::\"BillingRecordType\", 0, 0, now(), $3, NULL, $4)",
                )
                .bind(instance_id)
                .bind(target_user_id)
                .bind(expires_at)
                .bind(format!(
                    "{}赠送付费实例免费时长 {days} 天",
                    if is_admin { "管理员" } else { "节点所有者" }
                ))
                .execute(&mut *tx)
                .await
                .map_err(ApiError::from_sql)?;
            }
        }

        Ok::<i32, ApiError>(instance_id)
    })()
    .await;

    let instance_id = match reservation {
        Ok(instance_id) => instance_id,
        Err(err) => {
            if err.error.contains("HOST_RESOURCES_INSUFFICIENT") {
                return Ok((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "当前节点资源不足或已被占用" })),
                )
                    .into_response());
            }
            return Ok(bare_bad_request("创建实例失败，请稍后重试"));
        }
    };
    let reserved_host = pre_check_host;

    // IP allocation (outside the tx like the TS).
    let mut static_ipv4: Option<String> = None;
    for _ in 0..50 {
        let candidate = generate_random_ipv4();
        match is_ipv4_exists_on_host(&state, &candidate, reserved_host.id).await {
            Ok(false) => {
                static_ipv4 = Some(candidate);
                break;
            }
            Ok(true) => continue,
            Err(err) => {
                tracing::warn!("[Host Create For User] failed to allocate IPv4: {err}");
                break;
            }
        }
    }
    let mut static_ipv6: Option<String> = None;
    let needs_routed_ipv6 = matches!(network_mode.as_str(), "nat_ipv6" | "ipv6_only");
    if let Some(subnet) = &reserved_host.ipv6_subnet {
        if needs_routed_ipv6 {
            for _ in 0..50 {
                match generate_random_ipv6(subnet) {
                    Ok(candidate) => {
                        match is_ipv6_exists(&state, &candidate).await {
                            Ok(false) => {
                                static_ipv6 = Some(candidate);
                                break;
                            }
                            Ok(true) => continue,
                            Err(err) => {
                                tracing::warn!("[Host Create For User] failed to allocate IPv6: {err}");
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    let network_config = static_ipv4.as_ref().map(|ip| {
        crate::libs::incus::incus_config_container::StaticNetworkConfig {
            ip_address: Some(format!("{ip}/22")),
            gateway: Some("10.10.0.1".to_string()),
            dns: Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]),
            ipv6_address: static_ipv6
                .as_ref()
                .map(|v6| {
                    if pkg_instance_type == "vm" {
                        v6.clone()
                    } else {
                        format!("{v6}/128")
                    }
                }),
            ipv6_gateway: if pkg_instance_type == "vm" {
                static_ipv6.as_ref().map(|_| reserved_host.ipv6_gateway.clone().unwrap_or_default())
            } else {
                static_ipv6.as_ref().map(|_| "fe80::1".to_string())
            },
            ipv6_dns: None,
        }
    });
    let final_config = if pkg_instance_type == "vm" {
        generate_vm_config(&IncusConfigParams {
            instance_name: name.clone(),
            image_alias: image.clone(),
            root_password: initial_config
                .meta_data
                .as_ref()
                .map(|m| m.root_password.clone())
                .unwrap_or_else(|| auto_password.clone()),
            ssh_key: Some(ssh_key.clone()),
            instance_type: Some("virtual-machine".to_string()),
            network_mode: Some(network_mode.clone()),
            network: network_config,
            extra_shell_commands: None,
            instance_id_seed: Some(incus_id.clone()),
        })
    } else if static_ipv4.is_some() {
        generate_incus_config(&IncusConfigParams {
            instance_name: name.clone(),
            image_alias: image.clone(),
            root_password: initial_config
                .meta_data
                .as_ref()
                .map(|m| m.root_password.clone())
                .unwrap_or_else(|| auto_password.clone()),
            ssh_key: Some(ssh_key.clone()),
            instance_type: Some("container".to_string()),
            network_mode: Some(network_mode.clone()),
            network: network_config,
            extra_shell_commands: None,
            instance_id_seed: None,
        })
        .unwrap_or(initial_config)
    } else {
        initial_config
    };

    let selected_storage_pool = {
        let mut conn = state.db.acquire().await?;
        resolve_storage_pool_for_new_instance(&mut conn, reserved_host.id, Some(package_id))
            .await?
            .unwrap_or_else(|| "default".to_string())
    };
    sqlx::query("UPDATE instances SET storage_pool_name = $2 WHERE id = $1")
        .bind(instance_id)
        .bind(&selected_storage_pool)
        .execute(&state.db)
        .await?;

    let root_password_for_provision = final_config
        .meta_data
        .as_ref()
        .map(|m| m.root_password.clone())
        .unwrap_or_else(|| auto_password.clone());
    let cloud_init_map: Map<String, Value> = match serde_json::to_value(final_config.config_payload) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    };

    let _ = root_password_for_provision;
    let provision_state = state.clone();
    let provision_pool = state.incus_pool.clone();
    let provision_host = pool_host_from(&reserved_host);
    let provision_config = ManagedInstanceProvisionConfig {
        name: incus_id.clone(),
        image: image.clone(),
        cpu: requested_cpu as i64,
        memory: requested_memory as i64,
        disk: requested_disk as i64,
        cloud_init_config: Some(cloud_init_map),
        network_mode: NetworkMode::parse(&network_mode).unwrap_or(NetworkMode::Nat),
        nested: Some(pkg_nested),
        privileged: Some(pkg_privileged),
        port_limit: Some(pkg_port_limit as i64),
        instance_type: Some(pkg_instance_type.clone()),
        ssh_port: Some(ssh_port),
        storage_pool: Some(selected_storage_pool.clone()),
        ipv4_address: static_ipv4.clone(),
        ipv6_address: static_ipv6.clone(),
        ipv6_gateway: reserved_host.ipv6_gateway.clone(),
        host_interface: Some(reserved_host.ipv6_parent_interface.clone().unwrap_or_else(|| "eth0".to_string())),
        limits_read: if pkg_io_limit_mode == "throughput" { Some(pkg_limits_read.clone()) } else { None },
        limits_write: if pkg_io_limit_mode == "throughput" { Some(pkg_limits_write.clone()) } else { None },
        limits_read_iops: if pkg_io_limit_mode == "iops" { Some(pkg_limits_read_iops as i64) } else { None },
        limits_write_iops: if pkg_io_limit_mode == "iops" { Some(pkg_limits_write_iops as i64) } else { None },
        limits_ingress: plan_traffic_speed.clone().or(Some(pkg_limits_ingress.clone())),
        limits_egress: plan_traffic_speed.clone().or(Some(pkg_limits_egress.clone())),
        limits_processes: Some(pkg_limits_processes as i64),
        limits_cpu_priority: Some(pkg_limits_cpu_priority as i64),
        boot_autostart: Some(pkg_boot_autostart),
        boot_autostart_priority: Some(pkg_boot_autostart_priority as i64),
        boot_autostart_delay: Some(pkg_boot_autostart_delay as i64),
        boot_host_shutdown_timeout: Some(pkg_boot_host_shutdown_timeout as i64),
    };
    tokio::spawn(async move {
        if let Err(err) = provision_managed_instance_async(
            &provision_state.db,
            &provision_pool,
            instance_id as i64,
            &provision_host,
            &provision_config,
        )
        .await
        {
            tracing::error!("[Host Create For User] instance {instance_id} provisioning failed: {err}");
        }
    });

    let log_detail = match selected_plan.as_ref() {
        Some(plan) => format!(
            "{} created paid instance \"{}\" for user {} on host \"{}\" (Package: {}, Plan: {}, Gift: {} days free)",
            if is_admin { "Admin" } else { "Host owner" },
            name,
            target_username,
            reserved_host.name,
            pkg_name,
            plan.name,
            paid_gift_days.unwrap_or(0),
        ),
        None => format!(
            "{} created free instance \"{}\" for user {} on host \"{}\" (Package: {})",
            if is_admin { "Admin" } else { "Host owner" },
            name,
            target_username,
            reserved_host.name,
            pkg_name,
        ),
    };
    create_log(&state, operator.id, "host", "host.instance_create_for_user", &log_detail, "success").await;

    let format_memory = |mb: i32| if mb >= 1024 { format!("{:.1} GB", mb as f64 / 1024.0) } else { format!("{mb} MB") };
    let format_disk = |mb: i32| if mb >= 1024 { format!("{} GB", mb / 1024) } else { format!("{mb} MB") };
    let resource_info = format!(
        "CPU {}% | 内存 {} | 磁盘 {}",
        requested_cpu,
        format_memory(requested_memory),
        format_disk(requested_disk)
    );
    let (notify_title, notify_content) = match &selected_plan {
        Some(plan) => (
            if is_admin {
                "收到管理员赠送的付费实例".to_string()
            } else {
                "收到节点所有者赠送的付费实例".to_string()
            },
            format!(
                "{} {} 为您赠送了一台付费实例：{}\n套餐：{}\n方案：{}\n配置：{}\n节点：{}\n免费时长：{} 天\n到期时间：{}\n到期后将按方案价格正常计费",
                if is_admin { "管理员" } else { "节点所有者" },
                operator.username,
                name,
                pkg_name,
                plan.name,
                resource_info,
                reserved_host.name,
                paid_gift_days.unwrap_or(0),
                paid_gift_expires_at
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default(),
            ),
        ),
        None => (
            if is_admin {
                "收到管理员赠送的实例".to_string()
            } else {
                "收到节点所有者赠送的实例".to_string()
            },
            format!(
                "{} {} 为您创建了一台实例：{}\n套餐：{}\n配置：{}\n节点：{}",
                if is_admin { "管理员" } else { "节点所有者" },
                operator.username,
                name,
                pkg_name,
                resource_info,
                reserved_host.name,
            ),
        ),
    };
    create_inbox_notification(
        &state,
        target_user_id,
        if selected_plan.is_some() {
            "instance_paid_created"
        } else {
            "instance_gift"
        },
        &notify_title,
        &notify_content,
        json!({
            "instanceId": instance_id,
            "instanceName": name,
            "packageName": pkg_name,
            "planName": selected_plan.as_ref().map(|p| p.name.clone()),
            "cpu": requested_cpu,
            "memory": requested_memory,
            "disk": requested_disk,
            "hostName": reserved_host.name,
            "isPaid": selected_plan.is_some(),
            "charged": false,
            "amount": 0,
            "expiresAt": paid_gift_expires_at.map(|d| iso(d)),
            "giftDays": paid_gift_days,
            "createdBy": operator.username,
            "creatorType": if is_admin { "admin" } else { "host_owner" },
        }),
    )
    .await;
    // Email delivery stubbed (libs/external.rs).

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "message": "实例创建中",
            "instance": {
                "id": instance_id,
                "name": name,
                "incusId": incus_id,
                "host": reserved_host.name,
                "status": "creating",
                "user": { "id": target_user_id, "username": target_username },
                "isPaid": selected_plan.is_some(),
                "planName": selected_plan.as_ref().map(|p| p.name.clone()),
                "charged": false,
                "amount": 0,
                "expiresAt": paid_gift_expires_at.map(|d| iso(d)),
                "giftDays": paid_gift_days,
                "generatedPrivateKey": Value::Null,
            },
        })),
    )
        .into_response())
}

// ===========================================================================
// POST /:id/instances/gift-days — 节点所有者为实例赠送时长（免费）
// ===========================================================================

async fn gift_days(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_ids: Vec<i32> = body
        .get("instanceIds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_i64().map(|v| v as i32)).collect())
        .unwrap_or_default();
    let days = body_int(body.get("days")).unwrap_or(0);
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    // Only the host owner (admins included via ownership check below).
    if host.user_id != user.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    let instances: Vec<(i32, String, Option<DateTime<Utc>>, String, Option<String>, Option<DateTime<Utc>>, Option<i32>)> = sqlx::query_as(
        "SELECT id, name, expires_at, status::text AS status, suspend_reason, suspended_at, suspended_by \
         FROM instances WHERE id = ANY($1) AND host_id = $2 AND status <> 'deleted' \
         AND billing_mode = 'package'::\"InstanceBillingMode\" AND package_plan_id IS NOT NULL",
    )
    .bind(&instance_ids)
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;
    if instances.is_empty() {
        return Ok(bare_bad_request("没有找到可赠送时长的付费实例"));
    }
    let mut results: Vec<Value> = Vec::new();
    let now = Utc::now();
    let instances_total = instances.len() as i64;
    for (instance_id, name, expires_at, status, suspend_reason, suspended_at, suspended_by) in instances {
        let base_date = match expires_at {
            Some(expires) if expires > now => expires,
            _ => now,
        };
        let new_expires_at = base_date + chrono::Duration::days(days as i64);
        let expired_suspension = status == "suspended" && suspend_reason.as_deref() == Some("expired");
        let update = sqlx::query(
            "UPDATE instances SET expires_at = $2, \
             status = CASE WHEN $3 THEN 'stopped'::\"InstanceStatus\" ELSE status END, \
             suspended_at = CASE WHEN $3 THEN NULL ELSE suspended_at END, \
             suspended_by = CASE WHEN $3 THEN NULL ELSE suspended_by END, \
             suspend_reason = CASE WHEN $3 THEN NULL ELSE suspend_reason END \
             WHERE id = $1",
        )
        .bind(instance_id)
        .bind(new_expires_at)
        .bind(expired_suspension)
        .execute(&state.db)
        .await;
        match update {
            Ok(_) => {
                let _ = (suspended_at, suspended_by);
                results.push(json!({
                    "instanceId": instance_id,
                    "instanceName": name,
                    "success": true,
                    "newExpiresAt": iso(new_expires_at),
                }));
            }
            Err(err) => {
                results.push(json!({
                    "instanceId": instance_id,
                    "instanceName": name,
                    "success": false,
                    "error": format!("{err}"),
                }));
            }
        }
    }
    let success_count = results.iter().filter(|r| r["success"].as_bool() == Some(true)).count();
    let failed_count = results.len() - success_count;
    Ok(Json(json!({
        "message": format!(
            "成功为 {success_count} 个实例赠送 {days} 天{}",
            if failed_count > 0 { format!("，{failed_count} 个失败") } else { String::new() }
        ),
        "results": results,
        "successCount": success_count,
        "failedCount": failed_count,
        "skippedCount": instance_ids.len() as i64 - instances_total,
    })).into_response())
}

// ===========================================================================
// PATCH /:id/instances/:instanceId/renewal-price
// ===========================================================================

async fn update_renewal_price(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, instance_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_id = js_number_id(&instance_id)?;
    let new_price_f = body.get("newPrice").and_then(Value::as_f64).unwrap_or(-1.0);
    if new_price_f < 0.0 || new_price_f > 99999.0 {
        return Err(ApiError::bad_request(code::INVALID_ID));
    }
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if host.user_id != user.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.host_id != host_id {
        return Ok(bare_bad_request("实例不属于该节点"));
    }
    if instance.package_plan_id.is_none() {
        return Ok(bare_bad_request("只能修改付费实例的续费价格"));
    }
    if instance.status == "deleted" {
        return Ok(bare_bad_request("实例已删除"));
    }
    let old_price = instance.billing_price.map(decimal_to_f64).unwrap_or(0.0);
    if (old_price - new_price_f).abs() < 0.001 {
        return Ok(bare_bad_request("新价格与原价格相同，无需修改"));
    }
    sqlx::query("UPDATE instances SET billing_price = $2 WHERE id = $1")
        .bind(instance_id)
        .bind(billing::dec_from_f64(new_price_f)?)
        .execute(&state.db)
        .await?;
    send_notification(
        &state,
        instance.user_id,
        "instance_renewal_price_updated",
        &json!({
            "instanceName": instance.name,
            "oldPrice": old_price,
            "newPrice": new_price_f,
            "hostName": host.name,
        }),
    )
    .await;
    create_log(
        &state,
        user.id,
        "host",
        "host.update_instance_renewal_price",
        &format!(
            "Updated renewal price for instance \"{}\" (ID: {}): ¥{old_price:.2} -> ¥{new_price_f:.2}",
            instance.name, instance_id
        ),
        "success",
    )
    .await;
    Ok(Json(json!({
        "message": "续费价格已更新",
        "instanceId": instance_id,
        "instanceName": instance.name,
        "oldPrice": old_price,
        "newPrice": new_price_f,
    })).into_response())
}

// ===========================================================================
// POST /:id/ops/discover — 宿主机实例盘点
// ===========================================================================

async fn ops_discover(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let flow = async {
        let client = get_incus_client(&state, &host).await?;
        let incus_instances = list_instances(&client).await.map_err(ApiError::from)?;
        let db_instances: Vec<(i32, String, String, String)> = sqlx::query_as(
            "SELECT id, name, incus_id, status::text AS status FROM instances \
             WHERE host_id = $1 AND status <> 'deleted'",
        )
        .bind(host_id)
        .fetch_all(&state.db)
        .await?;
        let mut managed: Vec<Value> = Vec::new();
        let mut orphaned: Vec<Value> = Vec::new();
        for inst in &incus_instances {
            match db_instances.iter().find(|(_, _, incus_id, _)| *incus_id == inst.name) {
                Some((db_id, _, _, db_status)) => {
                    managed.push(json!({
                        "incusName": inst.name,
                        "incusType": inst.instance_type,
                        "incusStatus": inst.status,
                        "dbId": db_id,
                        "dbStatus": db_status,
                    }));
                }
                None => {
                    orphaned.push(json!({
                        "incusName": inst.name,
                        "incusType": inst.instance_type,
                        "incusStatus": inst.status,
                    }));
                }
            }
        }
        let mut missing: Vec<Value> = Vec::new();
        for (db_id, db_name, incus_id, db_status) in &db_instances {
            if !incus_instances.iter().any(|i| i.name == *incus_id) {
                missing.push(json!({
                    "dbId": db_id,
                    "dbName": db_name,
                    "incusId": incus_id,
                    "dbStatus": db_status,
                }));
            }
        }
        let summary = json!({
            "totalIncus": incus_instances.len(),
            "totalDb": db_instances.len(),
            "managedCount": managed.len(),
            "orphanedCount": orphaned.len(),
            "missingCount": missing.len(),
        });
        Ok::<_, ApiError>(json!({
            "managed": managed,
            "orphaned": orphaned,
            "missing": missing,
            "summary": summary,
        }))
    };
    match flow.await {
        Ok(payload) => Ok((StatusCode::OK, Json(payload)).into_response()),
        Err(err) => Ok(bare_bad_request(format!("{err}"))),
    }
}

// ===========================================================================
// POST /:id/ops/baseline-sync — 资源同步 + running 实例状态/IP 同步
// ===========================================================================

async fn ops_baseline_sync(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let flow = async {
        let used = sync_host_resources(&state, &host).await.map_err(|e| format!("{e}"))?.0;
        let instances: Vec<BatchInstanceRow> = sqlx::query_as(&format!(
            "SELECT {BATCH_INSTANCE_COLUMNS} FROM instances WHERE host_id = $1 AND status = 'running'"
        ))
        .bind(host_id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| format!("{e}"))?;
        let mut synced = 0i64;
        let mut ip_changed = 0i64;
        if !instances.is_empty() {
            let client = get_incus_client(&state, &host).await.map_err(|e| format!("{e}"))?;
            for instance in &instances {
                let attempt = async {
                    let incus_state = get_instance_state(&client, &instance.incus_id).await.map_err(|e| incus_error_message(&e))?;
                    let incus_instance = get_instance(&client, &instance.incus_id).await.map_err(|e| incus_error_message(&e))?;
                    let raw_status = incus_state.get("status").and_then(Value::as_str).unwrap_or("");
                    if !raw_status.is_empty() {
                        let mapped = map_instance_status(raw_status);
                        if mapped != "unknown" && mapped != instance.status {
                            update_instance_status(&state.db, instance.id, mapped)
                                .await
                                .map_err(|e| format!("{e}"))?;
                        }
                    }
                    let target = InstanceNetworkSyncTarget {
                        id: instance.id as i64,
                        name: Some(instance.name.clone()),
                        host_id: Some(host.id as i64),
                        network_mode: Some(instance.network_mode.clone()),
                        ipv4: instance.ipv4.clone(),
                        ipv6: instance.ipv6.clone(),
                    };
                    let (ipv4_changed, _, _, ipv6_changed, _, _) = persist_network_addresses(
                        &state,
                        &target,
                        instance.ipv4.clone(),
                        instance.ipv6.clone(),
                        Some(&Value::Object(incus_instance.devices.clone())),
                        Some(&Value::Object(incus_instance.expanded_devices.clone())),
                        Some(&incus_state),
                        true,
                    )
                    .await
                    .map_err(|e| format!("{e}"))?;
                    Ok::<_, String>((ipv4_changed, ipv6_changed))
                };
                match attempt.await {
                    Ok((v4, v6)) => {
                        if v4 || v6 {
                            ip_changed += 1;
                        }
                        synced += 1;
                    }
                    Err(message) => {
                        tracing::warn!("[ops/baseline-sync] instance {} sync failed: {message}", instance.incus_id);
                    }
                }
            }
        }
        Ok::<_, String>(json!({
            "message": "Baseline sync completed",
            "resources": {
                "cpuUsed": used.0,
                "memoryUsed": used.1,
                "diskUsed": used.2,
            },
            "instanceSync": {
                "total": instances.len(),
                "synced": synced,
                "ipChanged": ip_changed,
            },
        }))
    };
    match flow.await {
        Ok(payload) => Ok((StatusCode::OK, Json(payload)).into_response()),
        Err(message) => Ok(bare_bad_request(message)),
    }
}

// ===========================================================================
// POST /:id/ops/network-repair — 对所有实例批量同步 IP/状态
// ===========================================================================

async fn ops_network_repair(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let client = match get_incus_client(&state, &host).await {
        Ok(client) => client,
        Err(err) => {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": format!("无法连接到节点: {}", err.error) })),
            )
                .into_response());
        }
    };
    let instances: Vec<BatchInstanceRow> = sqlx::query_as(&format!(
        "SELECT {BATCH_INSTANCE_COLUMNS} FROM instances \
         WHERE host_id = $1 AND status NOT IN ('deleted','creating')"
    ))
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;

    let mut results: Vec<Value> = Vec::new();
    let mut success_count = 0i64;
    let mut changed_count = 0i64;
    for instance in &instances {
        let attempt = async {
            let incus_state = get_instance_state(&client, &instance.incus_id).await.map_err(|e| incus_error_message(&e))?;
            let incus_instance = get_instance(&client, &instance.incus_id).await.map_err(|e| incus_error_message(&e))?;
            let mut status_changed = false;
            let mut new_status = instance.status.clone();
            let raw_status = incus_state.get("status").and_then(Value::as_str).unwrap_or("");
            if !raw_status.is_empty() {
                let mapped = map_instance_status(raw_status);
                if mapped != "unknown" && mapped != instance.status {
                    update_instance_status(&state.db, instance.id, mapped)
                        .await
                        .map_err(|e| format!("{e}"))?;
                    status_changed = true;
                    new_status = mapped.to_string();
                    changed_count += 1;
                }
            }
            let target = InstanceNetworkSyncTarget {
                id: instance.id as i64,
                name: Some(instance.name.clone()),
                host_id: Some(host.id as i64),
                network_mode: Some(instance.network_mode.clone()),
                ipv4: instance.ipv4.clone(),
                ipv6: instance.ipv6.clone(),
            };
            let (ipv4_changed, old_v4, new_v4, ipv6_changed, old_v6, new_v6) = persist_network_addresses(
                &state,
                &target,
                instance.ipv4.clone(),
                instance.ipv6.clone(),
                Some(&Value::Object(incus_instance.devices.clone())),
                Some(&Value::Object(incus_instance.expanded_devices.clone())),
                Some(&incus_state),
                true,
            )
            .await
            .map_err(|e| format!("{e}"))?;
            if ipv4_changed || ipv6_changed {
                changed_count += 1;
            }
            let mut payload = json!({ "id": instance.id, "name": instance.name, "success": true });
            if status_changed {
                payload["statusChanged"] = json!(true);
                payload["oldStatus"] = json!(instance.status);
                payload["newStatus"] = json!(new_status);
            }
            if ipv4_changed {
                payload["ipv4Changed"] = json!(true);
                payload["oldIpv4"] = json!(old_v4);
                payload["newIpv4"] = json!(new_v4);
            }
            if ipv6_changed {
                payload["ipv6Changed"] = json!(true);
                payload["oldIpv6"] = json!(old_v6);
                payload["newIpv6"] = json!(new_v6);
            }
            Ok::<_, String>(payload)
        };
        match attempt.await {
            Ok(payload) => {
                success_count += 1;
                results.push(payload);
            }
            Err(message) => {
                results.push(json!({
                    "id": instance.id,
                    "name": instance.name,
                    "success": false,
                    "error": message,
                }));
            }
        }
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "message": "Network repair completed",
            "results": results,
            "summary": {
                "total": instances.len(),
                "success": success_count,
                "failed": instances.len() as i64 - success_count,
                "changed": changed_count,
            },
        })),
    )
        .into_response())
}

// ===========================================================================
// POST /:id/ops/instances/:instanceId/preview
// ===========================================================================

async fn ops_instance_preview(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, instance_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_id = js_number_id(&instance_id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.host_id != host_id {
        return Ok(bare_bad_request("实例不属于该节点"));
    }
    let active_task = get_active_task_for_instance(&state, instance_id).await?;
    let is_stopped = instance.status == "stopped";
    let is_suspended = instance.status == "suspended";
    let can_sync = active_task.is_none();
    let can_restart = active_task.is_none() && !is_suspended;
    let can_rebuild = active_task.is_none() && !is_suspended && is_stopped;
    let can_recreate = active_task.is_none() && !is_suspended;

    let mut notes: Vec<String> = Vec::new();
    if let Some(task) = &active_task {
        notes.push(format!("当前存在进行中的 {} 任务 #{}", task.1, task.0));
    }
    if is_suspended {
        notes.push(if instance.suspend_reason.as_deref() == Some("expired") {
            "实例处于到期封停状态，不允许高风险操作".to_string()
        } else {
            "实例处于封停状态，不允许高风险操作".to_string()
        });
    }
    if !is_stopped {
        notes.push("实例当前不是 stopped，高风险重装需先停机".to_string());
    }
    let suggested_action = if active_task.is_some() || is_suspended {
        "none"
    } else if !is_stopped {
        "sync"
    } else {
        "rebuild"
    };

    let has_active_task = active_task.is_some();
    let active_task_json = active_task.map(|(id, task_type, status)| json!({
        "id": id,
        "taskType": task_type,
        "status": status,
    }));
    Ok(Json(json!({
        "instanceId": instance.id,
        "instanceName": instance.name,
        "incusId": instance.incus_id,
        "instanceStatus": instance.status,
        "hostName": host.name,
        "hostId": host.id,
        "imageAlias": instance.image,
        "canSync": can_sync,
        "canRestart": can_restart,
        "canForceRestart": can_restart,
        "canRebuild": can_rebuild,
        "canRecreate": can_recreate,
        "activeTask": active_task_json,
        "risk": {
            "status": instance.status,
            "isStopped": is_stopped,
            "hasActiveTask": has_active_task,
            "suggestedAction": suggested_action,
            "notes": notes,
        },
    })).into_response())
}

// ===========================================================================
// GET /:id/ops/instances/:instanceId/ssh-keys | init-commands
// ===========================================================================

async fn ops_instance_ssh_keys(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, instance_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_id = js_number_id(&instance_id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.host_id != host_id {
        return Ok(bare_bad_request("实例不属于该节点"));
    }
    let key_rows: Vec<(i32, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, name, fingerprint, created_at FROM ssh_keys WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(instance.user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "keys": key_rows
            .iter()
            .map(|(id, name, fingerprint, created_at)| json!({
                "id": id,
                "name": name,
                "fingerprint": fingerprint,
                "created_at": iso(*created_at),
            }))
            .collect::<Vec<_>>(),
    })).into_response())
}

async fn ops_instance_init_commands(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, instance_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_id = js_number_id(&instance_id)?;
    let distro = params.get("distro").map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("linux");
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.host_id != host_id {
        return Ok(bare_bad_request("实例不属于该节点"));
    }
    let commands = get_enabled_commands_by_distro(&state, instance.user_id, distro).await?;
    Ok(Json(json!({
        "commands": commands
            .iter()
            .map(|(id, name, command, distros, description)| {
                let line_count = command
                    .split(|c| c == '\n' || c == '\r')
                    .filter(|line| !line.trim().is_empty())
                    .count();
                json!({
                    "id": id,
                    "name": name,
                    "commandLineCount": line_count,
                    "distros": distros,
                    "description": description,
                })
            })
            .collect::<Vec<_>>(),
    })).into_response())
}

// ===========================================================================
// POST /:id/ops/instances/:instanceId/sync
// ===========================================================================

async fn ops_instance_sync(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, instance_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_id = js_number_id(&instance_id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.host_id != host_id {
        return Ok(bare_bad_request("实例不属于该节点"));
    }
    let flow = async {
        let client = match get_incus_client(&state, &host).await {
            Ok(client) => client,
            Err(err) => return Err(format!("{err}")),
        };
        let incus_state = match get_instance_state(&client, &instance.incus_id).await {
            Ok(v) => v,
            Err(err) => return Err(incus_error_message(&err)),
        };
        let incus_instance = match get_instance(&client, &instance.incus_id).await {
            Ok(v) => v,
            Err(err) => return Err(incus_error_message(&err)),
        };
        let raw_status = incus_state.get("status").and_then(Value::as_str).unwrap_or("");
        if raw_status.is_empty() {
            return Err("无法获取实例状态".to_string());
        }
        let incus_status = map_instance_status(raw_status);
        if incus_status == "unknown" {
            return Err(format!("未知状态: {raw_status}"));
        }
        let mut status_changed = false;
        let mut from: Option<String> = None;
        let mut to: Option<String> = None;
        if instance.status != incus_status {
            update_instance_status(&state.db, instance_id, incus_status)
                .await
                .map_err(|e| format!("{e}"))?;
            status_changed = true;
            from = Some(instance.status.clone());
            to = Some(incus_status.to_string());
        }
        let target = InstanceNetworkSyncTarget {
            id: instance_id as i64,
            name: Some(instance.name.clone()),
            host_id: Some(instance.host_id as i64),
            network_mode: Some(instance.network_mode.clone()),
            ipv4: instance.ipv4.clone(),
            ipv6: instance.ipv6.clone(),
        };
        let (ipv4_changed, old_v4, new_v4, ipv6_changed, old_v6, new_v6) = persist_network_addresses(
            &state,
            &target,
            instance.ipv4.clone(),
            instance.ipv6.clone(),
            Some(&Value::Object(incus_instance.devices.clone())),
            Some(&Value::Object(incus_instance.expanded_devices.clone())),
            Some(&incus_state),
            true,
        )
        .await
        .map_err(|e| format!("{e}"))?;
        let mut payload = json!({
            "success": true,
            "message": "实例状态/IP 已同步",
            "statusChanged": status_changed,
            "from": from,
            "to": to,
            "currentStatus": incus_status,
            "ipv4Changed": ipv4_changed,
            "ipv6Changed": ipv6_changed,
        });
        if ipv4_changed {
            payload["oldIpv4"] = json!(old_v4);
            payload["newIpv4"] = json!(new_v4);
        }
        if ipv6_changed {
            payload["oldIpv6"] = json!(old_v6);
            payload["newIpv6"] = json!(new_v6);
        }
        Ok::<_, String>(payload)
    };
    match flow.await {
        Ok(payload) => Ok((StatusCode::OK, Json(payload)).into_response()),
        Err(message) => {
            if message.contains("not found") || message.contains("Instance not found") {
                return Ok((StatusCode::NOT_FOUND, Json(json!({ "error": "实例在节点上不存在" }))).into_response());
            }
            Ok(bare_bad_request(format!("同步失败: {message}")))
        }
    }
}

// ===========================================================================
// POST /:id/ops/instances/:instanceId/restart
// ===========================================================================

async fn ops_instance_restart(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, instance_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_id = js_number_id(&instance_id)?;
    let force = body.get("force") == Some(&Value::Bool(true));
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.host_id != host_id {
        return Ok(bare_bad_request("实例不属于该节点"));
    }
    if instance.status == "suspended" {
        return Ok(bare_bad_request("实例处于封停状态"));
    }
    if let Some(task) = get_active_task_for_instance(&state, instance_id).await? {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Instance has an active task",
                "code": "TASK_IN_PROGRESS",
                "taskId": task.0,
                "taskType": task.1,
                "status": task.2,
            })),
        )
            .into_response());
    }
    match (async {
        let client = get_incus_client(&state, &host).await.map_err(|e| format!("{e}"))?;
        restart_instance(&client, &instance.incus_id, force)
            .await
            .map_err(|e| incus_error_message(&e))
    })
    .await
    {
        Ok(_) => Ok((
            StatusCode::OK,
            Json(json!({
                "success": true,
                "message": if force { "实例已强制重启" } else { "实例已安全重启" },
            })),
        )
            .into_response()),
        Err(message) => Ok(bare_bad_request(format!("重启失败: {message}"))),
    }
}

// ===========================================================================
// GET /:id/ops/audit/rules — list; POST — create
// ===========================================================================

async fn audit_rules_list(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let _ = get_authorized_ops_host(&state, host_id, &user).await?;
    let mut rules = get_audit_rule_responses(&state, host_id).await?;
    rules["canCreateGlobal"] = json!(user.role == "admin");
    Ok(Json(rules).into_response())
}

async fn audit_rules_create(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_authorized_ops_host(&state, host_id, &user).await?;
    let scope = if body.get("scope").and_then(Value::as_str) == Some("global") {
        "global"
    } else {
        "host"
    };
    if scope == "global" && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    let name = body.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let pattern = body.get("pattern").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if name.chars().count() < 2 || name.chars().count() > 80 || pattern.is_empty() || pattern.chars().count() > 500 {
        return Ok(bare_bad_request("body/name must be 2-80 characters and body/pattern 1-500"));
    }
    let match_type = normalize_audit_match_type(body.get("matchType"));
    if validate_audit_regex(&match_type, &pattern).is_err() {
        return Ok(bare_bad_request("正则表达式无效"));
    }
    let severity = normalize_audit_severity_value(body.get("severity"));
    let category = body
        .get("category")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "custom".to_string());
    let target_types = json!(normalize_audit_target_types(body.get("targetTypes")));
    let description = body
        .get("description")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let case_sensitive = body.get("caseSensitive") == Some(&Value::Bool(true));
    let recommendation = body
        .get("recommendation")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let enabled = match body.get("enabled") {
        Some(Value::Bool(v)) => *v,
        _ => true,
    };
    let row: AuditCustomRuleRow = sqlx::query_as(&format!(
        "INSERT INTO instance_audit_rules (host_id, created_by_id, name, description, severity, \
         category, target_types, match_type, pattern, case_sensitive, recommendation, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         RETURNING {AUDIT_RULE_COLUMNS}",
    ))
    .bind(if scope == "global" { None } else { Some(host_id) })
    .bind(user.id)
    .bind(&name)
    .bind(&description)
    .bind(&severity)
    .bind(&category)
    .bind(&target_types)
    .bind(&match_type)
    .bind(&pattern)
    .bind(case_sensitive)
    .bind(&recommendation)
    .bind(enabled)
    .fetch_one(&state.db)
    .await?;
    create_log(
        &state,
        user.id,
        "host",
        "host.ops.audit.rule.create",
        &format!("Created {scope} audit rule \"{}\" on host \"{}\"", row.name, host.name),
        "success",
    )
    .await;
    Ok(Json(custom_rule_response(&row, host_id)).into_response())
}

async fn audit_rule_update(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, rule_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let rule_id = js_number_id(&rule_id)?;
    let host = get_authorized_ops_host(&state, host_id, &user).await?;
    let existing: Option<AuditCustomRuleRow> = sqlx::query_as(&format!(
        "SELECT {AUDIT_RULE_COLUMNS} FROM instance_audit_rules WHERE id = $1"
    ))
    .bind(rule_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(existing) = existing else {
        return Ok(bare_bad_request("审查规则不存在"));
    };
    if existing.host_id != Some(host_id) && existing.host_id.is_some() {
        return Ok(bare_bad_request("审查规则不存在"));
    }
    if existing.host_id.is_none() && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    let match_type = match body.get("matchType") {
        Some(_) => normalize_audit_match_type(body.get("matchType")),
        None => existing.match_type.clone(),
    };
    let pattern = match body.get("pattern") {
        Some(Value::String(p)) => p.trim().to_string(),
        _ => existing.pattern.clone(),
    };
    if validate_audit_regex(&match_type, &pattern).is_err() {
        return Ok(bare_bad_request("正则表达式无效"));
    }
    let name = match body.get("name") {
        Some(Value::String(v)) => Some(v.trim().to_string()),
        _ => None,
    };
    let description = match body.get("description") {
        Some(Value::String(v)) => Some(Some(v.trim().to_string()).filter(|s| !s.is_empty())),
        Some(Value::Null) => Some(None),
        _ => None,
    };
    let severity = match body.get("severity") {
        Some(_) => Some(normalize_audit_severity_value(body.get("severity"))),
        None => None,
    };
    let category = match body.get("category") {
        Some(Value::String(v)) => Some(if v.trim().is_empty() { "custom".to_string() } else { v.trim().to_string() }),
        _ => None,
    };
    let target_types = match body.get("targetTypes") {
        Some(_) => Some(json!(normalize_audit_target_types(body.get("targetTypes")))),
        None => None,
    };
    let case_sensitive = body.get("caseSensitive").and_then(Value::as_bool);
    let recommendation = match body.get("recommendation") {
        Some(Value::String(v)) => Some(Some(v.trim().to_string()).filter(|s| !s.is_empty())),
        Some(Value::Null) => Some(None),
        _ => None,
    };
    let enabled = body.get("enabled").and_then(Value::as_bool);

    let updated: AuditCustomRuleRow = sqlx::query_as(&format!(
        "UPDATE instance_audit_rules SET \
         name = COALESCE($2, name), description = COALESCE($3, description), \
         severity = COALESCE($4, severity), category = COALESCE($5, category), \
         target_types = COALESCE($6, target_types), match_type = COALESCE($7, match_type), \
         pattern = COALESCE($8, pattern), case_sensitive = COALESCE($9, case_sensitive), \
         recommendation = COALESCE($10, recommendation), enabled = COALESCE($11, enabled) \
         WHERE id = $1 RETURNING {AUDIT_RULE_COLUMNS}",
    ))
    .bind(rule_id)
    .bind(&name)
    .bind(&description)
    .bind(&severity)
    .bind(&category)
    .bind(&target_types)
    .bind(&match_type)
    .bind(&pattern)
    .bind(case_sensitive)
    .bind(&recommendation)
    .bind(enabled)
    .fetch_one(&state.db)
    .await?;
    create_log(
        &state,
        user.id,
        "host",
        "host.ops.audit.rule.update",
        &format!("Updated audit rule \"{}\" on host \"{}\"", updated.name, host.name),
        "success",
    )
    .await;
    Ok(Json(custom_rule_response(&updated, host_id)).into_response())
}

async fn audit_rule_delete(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, rule_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let rule_id = js_number_id(&rule_id)?;
    let host = get_authorized_ops_host(&state, host_id, &user).await?;
    let existing: Option<AuditCustomRuleRow> = sqlx::query_as(&format!(
        "SELECT {AUDIT_RULE_COLUMNS} FROM instance_audit_rules WHERE id = $1"
    ))
    .bind(rule_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(existing) = existing else {
        return Ok(bare_bad_request("审查规则不存在"));
    };
    if existing.host_id != Some(host_id) && existing.host_id.is_some() {
        return Ok(bare_bad_request("审查规则不存在"));
    }
    if existing.host_id.is_none() && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    sqlx::query("DELETE FROM instance_audit_rules WHERE id = $1")
        .bind(rule_id)
        .execute(&state.db)
        .await?;
    create_log(
        &state,
        user.id,
        "host",
        "host.ops.audit.rule.delete",
        &format!("Deleted audit rule \"{}\" on host \"{}\"", existing.name, host.name),
        "warning",
    )
    .await;
    Ok(Json(json!({ "success": true })).into_response())
}

async fn audit_builtin_rule_override(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, rule_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_authorized_ops_host(&state, host_id, &user).await?;
    let base_rule = find_builtin_audit_rule(&rule_id)
        .ok_or_else(|| bare_err("系统内置规则不存在"))?;
    let match_type = match body.get("matchType") {
        Some(_) => normalize_audit_match_type(body.get("matchType")),
        None => base_rule.match_type.clone(),
    };
    let pattern = match body.get("pattern") {
        Some(Value::String(p)) => p.trim().to_string(),
        _ => base_rule.pattern_text.clone(),
    };
    if validate_audit_regex(&match_type, &pattern).is_err() {
        return Ok(bare_bad_request("正则表达式无效"));
    }
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| base_rule.name.clone());
    let description: Option<String> = match body.get("description") {
        Some(Value::String(v)) => Some(v.trim().to_string()).filter(|s| !s.is_empty()),
        Some(Value::Null) => None,
        _ => base_rule.description.clone(),
    };
    let severity = match body.get("severity") {
        Some(_) => normalize_audit_severity_value(body.get("severity")),
        None => base_rule.severity.clone(),
    };
    let category = body
        .get("category")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| base_rule.category.clone());
    let target_types = match body.get("targetTypes") {
        Some(_) => json!(normalize_audit_target_types(body.get("targetTypes"))),
        None => json!(base_rule.target_types),
    };
    let case_sensitive = match body.get("caseSensitive") {
        Some(Value::Bool(v)) => *v,
        _ => base_rule.case_sensitive,
    };
    let recommendation: Option<String> = match body.get("recommendation") {
        Some(Value::String(v)) => Some(v.trim().to_string()).filter(|s| !s.is_empty()),
        Some(Value::Null) => None,
        _ => base_rule.recommendation.clone(),
    };
    let enabled = match body.get("enabled") {
        Some(Value::Bool(v)) => *v,
        _ => base_rule.enabled,
    };
    let override_row: AuditBuiltinOverrideRow = sqlx::query_as(&format!(
        "INSERT INTO instance_audit_builtin_rule_overrides (host_id, builtin_rule_id, created_by_id, \
         name, description, severity, category, target_types, match_type, pattern, case_sensitive, \
         recommendation, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         ON CONFLICT (host_id, builtin_rule_id) DO UPDATE SET \
         created_by_id = $3, name = $4, description = $5, severity = $6, category = $7, \
         target_types = $8, match_type = $9, pattern = $10, case_sensitive = $11, \
         recommendation = $12, enabled = $13 \
         RETURNING {AUDIT_OVERRIDE_COLUMNS}",
    ))
    .bind(host_id)
    .bind(&base_rule.id)
    .bind(user.id)
    .bind(&name)
    .bind(&description)
    .bind(&severity)
    .bind(&category)
    .bind(&target_types)
    .bind(&match_type)
    .bind(&pattern)
    .bind(case_sensitive)
    .bind(&recommendation)
    .bind(enabled)
    .fetch_one(&state.db)
    .await?;
    create_log(
        &state,
        user.id,
        "host",
        "host.ops.audit.builtin_rule.override",
        &format!(
            "Updated builtin audit rule override \"{}\" on host \"{}\"",
            base_rule.id, host.name
        ),
        "success",
    )
    .await;
    let applied = apply_builtin_audit_rule_override(&base_rule, Some(&override_row));
    Ok(Json(builtin_rule_response(&applied, &base_rule, Some(&override_row), host_id)).into_response())
}

async fn audit_builtin_rule_reset(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, rule_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_authorized_ops_host(&state, host_id, &user).await?;
    let base_rule = find_builtin_audit_rule(&rule_id)
        .ok_or_else(|| bare_err("系统内置规则不存在"))?;
    sqlx::query(
        "DELETE FROM instance_audit_builtin_rule_overrides WHERE host_id = $1 AND builtin_rule_id = $2",
    )
    .bind(host_id)
    .bind(&base_rule.id)
    .execute(&state.db)
    .await?;
    create_log(
        &state,
        user.id,
        "host",
        "host.ops.audit.builtin_rule.reset",
        &format!(
            "Reset builtin audit rule override \"{}\" on host \"{}\"",
            base_rule.id, host.name
        ),
        "warning",
    )
    .await;
    Ok(Json(json!({ "success": true })).into_response())
}

// ===========================================================================
// GET/POST /:id/ops/audit/ignores, DELETE .../:ignoreId, GET history
// ===========================================================================

async fn audit_ignores_list(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_filter = params.get("instanceId");
    let _ = get_authorized_ops_host(&state, host_id, &user).await?;
    let instance_id = match instance_filter {
        Some(raw) => Some(js_number_id(raw)?),
        None => None,
    };
    let rows: Vec<(i32, Option<i32>, Option<String>, Option<String>, Option<String>, String, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, instance_id, rule_id, target_type, match_text, scope, reason, expires_at, created_at \
         FROM instance_audit_ignores WHERE host_id = $1 AND enabled = true \
         AND ($2::int IS NULL OR instance_id IS NULL OR instance_id = $2) \
         ORDER BY created_at DESC LIMIT 100",
    )
    .bind(host_id)
    .bind(instance_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "ignores": rows
            .iter()
            .map(|(id, instance_id, rule_id, target_type, match_text, scope, reason, expires_at, created_at)| json!({
                "id": id,
                "hostId": host_id,
                "instanceId": instance_id,
                "ruleId": rule_id,
                "targetType": target_type,
                "matchText": match_text,
                "scope": scope,
                "reason": reason,
                "expiresAt": iso_opt(*expires_at),
                "createdAt": iso(*created_at),
            }))
            .collect::<Vec<_>>(),
    })))
}

async fn audit_ignores_create(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let host = get_authorized_ops_host(&state, host_id, &user).await?;
    let scope = if body.get("scope").and_then(Value::as_str) == Some("host") {
        "host"
    } else {
        "instance"
    };
    let mut instance_id: Option<i32> = None;
    if scope == "instance" {
        let raw = body_int(body.get("instanceId")).unwrap_or(0) as i32;
        if raw == 0 {
            return Err(ApiError::bad_request(code::INVALID_ID));
        }
        let instance = get_instance_by_id(&state, raw).await?;
        match instance {
            Some(instance) if instance.host_id == host_id => {}
            _ => return Err(ApiError::not_found(code::INSTANCE_NOT_FOUND)),
        }
        instance_id = Some(raw);
    }
    let rule_id = body
        .get("ruleId")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let match_text = body
        .get("matchText")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if rule_id.is_none() && match_text.is_none() {
        return Ok(bare_bad_request("白名单至少需要规则 ID 或匹配文本"));
    }
    let expires_in_days = body_int(body.get("expiresInDays")).unwrap_or(0);
    let expires_at = if expires_in_days > 0 {
        Some(Utc::now() + chrono::Duration::days(expires_in_days.min(365) as i64))
    } else {
        None
    };
    let target_type = normalize_audit_finding_target(body.get("targetType"));
    let reason = body
        .get("reason")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let (ignore_id, created_at): (i32, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO instance_audit_ignores (host_id, instance_id, created_by_id, rule_id, \
         target_type, match_text, scope, reason, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, created_at",
    )
    .bind(host_id)
    .bind(instance_id)
    .bind(user.id)
    .bind(&rule_id)
    .bind(&target_type)
    .bind(&match_text)
    .bind(scope)
    .bind(&reason)
    .bind(expires_at)
    .fetch_one(&state.db)
    .await?;
    create_log(
        &state,
        user.id,
        "host",
        "host.ops.audit.ignore.create",
        &format!("Created {scope} audit whitelist on host \"{}\"", host.name),
        "success",
    )
    .await;
    Ok(Json(json!({
        "id": ignore_id,
        "hostId": host_id,
        "instanceId": instance_id,
        "createdById": user.id,
        "ruleId": rule_id,
        "targetType": target_type,
        "matchText": match_text,
        "scope": scope,
        "reason": reason,
        "expiresAt": iso_opt(expires_at),
        "createdAt": iso(created_at),
    })).into_response())
}

async fn audit_ignores_delete(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, ignore_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let ignore_id = js_number_id(&ignore_id)?;
    let host = get_authorized_ops_host(&state, host_id, &user).await?;
    let existing: Option<i32> =
        sqlx::query_scalar("SELECT id FROM instance_audit_ignores WHERE id = $1 AND host_id = $2")
            .bind(ignore_id)
            .bind(host_id)
            .fetch_optional(&state.db)
            .await?;
    if existing.is_none() {
        return Ok(bare_bad_request("白名单不存在"));
    }
    sqlx::query("UPDATE instance_audit_ignores SET enabled = false WHERE id = $1")
        .bind(ignore_id)
        .execute(&state.db)
        .await?;
    create_log(
        &state,
        user.id,
        "host",
        "host.ops.audit.ignore.delete",
        &format!("Disabled audit whitelist #{ignore_id} on host \"{}\"", host.name),
        "warning",
    )
    .await;
    Ok(Json(json!({ "success": true })).into_response())
}

#[derive(Debug, sqlx::FromRow)]
struct AuditHistoryScanRow {
    pub id: i32,
    pub host_id: i32,
    pub instance_id: i32,
    pub user_id: i32,
    pub status: String,
    pub capability: Option<String>,
    pub risk_level: String,
    pub finding_count: i32,
    pub ignored_count: i32,
    pub process_count: i32,
    pub connection_count: i32,
    pub listening_count: i32,
    pub startup_item_count: i32,
    pub findings: Value,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub uid: Option<i32>,
    pub username: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct AuditHistoryActionRow {
    pub id: i32,
    pub scan_id: Option<i32>,
    pub host_id: i32,
    pub instance_id: i32,
    pub user_id: i32,
    pub action_type: String,
    pub pid: Option<i32>,
    pub signal: Option<String>,
    pub process_command: Option<String>,
    pub reason: String,
    pub result: String,
    pub stderr: Option<String>,
    pub created_at: DateTime<Utc>,
    pub uid: Option<i32>,
    pub username: Option<String>,
}

async fn audit_history(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let _ = get_authorized_ops_host(&state, host_id, &user).await?;
    let instance_id = match params.get("instanceId") {
        Some(raw) if !raw.trim().is_empty() => Some(js_number_id(raw)?),
        _ => None,
    };
    let page_size = clamp_int_query(params.get("pageSize"), 20, 1, 50);
    let scans: Vec<AuditHistoryScanRow> = sqlx::query_as(
        "SELECT s.id, s.host_id, s.instance_id, s.user_id, s.status, s.capability, s.risk_level, \
         s.finding_count, s.ignored_count, s.process_count, s.connection_count, s.listening_count, \
         s.startup_item_count, s.findings, s.error, s.created_at, u.id, u.username \
         FROM instance_audit_scans s LEFT JOIN users u ON u.id = s.user_id \
         WHERE s.host_id = $1 AND ($2::int IS NULL OR s.instance_id = $2) \
         ORDER BY s.created_at DESC LIMIT $3",
    )
    .bind(host_id)
    .bind(instance_id)
    .bind(page_size as i64)
    .fetch_all(&state.db)
    .await?;
    let actions: Vec<AuditHistoryActionRow> = sqlx::query_as(
        "SELECT a.id, a.scan_id, a.host_id, a.instance_id, a.user_id, a.action_type, a.pid, a.signal, \
         a.process_command, a.reason, a.result, a.stderr, a.created_at, u.id, u.username \
         FROM instance_audit_actions a LEFT JOIN users u ON u.id = a.user_id \
         WHERE a.host_id = $1 AND ($2::int IS NULL OR a.instance_id = $2) \
         ORDER BY a.created_at DESC LIMIT $3",
    )
    .bind(host_id)
    .bind(instance_id)
    .bind(page_size as i64)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "scans": scans
            .iter()
            .map(|s| json!({
                "id": s.id,
                "hostId": s.host_id,
                "instanceId": s.instance_id,
                "userId": s.user_id,
                "status": s.status,
                "capability": s.capability,
                "riskLevel": s.risk_level,
                "findingCount": s.finding_count,
                "ignoredCount": s.ignored_count,
                "processCount": s.process_count,
                "connectionCount": s.connection_count,
                "listeningCount": s.listening_count,
                "startupItemCount": s.startup_item_count,
                "findings": s.findings,
                "error": s.error,
                "createdAt": iso(s.created_at),
                "user": s.uid.map(|id| json!({ "id": id, "username": s.username })),
            }))
            .collect::<Vec<_>>(),
        "actions": actions
            .iter()
            .map(|a| json!({
                "id": a.id,
                "scanId": a.scan_id,
                "hostId": a.host_id,
                "instanceId": a.instance_id,
                "userId": a.user_id,
                "actionType": a.action_type,
                "pid": a.pid,
                "signal": a.signal,
                "processCommand": a.process_command,
                "reason": a.reason,
                "result": a.result,
                "stdout": Value::Null,
                "stderr": a.stderr,
                "createdAt": iso(a.created_at),
                "user": a.uid.map(|id| json!({ "id": id, "username": a.username })),
            }))
            .collect::<Vec<_>>(),
    })).into_response())
}

// ===========================================================================
// POST /:id/ops/instances/:instanceId/audit/scan
// ===========================================================================

async fn audit_scan(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, instance_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_id = js_number_id(&instance_id)?;
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.host_id != host_id {
        return Ok(bare_bad_request("实例不属于该节点"));
    }

    // Touch/ensure the agent audit config row like the TS upsert.
    sqlx::query(
        "INSERT INTO host_agent_audit_configs (host_id, enabled, interval_seconds, batch_size, \
         last_requested_at, updated_by_id) \
         VALUES ($1, false, 300, 8, now(), $2) \
         ON CONFLICT (host_id) DO UPDATE SET last_requested_at = now(), updated_by_id = $2",
    )
    .bind(host_id)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    let flow = async {
        let client = get_incus_client(&state, &host).await?;
        let incus_state = get_instance_state(&client, &instance.incus_id).await?;
        let incus_instance = get_instance(&client, &instance.incus_id).await?;
        let incus_status = incus_state
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or(&incus_instance.status)
            .to_string();
        if incus_status != "Running" {
            return Err(ScanFlowError::NotRunning(incus_status));
        }
        let instance_type = if incus_instance.instance_type.is_empty() {
            "unknown".to_string()
        } else {
            incus_instance.instance_type.clone()
        };

        let exec_results = tokio::join!(
            exec_with_output(&client, &instance.incus_id, IncusExecCommand::Shell(build_process_audit_command()), None, 45_000),
            exec_with_output(&client, &instance.incus_id, IncusExecCommand::Shell(build_connection_audit_command()), None, 45_000),
            exec_with_output(&client, &instance.incus_id, IncusExecCommand::Shell(build_startup_audit_command()), None, 45_000),
        );
        let (process_result, connection_result, startup_result) = exec_results;
        let mut stderr: Vec<String> = Vec::new();
        let (process_output, connection_output, startup_output) = match (
            process_result,
            connection_result,
            startup_result,
        ) {
            (Ok(p), Ok(c), Ok(s)) => {
                for item in [&p.stderr, &c.stderr, &s.stderr] {
                    let trimmed = item.trim();
                    if !trimmed.is_empty() {
                        stderr.push(trimmed.chars().take(1000).collect());
                    }
                }
                (p.stdout, c.stdout, s.stdout)
            }
            exec_err => {
                let message = match (&exec_err.0, &exec_err.1, &exec_err.2) {
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => incus_error_message(e),
                    _ => "exec failed".to_string(),
                };
                return Err(ScanFlowError::ExecUnavailable(message, instance_type, incus_status));
            }
        };

        let mut processes = parse_processes(&process_output, 300);
        let connections = parse_connections(&connection_output, 300);
        let mut startup_items = parse_startup_items(&startup_output, 300);
        let rules = get_audit_rule_definitions(&state, host_id).await?;
        let ignores = get_audit_ignores_for_scan(&state, host_id, instance.id).await?;
        let (findings, summary) = analyze_audit_data(&mut processes, &connections, &mut startup_items, &rules, &ignores);
        let ignored_count = findings
            .iter()
            .filter(|f| f.get("ignored").and_then(Value::as_bool) == Some(true))
            .count();
        let capability = if instance_type == "virtual-machine" {
            "guest-agent"
        } else {
            "container-exec"
        };
        let scan_id: i32 = sqlx::query_scalar(
            "INSERT INTO instance_audit_scans (host_id, instance_id, user_id, status, capability, \
             risk_level, finding_count, ignored_count, process_count, connection_count, \
             listening_count, startup_item_count, findings) \
             VALUES ($1, $2, $3, 'success', $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
        )
        .bind(host_id)
        .bind(instance.id)
        .bind(user.id)
        .bind(capability)
        .bind(summary["riskLevel"].as_str().unwrap_or("info"))
        .bind(summary["findingCount"].as_i64().unwrap_or(0) as i32)
        .bind(ignored_count as i32)
        .bind(summary["processCount"].as_i64().unwrap_or(0) as i32)
        .bind(summary["connectionCount"].as_i64().unwrap_or(0) as i32)
        .bind(summary["listeningCount"].as_i64().unwrap_or(0) as i32)
        .bind(summary["startupItemCount"].as_i64().unwrap_or(0) as i32)
        .bind(json!(findings.iter().take(80).cloned().collect::<Vec<_>>()))
        .fetch_one(&state.db)
        .await
        .map_err(ApiError::from)?;

        create_log_with_instance(
            &state,
            user.id,
            "host",
            "host.ops.audit.scan",
            &format!(
                "Ran manual audit scan for instance \"{}\" on host \"{}\" ({} finding(s))",
                instance.name, host.name, summary["findingCount"].as_i64().unwrap_or(0)
            ),
            "success",
            instance.id,
        )
        .await;

        let mut sorted_processes = processes.clone();
        sorted_processes.sort_by(|a, b| {
            b.findings.len().cmp(&a.findings.len()).then(
                (b.cpu_percent.unwrap_or(0.0))
                    .partial_cmp(&(a.cpu_percent.unwrap_or(0.0)))
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });
        let mut sorted_startup = startup_items.clone();
        sorted_startup.sort_by(|a, b| b.findings.len().cmp(&a.findings.len()));

        Ok(json!({
            "success": true,
            "scanId": scan_id,
            "scannedAt": iso(Utc::now()),
            "capability": capability,
            "instance": {
                "id": instance.id,
                "name": instance.name,
                "incusId": instance.incus_id,
                "type": instance_type,
                "status": incus_status,
            },
            "summary": summary,
            "ignoredCount": ignored_count,
            "rules": rules.iter().map(|rule| json!({
                "id": rule.id,
                "source": rule.source,
                "name": rule.name,
                "category": rule.category,
                "severity": rule.severity,
                "targetTypes": rule.target_types,
                "matchType": rule.match_type,
                "pattern": rule.pattern_text,
                "caseSensitive": rule.case_sensitive,
                "enabled": rule.enabled,
                "recommendation": rule.recommendation,
            })).collect::<Vec<_>>(),
            "findings": findings,
            "processes": sorted_processes
                .iter()
                .take(200)
                .map(process_json)
                .collect::<Vec<_>>(),
            "connections": connections.iter().take(200).map(connection_json).collect::<Vec<_>>(),
            "startupItems": sorted_startup.iter().take(120).map(startup_item_json).collect::<Vec<_>>(),
            "stderr": stderr,
        }))
    };

    match flow.await {
        Ok(payload) => Ok((StatusCode::OK, Json(payload)).into_response()),
        Err(ScanFlowError::NotRunning(status)) => Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "实例未运行，无法执行审查扫描",
                "status": if status.is_empty() { json!(instance.status) } else { json!(status) },
            })),
        )
            .into_response()),
        Err(ScanFlowError::ExecUnavailable(message, instance_type, incus_status)) => {
            let _ = sqlx::query(
                "INSERT INTO instance_audit_scans (host_id, instance_id, user_id, status, capability, \
                 risk_level, error) VALUES ($1, $2, $3, 'failed', 'unavailable', 'info', $4)",
            )
            .bind(host_id)
            .bind(instance.id)
            .bind(user.id)
            .bind(message.chars().take(2000).collect::<String>())
            .execute(&state.db)
            .await;
            create_log_with_instance(
                &state,
                user.id,
                "host",
                "host.ops.audit.scan",
                &format!(
                    "Audit scan unavailable for instance \"{}\" on host \"{}\": {message}",
                    instance.name, host.name
                ),
                "failed",
                instance.id,
            )
            .await;
            Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "success": false,
                    "capability": "unavailable",
                    "error": format!("无法在实例内执行审查命令: {message}"),
                    "instance": {
                        "id": instance.id,
                        "name": instance.name,
                        "incusId": instance.incus_id,
                        "type": instance_type,
                        "status": incus_status,
                    },
                })),
            )
                .into_response())
        }
        Err(ScanFlowError::Other(message)) => {
            Ok(bare_bad_request(format!("审查扫描失败: {message}")))
        }
    }
}

enum ScanFlowError {
    NotRunning(String),
    ExecUnavailable(String, String, String),
    Other(String),
}

impl From<ApiError> for ScanFlowError {
    fn from(err: ApiError) -> Self {
        ScanFlowError::Other(err.error)
    }
}

impl From<IncusError> for ScanFlowError {
    fn from(err: IncusError) -> Self {
        ScanFlowError::Other(incus_error_message(&err))
    }
}

impl From<String> for ScanFlowError {
    fn from(message: String) -> Self {
        ScanFlowError::Other(message)
    }
}

impl From<IncusMessageErr> for ScanFlowError {
    fn from(err: IncusMessageErr) -> Self {
        ScanFlowError::Other(err.0)
    }
}

/// Wrapper so `?` on IncusError inside the scan flow maps to a string message.
struct IncusMessageErr(String);

impl From<IncusError> for IncusMessageErr {
    fn from(err: IncusError) -> Self {
        IncusMessageErr(incus_error_message(&err))
    }
}

impl From<sqlx::Error> for IncusMessageErr {
    fn from(err: sqlx::Error) -> Self {
        IncusMessageErr(format!("{err}"))
    }
}

// ===========================================================================
// POST /:id/ops/instances/:instanceId/audit/kill-process
// ===========================================================================

fn normalize_process_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

async fn audit_kill_process(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, instance_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_id = js_number_id(&instance_id)?;
    let pid = body_int(body.get("pid")).unwrap_or(0);
    let signal = if body.get("signal").and_then(Value::as_str) == Some("KILL") {
        "KILL"
    } else {
        "TERM"
    };
    let reason = body.get("reason").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let confirmation_text = body
        .get("confirmationText")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let scan_id = body_int(body.get("scanId")).filter(|v| *v != 0).map(|v| v as i32);
    let expected_command = normalize_process_text(body.get("expectedCommand").and_then(Value::as_str).unwrap_or(""));

    if pid < 2 || pid > 4_194_304 {
        return Err(ApiError::bad_request(code::INVALID_ID));
    }
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.host_id != host_id {
        return Ok(bare_bad_request("实例不属于该节点"));
    }
    if confirmation_text != instance.incus_id {
        return Ok(bare_bad_request("确认文本不匹配实例名称"));
    }
    if reason.chars().count() < 3 {
        return Ok(bare_bad_request("请填写处置原因"));
    }

    let insert_action = |result: String, stdout: Option<String>, stderr: Option<String>, process_command: Option<String>| {
        let state = state.clone();
        let reason = reason.clone();
        async move {
            let _ = sqlx::query(
                "INSERT INTO instance_audit_actions (scan_id, host_id, instance_id, user_id, \
                 action_type, pid, signal, process_command, reason, result, stdout, stderr) \
                 VALUES ($1, $2, $3, $4, 'kill_process', $5, $6, $7, $8, $9, $10, $11)",
            )
            .bind(scan_id)
            .bind(host_id)
            .bind(instance.id)
            .bind(user.id)
            .bind(pid as i32)
            .bind(signal)
            .bind(process_command)
            .bind(&reason)
            .bind(result)
            .bind(stdout)
            .bind(stderr)
            .execute(&state.db)
            .await;
        }
    };

    let flow = async {
        let client = get_incus_client(&state, &host).await?;
        let incus_state = get_instance_state(&client, &instance.incus_id).await?;
        let raw_status = incus_state.get("status").and_then(Value::as_str).unwrap_or("").to_string();
        if raw_status != "Running" {
            return Err(KillFlowError::NotRunning(raw_status));
        }
        let process_check = exec_with_output(
            &client,
            &instance.incus_id,
            IncusExecCommand::Shell(format!("ps -p {pid} -o pid=,comm=,args= 2>/dev/null || true")),
            None,
            30_000,
        )
        .await?;
        let current_process_text = normalize_process_text(&process_check.stdout);
        if current_process_text.is_empty() {
            return Err(KillFlowError::Conflict("该 PID 当前不存在，请重新扫描后再操作".to_string(), None));
        }
        if !expected_command.is_empty()
            && !current_process_text.to_lowercase().contains(&expected_command.to_lowercase())
        {
            return Err(KillFlowError::Conflict(
                "PID 当前进程与扫描时不一致，请重新扫描确认后再操作".to_string(),
                Some(current_process_text.clone()),
            ));
        }
        let result = exec_with_output(
            &client,
            &instance.incus_id,
            IncusExecCommand::Shell(format!("kill -{signal} -- {pid}")),
            None,
            30_000,
        )
        .await?;
        Ok((current_process_text, result.stdout, result.stderr))
    };

    match flow.await {
        Ok((current_process_text, stdout, stderr)) => {
            insert_action(
                "success".to_string(),
                Some(stdout.chars().take(2000).collect()),
                Some(stderr.chars().take(2000).collect()),
                Some(current_process_text.chars().take(2000).collect()),
            )
            .await;
            create_log_with_instance(
                &state,
                user.id,
                "host",
                "host.ops.audit.kill_process",
                &format!(
                    "Sent SIG{signal} to PID {pid} in instance \"{}\" on host \"{}\". Reason: {reason}",
                    instance.name, host.name
                ),
                "warning",
                instance.id,
            )
            .await;
            Ok((
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "message": format!("已向 PID {pid} 发送 SIG{signal}"),
                    "pid": pid,
                    "signal": signal,
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            )
                .into_response())
        }
        Err(KillFlowError::NotRunning(status)) => Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "实例未运行，无法停止进程",
                "status": if status.is_empty() { json!(instance.status) } else { json!(status) },
            })),
        )
            .into_response()),
        Err(KillFlowError::Conflict(message, current_process)) => {
            let mut body = json!({ "error": message });
            if let Some(process) = current_process {
                body["currentProcess"] = json!(process);
            }
            Ok((StatusCode::CONFLICT, Json(body)).into_response())
        }
        Err(KillFlowError::Other(message)) => {
            insert_action("failed".to_string(), None, Some(message.chars().take(2000).collect()), None).await;
            create_log_with_instance(
                &state,
                user.id,
                "host",
                "host.ops.audit.kill_process",
                &format!(
                    "Failed to send SIG{signal} to PID {pid} in instance \"{}\" on host \"{}\": {message}",
                    instance.name, host.name
                ),
                "failed",
                instance.id,
            )
            .await;
            Ok(bare_bad_request(format!("停止进程失败: {message}")))
        }
    }
}

enum KillFlowError {
    NotRunning(String),
    Conflict(String, Option<String>),
    Other(String),
}

impl From<ApiError> for KillFlowError {
    fn from(err: ApiError) -> Self {
        KillFlowError::Other(err.error)
    }
}

impl From<IncusError> for KillFlowError {
    fn from(err: IncusError) -> Self {
        KillFlowError::Other(incus_error_message(&err))
    }
}

impl From<IncusMessageErr> for KillFlowError {
    fn from(err: IncusMessageErr) -> Self {
        KillFlowError::Other(err.0)
    }
}

// ===========================================================================
// POST /:id/ops/instances/:instanceId/dangerous-action
// ===========================================================================

async fn ops_instance_dangerous_action(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, instance_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let host_id = js_number_id(&id)?;
    let instance_id = js_number_id(&instance_id)?;
    let action = body.get("action").and_then(Value::as_str).unwrap_or("").to_string();
    let image_alias = body.get("imageAlias").and_then(Value::as_str).unwrap_or("").to_string();
    let ssh_key_id = body_int(body.get("sshKeyId")).map(|v| v as i32);
    let custom_init_command_ids: Option<Vec<i64>> = body
        .get("customInitCommandIds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect());
    let confirmation_text = body.get("confirmationText").and_then(Value::as_str).unwrap_or("").to_string();
    let risk_confirmed = body.get("riskConfirmed") == Some(&Value::Bool(true));

    if action != "rebuild" && action != "recreate" {
        return Ok(bare_bad_request("body/action must be equal to one of the allowed values"));
    }
    let host = get_host_by_id(&state, host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;
    if let Some(err) = host_access_error(&host, &user) {
        return Err(err);
    }
    let instance = get_instance_by_id(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::INSTANCE_NOT_FOUND))?;
    if instance.host_id != host_id {
        return Ok(bare_bad_request("实例不属于该节点"));
    }
    // Host owners may not rebuild/recreate other tenants; admins are the
    // explicit cross-tenant path.
    if user.role != "admin" && instance.user_id != user.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    if !risk_confirmed {
        return Ok(bare_bad_request("请先确认风险提示"));
    }
    if confirmation_text.trim() != instance.incus_id {
        return Ok(bare_bad_request("确认文本不匹配实例名称"));
    }
    if instance.status == "suspended" {
        return Ok(bare_bad_request("实例处于封停状态"));
    }
    if action == "rebuild" && instance.status != "stopped" {
        return Err(ApiError::bad_request(code::INSTANCE_STOP_REQUIRED));
    }
    if let Some(task) = get_active_task_for_instance(&state, instance_id).await? {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Instance has an active task",
                "code": "TASK_IN_PROGRESS",
                "taskId": task.0,
                "taskType": task.1,
                "status": task.2,
            })),
        )
            .into_response());
    }
    if !is_valid_system_image(&state, &image_alias).await? {
        return Err(ApiError::bad_request(code::IMAGE_NOT_FOUND));
    }
    if !is_image_compatible_with_memory(&state, &image_alias, instance.memory as i64).await? {
        return Err(ApiError::bad_request(code::IMAGE_MEMORY_INCOMPATIBLE));
    }
    let package_instance_type: Option<String> = match instance.package_id {
        Some(package_id) => {
            sqlx::query_scalar("SELECT instance_type::text FROM packages WHERE id = $1")
                .bind(package_id)
                .fetch_optional(&state.db)
                .await?
        }
        None => None,
    };
    let instance_type = package_instance_type.unwrap_or_else(|| "container".to_string());
    match get_system_image_availability_for_host(
        &state,
        &image_alias,
        instance.host_id,
        Some(&instance_type),
        Some(instance.memory as i64),
    )
    .await?
    {
        Ok(_) => {}
        Err(reason) => {
            return Err(match reason.as_str() {
                "host_not_found" => ApiError::not_found(code::HOST_NOT_FOUND),
                "image_not_found" => ApiError::bad_request(code::IMAGE_NOT_FOUND),
                "memory_incompatible" => ApiError::bad_request(code::IMAGE_MEMORY_INCOMPATIBLE),
                "instance_type_mismatch" => ApiError::bad_request(code::IMAGE_TYPE_MISMATCH),
                "host_instance_type_mismatch" => ApiError::bad_request(code::HOST_INSTANCE_TYPE_MISMATCH),
                _ => ApiError::bad_request(code::INSTANCE_IMAGE_UNAVAILABLE),
            });
        }
    }
    if let Some(ssh_key_id) = ssh_key_id {
        match get_ssh_key_by_id(&state, ssh_key_id).await? {
            Some((_, owner_id)) if owner_id == instance.user_id => {}
            _ => return Err(ApiError::bad_request(code::SSH_KEY_NOT_OWNED)),
        }
    }
    if let Some(ids) = &custom_init_command_ids {
        if !ids.is_empty() {
            let valid = validate_commands_ownership(&state, ids, instance.user_id).await?;
            if !valid {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Invalid custom init command IDs",
                        "code": "INVALID_COMMAND_IDS",
                    })),
                )
                    .into_response());
            }
        }
    }

    let task = match create_instance_task(
        &state,
        instance_id,
        instance.host_id,
        user.id,
        &action,
        Some(&image_alias),
        ssh_key_id,
        custom_init_command_ids,
    )
    .await
    {
        Ok(task) => task,
        Err(Ok((active_id, active_type, active_status))) => {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "Instance has an active task",
                    "code": "TASK_IN_PROGRESS",
                    "taskId": active_id,
                    "taskType": active_type,
                    "status": active_status,
                })),
            )
                .into_response());
        }
        Err(Err(err)) => return Err(err),
    };

    create_log_with_instance(
        &state,
        user.id,
        "host",
        &format!("host.ops.{action}"),
        &format!(
            "Queued {action} task for instance \"{}\" on host \"{}\" with image {image_alias}",
            instance.name, host.name
        ),
        "success",
        instance_id,
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "success": true,
            "message": if action == "rebuild" { "实例重装任务已排队" } else { "实例重建任务已排队" },
            "taskId": task.id,
            "status": task.status,
        })),
    )
        .into_response())
}

// ===========================================================================
// router self-test: catch matchit route conflicts at test time.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_builds_without_conflicts() {
        let _ = router();
    }
}















