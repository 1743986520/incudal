//! 宿主机 Agent 路由 — port of server/src/routes/agent.ts (mounted at /api/agent).
//!
//! Endpoint map (auth ordering mirrors the TS decorators exactly):
//! - GET  /install.sh                                public
//! - GET  /manifest.json                             public
//! - GET  /install-config/{token}                    public (one-time install token)
//! - GET  /binary/{name}                             public
//! - GET  /hosts/{hostId}/status                     JWT (owner or admin)
//! - POST /hosts/{hostId}/upgrade                    JWT (owner or admin)
//! - POST /upgrade-all                               JWT admin
//! - POST /hosts/{hostId}/install-command            JWT (owner or admin)
//! - GET  /admin/hosts/{hostId}/status               JWT admin
//! - POST /admin/hosts/{hostId}/credentials          JWT admin
//! - POST /admin/hosts/{hostId}/install-command      JWT admin
//! - POST /heartbeat                                 Agent HMAC (verify_agent_request)
//!
//! Reported deviations (see the notes inline):
//! - sendSecurityIncidentNotification (Telegram fan-out, traffic-notifier.ts) is
//!   stubbed with a warning — external channel delivery is not ported, the
//!   dedupe bookkeeping still runs.
//! - Hourly billing activate/pause run the same "prepaid release only" subset
//!   as routes/hosts.rs (settlement math belongs to the hourly-billing port).
//! - The policy-bundle revision hash uses a deterministic Rust serialization;
//!   it is stable within this server but is not byte-identical to the TS hash.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use futures::stream;
use futures::StreamExt;
use rust_decimal::Decimal;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::auth::{AdminAuth, AuthUser};
use crate::error::{code, ApiError};
use sqlx::Row;
use crate::libs::agent_auth::verify_agent_request;
use crate::libs::host_agent_credentials as agent_creds;
use crate::libs::host_audit::{
    analyze_audit_data, builtin_audit_rules, parse_connections, parse_processes,
    parse_startup_items, AuditIgnoreDefinition, AuditRuleDefinition,
};
use crate::libs::incus::incus_utils::map_instance_status;
use crate::routes::users::create_log;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/install.sh", get(install_sh))
        .route("/manifest.json", get(manifest_json))
        .route("/install-config/{token}", get(install_config))
        .route("/binary/{name}", get(binary_download))
        .route("/hosts/{host_id}/status", get(host_status))
        .route("/hosts/{host_id}/upgrade", post(host_upgrade))
        .route("/hosts/{host_id}/install-command", post(host_install_command))
        .route("/upgrade-all", post(upgrade_all))
        .route("/admin/hosts/{host_id}/status", get(admin_host_status))
        .route("/admin/hosts/{host_id}/credentials", post(admin_host_credentials))
        .route(
            "/admin/hosts/{host_id}/install-command",
            post(admin_host_install_command),
        )
        .route("/heartbeat", post(heartbeat))
}

// ===========================================================================
// constants (module-level values in agent.ts)
// ===========================================================================

const AGENT_BINARY_NAME_PATTERN_PLAIN: &str = "incudal-agent-linux-";
const DEFAULT_AGENT_RELEASE_REPOSITORY: &str = "1743986520/incudal";
const GITHUB_API_BASE_URL: &str = "https://api.github.com";
const GITHUB_DOWNLOAD_BASE_URL: &str = "https://github.com";
const AGENT_RELEASE_CACHE_TTL_MS: i64 = 5 * 60 * 1000;
const AGENT_BINARY_DOWNLOAD_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_AGENT_HEARTBEAT_INTERVAL_SECONDS: i64 = 30;
const MIN_AGENT_HEARTBEAT_INTERVAL_SECONDS: i64 = 5;
const MAX_AGENT_HEARTBEAT_INTERVAL_SECONDS: i64 = 3600;
const MIN_AGENT_OFFLINE_THRESHOLD_SECONDS: i64 = 120;
const HOURLY_SUSPEND_REASON: &str = "hourly_billing_insufficient_balance";

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

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// sanitizeShortString: typeof string -> trim -> empty -> null -> slice(max).
fn sanitize_short_string(value: Option<&Value>, max_length: usize) -> Option<String> {
    let raw = value?.as_str()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(max_length).collect())
}

fn sanitize_str(raw: Option<&str>, max_length: usize) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(max_length).collect())
}

/// parseInteger (agent.ts): safe number or digit-only string.
fn parse_integer(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Number(n) => {
            let v = n.as_i64()?;
            // Number.isSafeInteger check via f64 round-trip.
            if v.abs() < 9_007_199_254_740_991 {
                Some(v)
            } else {
                None
            }
        }
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let parsed: i64 = t.parse().ok()?;
            if parsed.abs() < 9_007_199_254_740_991 {
                Some(parsed)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// JS parseInt(value, 10) prefix semantics (used by parsePositiveId).
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

fn parse_positive_id(raw: &str) -> Option<i32> {
    match js_parse_int(raw) {
        Some(v) if v > 0 && v <= i32::MAX as i64 => Some(v as i32),
        _ => None,
    }
}

fn is_record(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Object(_)))
}

fn is_sha256(value: Option<&str>) -> bool {
    match value {
        Some(v) => v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

fn is_mac_address(value: &str) -> bool {
    // ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ (case-insensitive callers lowercase first)
    let bytes = value.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        if i % 3 == 2 {
            if *b != b':' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() || b.is_ascii_uppercase() {
            return false;
        }
    }
    true
}

fn is_mac_address_ci(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        if i % 3 == 2 {
            if *b != b':' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn is_ip(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

/// agentBinaryNamePattern: ^incudal-agent-linux-(amd64|arm64)(?:\.gz)?$
fn matches_agent_binary_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(AGENT_BINARY_NAME_PATTERN_PLAIN) else {
        return false;
    };
    rest == "amd64" || rest == "arm64" || rest == "amd64.gz" || rest == "arm64.gz"
}

/// agentReleaseBinaryNamePattern:
/// ^incudal-agent-(x86_64|aarch64)-v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$
fn matches_agent_release_binary_name(name: &str) -> bool {
    let rest = name
        .strip_prefix("incudal-agent-x86_64-")
        .or_else(|| name.strip_prefix("incudal-agent-aarch64-"));
    let Some(version) = rest else {
        return false;
    };
    is_release_version(version)
}

/// ^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$ (agent release tags)
fn is_release_version(version: &str) -> bool {
    let core = match version.strip_prefix('v') {
        Some(c) => c,
        None => return false,
    };
    let (numeric, pre) = match core.split_once('-') {
        Some((n, p)) => (n, Some(p)),
        None => (core, None),
    };
    let parts: Vec<&str> = numeric.split('.').collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    if let Some(pre) = pre {
        if pre.is_empty()
            || !pre
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return false;
        }
    }
    true
}

fn text_response(status: StatusCode, content_type: &str, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response()
}

// ===========================================================================
// URL / header helpers
// ===========================================================================

fn first_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn normalize_base_url(value: Option<&str>) -> Option<String> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = reqwest::Url::parse(trimmed).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    let mut out = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or_default());
    if let Some(port) = parsed.port() {
        out = format!("{out}:{port}");
    }
    Some(out)
}

/// derivePanelUrl(request, explicitBaseUrl?) — the agent.ts version (headers
/// are consulted; hosts.rs has its own PUBLIC_URL-flavoured variant).
fn derive_panel_url(headers: &HeaderMap, explicit_base_url: Option<&str>) -> String {
    if let Some(explicit) = normalize_base_url(explicit_base_url) {
        return explicit;
    }

    let frontend_url = std::env::var("FRONTEND_URL")
        .ok()
        .and_then(|v| v.split(',').next().map(|s| s.to_string()));
    if let Some(frontend) = normalize_base_url(frontend_url.as_deref()) {
        return frontend;
    }

    let origin = first_header(headers, "origin");
    let referer = first_header(headers, "referer");
    let referer_base_url = normalize_base_url(origin.as_deref().or(referer.as_deref()));
    if let Some(base) = referer_base_url {
        return base;
    }

    let forwarded_proto = first_header(headers, "x-forwarded-proto")
        .and_then(|v| v.split(',').next().map(|s| s.trim().to_string()));
    let forwarded_host = first_header(headers, "x-forwarded-host")
        .and_then(|v| v.split(',').next().map(|s| s.trim().to_string()));
    let direct_host = first_header(headers, "host").map(|v| v.trim().to_string());
    let protocol = match forwarded_proto.as_deref() {
        Some("https") => "https",
        Some("http") => "http",
        // request.protocol on the plain axum listener is http.
        _ => "http",
    };
    let host = forwarded_host.or(direct_host).filter(|h| !h.is_empty());
    if let Some(host) = host {
        return format!("{protocol}://{host}");
    }

    "https://incudal.com".to_string()
}

fn shell_escape(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn validate_custom_agent_binary(
    binary_url: Option<&Value>,
    binary_sha256: Option<&Value>,
) -> Option<String> {
    let url = binary_url.and_then(Value::as_str).unwrap_or("").trim();
    let sha256 = binary_sha256.and_then(Value::as_str).unwrap_or("").trim();

    if url.is_empty() && sha256.is_empty() {
        return None;
    }
    if url.is_empty() {
        return Some("binarySha256 不能脱离 binaryUrl 单独提供".to_string());
    }
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some("自定义 Agent 二进制必须提供 64 位十六进制 SHA-256 摘要".to_string());
    }
    match reqwest::Url::parse(url) {
        Ok(parsed) => {
            if parsed.scheme() != "https" || parsed.host_str().is_none() {
                return Some("自定义 Agent 二进制 URL 必须使用 HTTPS".to_string());
            }
        }
        Err(_) => return Some("自定义 Agent 二进制 URL 无效".to_string()),
    }
    None
}

fn build_agent_install_command(
    panel_url: &str,
    install_token: &str,
    binary_url: Option<&str>,
    binary_sha256: Option<&str>,
) -> String {
    let mut env_parts = vec![
        format!("INCUDAL_PANEL_URL={}", shell_escape(panel_url)),
        format!("INCUDAL_AGENT_INSTALL_TOKEN={}", shell_escape(install_token)),
    ];
    if let Some(url) = binary_url.map(str::trim).filter(|v| !v.is_empty()) {
        env_parts.push(format!("INCUDAL_AGENT_BINARY_URL={}", shell_escape(url)));
        env_parts.push(format!(
            "INCUDAL_AGENT_BINARY_SHA256={}",
            shell_escape(binary_sha256.unwrap_or("").trim())
        ));
    }
    format!(
        "curl -fsSL {} | sudo env {} bash",
        shell_escape(&format!("{panel_url}/api/agent/install.sh")),
        env_parts.join(" ")
    )
}

fn build_agent_install_config(agent_id: &str, agent_secret: &str) -> Result<String, &'static str> {
    // The installer consumes this as a data-only key/value file. Keep the
    // format deliberately narrower than a shell script so a compromised or
    // malformed response cannot add commands to a root installation.
    let agent_id_ok = agent_id.len() >= 28
        && agent_id.len() <= 68
        && agent_id.strip_prefix("agt_").is_some_and(|rest| {
            rest.len() >= 24
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        });
    if !agent_id_ok {
        return Err("AGENT_ID_INVALID");
    }
    // isValidAgentSecret: /^ias_[A-Za-z0-9_-]{32,96}$/
    let secret_body_len = agent_secret.len().saturating_sub(4);
    let secret_ok = agent_secret.strip_prefix("ias_").is_some_and(|rest| {
        (32..=96).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }) && secret_body_len >= 32;
    if !secret_ok {
        return Err("AGENT_SECRET_INVALID");
    }
    Ok(format!(
        "INCUDAL_AGENT_ID={agent_id}\nINCUDAL_AGENT_SECRET={agent_secret}\n"
    ))
}

// ===========================================================================
// GitHub release repository / manifest plumbing
// ===========================================================================

fn normalize_github_repository(value: &str) -> Option<String> {
    let candidate = value.trim().trim_end_matches('/').trim_end_matches(".git");
    let seg_ok =
        |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    let parts: Vec<&str> = candidate.split('/').collect();
    if parts.len() == 2 && parts.iter().all(|p| seg_ok(p)) {
        return Some(candidate.to_string());
    }
    let parsed = reqwest::Url::parse(candidate).ok()?;
    if parsed.scheme() != "https"
        || parsed.host_str().map(|h| h.to_lowercase()) != Some("github.com".to_string())
    {
        return None;
    }
    let parts: Vec<&str> = parsed.path().split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() != 2 || !parts.iter().all(|p| seg_ok(p)) {
        return None;
    }
    Some(format!("{}/{}", parts[0], parts[1]))
}

fn get_agent_release_repository() -> String {
    for candidate in [
        std::env::var("INCUDAL_AGENT_RELEASE_URL").ok(),
        std::env::var("INCUDAL_AGENT_RELEASE_REPOSITORY").ok(),
        std::env::var("GITHUB_REPOSITORY").ok(),
    ]
    .into_iter()
    .flatten()
    {
        if candidate.is_empty() {
            continue;
        }
        if let Some(repository) = normalize_github_repository(&candidate) {
            return repository;
        }
    }
    DEFAULT_AGENT_RELEASE_REPOSITORY.to_string()
}

fn get_agent_release_api_url() -> String {
    format!("{GITHUB_API_BASE_URL}/repos/{}/releases", get_agent_release_repository())
}

fn get_github_headers(_state: &SharedAppState, accept: &str) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Accept".to_string(), accept.to_string()),
        ("User-Agent".to_string(), "incudal-panel".to_string()),
    ];
    let token = std::env::var("INCUDAL_AGENT_RELEASE_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if let Some(token) = token {
        headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    }
    headers
}

fn get_agent_release_asset_url(tag: &str, asset_name: &str) -> String {
    let repository = get_agent_release_repository();
    format!(
        "{GITHUB_DOWNLOAD_BASE_URL}/{repository}/releases/download/{}/{}",
        urlencode(tag),
        urlencode(asset_name)
    )
}

fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// normalizeAgentReleaseVersion: tag `agent-vX.Y.Z(-pre)` -> `vX.Y.Z(-pre)`.
fn normalize_agent_release_version(tag_name: Option<&str>) -> Option<String> {
    let tag = sanitize_str(tag_name, 128)?;
    let version = tag.strip_prefix("agent-")?;
    if is_release_version(version) {
        Some(version.to_string())
    } else {
        None
    }
}

fn agent_api_binary_name_to_release_asset_name(name: &str, version: &str) -> Option<String> {
    match name {
        "incudal-agent-linux-amd64" => Some(format!("incudal-agent-x86_64-{version}")),
        "incudal-agent-linux-arm64" => Some(format!("incudal-agent-aarch64-{version}")),
        _ => None,
    }
}

fn release_asset_name_to_agent_platform(name: &str) -> Option<&'static str> {
    if name.starts_with("incudal-agent-x86_64-") {
        Some("linux-amd64")
    } else if name.starts_with("incudal-agent-aarch64-") {
        Some("linux-arm64")
    } else {
        None
    }
}

// ---- caches (TS module-level let bindings) ----

struct ManifestCache {
    expires_at: i64,
    manifest: Value,
}

struct AssetCache {
    expires_at: i64,
    assets: HashMap<String, Value>,
}

struct BinaryCache {
    expires_at: i64,
    binaries: HashMap<String, Arc<Vec<u8>>>,
}

static MANIFEST_CACHE: Mutex<Option<ManifestCache>> = Mutex::new(None);
static ASSET_CACHE: Mutex<Option<AssetCache>> = Mutex::new(None);
static BINARY_CACHE: Mutex<Option<BinaryCache>> = Mutex::new(None);

fn cached_manifest() -> Option<Value> {
    let guard = MANIFEST_CACHE.lock().expect("manifest cache");
    let cache = guard.as_ref()?;
    if cache.expires_at > now_ms() {
        Some(cache.manifest.clone())
    } else {
        None
    }
}

fn get_local_agent_dist_path() -> String {
    std::env::var("INCUDAL_AGENT_LOCAL_DIST")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../agent/dist").to_string())
}

/// readLocalAgentManifest: validates the on-disk dist and caches its binaries.
fn read_local_agent_manifest() -> Option<Value> {
    let result = (|| -> Option<Value> {
        let dist_path = get_local_agent_dist_path();
        let raw: Value =
            serde_json::from_str(&std::fs::read_to_string(format!("{dist_path}/manifest.json")).ok()?)
                .ok()?;
        let version = sanitize_short_string(raw.get("version"), 128)?;
        if !is_release_version(&version) {
            return None;
        }

        let mut files = Map::new();
        let mut binaries: HashMap<String, Arc<Vec<u8>>> = HashMap::new();

        for platform in ["linux-amd64", "linux-arm64"] {
            let file = raw.pointer(&format!("/files/{platform}")).cloned().unwrap_or(Value::Null);
            let name = sanitize_short_string(Some(&file.get("name").cloned().unwrap_or(Value::Null)), 128)?;
            if !matches_agent_binary_name(&name) || !is_sha256(file.get("sha256").and_then(Value::as_str))
            {
                return None;
            }
            let expected_name = format!("incudal-agent-{platform}");
            if name != expected_name && name != format!("{expected_name}.gz") {
                return None;
            }

            let binary = std::fs::read(format!("{dist_path}/{name}")).ok()?;
            if binary.is_empty() || binary.len() > AGENT_BINARY_DOWNLOAD_LIMIT_BYTES {
                return None;
            }
            let actual_sha256 = hex::encode(Sha256::digest(&binary));
            if actual_sha256 != file["sha256"].as_str().unwrap_or("").to_lowercase() {
                tracing::warn!("[AgentRelease] Local Agent binary checksum mismatch name={name}");
                return None;
            }

            let gzip = file.get("gzip").and_then(Value::as_bool).unwrap_or_else(|| name.ends_with(".gz"));
            files.insert(
                platform.to_string(),
                json!({
                    "name": name,
                    "sha256": actual_sha256,
                    "size": binary.len(),
                    "gzip": gzip,
                }),
            );
            binaries.insert(format!("{version}:{name}:{actual_sha256}"), Arc::new(binary));
        }

        *BINARY_CACHE.lock().expect("binary cache") = Some(BinaryCache {
            expires_at: now_ms() + AGENT_RELEASE_CACHE_TTL_MS,
            binaries,
        });

        let generated_at = sanitize_short_string(raw.get("generatedAt"), 80)
            .unwrap_or_else(|| Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        Some(json!({
            "version": version,
            "generatedAt": generated_at,
            "files": Value::Object(files),
        }))
    })();

    if result.is_none() {
        tracing::warn!("[AgentRelease] Local Agent release is unavailable");
    }
    result
}

async fn fetch_json_from_github(state: &SharedAppState, url: &str) -> Result<Value, String> {
    let mut request = state.http.get(url);
    for (name, value) in get_github_headers(state, "application/vnd.github+json") {
        request = request.header(name, value);
    }
    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GitHub request failed: {} {}", status.as_u16(), ""));
    }
    response.json().await.map_err(|e| e.to_string())
}

/// fetchLatestAgentRelease: first release with an agent-v tag and assets.
async fn fetch_latest_agent_release(state: &SharedAppState) -> Option<Value> {
    let releases = fetch_json_from_github(state, &get_agent_release_api_url())
        .await
        .ok()?;
    let items = releases.as_array()?;
    for release in items {
        let Some(obj) = release.as_object() else {
            continue;
        };
        let version = normalize_agent_release_version(obj.get("tag_name").and_then(Value::as_str));
        let assets = obj.get("assets").and_then(Value::as_array);
        if let (Some(_), Some(assets)) = (version, assets) {
            if !assets.is_empty() {
                return Some(release.clone());
            }
        }
    }
    None
}

/// fetchAgentReleaseAssetSha256: stream the asset (octet-stream) and hash it.
async fn fetch_agent_release_asset_sha256(
    state: &SharedAppState,
    asset: &Value,
) -> Result<String, String> {
    let download_url = sanitize_short_string(asset.get("url"), 2048)
        .or_else(|| sanitize_short_string(asset.get("browser_download_url"), 2048))
        .ok_or_else(|| "missing asset url".to_string())?;

    let mut request = state.http.get(&download_url);
    for (name, value) in get_github_headers(state, "application/octet-stream") {
        request = request.header(name, value);
    }
    let mut response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "Agent release asset download failed: {} {}",
            status.as_u16(),
            ""
        ));
    }

    let mut hasher = Sha256::new();
    let mut total_bytes = 0usize;
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        total_bytes += chunk.len();
        if total_bytes > AGENT_BINARY_DOWNLOAD_LIMIT_BYTES {
            return Err("Agent release asset exceeds download limit".to_string());
        }
        hasher.update(&chunk);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// readAgentUpgradeManifest: local dist first, then the GitHub release.
async fn read_agent_upgrade_manifest(state: &SharedAppState) -> Option<Value> {
    if let Some(manifest) = cached_manifest() {
        return Some(manifest);
    }

    if let Some(local_manifest) = read_local_agent_manifest() {
        *MANIFEST_CACHE.lock().expect("manifest cache") = Some(ManifestCache {
            expires_at: now_ms() + AGENT_RELEASE_CACHE_TTL_MS,
            manifest: local_manifest.clone(),
        });
        return Some(local_manifest);
    }

    let release = match fetch_latest_agent_release(state).await {
        Some(release) => release,
        None => {
            tracing::warn!("[AgentRelease] Failed to fetch latest Agent release");
            return None;
        }
    };
    let version = normalize_agent_release_version(release.get("tag_name").and_then(Value::as_str))?;
    let assets = release.get("assets").and_then(Value::as_array)?;

    let mut files = Map::new();
    let mut asset_map: HashMap<String, Value> = HashMap::new();

    for asset in assets {
        if asset.as_object().is_none() {
            continue;
        }
        let name = match sanitize_short_string(asset.get("name"), 256) {
            Some(n) => n,
            None => continue,
        };
        let size = asset.get("size").and_then(Value::as_i64).filter(|s| *s >= 0);
        if !matches_agent_release_binary_name(&name) || !name.ends_with(&format!("-{version}")) {
            continue;
        }
        let platform = match release_asset_name_to_agent_platform(&name) {
            Some(p) => p,
            None => continue,
        };
        let sha256 = match fetch_agent_release_asset_sha256(state, asset).await {
            Ok(s) => s,
            Err(error) => {
                tracing::warn!("[AgentRelease] Failed to hash Agent release asset name={name} error={error}");
                continue;
            }
        };

        files.insert(
            platform.to_string(),
            json!({
                "name": if platform == "linux-amd64" {
                    "incudal-agent-linux-amd64"
                } else {
                    "incudal-agent-linux-arm64"
                },
                "sha256": sha256,
                "size": size,
                "gzip": false,
            }),
        );
        asset_map.insert(name, asset.clone());
    }

    if !files.contains_key("linux-amd64") || !files.contains_key("linux-arm64") {
        return None;
    }

    let manifest = json!({
        "version": version,
        "generatedAt": sanitize_short_string(release.get("published_at"), 80)
            .unwrap_or_else(|| Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        "files": Value::Object(files),
    });

    *MANIFEST_CACHE.lock().expect("manifest cache") = Some(ManifestCache {
        expires_at: now_ms() + AGENT_RELEASE_CACHE_TTL_MS,
        manifest: manifest.clone(),
    });
    *ASSET_CACHE.lock().expect("asset cache") = Some(AssetCache {
        expires_at: now_ms() + AGENT_RELEASE_CACHE_TTL_MS,
        assets: asset_map,
    });

    Some(manifest)
}

async fn get_agent_release_asset(
    state: &SharedAppState,
    name: &str,
    version: &str,
) -> Option<Value> {
    let asset_name = agent_api_binary_name_to_release_asset_name(name, version)?;

    // Refresh the asset cache when it is missing/expired (readAgentUpgradeManifest).
    let fresh = {
        let guard = ASSET_CACHE.lock().expect("asset cache");
        guard
            .as_ref()
            .map(|c| c.expires_at > now_ms())
            .unwrap_or(false)
    };
    if !fresh {
        read_agent_upgrade_manifest(state).await;
    }

    let guard = ASSET_CACHE.lock().expect("asset cache");
    if let Some(cache) = guard.as_ref() {
        if let Some(asset) = cache.assets.get(&asset_name) {
            return Some(asset.clone());
        }
    }

    Some(json!({
        "name": asset_name,
        "browser_download_url": get_agent_release_asset_url(&format!("agent-{version}"), &asset_name),
    }))
}

async fn download_agent_release_binary(
    state: &SharedAppState,
    name: &str,
    version: &str,
    expected_sha256: &str,
) -> Result<Option<Arc<Vec<u8>>>, String> {
    let cache_key = format!("{version}:{name}:{}", expected_sha256.to_lowercase());
    {
        let guard = BINARY_CACHE.lock().expect("binary cache");
        if let Some(cache) = guard.as_ref() {
            if cache.expires_at > now_ms() {
                if let Some(binary) = cache.binaries.get(&cache_key) {
                    return Ok(Some(binary.clone()));
                }
            }
        }
    }

    let asset = get_agent_release_asset(state, name, version).await;
    let asset_name = sanitize_short_string(asset.as_ref().and_then(|a| a.get("name")), 256);
    let Some(asset_name) = asset_name else {
        return Ok(None);
    };
    if !matches_agent_release_binary_name(&asset_name) {
        return Ok(None);
    }

    let download_url = sanitize_short_string(asset.as_ref().and_then(|a| a.get("url")), 2048)
        .unwrap_or_else(|| get_agent_release_asset_url(&format!("agent-{version}"), &asset_name));

    let mut request = state.http.get(&download_url);
    for (name_, value) in get_github_headers(state, "application/octet-stream") {
        request = request.header(name_, value);
    }
    let mut response = request
        .send()
        .await
        .map_err(|e| format!("Agent release binary download failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "Agent release binary download failed: {} {}",
            status.as_u16(),
            ""
        ));
    }

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut hasher = Sha256::new();
    let mut total_bytes = 0usize;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("Agent release binary download failed: {e}"))?
    {
        total_bytes += chunk.len();
        if total_bytes > AGENT_BINARY_DOWNLOAD_LIMIT_BYTES {
            return Err("Agent release binary exceeds download limit".to_string());
        }
        chunks.push(chunk.to_vec());
        hasher.update(&chunk);
    }

    let actual_sha256 = hex::encode(hasher.finalize());
    if !is_sha256(Some(expected_sha256)) || actual_sha256 != expected_sha256.to_lowercase() {
        return Err(format!(
            "Agent release binary sha256 mismatch: expected={expected_sha256} actual={actual_sha256}"
        ));
    }

    let binary = Arc::new(chunks.concat());
    {
        let mut guard = BINARY_CACHE.lock().expect("binary cache");
        let expired = guard
            .as_ref()
            .map(|c| c.expires_at <= now_ms())
            .unwrap_or(true);
        if expired {
            *guard = Some(BinaryCache {
                expires_at: now_ms() + AGENT_RELEASE_CACHE_TTL_MS,
                binaries: HashMap::new(),
            });
        }
        guard
            .as_mut()
            .expect("binary cache just inserted")
            .binaries
            .insert(cache_key, binary.clone());
    }
    Ok(Some(binary))
}

async fn get_latest_agent_version(state: &SharedAppState) -> Option<String> {
    let manifest = read_agent_upgrade_manifest(state).await;
    sanitize_short_string(manifest.as_ref().map(|m| m.get("version").cloned().unwrap_or(Value::Null)).as_ref(), 128)
}

fn get_agent_version_status(agent_version: Option<&str>, latest_version: Option<&str>) -> &'static str {
    let (Some(_), Some(_)) = (agent_version, latest_version) else {
        return "unknown";
    };
    if agent_version == latest_version {
        "latest"
    } else {
        "outdated"
    }
}

// ===========================================================================
// agent rows (host_agents) + serializers
// ===========================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
struct AgentFullRow {
    pub id: i32,
    pub host_id: i32,
    pub agent_id: String,
    pub secret_hash: String,
    pub secret_encrypted: String,
    #[allow(dead_code)] // consumed via the SQL guard in consume_install_token
    pub install_token_hash: Option<String>,
    pub install_token_expires_at: Option<DateTime<Utc>>,
    pub install_token_used_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub status: String,
    pub version: Option<String>,
    pub capabilities: Option<Value>,
    pub last_report: Option<Value>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_heartbeat_ip: Option<String>,
    pub upgrade_requested_at: Option<DateTime<Utc>>,
    pub upgrade_target_version: Option<String>,
    pub upgrade_force: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const AGENT_COLUMNS: &str = "id, host_id, agent_id, secret_hash, secret_encrypted, \
    install_token_hash, install_token_expires_at, install_token_used_at, enabled, \
    status::text AS status, version, capabilities, last_report, last_seen_at, \
    last_heartbeat_ip, upgrade_requested_at, upgrade_target_version, upgrade_force, \
    created_at, updated_at";

const AGENT_SELECT: &str = "SELECT id, host_id, agent_id, secret_hash, secret_encrypted, \
    install_token_hash, install_token_expires_at, install_token_used_at, enabled, \
    status::text AS status, version, capabilities, last_report, last_seen_at, \
    last_heartbeat_ip, upgrade_requested_at, upgrade_target_version, upgrade_force, \
    created_at, updated_at FROM host_agents";

async fn get_agent_by_host_id(
    state: &SharedAppState,
    host_id: i32,
) -> Result<Option<AgentFullRow>, ApiError> {
    let row = sqlx::query_as::<_, AgentFullRow>(&format!(
        "{AGENT_SELECT} WHERE host_id = $1"
    ))
    .bind(host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(row)
}

async fn get_agent_by_agent_id(
    state: &SharedAppState,
    agent_id: &str,
) -> Result<Option<AgentFullRow>, ApiError> {
    let row = sqlx::query_as::<_, AgentFullRow>(&format!(
        "{AGENT_SELECT} WHERE agent_id = $1"
    ))
    .bind(agent_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(row)
}

/// getAgentHeartbeatIntervalSeconds(agent): lastReport.metrics.heartbeatIntervalSeconds.
fn get_agent_heartbeat_interval_seconds(agent: &AgentFullRow) -> i64 {
    let Some(report) = agent.last_report.as_ref() else {
        return DEFAULT_AGENT_HEARTBEAT_INTERVAL_SECONDS;
    };
    if !is_record(Some(report)) {
        return DEFAULT_AGENT_HEARTBEAT_INTERVAL_SECONDS;
    }
    let metrics = report.get("metrics");
    if !is_record(metrics) {
        return DEFAULT_AGENT_HEARTBEAT_INTERVAL_SECONDS;
    }
    clamp_heartbeat_interval_seconds(metrics.unwrap().get("heartbeatIntervalSeconds"))
}

fn clamp_heartbeat_interval_seconds(value: Option<&Value>) -> i64 {
    match parse_integer(value) {
        None => DEFAULT_AGENT_HEARTBEAT_INTERVAL_SECONDS,
        Some(parsed) if parsed < MIN_AGENT_HEARTBEAT_INTERVAL_SECONDS => {
            MIN_AGENT_HEARTBEAT_INTERVAL_SECONDS
        }
        Some(parsed) if parsed > MAX_AGENT_HEARTBEAT_INTERVAL_SECONDS => {
            MAX_AGENT_HEARTBEAT_INTERVAL_SECONDS
        }
        Some(parsed) => parsed,
    }
}

/// deriveAgentStatus: an online agent whose last heartbeat is too old flips to
/// offline based on its own reported heartbeat interval.
fn derive_agent_status(agent: &AgentFullRow) -> String {
    if !agent.enabled || agent.status != "online" {
        return agent.status.clone();
    }
    let Some(last_seen_at) = agent.last_seen_at else {
        return "offline".to_string();
    };

    let heartbeat_interval_seconds = get_agent_heartbeat_interval_seconds(agent);
    let offline_threshold_seconds =
        (heartbeat_interval_seconds * 3).max(MIN_AGENT_OFFLINE_THRESHOLD_SECONDS);
    let last_seen_age_ms = now_ms() - last_seen_at.timestamp_millis();

    if last_seen_age_ms > offline_threshold_seconds * 1000 {
        "offline".to_string()
    } else {
        agent.status.clone()
    }
}

async fn serialize_agent(
    state: &SharedAppState,
    agent: &AgentFullRow,
) -> Result<Value, ApiError> {
    let latest_version = get_latest_agent_version(state).await;
    let version_status = get_agent_version_status(agent.version.as_deref(), latest_version.as_deref());

    Ok(json!({
        "id": agent.id,
        "hostId": agent.host_id,
        "agentId": agent.agent_id,
        "secretHash": agent.secret_hash,
        "enabled": agent.enabled,
        "status": derive_agent_status(agent),
        "version": agent.version,
        "latestVersion": latest_version,
        "versionStatus": version_status,
        "capabilities": agent.capabilities.clone().unwrap_or_else(|| json!([])),
        "lastReport": agent.last_report.clone().unwrap_or_else(|| json!({})),
        "lastSeenAt": iso_opt(agent.last_seen_at),
        "lastHeartbeatIp": agent.last_heartbeat_ip,
        "createdAt": iso(agent.created_at),
        "updatedAt": iso(agent.updated_at),
    }))
}

async fn serialize_agent_status(
    state: &SharedAppState,
    agent: &AgentFullRow,
) -> Result<Value, ApiError> {
    let latest_version = get_latest_agent_version(state).await;
    let version_status = get_agent_version_status(agent.version.as_deref(), latest_version.as_deref());

    Ok(json!({
        "id": agent.id,
        "hostId": agent.host_id,
        "agentId": agent.agent_id,
        "enabled": agent.enabled,
        "status": derive_agent_status(agent),
        "version": agent.version,
        "latestVersion": latest_version,
        "versionStatus": version_status,
        "capabilities": agent.capabilities.clone().unwrap_or_else(|| json!([])),
        "lastReport": agent.last_report.clone().unwrap_or_else(|| json!({})),
        "lastSeenAt": iso_opt(agent.last_seen_at),
        "lastHeartbeatIp": agent.last_heartbeat_ip,
        "createdAt": iso(agent.created_at),
        "updatedAt": iso(agent.updated_at),
    }))
}

// ===========================================================================
// upgrade instruction (buildAgentUpgradeInstruction)
// ===========================================================================

async fn build_agent_upgrade_instruction(
    state: &SharedAppState,
    headers: &HeaderMap,
    body: &Value,
    agent: &AgentFullRow,
) -> Result<Value, ApiError> {
    let manifest = read_agent_upgrade_manifest(state).await;
    let manifest_version =
        sanitize_short_string(manifest.as_ref().map(|m| m.get("version").cloned().unwrap_or(Value::Null)).as_ref(), 128);
    let Some(manifest) = manifest else {
        return Ok(json!({ "available": false }));
    };
    let Some(manifest_version) = manifest_version else {
        return Ok(json!({ "available": false }));
    };

    let current_version = sanitize_short_string(body.get("version"), 128);
    let requested_target = sanitize_short_string(agent.upgrade_target_version.as_deref().map(|s| Value::String(s.to_string())).as_ref(), 128);
    let has_pending_request =
        agent.upgrade_requested_at.is_some() && requested_target.as_deref() == Some(manifest_version.as_str());
    let request_already_delivered = has_pending_request
        && agent.last_seen_at.is_some()
        && agent.upgrade_requested_at.is_some()
        && agent.last_seen_at.unwrap() >= agent.upgrade_requested_at.unwrap();
    if request_already_delivered && current_version.as_deref() == Some(manifest_version.as_str()) {
        sqlx::query(
            "UPDATE host_agents SET upgrade_requested_at = NULL, upgrade_target_version = NULL, \
             upgrade_force = false WHERE id = $1",
        )
        .bind(agent.id)
        .execute(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
        return Ok(json!({ "available": false, "version": manifest_version }));
    }
    if current_version.as_deref() == Some(manifest_version.as_str())
        && !(has_pending_request && agent.upgrade_force)
    {
        return Ok(json!({ "available": false, "version": manifest_version }));
    }

    let runtime_info = body.get("runtime").cloned().unwrap_or(Value::Null);
    let goos = sanitize_short_string(runtime_info.get("goos"), 32);
    let goarch = sanitize_short_string(runtime_info.get("goarch"), 32);
    if goos.as_deref() != Some("linux")
        || !matches!(goarch.as_deref(), Some("amd64") | Some("arm64"))
    {
        return Ok(json!({ "available": false, "version": manifest_version }));
    }

    let file = manifest.pointer(&format!("/files/{}-{}", goos.unwrap(), goarch.unwrap()));
    let name = file.and_then(|f| f.get("name")).and_then(Value::as_str).map(|s| s.to_string());
    let Some(name) = name else {
        return Ok(json!({ "available": false, "version": manifest_version }));
    };
    if !matches_agent_binary_name(&name) || !is_sha256(file.unwrap().get("sha256").and_then(Value::as_str))
    {
        return Ok(json!({ "available": false, "version": manifest_version }));
    }

    let sha256 = file.unwrap().get("sha256").and_then(Value::as_str).unwrap_or("");
    let upgrade_url = format!(
        "{}/api/agent/binary/{}?v={}&sha256={}",
        derive_panel_url(headers, None),
        urlencode(&name),
        urlencode(&manifest_version),
        urlencode(sha256),
    );
    let mut instruction = json!({
        "available": true,
        "version": manifest_version,
        "url": upgrade_url,
        "sha256": sha256,
        "gzip": file.unwrap().get("gzip").and_then(Value::as_bool)
            .unwrap_or_else(|| name.ends_with(".gz")),
    });
    if let Some(size) = file.unwrap().get("size").and_then(Value::as_i64).filter(|s| *s > 0) {
        instruction["size"] = json!(size);
    }
    Ok(instruction)
}

// ===========================================================================
// heartbeat report (buildHeartbeatReport)
// ===========================================================================

fn normalize_agent_metrics(metrics: Option<&Value>) -> Value {
    let mut out = match metrics {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    out.insert(
        "heartbeatIntervalSeconds".to_string(),
        json!(clamp_heartbeat_interval_seconds(metrics.and_then(|m| m.get("heartbeatIntervalSeconds")))),
    );
    Value::Object(out)
}

fn build_heartbeat_report(body: &Value) -> Value {
    let raw_instances = body
        .get("instances")
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));

    let mut items: Vec<Value> = Vec::new();
    if let Some(raw_items) = raw_instances.get("items").and_then(Value::as_array) {
        for raw_item in raw_items.iter().take(1000) {
            let Some(item_obj) = raw_item.as_object() else {
                continue;
            };
            let mut item = Map::new();
            if let Some(name) = sanitize_short_string(item_obj.get("name"), 200) {
                item.insert("name".to_string(), json!(name));
            }
            if let Some(status) = sanitize_short_string(item_obj.get("status"), 64) {
                item.insert("status".to_string(), json!(status));
            }
            if let Some(type_) = sanitize_short_string(item_obj.get("type"), 64) {
                item.insert("type".to_string(), json!(type_));
            }
            if let Some(status_code) = parse_integer(item_obj.get("statusCode")) {
                item.insert("statusCode".to_string(), json!(status_code));
            }

            if let Some(network) = item_obj.get("network").filter(|v| v.is_object()) {
                let mut network_obj = Map::new();
                for key in ["ipv4", "ipv6", "mac"] {
                    if let Some(value) = sanitize_short_string(network.get(key), 128) {
                        if key != "mac" || is_mac_address_ci(&value) {
                            network_obj.insert(
                                key.to_string(),
                                json!(if key == "mac" { value.to_lowercase() } else { value }),
                            );
                        }
                    }
                }
                if !network_obj.is_empty() {
                    item.insert("network".to_string(), Value::Object(network_obj));
                }
            }

            if let Some(traffic) = item_obj.get("traffic").filter(|v| v.is_object()) {
                let mut traffic_obj = Map::new();
                for key in ["rxBytes", "txBytes"] {
                    if let Some(value) = sanitize_short_string(traffic.get(key), 32) {
                        if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
                            traffic_obj.insert(key.to_string(), json!(value));
                        }
                    }
                }
                if !traffic_obj.is_empty() {
                    item.insert("traffic".to_string(), Value::Object(traffic_obj));
                }
            }

            if !item.is_empty() {
                items.push(Value::Object(item));
            }
        }
    }

    let total = parse_integer(raw_instances.get("total"))
        .unwrap_or(items.len() as i64)
        .clamp(0, 1000);

    json!({
        "runtime": body.get("runtime").cloned().unwrap_or_else(|| json!({})),
        "incus": body.get("incus").cloned().unwrap_or_else(|| json!({})),
        "instances": {
            "available": raw_instances.get("available") == Some(&Value::Bool(true)),
            "reportedAt": sanitize_short_string(raw_instances.get("reportedAt"), 80),
            "total": total,
            "truncated": raw_instances.get("truncated") == Some(&Value::Bool(true)),
            "items": items,
        },
        "resources": body.get("resources").cloned().unwrap_or_else(|| json!({})),
        "metrics": normalize_agent_metrics(body.get("metrics")),
    })
}

fn normalize_capabilities(value: Option<&Value>) -> Vec<String> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut unique: Vec<String> = Vec::new();
    for item in items {
        if let Some(capability) = sanitize_short_string(Some(item), 80) {
            if !unique.contains(&capability) {
                unique.push(capability);
            }
        }
        if unique.len() >= 64 {
            break;
        }
    }
    unique
}

// ===========================================================================
// agent heartbeat IP (Fastify request.ip + forwarded headers)
// ===========================================================================

fn normalize_ip_candidate(value: Option<&str>) -> Option<String> {
    let candidate = value?.trim();
    if candidate.is_empty() {
        return None;
    }

    let mut candidate = candidate.to_string();
    if candidate.starts_with('[') {
        if let Some(closing) = candidate.find(']') {
            if closing > 0 {
                candidate = candidate[1..closing].to_string();
            }
        }
    }

    // ipv4:port
    if let Some(dot_pos) = candidate.find('.') {
        if let Some(colon) = candidate[dot_pos..].find(':') {
            let candidate_ipv4 = candidate[..dot_pos + colon].to_string();
            let octets: Vec<&str> = candidate_ipv4.split('.').collect();
            if octets.len() == 4
                && octets.iter().all(|o| !o.is_empty() && o.len() <= 3 && o.bytes().all(|b| b.is_ascii_digit()))
            {
                candidate = candidate_ipv4;
            }
        }
    }

    if let Some(mapped) = candidate.strip_prefix("::ffff:") {
        if is_ip(mapped) {
            return Some(mapped.to_string());
        }
    }

    if is_ip(&candidate) {
        Some(candidate)
    } else {
        None
    }
}

fn first_forwarded_ip(headers: &HeaderMap) -> Option<String> {
    let header_values = [
        first_header(headers, "cf-connecting-ip"),
        first_header(headers, "true-client-ip"),
        first_header(headers, "x-real-ip"),
        first_header(headers, "x-forwarded-for"),
    ];
    for value in header_values.into_iter().flatten() {
        for part in value.split(',') {
            if let Some(ip) = normalize_ip_candidate(Some(part)) {
                return Some(ip);
            }
        }
    }
    None
}

fn is_local_or_private_ip(ip: Option<&str>) -> bool {
    let Some(ip) = ip else {
        return false;
    };
    if ip == "::1" || ip == "127.0.0.1" || ip.starts_with("127.") {
        return true;
    }
    if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("169.254.") {
        return true;
    }
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        let first: i64 = parts[0].parse().unwrap_or(-1);
        let second: i64 = parts[1].parse().unwrap_or(-1);
        if (0..=255).contains(&first) && (0..=255).contains(&second) {
            return first == 172 && (16..=31).contains(&second);
        }
    }
    let lower = ip.to_lowercase();
    lower.starts_with("fc") || lower.starts_with("fd") || lower.starts_with("fe80:")
}

fn get_agent_heartbeat_ip(headers: &HeaderMap, peer_ip: &str) -> Option<String> {
    let direct_ip = normalize_ip_candidate(Some(peer_ip)).unwrap_or_else(|| peer_ip.to_string());
    let forwarded_ip = first_forwarded_ip(headers);
    let trust_forwarded_ip = std::env::var("AGENT_TRUST_FORWARDED_IP").as_deref() == Ok("true")
        || is_local_or_private_ip(Some(&direct_ip));

    match forwarded_ip {
        Some(forwarded) if trust_forwarded_ip => Some(forwarded),
        _ => Some(direct_ip),
    }
}

// ===========================================================================
// host network policy bundle (services/host-network-policy.ts subset)
// ===========================================================================

/// lastReportMacMap: instance name -> reported MAC.
fn last_report_mac_map(last_report: Option<&Value>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(report) = last_report else {
        return map;
    };
    let Some(items) = report.pointer("/instances/items").and_then(Value::as_array) else {
        return map;
    };
    for item in items {
        let name = item.get("name").and_then(Value::as_str).unwrap_or("");
        let mac = item
            .pointer("/network/mac")
            .and_then(Value::as_str)
            .map(str::to_lowercase)
            .unwrap_or_default();
        if !name.is_empty() && is_mac_address(&mac) {
            map.insert(name.to_string(), mac);
        }
    }
    map
}

fn has_missing_target_mac(bundle: &Value) -> bool {
    bundle["policies"]
        .as_array()
        .map(|policies| {
            policies.iter().any(|policy| {
                policy["targets"]
                    .as_array()
                    .map(|targets| {
                        targets.iter().any(|target| {
                            let mac = target["mac"]
                                .as_str()
                                .map(|m| m.trim().to_lowercase())
                                .unwrap_or_default();
                            !is_mac_address(&mac)
                        })
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// buildHostAgentPolicyBundle. The revision hash serializes the compiled bundle
/// in the TS key order via a hand-rolled writer (serde_json's BTreeMap ordering
/// would silently change the hash); the value is stable within this server.
async fn build_host_agent_policy_bundle(
    state: &SharedAppState,
    host_id: i32,
) -> Result<Value, ApiError> {
    let agent_last_report: Option<Value> = sqlx::query(
        "SELECT last_report FROM host_agents WHERE host_id = $1",
    )
    .bind(host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?
    .and_then(|row| row.try_get::<Option<Value>, _>("last_report").ok())
    .flatten();

    #[derive(sqlx::FromRow)]
    struct PolicyRow {
        pub id: i32,
        pub revision: i32,
        pub policy_type: String,
        pub target_mode: String,
        pub target_instance_ids: Value,
        pub config: Value,
    }
    let policies: Vec<PolicyRow> = sqlx::query_as(
        "SELECT id, revision, policy_type, target_mode, target_instance_ids, config \
         FROM host_network_policies WHERE host_id = $1 AND enabled = true ORDER BY id ASC",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from_sql)?;

    let instances: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT id, incus_id, name FROM instances WHERE host_id = $1 AND status <> 'deleted'",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from_sql)?;

    let mac_by_incus_id = last_report_mac_map(agent_last_report.as_ref());

    let mut compiled_strings: Vec<String> = Vec::new();
    let mut compiled_values: Vec<Value> = Vec::new();
    for policy in &policies {
        let selected: HashSet<i64> = policy
            .target_instance_ids
            .as_array()
            .map(|items| items.iter().filter_map(Value::as_i64).collect())
            .unwrap_or_default();

        let mut target_strings: Vec<String> = Vec::new();
        let mut target_values: Vec<Value> = Vec::new();
        let mut present: HashSet<i64> = HashSet::new();
        for (instance_id, incus_id, instance_name) in &instances {
            if policy.target_mode != "selected" || selected.contains(&(*instance_id as i64)) {
                let mac = mac_by_incus_id.get(incus_id).cloned();
                target_strings.push(format!(
                    "{{\"instanceId\":{},\"instanceName\":{},\"incusId\":{},\"mac\":{}}}",
                    instance_id,
                    serde_json::to_string(instance_name).unwrap_or_default(),
                    serde_json::to_string(incus_id).unwrap_or_default(),
                    match &mac {
                        Some(m) => serde_json::to_string(m).unwrap_or_default(),
                        None => "null".to_string(),
                    },
                ));
                target_values.push(json!({
                    "instanceId": instance_id,
                    "instanceName": instance_name,
                    "incusId": incus_id,
                    "mac": mac,
                }));
                present.insert(*instance_id as i64);
            }
        }
        // Preserve unresolved selected targets in the bundle. The agent must see
        // the missing MAC and report failure instead of applying a partial,
        // fail-open policy after the instance disappeared or was not reported.
        if policy.target_mode == "selected" {
            let mut missing: Vec<i64> = selected
                .iter()
                .filter(|id| !present.contains(id))
                .copied()
                .collect();
            missing.sort_unstable();
            for instance_id in missing {
                target_strings.push(format!(
                    "{{\"instanceId\":{},\"instanceName\":\"\",\"incusId\":\"\",\"mac\":null}}",
                    instance_id
                ));
                target_values.push(json!({
                    "instanceId": instance_id,
                    "instanceName": "",
                    "incusId": "",
                    "mac": Value::Null,
                }));
            }
        }

        let config_string = serde_json::to_string(&policy.config).unwrap_or_default();
        compiled_strings.push(format!(
            "{{\"id\":{},\"revision\":{},\"type\":{},\"config\":{},\"targets\":[{}]}}",
            policy.id,
            policy.revision,
            serde_json::to_string(&policy.policy_type).unwrap_or_default(),
            config_string,
            target_strings.join(","),
        ));
        compiled_values.push(json!({
            "id": policy.id,
            "revision": policy.revision,
            "type": policy.policy_type,
            "config": policy.config,
            "targets": target_values,
        }));
    }

    let compiled_json = format!("[{}]", compiled_strings.join(","));
    let revision = hex::encode(Sha256::digest(compiled_json.as_bytes()));
    Ok(json!({
        "revision": revision,
        "policies": compiled_values,
    }))
}

// ===========================================================================
// security events (processAgentSecurityEvents) — notification stubbed
// ===========================================================================

static SECURITY_INCIDENT_DEDUPE: Mutex<Option<HashMap<String, i64>>> = Mutex::new(None);

async fn process_agent_security_events(
    state: &SharedAppState,
    host_id: i32,
    host_name: Option<String>,
    events: Option<&Value>,
    instances_report: Option<&Value>,
) {
    let Some(events) = events.and_then(Value::as_array) else {
        return;
    };
    if events.is_empty() {
        return;
    }
    let now = now_ms();

    let mut instance_name_by_mac: HashMap<String, String> = HashMap::new();
    if let Some(report) = instances_report {
        if let Some(items) = report.pointer("/items").and_then(Value::as_array) {
            for raw_item in items {
                let Some(item) = raw_item.as_object() else {
                    continue;
                };
                let name = sanitize_short_string(item.get("name"), 200);
                let mac = sanitize_short_string(item.get("network").and_then(|n| n.get("mac")), 32)
                    .map(|m| m.to_lowercase());
                if let (Some(name), Some(mac)) = (name, mac) {
                    if is_mac_address(&mac) {
                        instance_name_by_mac.insert(mac, name);
                    }
                }
            }
        }
    }

    {
        let mut dedupe_guard = SECURITY_INCIDENT_DEDUPE.lock().expect("dedupe map");
        let dedupe = dedupe_guard.get_or_insert_with(HashMap::new);
        dedupe.retain(|_, expires_at| *expires_at > now);
    }

    for raw in events.iter().take(64) {
        let Some(event) = raw.as_object() else {
            continue;
        };
        let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
        let is_network_blocked = event_type == "single_target_pps_block";
        let is_observation = event_type == "single_target_pps_observation";
        if !is_network_blocked && !is_observation {
            continue;
        }
        let source_mac = sanitize_short_string(event.get("sourceMac"), 32).unwrap_or_default();
        let destination_ip = sanitize_short_string(event.get("destinationIp"), 128).unwrap_or_default();
        if !is_mac_address_ci(&source_mac) || destination_ip.is_empty() || !is_ip(&destination_ip)
        {
            continue;
        }
        let expires_in_seconds = (event
            .get("expiresInSeconds")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            .max(0.0) as i64)
            .min(86400);
        let dedupe_key = format!(
            "{host_id}:{event_type}:{}:{destination_ip}",
            source_mac.to_lowercase()
        );
        {
            let mut dedupe_guard = SECURITY_INCIDENT_DEDUPE.lock().expect("dedupe map");
            let dedupe = dedupe_guard.get_or_insert_with(HashMap::new);
            if dedupe.contains_key(&dedupe_key) {
                continue;
            }
            dedupe.insert(
                dedupe_key,
                now + (60_000i64).max(expires_in_seconds * 1000),
            );
        }

        let reported_name = instance_name_by_mac.get(&source_mac.to_lowercase());
        let mut instance: Option<(i32, String, Option<String>, String, String)> = None;
        if let Some(name) = reported_name {
            instance = sqlx::query_as(
                "SELECT i.id, i.name, i.user_id, u.username, u.role::text AS role \
                 FROM instances i LEFT JOIN users u ON u.id = i.user_id \
                 WHERE i.host_id = $1 AND i.incus_id = $2 AND i.status <> 'deleted' LIMIT 1",
            )
            .bind(host_id)
            .bind(name)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::warn!("[Agent] security event instance lookup failed: {e}");
                e
            })
            .ok()
            .flatten();
        }

        let suspension_result = match &instance {
            Some((_, _, _, _, role)) if role == "admin" => {
                if is_network_blocked {
                    "目标属于管理员账户，安全规则拒绝自动封禁并已上报"
                } else {
                    "目标属于管理员账户，UDP 观察事件已上报"
                }
            }
            _ => {
                // PPS is a network signal, not proof of abuse; account state is
                // never changed automatically. (The banned-user and normal-user
                // branches differ only in notification wording, and the
                // notification itself is stubbed below.)
                if is_network_blocked {
                    "仅执行网络层目标封锁，未自动封禁账户；需管理员复核"
                } else {
                    "仅记录并通知管理员，未执行网络层目标封锁或账户封禁"
                }
            }
        };

        // sendSecurityIncidentNotification (Telegram fan-out) is not ported;
        // log the incident the way the TS would have notified it.
        tracing::warn!(
            "[Agent] PPS security incident (notification stubbed): host=#{host_id} \
             host={host_name:?} mac={source_mac} dst={destination_ip} blocked={is_network_blocked} \
             instance={:?} suspensionResult={suspension_result}",
            instance.as_ref().map(|(_, name, _, username, _)| (name.clone(), username.clone()))
        );
    }
}

// ===========================================================================
// hourly billing hooks (activateHourlyBilling / pauseHourlyBilling subsets)
// ===========================================================================

/// activateHourlyBilling subset: guards + suspend transitions. The paused-resume
/// reserve quantum math belongs to the hourly-billing module port (same scope
/// cut as routes/hosts.rs).
async fn activate_hourly_billing(state: &SharedAppState, instance_id: i32) -> Result<bool, ApiError> {
    let account: Option<(i32, Decimal, String, Decimal)> = sqlx::query_as(
        "SELECT id, prepaid_balance, status::text AS status, outstanding_amount \
         FROM hourly_billing_accounts WHERE instance_id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;

    let Some((_account_id, _prepaid, status, outstanding)) = account else {
        return Ok(false);
    };
    if status == "active" {
        return Ok(true);
    }
    if status == "suspended" {
        let now = Utc::now();
        sqlx::query(
            "UPDATE instances SET status = 'suspended'::\"InstanceStatus\", suspended_at = $2, \
             suspended_by = NULL, suspend_reason = $3, version = version + 1 \
             WHERE id = $1 AND status::text IN ('running', 'stopped')",
        )
        .bind(instance_id)
        .bind(now)
        .bind(HOURLY_SUSPEND_REASON)
        .execute(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
        return Ok(false);
    }
    if status != "paused" {
        return Ok(false);
    }
    if outstanding > Decimal::ZERO {
        let now = Utc::now();
        sqlx::query(
            "UPDATE instances SET status = 'suspended'::\"InstanceStatus\", suspended_at = $2, \
             suspended_by = NULL, suspend_reason = $3, version = version + 1 \
             WHERE id = $1 AND status::text IN ('running', 'stopped')",
        )
        .bind(instance_id)
        .bind(now)
        .bind(HOURLY_SUSPEND_REASON)
        .execute(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
        sqlx::query(
            "UPDATE hourly_billing_accounts SET status = 'suspended', next_settlement_at = NULL, \
             version = version + 1 WHERE instance_id = $1",
        )
        .bind(instance_id)
        .execute(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
        return Ok(false);
    }
    // Paused -> active requires the reserve-quantum settlement math (not ported).
    tracing::warn!(
        "[HourlyBilling] activate settlement math not ported; instance #{instance_id} stays paused"
    );
    Ok(false)
}

/// pauseHourlyBilling subset (same as routes/hosts.rs): prepaid release only.
async fn pause_hourly_billing(state: &SharedAppState, instance_id: i32) -> Result<(), ApiError> {
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
        return Ok(());
    };
    if status == "closed" {
        return Ok(());
    }
    if status == "suspended" || outstanding > Decimal::ZERO {
        return Ok(());
    }

    if prepaid > Decimal::ZERO {
        let (user_id,): (i32,) =
            sqlx::query_as("SELECT user_id FROM instances WHERE id = $1")
                .bind(instance_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(ApiError::from_sql)?;
        let (balance_before,): (Decimal,) =
            sqlx::query_as("SELECT balance FROM users WHERE id = $1")
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
    Ok(())
}

// ===========================================================================
// agent instance report (services/agent-instance-report.ts)
// ===========================================================================

const MAX_AGENT_INSTANCE_REPORT_ITEMS: usize = 2000;
const AGENT_REPORT_CONCURRENCY: usize = 8;
const TRAFFIC_LOCK_EXPIRE_MS: i64 = 30_000;
const TRAFFIC_LOCK_WAIT_TIMEOUT_MS: i64 = 3_000;
const TRAFFIC_LOCK_RETRY_INTERVAL_MS: u64 = 50;

#[derive(Debug, Clone)]
struct NormalizedAgentInstanceItem {
    name: String,
    status: Option<&'static str>,
    rx_bytes: Option<i64>,
    tx_bytes: Option<i64>,
    /// None = absent, Some(None) = null, Some(Some(v)) = address.
    ipv6: Option<Option<String>>,
}

fn parse_counter(value: Option<&Value>) -> Option<i64> {
    let max_counter = 9_223_372_036_854_775_807i64;
    match value? {
        Value::Number(n) => {
            let v = n.as_i64()?;
            if v >= 0 && v <= max_counter {
                Some(v)
            } else {
                None
            }
        }
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() || t.len() > 30 || !t.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            t.parse::<i64>().ok().filter(|v| *v <= max_counter)
        }
        _ => None,
    }
}

fn normalize_report_status(value: Option<&Value>) -> Option<&'static str> {
    let raw = sanitize_short_string(value, 40)?;
    if raw == "running" || raw == "stopped" || raw == "error" {
        return match raw.as_str() {
            "running" => Some("running"),
            "stopped" => Some("stopped"),
            _ => Some("error"),
        };
    }
    match map_instance_status(&raw) {
        "running" => Some("running"),
        "stopped" => Some("stopped"),
        "error" => Some("error"),
        _ => None,
    }
}

/// normalizeReportedIpv6: undefined -> None (do not touch the column);
/// bridge ULA / link-local observations are ignored (None) so a routed public
/// IPv6 already assigned to the instance is not replaced.
fn normalize_reported_ipv6(value: Option<&Value>) -> Option<Option<String>> {
    let Some(value) = value else {
        return None;
    };
    if matches!(value, Value::Null) {
        return Some(None);
    }
    let address = match sanitize_short_string(Some(value), 128) {
        Some(a) => a,
        None => return Some(None),
    };
    let normalized = address.split('/').next().unwrap_or("").to_lowercase();
    if normalized.starts_with("fc") || normalized.starts_with("fd") || normalized.starts_with("fe80:")
    {
        return None;
    }
    Some(Some(address))
}

fn normalize_agent_instance_items(payload: Option<&Value>) -> Vec<NormalizedAgentInstanceItem> {
    let Some(payload) = payload else {
        return Vec::new();
    };
    let Some(items) = payload.get("items").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut out: Vec<NormalizedAgentInstanceItem> = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    for raw_item in items.iter().take(MAX_AGENT_INSTANCE_REPORT_ITEMS) {
        let Some(item_obj) = raw_item.as_object() else {
            continue;
        };
        let Some(name) = sanitize_short_string(item_obj.get("name"), 256) else {
            continue;
        };
        // A heartbeat must contain at most one record per Incus instance.
        if !seen_names.insert(name.clone()) {
            continue;
        }
        let traffic = item_obj.get("traffic");
        let network = item_obj.get("network");
        out.push(NormalizedAgentInstanceItem {
            name,
            status: normalize_report_status(item_obj.get("status")),
            rx_bytes: parse_counter(traffic.and_then(|t| t.get("rxBytes"))),
            tx_bytes: parse_counter(traffic.and_then(|t| t.get("txBytes"))),
            ipv6: normalize_reported_ipv6(network.and_then(|n| n.get("ipv6"))),
        });
    }
    out
}

fn should_sync_status(current_status: &str, reported_status: Option<&str>) -> bool {
    let Some(reported) = reported_status else {
        return false;
    };
    // 不让只读 Agent 心跳改动封停、删除和创建中实例，避免绕过业务流程。
    let _ = reported;
    current_status == "running" || current_status == "stopped" || current_status == "error"
}

fn should_apply_traffic(current_status: &str, item: &NormalizedAgentInstanceItem) -> bool {
    if item.status != Some("running") || item.rx_bytes.is_none() || item.tx_bytes.is_none() {
        return false;
    }
    // 流量属于计费数据，不处理创建中、封停和已删除实例。
    current_status == "running" || current_status == "stopped" || current_status == "error"
}

fn calculate_increment(current: i64, last: i64) -> i64 {
    if current < last {
        0
    } else {
        current - last
    }
}

fn is_transient_empty_counter_sample(current_rx: i64, current_tx: i64, last_rx: i64, last_tx: i64) -> bool {
    current_rx == 0 && current_tx == 0 && (last_rx > 0 || last_tx > 0)
}

// ---- distributed lock (lib/distributed-lock.ts, distributed_locks table) ----

fn generate_owner_id() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    let mut random = String::new();
    let mut rng = rand::thread_rng();
    for _ in 0..8 {
        random.push(ALPHABET[rng.gen_range(0..ALPHABET.len())] as char);
    }
    format!("{}-{}", std::process::id(), random)
}

struct LockGuard<'a> {
    state: &'a SharedAppState,
    lock_key: String,
    owner_id: String,
}

impl<'a> LockGuard<'a> {
    async fn release(self) {
        let _ = sqlx::query(
            "DELETE FROM distributed_locks WHERE lock_key = $1 AND owner_id = $2",
        )
        .bind(&self.lock_key)
        .bind(&self.owner_id)
        .execute(&self.state.db)
        .await;
    }
}

async fn acquire_lock<'a>(
    state: &'a SharedAppState,
    lock_key: &str,
    expire_ms: i64,
    wait_timeout_ms: i64,
    retry_interval_ms: u64,
) -> Option<LockGuard<'a>> {
    let owner_id = generate_owner_id();
    let start = std::time::Instant::now();
    loop {
        if (start.elapsed().as_millis() as i64) >= wait_timeout_ms {
            return None;
        }
        let now = Utc::now();
        let expires_at = now + chrono::Duration::milliseconds(expire_ms);
        let row: Option<(i32, String)> = sqlx::query_as(
            "INSERT INTO distributed_locks (lock_key, owner_id, acquired_at, expires_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (lock_key) DO UPDATE SET \
               owner_id = EXCLUDED.owner_id, acquired_at = EXCLUDED.acquired_at, \
               expires_at = EXCLUDED.expires_at \
             WHERE distributed_locks.expires_at <= $3 OR distributed_locks.owner_id = EXCLUDED.owner_id \
             RETURNING id, owner_id",
        )
        .bind(lock_key)
        .bind(&owner_id)
        .bind(now)
        .bind(expires_at)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
        if let Some((_, acquired_owner)) = row {
            if acquired_owner == owner_id {
                return Some(LockGuard {
                    state,
                    lock_key: lock_key.to_string(),
                    owner_id,
                });
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(retry_interval_ms)).await;
    }
}

/// applyReportedTrafficCounters inside the per-instance traffic lock.
async fn apply_reported_traffic_counters(
    state: &SharedAppState,
    instance: &ReportedDbInstance,
    item: &NormalizedAgentInstanceItem,
    now: DateTime<Utc>,
) -> Result<(bool, i64), String> {
    if !should_apply_traffic(&instance.status, item) {
        return Ok((false, 0));
    }

    let lock_key = format!("traffic:instance:{}", instance.id);
    let Some(lock) = acquire_lock(
        state,
        &lock_key,
        TRAFFIC_LOCK_EXPIRE_MS,
        TRAFFIC_LOCK_WAIT_TIMEOUT_MS,
        TRAFFIC_LOCK_RETRY_INTERVAL_MS,
    )
    .await
    else {
        return Err("Agent traffic lock acquisition failed".to_string());
    };

    let mut tx = state.db.begin().await.map_err(|e| e.to_string())?;

    let current_status: Option<String> = sqlx::query_as(
        "SELECT status::text AS status FROM instances WHERE id = $1",
    )
    .bind(instance.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .map(|(s,)| s);
    let Some(current_status) = current_status else {
        return Ok((false, 0));
    };
    if !should_apply_traffic(&current_status, item) {
        return Ok((false, 0));
    }

    let latest_snapshot: Option<(i64, i64)> = sqlx::query_as(
        "SELECT rx_raw, tx_raw FROM traffic_snapshots WHERE instance_id = $1",
    )
    .bind(instance.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let rx = item.rx_bytes.unwrap_or(0);
    let tx_bytes_val = item.tx_bytes.unwrap_or(0);
    if let Some((last_rx, last_tx)) = latest_snapshot {
        if is_transient_empty_counter_sample(rx, tx_bytes_val, last_rx, last_tx) {
            return Ok((false, 0));
        }
    }

    let rx_increment = latest_snapshot.map(|(last_rx, _)| calculate_increment(rx, last_rx)).unwrap_or(0);
    let tx_increment = latest_snapshot
        .map(|(_, last_tx)| calculate_increment(tx_bytes_val, last_tx))
        .unwrap_or(0);
    let total_delta = rx_increment + tx_increment;

    sqlx::query(
        "INSERT INTO traffic_snapshots (instance_id, rx_raw, tx_raw) VALUES ($1, $2, $3) \
         ON CONFLICT (instance_id) DO UPDATE SET rx_raw = EXCLUDED.rx_raw, \
         tx_raw = EXCLUDED.tx_raw, updated_at = now()",
    )
    .bind(instance.id)
    .bind(rx)
    .bind(tx_bytes_val)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    if total_delta > 0 {
        sqlx::query(
            "UPDATE instances SET monthly_traffic_used = monthly_traffic_used + $2 WHERE id = $1",
        )
        .bind(instance.id)
        .bind(total_delta)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        sqlx::query(
            "UPDATE user_quotas SET monthly_traffic_used = monthly_traffic_used + $2 WHERE user_id = $1",
        )
        .bind(instance.user_id)
        .bind(total_delta)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        // new Date(year, month, day) local-midnight date bucket.
        let local_date = now.with_timezone(&chrono::Local).date_naive();
        sqlx::query(
            "INSERT INTO daily_traffic (instance_id, date, rx_total, tx_total) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (instance_id, date) DO UPDATE SET \
               rx_total = daily_traffic.rx_total + EXCLUDED.rx_total, \
               tx_total = daily_traffic.tx_total + EXCLUDED.tx_total",
        )
        .bind(instance.id)
        .bind(local_date)
        .bind(rx_increment)
        .bind(tx_increment)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }

    tx.commit().await.map_err(|e| e.to_string())?;
    lock.release().await;
    Ok((true, total_delta))
}

#[derive(Debug, Clone)]
struct ReportedDbInstance {
    id: i32,
    user_id: i32,
    status: String,
    billing_mode: String,
}

/// processOneAgentInstanceReport.
async fn process_one_agent_instance_report(
    state: &SharedAppState,
    instance: &ReportedDbInstance,
    item: &NormalizedAgentInstanceItem,
    now: DateTime<Utc>,
) -> (i64, i64, i64, i64, i64) {
    // (statusUpdated, trafficUpdated, trafficDelta, skipped, errors)
    let mut status_updated = 0i64;
    let mut traffic_updated = 0i64;
    let mut traffic_delta = 0i64;
    let mut skipped = 0i64;
    let mut errors = 0i64;

    if should_sync_status(&instance.status, item.status) && item.status.is_some() {
        let target_status = item.status.unwrap();
        // Bound parameters: ipv6 is agent-controlled and must never be
        // interpolated into the SQL text.
        let mut binds: Vec<String> = Vec::new();
        let mut sets = vec![
            {
                binds.push(target_status.to_string());
                format!("status = ${}::\"InstanceStatus\"", binds.len())
            },
            {
                binds.push(now.to_rfc3339());
                format!("last_synced_at = ${}::timestamptz", binds.len())
            },
        ];
        if let Some(ipv6) = &item.ipv6 {
            match ipv6 {
                Some(v) => {
                    binds.push(v.clone());
                    sets.push(format!("ipv6 = ${}", binds.len()));
                }
                None => sets.push("ipv6 = NULL".to_string()),
            }
        }
        binds.push(instance.status.clone());
        let status_guard = format!("${}::\"InstanceStatus\"", binds.len());
        let sql = format!(
            "UPDATE instances SET {} WHERE id = {} AND status = {}",
            sets.join(", "),
            instance.id,
            status_guard
        );
        let mut query = sqlx::query(&sql);
        for value in &binds {
            query = query.bind(value);
        }
        match query.execute(&state.db).await {
            Ok(result) => {
                status_updated = result.rows_affected() as i64;
                if result.rows_affected() == 1 && instance.billing_mode == "hourly" {
                    if item.status == Some("running") {
                        if let Err(err) = activate_hourly_billing(state, instance.id).await {
                            tracing::warn!("[AgentReport] activateHourlyBilling failed: {err}");
                        }
                    } else if item.status == Some("stopped") {
                        if let Err(err) = pause_hourly_billing(state, instance.id).await {
                            tracing::warn!("[AgentReport] pauseHourlyBilling failed: {err}");
                        }
                    }
                }
            }
            Err(err) => {
                errors += 1;
                tracing::warn!("[AgentReport] status update failed for instance {}: {err}", instance.id);
                return (status_updated, traffic_updated, traffic_delta, skipped, errors);
            }
        }
    } else {
        skipped += 1;
    }

    match apply_reported_traffic_counters(state, instance, item, now).await {
        Ok((updated, delta)) => {
            if updated {
                traffic_updated = 1;
                traffic_delta = delta;
            }
        }
        Err(err) => {
            errors += 1;
            tracing::warn!("[AgentReport] traffic update failed for instance {}: {err}", instance.id);
        }
    }

    (status_updated, traffic_updated, traffic_delta, skipped, errors)
}

/// processAgentInstanceReport (concurrency 8 like p-limit).
async fn process_agent_instance_report(
    state: &SharedAppState,
    host_id: i32,
    payload: Option<&Value>,
) -> Result<Value, ApiError> {
    let items = normalize_agent_instance_items(payload);
    if items.is_empty() {
        return Ok(json!({
            "received": 0,
            "matched": 0,
            "statusUpdated": 0,
            "trafficUpdated": 0,
            "trafficDeltaBytes": "0",
            "skipped": 0,
            "errors": 0,
        }));
    }

    let incus_ids: Vec<String> = {
        let mut ids: Vec<String> = Vec::new();
        for item in &items {
            if !ids.contains(&item.name) {
                ids.push(item.name.clone());
            }
        }
        ids
    };

    let rows: Vec<(i32, String, i32, String, String)> = sqlx::query_as(
        "SELECT id, incus_id, user_id, status::text AS status, billing_mode::text AS billing_mode \
         FROM instances WHERE host_id = $1 AND incus_id = ANY($2) AND status <> 'deleted'",
    )
    .bind(host_id)
    .bind(&incus_ids)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    let map: HashMap<String, ReportedDbInstance> = rows
        .into_iter()
        .map(|(id, incus_id, user_id, status, billing_mode)| {
            (
                incus_id,
                ReportedDbInstance {
                    id,
                    user_id,
                    status,
                    billing_mode,
                },
            )
        })
        .collect();
    let instance_by_incus_id: std::sync::Arc<HashMap<String, ReportedDbInstance>> =
        std::sync::Arc::new(map);

    let items_count = items.len() as i64;
    let item_results: Vec<(i64, i64, i64, i64, i64, i64)> = stream::iter(items.into_iter())
        .map(|item| {
            let state = state.clone();
            let instance_by_incus_id = instance_by_incus_id.clone();
            async move {
                match instance_by_incus_id.get(&item.name) {
                    None => (0, 0, 0, 0, 1, 0),
                    Some(instance) => {
                        let (status_updated, traffic_updated, traffic_delta, skipped, errors) =
                            process_one_agent_instance_report(&state, instance, &item, Utc::now())
                                .await;
                        (1, status_updated, traffic_updated, traffic_delta, skipped, errors)
                    }
                }
            }
        })
        .buffer_unordered(AGENT_REPORT_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    let mut matched = 0i64;
    let mut status_updated = 0i64;
    let mut traffic_updated = 0i64;
    let mut traffic_delta = 0i64;
    let mut skipped = 0i64;
    let mut errors = 0i64;
    for (r, s, t, d, sk, e) in item_results {
        matched += r;
        status_updated += s;
        traffic_updated += t;
        traffic_delta += d;
        skipped += sk;
        errors += e;
    }

    Ok(json!({
        "received": items_count,
        "matched": matched,
        "statusUpdated": status_updated,
        "trafficUpdated": traffic_updated,
        "trafficDeltaBytes": traffic_delta.to_string(),
        "skipped": skipped,
        "errors": errors,
    }))
}

// ===========================================================================
// audit snapshots (heartbeat auditSnapshots -> instance_audit_scans)
// ===========================================================================

fn normalize_severity(value: &str) -> &'static str {
    if ["info", "low", "medium", "high"].contains(&value) {
        match value {
            "info" => "info",
            "low" => "low",
            "high" => "high",
            _ => "medium",
        }
    } else {
        "medium"
    }
}

fn normalize_match(value: &str) -> &'static str {
    if ["contains", "regex", "exact"].contains(&value) {
        match value {
            "regex" => "regex",
            "exact" => "exact",
            _ => "contains",
        }
    } else {
        "contains"
    }
}

fn normalize_targets(value: Option<&Value>) -> Vec<String> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.as_str())
        .filter(|item| ["process", "network", "startup"].contains(item))
        .map(str::to_string)
        .collect()
}

async fn process_agent_audit_snapshots(
    state: &SharedAppState,
    host_id: i32,
    snapshots: Option<&Value>,
) -> Result<(), ApiError> {
    let Some(snapshots) = snapshots.and_then(Value::as_array) else {
        return Ok(());
    };

    let host_owner: Option<(i32,)> =
        sqlx::query_as("SELECT user_id FROM hosts WHERE id = $1")
            .bind(host_id)
            .fetch_optional(&state.db)
            .await
            .map_err(ApiError::from_sql)?;
    let Some((host_owner_user_id,)) = host_owner else {
        return Err(ApiError::internal("Agent host not found"));
    };

    for raw_snapshot in snapshots.iter().take(32) {
        let Some(snapshot) = raw_snapshot.as_object() else {
            continue;
        };
        let snapshot_value = Value::Object(snapshot.clone());
        let Some(incus_id) = sanitize_short_string(snapshot_value.get("incusId"), 200)
        else {
            continue;
        };
        let instance: Option<(i32,)> = sqlx::query_as(
            "SELECT id FROM instances WHERE host_id = $1 AND incus_id = $2 LIMIT 1",
        )
        .bind(host_id)
        .bind(&incus_id)
        .fetch_optional(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
        let Some((instance_id,)) = instance else {
            continue;
        };
        let process_output =
            sanitize_short_string(snapshot_value.get("processOutput"), 131_072)
                .unwrap_or_default();
        let connection_output =
            sanitize_short_string(snapshot_value.get("connectionOutput"), 131_072)
                .unwrap_or_default();
        let startup_output =
            sanitize_short_string(snapshot_value.get("startupOutput"), 131_072)
                .unwrap_or_default();
        // TS defaults: parseProcesses(300), parseConnections(300), parseStartupItems(200).
        let mut processes = parse_processes(&process_output, 300);
        let connections = parse_connections(&connection_output, 300);
        let mut startup_items = parse_startup_items(&startup_output, 200);

        let custom_rules: Vec<(
            i32,
            String,
            Option<String>,
            String,
            String,
            Value,
            String,
            String,
            bool,
            Option<String>,
            bool,
        )> = sqlx::query_as(
            "SELECT id, name, description, severity, category, target_types, match_type, \
             pattern, case_sensitive, recommendation, enabled FROM instance_audit_rules \
             WHERE enabled = true AND (host_id IS NULL OR host_id = $1)",
        )
        .bind(host_id)
        .fetch_all(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
        let overrides: Vec<(
            String,
            String,
            Option<String>,
            String,
            String,
            Value,
            String,
            String,
            bool,
            Option<String>,
            bool,
        )> = sqlx::query_as(
            "SELECT builtin_rule_id, name, description, severity, category, target_types, \
             match_type, pattern, case_sensitive, recommendation, enabled \
             FROM instance_audit_builtin_rule_overrides WHERE host_id = $1",
        )
        .bind(host_id)
        .fetch_all(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
        let ignores: Vec<(i32, Option<String>, Option<String>, Option<String>, Option<String>, Option<DateTime<Utc>>)> =
            sqlx::query_as(
                "SELECT id, rule_id, target_type, match_text, reason, expires_at \
                 FROM instance_audit_ignores WHERE host_id = $1 AND enabled = true \
                 AND (instance_id IS NULL OR instance_id = $2)",
            )
            .bind(host_id)
            .bind(instance_id)
            .fetch_all(&state.db)
            .await
            .map_err(ApiError::from_sql)?;

        let override_map: HashMap<String, &_> = overrides
            .iter()
            .map(|o| (o.0.clone(), o))
            .collect();
        let mut builtin_rules: Vec<AuditRuleDefinition> = builtin_audit_rules()
            .into_iter()
            .filter_map(|rule| {
                let (name, severity, category, target_types, match_type, pattern_text, case_sensitive, enabled, recommendation) =
                    match override_map.get(&rule.id) {
                        Some(o) => (
                            o.1.clone(),
                            normalize_severity(&o.3).to_string(),
                            o.4.clone(),
                            normalize_targets(Some(&o.5)),
                            normalize_match(&o.6).to_string(),
                            o.7.clone(),
                            o.8,
                            o.10,
                            o.9.clone(),
                        ),
                        None => (
                            rule.name.clone(),
                            rule.severity.clone(),
                            rule.category.clone(),
                            rule.target_types.clone(),
                            rule.match_type.to_string(),
                            rule.pattern_text.clone(),
                            rule.case_sensitive,
                            rule.enabled,
                            rule.recommendation.clone(),
                        ),
                    };
                if !enabled {
                    return None;
                }
                Some(AuditRuleDefinition {
                    name,
                    severity,
                    category,
                    target_types,
                    match_type: match_type.as_str().to_string(),
                    pattern_text,
                    case_sensitive,
                    recommendation,
                    ..rule
                })
            })
            .collect();
        for rule in &mut builtin_rules {
            // match_type/severity stay in their &'static-compatible String form.
            let _ = rule;
        }

        let mut rules: Vec<AuditRuleDefinition> = builtin_rules;
        for (_id, name, description, severity, category, target_types, match_type, pattern, case_sensitive, recommendation, _enabled) in
            custom_rules
        {
            rules.push(AuditRuleDefinition {
                id: format!("custom:{_id}"),
                name,
                description,
                severity: normalize_severity(&severity).to_string(),
                category,
                target_types: normalize_targets(Some(&target_types)),
                match_type: normalize_match(&match_type).to_string(),
                pattern_text: pattern,
                case_sensitive,
                source: "custom",
                enabled: _enabled,
                recommendation,
            });
        }

        let ignore_defs: Vec<AuditIgnoreDefinition> = ignores
            .iter()
            .map(|(_id, rule_id, target_type, match_text, reason, expires_at)| AuditIgnoreDefinition {
                rule_id: rule_id.clone(),
                target_type: target_type.clone(),
                match_text: match_text.clone(),
                reason: reason.clone(),
                expires_at: expires_at.map(|e| e.timestamp_millis()),
            })
            .collect();

        let (findings, summary) = analyze_audit_data(
            &mut processes,
            &connections,
            &mut startup_items,
            &rules,
            &ignore_defs,
        );
        let ignored_count = findings
            .iter()
            .filter(|f| f.get("ignored").and_then(Value::as_bool) == Some(true))
            .count() as i64;

        let status = if snapshot_value.get("success") == Some(&Value::Bool(false)) {
            "failed"
        } else {
            "success"
        };
        let capability = sanitize_short_string(snapshot_value.get("capability"), 80)
            .unwrap_or_else(|| "agent".to_string());
        let error = sanitize_short_string(snapshot_value.get("error"), 2000);

        sqlx::query(
            "INSERT INTO instance_audit_scans (host_id, instance_id, user_id, status, capability, \
             risk_level, finding_count, ignored_count, process_count, connection_count, \
             listening_count, startup_item_count, findings, error) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(host_id)
        .bind(instance_id)
        .bind(host_owner_user_id)
        .bind(status)
        .bind(capability)
        .bind(summary["riskLevel"].as_str().unwrap_or("info"))
        .bind(summary["findingCount"].as_i64().unwrap_or(0) as i32)
        .bind(ignored_count as i32)
        .bind(summary["processCount"].as_i64().unwrap_or(0) as i32)
        .bind(summary["connectionCount"].as_i64().unwrap_or(0) as i32)
        .bind(summary["listeningCount"].as_i64().unwrap_or(0) as i32)
        .bind(summary["startupItemCount"].as_i64().unwrap_or(0) as i32)
        .bind(Value::Array(findings.into_iter().take(80).collect()))
        .bind(error)
        .execute(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
    }
    Ok(())
}

// ===========================================================================
// credential rotation (lib/host-agent-credentials.ts)
// ===========================================================================

enum RotateError {
    HostNotFound,
    Db(ApiError),
}

async fn rotate_host_agent_credentials(
    state: &SharedAppState,
    host_id: i32,
    enabled: bool,
) -> Result<(AgentFullRow, (i32, String), String, String), RotateError> {
    // (agent row, host {id, name}, agentId, agentSecret)
    let host: Option<(i32, String)> =
        sqlx::query_as("SELECT id, name FROM hosts WHERE id = $1")
            .bind(host_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| RotateError::Db(ApiError::from_sql(e)))?;
    let Some(host) = host else {
        return Err(RotateError::HostNotFound);
    };

    let existing_agent_id: Option<(String,)> =
        sqlx::query_as("SELECT agent_id FROM host_agents WHERE host_id = $1")
            .bind(host_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| RotateError::Db(ApiError::from_sql(e)))?;
    if let Some((existing_agent_id,)) = existing_agent_id {
        // 轮换 agentId 前先清理旧 nonce，避免外键阻止 agent_id 更新。
        sqlx::query("DELETE FROM host_agent_nonces WHERE agent_id = $1")
            .bind(&existing_agent_id)
            .execute(&state.db)
            .await
            .map_err(|e| RotateError::Db(ApiError::from_sql(e)))?;
    }

    let key = &state.config.encryption_key;
    let mut agent_id = agent_creds::generate_agent_id();
    for _ in 0..8 {
        let exists: Option<(i32,)> =
            sqlx::query_as("SELECT id FROM host_agents WHERE agent_id = $1")
                .bind(&agent_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| RotateError::Db(ApiError::from_sql(e)))?;
        if exists.is_none() {
            break;
        }
        agent_id = agent_creds::generate_agent_id();
    }
    let agent_secret = agent_creds::generate_agent_secret();
    let secret_hash = agent_creds::hash_agent_secret(&agent_secret);
    let secret_encrypted = crate::libs::crypto::encrypt_sensitive_data(key, &agent_secret);

    let agent = sqlx::query_as::<_, AgentFullRow>(&format!(
        "INSERT INTO host_agents (host_id, agent_id, secret_hash, secret_encrypted, enabled, status) \
         VALUES ($1, $2, $3, $4, $5, 'offline') \
         ON CONFLICT (host_id) DO UPDATE SET \
           agent_id = EXCLUDED.agent_id, secret_hash = EXCLUDED.secret_hash, \
           secret_encrypted = EXCLUDED.secret_encrypted, install_token_hash = NULL, \
           install_token_expires_at = NULL, install_token_used_at = NULL, \
           enabled = EXCLUDED.enabled, status = 'offline', version = NULL, \
           capabilities = '[]'::jsonb, last_report = '{{}}'::jsonb, \
           last_seen_at = NULL, last_heartbeat_ip = NULL \
         RETURNING {AGENT_COLUMNS}"
    ))
    .bind(host_id)
    .bind(&agent_id)
    .bind(&secret_hash)
    .bind(&secret_encrypted)
    .bind(enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|e| RotateError::Db(ApiError::from_sql(e)))?;

    Ok((agent, host, agent_id, agent_secret))
}

struct IssueTokenResult {
    agent: AgentFullRow,
    host: (i32, String),
    install_token: String,
    install_token_expires_at: DateTime<Utc>,
}

async fn issue_host_agent_install_token(
    state: &SharedAppState,
    host_id: i32,
    enabled: bool,
) -> Result<IssueTokenResult, RotateError> {
    let (rotated_agent, host, _agent_id, _agent_secret) =
        rotate_host_agent_credentials(state, host_id, enabled).await?;
    let install_token = agent_creds::generate_agent_install_token();
    let install_token_expires_at =
        Utc::now() + chrono::Duration::milliseconds(agent_creds::AGENT_INSTALL_TOKEN_TTL_MS);

    let agent = sqlx::query_as::<_, AgentFullRow>(&format!(
        "UPDATE host_agents SET install_token_hash = $2, install_token_expires_at = $3, \
         install_token_used_at = NULL WHERE id = $1 RETURNING {AGENT_COLUMNS}"
    ))
    .bind(rotated_agent.id)
    .bind(agent_creds::hash_agent_install_token(&install_token))
    .bind(install_token_expires_at)
    .fetch_one(&state.db)
    .await
    .map_err(|e| RotateError::Db(ApiError::from_sql(e)))?;

    Ok(IssueTokenResult {
        agent,
        host,
        install_token,
        install_token_expires_at,
    })
}

// ===========================================================================
// handlers
// ===========================================================================

/// GET /install.sh
async fn install_sh(State(_state): State<SharedAppState>) -> Response {
    let script_path = format!(
        "{}/agent-install.sh",
        template_root()
    );
    match std::fs::read_to_string(&script_path) {
        Ok(script) => text_response(
            StatusCode::OK,
            "text/x-shellscript; charset=utf-8",
            script,
        ),
        Err(err) => {
            tracing::error!("agent install.sh read failed: {err}");
            ApiError::internal(format!("read agent-install.sh failed: {err}")).into_response()
        }
    }
}

/// templates root: PANEL_TEMPLATES_DIR > <repo>/server/templates.
fn template_root() -> String {
    if let Ok(dir) = std::env::var("PANEL_TEMPLATES_DIR") {
        if !dir.is_empty() {
            return dir;
        }
    }
    concat!(env!("CARGO_MANIFEST_DIR"), "/../server/templates").to_string()
}

/// GET /manifest.json
async fn manifest_json(State(state): State<SharedAppState>) -> Response {
    let Some(manifest) = read_agent_upgrade_manifest(&state).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Agent manifest not found",
                "code": "AGENT_MANIFEST_NOT_FOUND",
            })),
        )
            .into_response();
    };

    let mut response = (StatusCode::OK, Json(manifest)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        header::HeaderValue::from_static("attachment; filename=\"manifest.json\""),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static(
            "no-store, no-cache, must-revalidate, proxy-revalidate",
        ),
    );
    headers.insert(
        header::PRAGMA,
        header::HeaderValue::from_static("no-cache"),
    );
    headers.insert(header::EXPIRES, header::HeaderValue::from_static("0"));
    response
}

/// GET /install-config/{token}
async fn install_config(
    State(state): State<SharedAppState>,
    Path(token): Path<String>,
) -> Response {
    match consume_install_token(&state, &token).await {
        Ok(config) => text_response(StatusCode::OK, "text/plain; charset=utf-8", config),
        Err(InstallTokenError::Expired) => text_response(
            StatusCode::FORBIDDEN,
            "text/plain; charset=utf-8",
            "# Error: Agent install token has expired".to_string(),
        ),
        Err(InstallTokenError::Invalid) => text_response(
            StatusCode::FORBIDDEN,
            "text/plain; charset=utf-8",
            "# Error: Invalid Agent install token".to_string(),
        ),
        Err(InstallTokenError::Other(err)) => {
            tracing::error!("install-config failed: {err}");
            ApiError::internal(err).into_response()
        }
    }
}

enum InstallTokenError {
    Expired,
    Invalid,
    Other(String),
}

/// consumeHostAgentInstallToken + buildAgentInstallConfig + createLog.
async fn consume_install_token(
    state: &SharedAppState,
    token: &str,
) -> Result<String, InstallTokenError> {
    if !agent_creds::is_agent_install_token(token) {
        return Err(InstallTokenError::Invalid);
    }

    let token_hash = agent_creds::hash_agent_install_token(token);
    let row: Option<AgentFullRow> = sqlx::query_as(&format!(
        "{AGENT_SELECT} WHERE install_token_hash = $1"
    ))
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| InstallTokenError::Other(e.to_string()))?;

    let Some(agent) = row else {
        return Err(InstallTokenError::Invalid);
    };
    let Some(expires_at) = agent.install_token_expires_at else {
        return Err(InstallTokenError::Invalid);
    };
    if agent.install_token_used_at.is_some() {
        return Err(InstallTokenError::Invalid);
    }
    if expires_at < Utc::now() {
        return Err(InstallTokenError::Expired);
    }

    // Conditional one-time consumption (updateMany with the same guard).
    let updated = sqlx::query(
        "UPDATE host_agents SET install_token_hash = NULL, install_token_expires_at = NULL, \
         install_token_used_at = now() \
         WHERE id = $1 AND install_token_hash = $2 AND install_token_used_at IS NULL \
         AND install_token_expires_at >= now()",
    )
    .bind(agent.id)
    .bind(&token_hash)
    .execute(&state.db)
    .await
    .map_err(|e| InstallTokenError::Other(e.to_string()))?;
    if updated.rows_affected() != 1 {
        return Err(InstallTokenError::Invalid);
    }

    let agent_secret = crate::libs::crypto::decrypt_sensitive_data(
        &state.config.encryption_key,
        &agent.secret_encrypted,
    )
    .map_err(|_| InstallTokenError::Other("AGENT_SECRET_INVALID".to_string()))?;
    if agent_secret.is_empty() {
        return Err(InstallTokenError::Other("AGENT_SECRET_INVALID".to_string()));
    }

    let host: Option<(i32, String)> = sqlx::query_as("SELECT id, name FROM hosts WHERE id = $1")
        .bind(agent.host_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| InstallTokenError::Other(e.to_string()))?;
    let Some((host_id, host_name)) = host else {
        return Err(InstallTokenError::Invalid);
    };

    // createLog(null, LogModule.HOST, ...): the log row carries a NULL user_id.
    if let Err(err) = sqlx::query(
        "INSERT INTO logs (user_id, module, action, content, result) \
         VALUES (NULL, 'host', 'host.agent_install_token_consume', $1, 'success')",
    )
    .bind(format!(
        "宿主机 Agent 一次性安装 token 已消费: {host_name} (#{host_id})"
    ))
    .execute(&state.db)
    .await
    {
        tracing::warn!("create_log failed (ignored): {err}");
    }

    match build_agent_install_config(&agent.agent_id, &agent_secret) {
        Ok(config) => Ok(config),
        Err("AGENT_SECRET_INVALID") => Err(InstallTokenError::Invalid),
        Err(other) => Err(InstallTokenError::Other(other.to_string())),
    }
}

/// GET /binary/{name}
async fn binary_download(
    State(state): State<SharedAppState>,
    Path(name): Path<String>,
) -> Response {
    if !matches_agent_binary_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Invalid Agent binary name",
                "code": "INVALID_AGENT_BINARY_NAME",
            })),
        )
            .into_response();
    }

    let manifest = read_agent_upgrade_manifest(&state).await;
    let version = sanitize_short_string(
        manifest.as_ref().map(|m| m.get("version").cloned().unwrap_or(Value::Null)).as_ref(),
        128,
    );
    let platform = if name.contains("amd64") {
        "linux-amd64"
    } else {
        "linux-arm64"
    };
    let file = manifest
        .as_ref()
        .and_then(|m| m.pointer(&format!("/files/{platform}")).cloned());
    let file_ok = file
        .as_ref()
        .and_then(|f| f.get("sha256").and_then(Value::as_str))
        .map(|s| is_sha256(Some(s)))
        .unwrap_or(false);
    if file.is_none() || version.is_none() || !file_ok {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Agent binary not found",
                "code": "AGENT_BINARY_NOT_FOUND",
            })),
        )
            .into_response();
    }
    let expected_sha256 = file.unwrap()["sha256"].as_str().unwrap_or("").to_string();
    let Some(version) = version else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Agent binary not found",
                "code": "AGENT_BINARY_NOT_FOUND",
            })),
        )
            .into_response();
    };

    match download_agent_release_binary(&state, &name, &version, &expected_sha256).await {
        Ok(Some(binary)) => {
            let mut response = (StatusCode::OK, binary.as_ref().clone()).into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/octet-stream"),
            );
            if let Ok(value) = header::HeaderValue::from_str(&format!(
                "attachment; filename=\"{name}\""
            )) {
                headers.insert(header::CONTENT_DISPOSITION, value);
            }
            headers.insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static(
                    "no-store, no-cache, must-revalidate, proxy-revalidate",
                ),
            );
            headers.insert(
                header::PRAGMA,
                header::HeaderValue::from_static("no-cache"),
            );
            headers.insert(header::EXPIRES, header::HeaderValue::from_static("0"));
            response
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Agent binary not found",
                "code": "AGENT_BINARY_NOT_FOUND",
            })),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!("[Agent] Failed to download Agent release binary name={name} version={version} error={error}");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "Agent binary download failed",
                    "code": "AGENT_BINARY_DOWNLOAD_FAILED",
                })),
            )
                .into_response()
        }
    }
}

// ---- JWT-guarded endpoints ----

/// Ownership guard shared by the /hosts/{hostId} endpoints.
async fn load_owned_host(
    state: &SharedAppState,
    host_id_raw: &str,
    user: &AuthUser,
) -> Result<(i32, String, i32), ApiError> {
    let Some(host_id) = parse_positive_id(host_id_raw) else {
        return Err(ApiError::bad_request("INVALID_HOST_ID"));
    };
    let host: Option<(i32, String, i32)> =
        sqlx::query_as("SELECT id, name, user_id FROM hosts WHERE id = $1")
            .bind(host_id)
            .fetch_optional(&state.db)
            .await
            .map_err(ApiError::from_sql)?;
    let Some((id, name, user_id)) = host else {
        return Err(ApiError::not_found(code::HOST_NOT_FOUND));
    };
    if user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    Ok((id, name, user_id))
}

/// GET /hosts/{hostId}/status
async fn host_status(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(host_id_raw): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (host_id, host_name, _) = load_owned_host(&state, &host_id_raw, &user).await?;
    let agent = get_agent_by_host_id(&state, host_id).await?;
    let agent_json = match &agent {
        Some(agent) => serialize_agent_status(&state, agent).await?,
        None => Value::Null,
    };
    Ok(Json(json!({
        "host": { "id": host_id, "name": host_name },
        "agent": agent_json,
    })))
}

/// POST /hosts/{hostId}/upgrade
async fn host_upgrade(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(host_id_raw): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (host_id, host_name, _) = load_owned_host(&state, &host_id_raw, &user).await?;
    let Some(agent) = get_agent_by_host_id(&state, host_id).await? else {
        return Err(ApiError::not_found("AGENT_NOT_FOUND"));
    };

    let latest_version = get_latest_agent_version(&state).await;
    let version_status =
        get_agent_version_status(agent.version.as_deref(), latest_version.as_deref());
    let derived_status = derive_agent_status(&agent);

    let Some(latest_version) = latest_version else {
        return Err(ApiError::with_message(
            "AGENT_LATEST_VERSION_UNAVAILABLE",
            StatusCode::SERVICE_UNAVAILABLE,
            "Agent latest version unavailable",
        ));
    };
    if version_status == "unknown" {
        return Err(ApiError::with_message(
            "AGENT_VERSION_UNKNOWN",
            StatusCode::CONFLICT,
            "Agent version unknown",
        ));
    }
    if version_status == "latest" {
        return Ok(Json(json!({
            "requested": false,
            "currentVersion": agent.version,
            "latestVersion": latest_version,
            "versionStatus": version_status,
            "nextHeartbeatSeconds": get_agent_heartbeat_interval_seconds(&agent),
            "message": "Agent is already latest",
        })));
    }
    if !agent.enabled || derived_status != "online" {
        return Err(ApiError::with_message(
            "AGENT_NOT_ONLINE",
            StatusCode::CONFLICT,
            "Agent is not online",
        ));
    }

    let next_heartbeat_seconds = get_agent_heartbeat_interval_seconds(&agent);
    sqlx::query(
        "UPDATE host_agents SET upgrade_requested_at = now(), upgrade_target_version = $2, \
         upgrade_force = true WHERE id = $1",
    )
    .bind(agent.id)
    .bind(&latest_version)
    .execute(&state.db)
    .await
    .map_err(ApiError::from_sql)?;
    create_log(
        &state,
        user.id,
        "host",
        "host.agent_upgrade_request",
        &format!(
            "请求宿主机 Agent 升级: {host_name} (#{host_id}) {} -> {latest_version}",
            agent.version.clone().unwrap_or_else(|| "unknown".to_string())
        ),
        "success",
    )
    .await;

    Ok(Json(json!({
        "requested": true,
        "currentVersion": agent.version,
        "latestVersion": latest_version,
        "versionStatus": version_status,
        "nextHeartbeatSeconds": next_heartbeat_seconds,
        "message": "Agent upgrade request accepted; upgrade instruction will be delivered on next heartbeat",
    })))
}

/// POST /upgrade-all (admin)
async fn upgrade_all(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    let Some(latest_version) = get_latest_agent_version(&state).await else {
        return Err(ApiError::with_message(
            "AGENT_LATEST_VERSION_UNAVAILABLE",
            StatusCode::SERVICE_UNAVAILABLE,
            "Agent latest version unavailable",
        ));
    };
    let agents: Vec<(i32, String, Option<String>)> = sqlx::query_as(
        "SELECT id, status::text AS status, version FROM host_agents WHERE enabled = true",
    )
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::from_sql)?;

    let ids: Vec<i32> = agents.iter().map(|(id, _, _)| *id).collect();
    if !ids.is_empty() {
        sqlx::query(
            "UPDATE host_agents SET upgrade_requested_at = now(), upgrade_target_version = $2, \
             upgrade_force = true WHERE id = ANY($1)",
        )
        .bind(&ids)
        .bind(&latest_version)
        .execute(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
    }
    let online = agents.iter().filter(|(_, status, _)| status == "online").count();
    let offline = agents.len() - online;
    let already_latest = agents
        .iter()
        .filter(|(_, _, version)| version.as_deref() == Some(latest_version.as_str()))
        .count();
    create_log(
        &state,
        admin.0.id,
        "host",
        "host.agent_force_upgrade_all",
        &format!(
            "强制更新全部 Agent 到 {latest_version}: 总计 {}，在线 {online}，离线待执行 {offline}",
            agents.len()
        ),
        "success",
    )
    .await;

    Ok(Json(json!({
        "requested": agents.len(),
        "online": online,
        "pendingOffline": offline,
        "alreadyLatest": already_latest,
        "latestVersion": latest_version,
    })))
}

fn require_enabled_body(body: &Value, allowed: &[&str]) -> Result<(), ApiError> {
    // Fastify schema: additionalProperties false -> 400 VALIDATION_ERROR.
    if let Some(obj) = body.as_object() {
        for key in obj.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(ApiError::validation(&format!(
                    "body must NOT have additional properties ({key})"
                )));
            }
        }
    }
    if let Some(enabled) = body.get("enabled") {
        if !enabled.is_boolean() {
            return Err(ApiError::validation("enabled must be boolean"));
        }
    }
    Ok(())
}

/// POST /hosts/{hostId}/install-command (owner or admin)
async fn host_install_command(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(host_id_raw): Path<String>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    // Fastify validates the optional body schema; a missing body behaves as {}.
    let Json(body) = body.unwrap_or(Json(json!({})));
    require_enabled_body(&body, &["enabled"])?;
    let (host_id, _host_name, _) = load_owned_host(&state, &host_id_raw, &user).await?;

    let panel_url = derive_panel_url(&headers, None);
    if !panel_url.starts_with("https://") {
        return Err(ApiError::with_message(
            "AGENT_HTTPS_REQUIRED",
            StatusCode::BAD_REQUEST,
            "Agent 安装命令必须使用 HTTPS 面板地址",
        ));
    }
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let result = match issue_host_agent_install_token(&state, host_id, enabled).await {
        Ok(result) => result,
        Err(RotateError::HostNotFound) => {
            return Err(ApiError::not_found(code::HOST_NOT_FOUND));
        }
        Err(RotateError::Db(err)) => return Err(err),
    };
    let install_command =
        build_agent_install_command(&panel_url, &result.install_token, None, None);

    create_log(
        &state,
        user.id,
        "host",
        "host.agent_install_command_generate",
        &format!("生成宿主机 Agent 安装命令: {} (#{})", result.host.1, result.host.0),
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "host": { "id": result.host.0, "name": result.host.1 },
            "agent": serialize_agent_status(&state, &result.agent).await?,
            "installToken": result.install_token,
            "installTokenExpiresAt": iso(result.install_token_expires_at),
            "installScriptUrl": format!("{panel_url}/api/agent/install.sh"),
            "installCommand": install_command,
            "warning": "installCommand 内包含一次性 Agent 安装 token，30 分钟内有效且只能使用一次。",
        })),
    )
        .into_response())
}

/// GET /admin/hosts/{hostId}/status (admin)
async fn admin_host_status(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(host_id_raw): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let Some(host_id) = parse_positive_id(&host_id_raw) else {
        return Err(ApiError::bad_request("INVALID_HOST_ID"));
    };
    let host: Option<(i32, String)> = sqlx::query_as("SELECT id, name FROM hosts WHERE id = $1")
        .bind(host_id)
        .fetch_optional(&state.db)
        .await
        .map_err(ApiError::from_sql)?;
    let Some((id, name)) = host else {
        return Err(ApiError::not_found(code::HOST_NOT_FOUND));
    };
    let agent = get_agent_by_host_id(&state, host_id).await?;
    let agent_json = match &agent {
        Some(agent) => serialize_agent(&state, agent).await?,
        None => Value::Null,
    };
    Ok(Json(json!({
        "host": { "id": id, "name": name },
        "agent": agent_json,
    })))
}

/// POST /admin/hosts/{hostId}/credentials (admin)
async fn admin_host_credentials(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(host_id_raw): Path<String>,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let Json(body) = body.unwrap_or(Json(json!({})));
    require_enabled_body(&body, &["enabled"])?;
    let Some(host_id) = parse_positive_id(&host_id_raw) else {
        return Err(ApiError::bad_request("INVALID_HOST_ID"));
    };
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let (agent, host, agent_id, agent_secret) =
        match rotate_host_agent_credentials(&state, host_id, enabled).await {
            Ok(result) => result,
            Err(RotateError::HostNotFound) => {
                return Err(ApiError::not_found(code::HOST_NOT_FOUND));
            }
            Err(RotateError::Db(err)) => return Err(err),
        };

    create_log(
        &state,
        admin.0.id,
        "host",
        "host.agent_credentials_rotate",
        &format!("重置宿主机 Agent 凭据: {} (#{})", host.1, host.0),
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "host": { "id": host.0, "name": host.1 },
            "agent": serialize_agent(&state, &agent).await?,
            "credentials": {
                "agentId": agent_id,
                "agentSecret": agent_secret,
            },
            "warning": "agentSecret 只会在本次响应中返回，请写入宿主机 Agent 配置后妥善保存。",
        })),
    )
        .into_response())
}

/// POST /admin/hosts/{hostId}/install-command (admin)
async fn admin_host_install_command(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(host_id_raw): Path<String>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let Json(body) = body.unwrap_or(Json(json!({})));
    require_enabled_body(&body, &["enabled", "baseUrl", "binaryUrl", "binarySha256"])?;
    // Schema checks: strings minLength 1; binarySha256 exactly 64 chars.
    for key in ["baseUrl", "binaryUrl"] {
        if let Some(v) = body.get(key) {
            if v.as_str().map(str::is_empty).unwrap_or(true) {
                return Err(ApiError::validation(&format!("{key} must be at least 1 characters")));
            }
        }
    }
    if let Some(v) = body.get("binarySha256") {
        let len = v.as_str().map(str::len).unwrap_or(0);
        if len < 64 || len > 64 {
            return Err(ApiError::validation(
                "binarySha256 must NOT have fewer than 64 characters",
            ));
        }
    }

    let Some(host_id) = parse_positive_id(&host_id_raw) else {
        return Err(ApiError::bad_request("INVALID_HOST_ID"));
    };
    let base_url = body.get("baseUrl").and_then(Value::as_str);
    let panel_url = derive_panel_url(&headers, base_url);
    if !panel_url.starts_with("https://") {
        return Err(ApiError::with_message(
            "AGENT_HTTPS_REQUIRED",
            StatusCode::BAD_REQUEST,
            "Agent 安装命令必须使用 HTTPS 面板地址",
        ));
    }
    if let Some(message) =
        validate_custom_agent_binary(body.get("binaryUrl"), body.get("binarySha256"))
    {
        return Err(ApiError::with_message(
            "INVALID_AGENT_BINARY",
            StatusCode::BAD_REQUEST,
            message,
        ));
    }
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let result = match issue_host_agent_install_token(&state, host_id, enabled).await {
        Ok(result) => result,
        Err(RotateError::HostNotFound) => {
            return Err(ApiError::not_found(code::HOST_NOT_FOUND));
        }
        Err(RotateError::Db(err)) => return Err(err),
    };

    let install_command = build_agent_install_command(
        &panel_url,
        &result.install_token,
        body.get("binaryUrl").and_then(Value::as_str),
        body.get("binarySha256").and_then(Value::as_str),
    );

    create_log(
        &state,
        admin.0.id,
        "host",
        "host.agent_install_command_generate",
        &format!("生成宿主机 Agent 安装命令: {} (#{})", result.host.1, result.host.0),
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "host": { "id": result.host.0, "name": result.host.1 },
            "agent": serialize_agent(&state, &result.agent).await?,
            "installToken": result.install_token,
            "installTokenExpiresAt": iso(result.install_token_expires_at),
            "installScriptUrl": format!("{panel_url}/api/agent/install.sh"),
            "installCommand": install_command,
            "warning": "installCommand 内包含一次性 Agent 安装 token，30 分钟内有效且只能使用一次。",
        })),
    )
        .into_response())
}

/// POST /heartbeat — Agent HMAC auth via verify_agent_request.
async fn heartbeat(
    State(state): State<SharedAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    let method = request.method().as_str().to_string();
    // The signing path has NO query string.
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();
    let body_bytes = axum::body::to_bytes(request.into_body(), state.config.body_limit)
        .await
        .map_err(|_| ApiError::with_message("FST_ERR_CTP_INVALID_JSON", StatusCode::BAD_REQUEST, "Invalid JSON body"))?;
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|_| json!({}));

    let agent_record = verify_agent_request(&state, &method, &path, &headers, &body_bytes).await?;
    // The TS authenticateAgentRequest returns the full hostAgent row; re-read it.
    let Some(agent) = get_agent_by_agent_id(&state, &agent_record.agent_id).await? else {
        return Err(ApiError::with_message(
            code::AGENT_DISABLED,
            StatusCode::UNAUTHORIZED,
            "Agent is not enabled",
        ));
    };

    let now = Utc::now();
    let instance_report_result =
        process_agent_instance_report(&state, agent.host_id, body.get("instances")).await;
    let instance_report = match instance_report_result {
        Ok(report) => report,
        Err(error) => {
            tracing::warn!(
                "[Agent] Failed to process Agent instance report agentId={} hostId={} error={error}",
                agent.agent_id,
                agent.host_id
            );
            Value::Null
        }
    };

    // processAgentSecurityEvents never throws into the heartbeat path.
    let host_name: Option<String> =
        sqlx::query_as("SELECT name FROM hosts WHERE id = $1")
            .bind(agent.host_id)
            .fetch_optional(&state.db)
            .await
            .map_err(ApiError::from_sql)?
            .map(|(name,)| name);
    process_agent_security_events(
        &state,
        agent.host_id,
        host_name,
        body.get("securityEvents"),
        body.get("instances"),
    )
    .await;

    // Persist the current instance/MAC snapshot before compiling the policy
    // bundle below. Otherwise a newly reported MAC is invisible until the
    // next heartbeat, and a successful apply can be recorded against stale
    // target data.
    let capabilities = normalize_capabilities(body.get("capabilities"));
    let last_report = build_heartbeat_report(&body);
    let last_heartbeat_ip =
        get_agent_heartbeat_ip(&headers, &peer.ip().to_string()).and_then(|ip| {
            // sanitizeShortString(ip, 128)
            let trimmed = ip.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.chars().take(128).collect::<String>())
            }
        });
    let version = sanitize_short_string(body.get("version"), 128);
    sqlx::query(
        "UPDATE host_agents SET status = 'online', version = $2, capabilities = $3, \
         last_report = $4, last_seen_at = $5, last_heartbeat_ip = $6 WHERE agent_id = $1",
    )
    .bind(&agent.agent_id)
    .bind(version)
    .bind(&json!(capabilities))
    .bind(&last_report)
    .bind(now)
    .bind(last_heartbeat_ip)
    .execute(&state.db)
    .await
    .map_err(ApiError::from_sql)?;

    if let Some(network_policy_status) = body.get("networkPolicyStatus").filter(|v| v.is_object())
    {
        let status_revision = sanitize_short_string(network_policy_status.get("revision"), 128);
        let applied = network_policy_status.get("applied") == Some(&Value::Bool(true));
        let apply_error = sanitize_short_string(network_policy_status.get("error"), 2000);
        let policy_bundle = build_host_agent_policy_bundle(&state, agent.host_id).await?;
        if let Some(status_revision) = status_revision {
            if status_revision == policy_bundle["revision"].as_str().unwrap_or("") {
                let missing_target_mac = has_missing_target_mac(&policy_bundle);
                let effective_applied = applied && !missing_target_mac;
                let effective_error = if effective_applied {
                    None
                } else if missing_target_mac {
                    Some("Agent policy targets are missing valid MAC addresses".to_string())
                } else {
                    apply_error
                };
                sqlx::query(
                    "UPDATE host_network_policies SET apply_status = $2, apply_error = $3, \
                     applied_at = $4 WHERE host_id = $1 AND enabled = true",
                )
                .bind(agent.host_id)
                .bind(if effective_applied { "applied" } else { "failed" })
                .bind(effective_error)
                .bind(if effective_applied { Some(now) } else { None })
                .execute(&state.db)
                .await
                .map_err(ApiError::from_sql)?;
            }
        }
    }

    process_agent_audit_snapshots(&state, agent.host_id, body.get("auditSnapshots")).await?;

    let audit_config: Option<(bool, Option<DateTime<Utc>>, i32, i32)> = sqlx::query_as(
        "SELECT enabled, last_requested_at, interval_seconds, batch_size \
         FROM host_agent_audit_configs WHERE host_id = $1",
    )
    .bind(agent.host_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?;

    let monitoring = match &audit_config {
        Some((enabled, last_requested_at, interval_seconds, batch_size)) => {
            let force = match (last_requested_at.clone(), agent.last_seen_at) {
                (Some(last_requested), Some(last_seen)) => last_requested > last_seen,
                (Some(_), None) => true,
                (None, _) => false,
            };
            json!({
                "enabled": *enabled,
                "force": force,
                "intervalSeconds": if *interval_seconds != 0 { *interval_seconds } else { 300 },
                "batchSize": if *batch_size != 0 { *batch_size } else { 8 },
            })
        }
        None => json!({
            "enabled": false,
            "force": false,
            "intervalSeconds": 300,
            "batchSize": 8,
        }),
    };

    let upgrade = build_agent_upgrade_instruction(&state, &headers, &body, &agent).await?;
    let network_policies = build_host_agent_policy_bundle(&state, agent.host_id).await?;

    Ok(Json(json!({
        "ok": true,
        "serverTime": iso(now),
        "taskPollIntervalSeconds": 15,
        "instanceReport": instance_report,
        "upgrade": upgrade,
        "monitoring": monitoring,
        "networkPolicies": network_policies,
    }))
    .into_response())
}
