//! 认证路由 — port of server/src/routes/auth.ts (mounted at /api/auth).
//!
//! Endpoints (method + TS auth level):
//! - POST /login                         public (turnstileVerifier preHandler)
//! - POST /send-verification-code        public (strictTurnstileVerifier)
//! - POST /register                      public (strict turnstile when SMTP off)
//! - GET  /me                            fastify.authenticate
//! - POST /logout                        fastify.authenticate
//! - POST /refresh                       public
//! - POST /invite                        fastify.authenticateAdmin
//! - GET  /invites                       fastify.authenticateAdmin
//! - DELETE /invites/{id}                fastify.authenticateAdmin
//! - GET  /2fa/status                    fastify.authenticate
//! - POST /2fa/setup                     fastify.authenticate
//! - POST /2fa/enable                    fastify.authenticate
//! - POST /2fa/disable                   fastify.authenticate
//! - GET  /2fa/recovery-codes            fastify.authenticate
//! - POST /2fa/regenerate-recovery-codes fastify.authenticate
//! - POST /forgot-password/send-code     public (turnstileVerifier)
//! - POST /forgot-password/reset         public (turnstileVerifier)
//! - GET  /login-history                 fastify.authenticate
//!
//! Port deviations (see the porting report): email sending and external
//! notification push are stubbed in libs/external.rs; the 2FA QR code image is
//! returned empty (no `qrcode` crate in the shared Cargo.toml); terminal
//! websocket session closing is a no-op (terminal proxy not ported).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rand::Rng;
use regex::Regex;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use rust_decimal::{Decimal, RoundingStrategy};
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool};

use crate::auth::{sign_access_token, AdminAuth, AuthUser};
use crate::error::{code, ApiError};
use crate::libs::crypto;
use crate::libs::external;
use crate::libs::security::{
    create_refresh_token, generate_refresh_token, invalidate_session_access_token,
    revoke_refresh_token, update_session_activity, verify_refresh_token, USER_LEVEL_SESSION_ID,
};
use crate::libs::validators::{contains_dangerous_chars, validate_identifier, validate_password};
use crate::response::{num, parse_pagination};
use crate::routes::users::create_log;
use crate::state::{LoginLockState, SharedAppState};

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/login", post(login))
        .route("/send-verification-code", post(send_verification_code))
        .route("/register", post(register))
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh))
        .route("/invite", post(create_invite))
        .route("/invites", get(list_invites))
        .route("/invites/{id}", delete(delete_invite))
        .route("/2fa/status", get(two_fa_status))
        .route("/2fa/setup", post(two_fa_setup))
        .route("/2fa/enable", post(two_fa_enable))
        .route("/2fa/disable", post(two_fa_disable))
        .route("/2fa/recovery-codes", get(two_fa_recovery_codes))
        .route(
            "/2fa/regenerate-recovery-codes",
            post(two_fa_regenerate_recovery_codes),
        )
        .route("/forgot-password/send-code", post(forgot_password_send_code))
        .route("/forgot-password/reset", post(forgot_password_reset))
        .route("/login-history", get(login_history))
}

// ===========================================================================
// small serialization / request helpers
// ===========================================================================

/// TS `Date.toISOString()`: ISO 8601 UTC with milliseconds and `Z`.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn iso_opt(value: Option<DateTime<Utc>>) -> Value {
    match value {
        Some(v) => json!(iso(v)),
        None => Value::Null,
    }
}

/// Fastify 5's default Ajv runs with `validateFormats: false`, so the
/// wire-level body-schema errors are only required / type / minLength /
/// maxLength / pattern / minimum / maximum. The app.ts error handler maps the
/// FIRST ajv error to `400 { error, code: "VALIDATION_ERROR" }` (allErrors is
/// off by default, so `details` never carries an array here).
fn validation_error(message: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": message, "code": code::VALIDATION_ERROR })),
    )
        .into_response()
}

fn must_be_object() -> Response {
    validation_error("must be object".to_string())
}

/// ajv `type: string` failure; the app.ts error handler falls through to
/// `messages.push(err.message)` where ajv8's message is "must be string".
fn type_error() -> Response {
    validation_error("must be string".to_string())
}

fn required_error(field: &str) -> Response {
    validation_error(format!("{field} is required"))
}

/// The app.ts error handler rewrites minLength messages for known fields; the
/// schema-declared minimum itself is unused in the message (login password
/// minLength is 6 but the message says 8 — TS quirk preserved verbatim).
fn min_length_message(field: &str) -> String {
    match field {
        "password" => "Password must be at least 8 characters".to_string(),
        "username" => "Username must be at least 3 characters".to_string(),
        other => format!("{other} is too short"),
    }
}

/// Reads a required string property (ajv order: required before type checks).
fn require_string(body: &Value, field: &str) -> Result<String, Response> {
    if body.get(field).is_none() {
        return Err(required_error(field));
    }
    match body.get(field) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(type_error()),
    }
}

/// Reads an optional string property.
fn optional_string(body: &Value, field: &str) -> Result<Option<String>, Response> {
    match body.get(field) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(type_error()),
    }
}

/// minLength/maxLength checks (ajv order: minLength before maxLength).
fn check_len(field: &str, value: &str, min: Option<usize>, max: Option<usize>) -> Result<(), Response> {
    let len = value.chars().count();
    if let Some(min) = min {
        if len < min {
            return Err(validation_error(min_length_message(field)));
        }
    }
    if let Some(max) = max {
        if len > max {
            return Err(validation_error(format!("{field} is too long")));
        }
    }
    Ok(())
}

/// Mirrors rate_limit.rs client-ip trust rules (lib/client-ip.ts):
/// CF-Connecting-IP / X-Forwarded-For are only trusted for local peers.
fn client_ip_string(headers: &HeaderMap, peer: SocketAddr) -> String {
    let peer_is_local = is_local_peer_ip(peer.ip());
    if peer_is_local {
        if let Some(ip) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
        {
            return ip.to_string();
        }
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
        {
            return ip.to_string();
        }
    }
    peer.ip().to_string()
}

fn is_local_peer_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
    }
}

/// Manual cookie parsing (no axum-extra): split the Cookie header on ';'.
fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{name}=");
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(&prefix) {
            return Some(rest.to_string());
        }
    }
    None
}

fn with_set_cookie(mut response: Response, cookie: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

fn error_with_cookie(error: ApiError, cookie: &str) -> Response {
    with_set_cookie(error.into_response(), cookie)
}

fn request_user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

// ===========================================================================
// login lockout (port of lib/security.ts checkLoginLock / recordLoginFailure /
// clearLoginFailure) — in-memory via state.login_locks (std::sync::Mutex,
// never held across .await).
//
// TS entry shape { count, lastAttempt, lockedUntil } maps onto the shared
// LoginLockState { failures: Vec<Instant>, locked_until }: count == failures.len(),
// lastAttempt == failures.last().
// ===========================================================================

const LOGIN_MAX_ATTEMPTS: usize = 5;
const LOGIN_LOCK_DURATION: Duration = Duration::from_secs(15 * 60);
const LOGIN_ATTEMPT_WINDOW: Duration = Duration::from_secs(5 * 60);
const LOGIN_ATTEMPT_MAX_KEYS: usize = 20_000;

/// Key format matches TS: `${ip}:${username}` where username is `user:${id}`
/// for known users or the lowercased/trimmed identifier for unknown ones.
fn lock_key(ip: &str, identifier: &str) -> String {
    format!("{ip}:{identifier}")
}

/// Some(retry_after_seconds) while the key is locked; an expired lock deletes
/// the entry (checkLoginLock).
fn check_login_lock(state: &SharedAppState, ip: &str, identifier: &str) -> Option<u64> {
    let key = lock_key(ip, identifier);
    let mut map = state.login_locks.lock().expect("login locks poisoned");
    let entry = map.get(&key)?;
    if let Some(locked_until) = entry.locked_until {
        if Instant::now() < locked_until {
            let remaining = locked_until.saturating_duration_since(Instant::now());
            let secs = remaining.as_secs();
            let ceil = if remaining.subsec_nanos() > 0 { secs + 1 } else { secs };
            return Some(ceil);
        }
        map.remove(&key);
    }
    None
}

fn record_login_failure(state: &SharedAppState, ip: &str, identifier: &str) {
    let key = lock_key(ip, identifier);
    let now = Instant::now();
    let mut map = state.login_locks.lock().expect("login locks poisoned");
    let entry = map.entry(key).or_insert_with(|| LoginLockState {
        failures: Vec::new(),
        locked_until: None,
    });
    let window_expired = entry
        .failures
        .last()
        .map(|t| now.duration_since(*t) > LOGIN_ATTEMPT_WINDOW)
        .unwrap_or(true);
    if window_expired {
        // New attempt window: reset the counter (TS stores count=1,
        // lockedUntil=null).
        entry.failures.clear();
        entry.locked_until = None;
    }
    entry.failures.push(now);
    if entry.failures.len() >= LOGIN_MAX_ATTEMPTS {
        entry.locked_until = Some(now + LOGIN_LOCK_DURATION);
    }

    // P3-03: bound the map size — evict expired entries first, then arbitrary
    // ones (TS evicts in insertion order; a std HashMap has no order).
    if map.len() > LOGIN_ATTEMPT_MAX_KEYS {
        map.retain(|_, e| {
            let expires_at = e
                .locked_until
                .unwrap_or_else(|| e.failures.last().copied().unwrap_or(now) + LOGIN_ATTEMPT_WINDOW);
            now <= expires_at
        });
        while map.len() > LOGIN_ATTEMPT_MAX_KEYS {
            let Some(victim) = map.keys().next().cloned() else { break };
            map.remove(&victim);
        }
    }
}

fn clear_login_failure(state: &SharedAppState, ip: &str, identifier: &str) {
    let key = lock_key(ip, identifier);
    state
        .login_locks
        .lock()
        .expect("login locks poisoned")
        .remove(&key);
}

// ===========================================================================
// system-config access with the 5-minute cache (port of db/system-config.ts +
// lib/config-cache.ts; PERF001)
// ===========================================================================

const CONFIG_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const CONFIG_CACHE_MAX_SIZE: usize = 100;

/// Some(Some(v)) caches a value (possibly empty string); Some(None) caches a
/// miss so repeated lookups for absent keys do not hammer the DB (TS caches
/// null too).
static CONFIG_CACHE: Lazy<tokio::sync::RwLock<HashMap<String, (Option<String>, Instant)>>> =
    Lazy::new(|| tokio::sync::RwLock::new(HashMap::new()));

async fn cached_config_get(key: &str) -> Option<Option<String>> {
    let now = Instant::now();
    let mut cache = CONFIG_CACHE.write().await;
    match cache.get(key) {
        Some((value, expires_at)) if now <= *expires_at => Some(value.clone()),
        Some(_) => {
            cache.remove(key);
            None
        }
        None => None,
    }
}

async fn cached_config_set(key: &str, value: Option<String>) {
    let mut cache = CONFIG_CACHE.write().await;
    if cache.len() >= CONFIG_CACHE_MAX_SIZE {
        let now = Instant::now();
        cache.retain(|_, (_, expires_at)| now <= *expires_at);
        if cache.len() >= CONFIG_CACHE_MAX_SIZE {
            let victims: Vec<String> = cache.keys().take(10).cloned().collect();
            for k in victims {
                cache.remove(&k);
            }
        }
    }
    cache.insert(key.to_string(), (value, Instant::now() + CONFIG_CACHE_TTL));
}

const SENSITIVE_CONFIG_KEYS: &[&str] = &[
    "smtp_password",
    "turnstile_secret_key",
    "ticket_image_lsky_token",
    "telegram_bot_token",
    "telegram_webhook_secret",
];

/// Port of db/system-config.ts getSystemConfig(key, decrypt = true): sensitive
/// keys bypass the cache and are decrypted when stored in `iv:tag:ciphertext`
/// form; decryption failures log and return null (TS catch).
async fn get_system_config(state: &SharedAppState, key: &str) -> Result<Option<String>, ApiError> {
    let is_sensitive = SENSITIVE_CONFIG_KEYS.contains(&key);
    if !is_sensitive {
        if let Some(cached) = cached_config_get(key).await {
            return Ok(cached);
        }
    }

    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT value FROM system_configs WHERE key = $1")
            .bind(key)
            .fetch_optional(&state.db)
            .await?;
    let value: Option<String> = row.and_then(|(v,)| v);

    match &value {
        None => {
            if !is_sensitive {
                cached_config_set(key, None).await;
            }
            return Ok(None);
        }
        Some(v) if v.is_empty() => {
            // TS returns '' as-is (falsy but not null).
            if !is_sensitive {
                cached_config_set(key, value.clone()).await;
            }
            return Ok(value);
        }
        _ => {}
    }

    if is_sensitive {
        if let Some(v) = &value {
            if v.contains(':') {
                return Ok(crypto::decrypt_sensitive_data(&state.config.encryption_key, v)
                    .map_err(|_| {
                        tracing::warn!("Failed to decrypt system config {key}; returning null");
                    })
                    .ok());
            }
        }
    }

    if !is_sensitive {
        cached_config_set(key, value.clone()).await;
    }
    Ok(value)
}

async fn get_system_config_boolean(
    state: &SharedAppState,
    key: &str,
    default: bool,
) -> Result<bool, ApiError> {
    Ok(match get_system_config(state, key).await? {
        None => default,
        Some(v) => v == "true" || v == "1",
    })
}

async fn get_system_config_number(
    state: &SharedAppState,
    key: &str,
    default: i64,
) -> Result<i64, ApiError> {
    Ok(match get_system_config(state, key).await? {
        None => default,
        Some(v) => v.trim().parse().unwrap_or(default),
    })
}

async fn get_system_config_float(
    state: &SharedAppState,
    key: &str,
    default: f64,
) -> Result<f64, ApiError> {
    Ok(match get_system_config(state, key).await? {
        None => default,
        Some(v) => v.trim().parse().unwrap_or(default),
    })
}

async fn is_registration_enabled(state: &SharedAppState) -> Result<bool, ApiError> {
    get_system_config_boolean(state, "registration_enabled", true).await
}

async fn is_invite_code_required(state: &SharedAppState) -> Result<bool, ApiError> {
    get_system_config_boolean(state, "require_invite_code", true).await
}

async fn ensure_registration_enabled(state: &SharedAppState) -> Result<(), ApiError> {
    if !is_registration_enabled(state).await? {
        return Err(ApiError::forbidden(code::REGISTRATION_DISABLED));
    }
    Ok(())
}

/// Port of lib/mailer.ts isSmtpEnabled (reads smtp_* system configs; the
/// sensitive smtp_password is decrypted by get_system_config when stored
/// encrypted).
async fn is_smtp_enabled(state: &SharedAppState) -> Result<bool, ApiError> {
    let enabled = get_system_config_boolean(state, "smtp_enabled", false).await?;
    let host = get_system_config(state, "smtp_host").await?;
    let username = get_system_config(state, "smtp_username").await?;
    let password = get_system_config(state, "smtp_password").await?;
    let non_empty = |v: Option<String>| v.map(|s| !s.is_empty()).unwrap_or(false);
    Ok(enabled && non_empty(host) && non_empty(username) && non_empty(password))
}

// ===========================================================================
// Turnstile preHandler ports (lib/turnstile.ts + lib/turnstile-precheck.ts)
// ===========================================================================

struct TurnstileConfig {
    enabled: bool,
    secret_key: Option<String>,
}

async fn get_turnstile_config(state: &SharedAppState) -> Result<TurnstileConfig, ApiError> {
    let enabled = get_system_config_boolean(state, "turnstile_enabled", false).await?;
    // TS treats '' as falsy: an empty configured key means "not configured".
    let secret_key = get_system_config(state, "turnstile_secret_key")
        .await?
        .filter(|v| !v.is_empty());
    Ok(TurnstileConfig { enabled, secret_key })
}

/// Token source order (TS): body.turnstileToken || query.turnstileToken ||
/// x-turnstile-token header, first non-empty wins.
fn turnstile_token(
    body_token: Option<&str>,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Option<String> {
    body_token
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .or_else(|| {
            query
                .get("turnstileToken")
                .filter(|t| !t.is_empty())
                .cloned()
        })
        .or_else(|| {
            headers
                .get("x-turnstile-token")
                .and_then(|v| v.to_str().ok())
                .filter(|t| !t.is_empty())
                .map(|t| t.to_string())
        })
}

fn turnstile_missing_token() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "Turnstile verification required",
            "code": "TURNSTILE_TOKEN_MISSING",
        })),
    )
        .into_response()
}

fn turnstile_failed(details: String) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "Turnstile verification failed",
            "code": "TURNSTILE_VERIFICATION_FAILED",
            "details": details,
        })),
    )
        .into_response()
}

fn turnstile_not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": "Turnstile verification is not configured",
            "code": "TURNSTILE_NOT_CONFIGURED",
        })),
    )
        .into_response()
}

/// Port of createTurnstileVerifier(required = true). Skipping rule in effect:
/// no secret key configured. (When disabled but a key exists, TS still
/// verifies — quirk preserved.)
async fn verify_turnstile(
    state: &SharedAppState,
    body_token: Option<&str>,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
    client_ip: &str,
) -> Result<(), Response> {
    let config = get_turnstile_config(state)
        .await
        .map_err(|e| e.into_response())?;

    if !config.enabled && config.secret_key.is_none() {
        return Ok(());
    }
    let Some(secret_key) = &config.secret_key else {
        tracing::warn!("Turnstile enabled but secret key not configured");
        return Ok(());
    };

    let Some(token) = turnstile_token(body_token, query, headers) else {
        return Err(turnstile_missing_token());
    };

    match external::verify_turnstile_token(&token, secret_key, Some(client_ip)).await {
        Ok(()) => Ok(()),
        Err(detail) => Err(turnstile_failed(detail)),
    }
}

/// Port of createStrictTurnstileVerifier + getStrictTurnstilePrecheck.
async fn verify_strict_turnstile(
    state: &SharedAppState,
    body_token: Option<&str>,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
    client_ip: &str,
) -> Result<(), Response> {
    let config = get_turnstile_config(state)
        .await
        .map_err(|e| e.into_response())?;

    if !config.enabled {
        return Ok(());
    }
    let Some(secret_key) = &config.secret_key else {
        return Err(turnstile_not_configured());
    };
    let Some(token) = turnstile_token(body_token, query, headers) else {
        return Err(turnstile_missing_token());
    };

    match external::verify_turnstile_token(&token, secret_key, Some(client_ip)).await {
        Ok(()) => Ok(()),
        Err(detail) => Err(turnstile_failed(detail)),
    }
}

// ===========================================================================
// security event logging (port of lib/security.ts logSecurityEvent)
// ===========================================================================

mod security_event {
    pub const LOGIN_SUCCESS: &str = "login_success";
    pub const LOGIN_FAILED: &str = "login_failed";
    pub const REGISTER_SUCCESS: &str = "register_success";
    pub const LOGOUT: &str = "logout";
    pub const RATE_LIMIT_EXCEEDED: &str = "rate_limit_exceeded";
    pub const SUSPICIOUS_ACTIVITY: &str = "suspicious_activity";
}

struct SecurityDetails<'a> {
    ip: Option<&'a str>,
    username: Option<&'a str>,
    reason: Option<&'a str>,
    action: Option<&'a str>,
}

/// Fire-and-forget insert into `logs` (module 'security'); failures only warn.
/// The instanceId inference pass (db/logs.ts inferLogInstanceId) is not
/// replicated: its patterns (`instance #N`, `instance "name"`) never match the
/// security-event contents this module emits.
async fn log_security_event(
    state: &SharedAppState,
    event_type: &str,
    user_id: Option<i32>,
    details: SecurityDetails<'_>,
) {
    let username = details.username.unwrap_or("");
    let ip = details.ip.unwrap_or("");
    let reason = details.reason.unwrap_or("");

    let format_user_ip = |username: &str, ip: &str| {
        let mut parts: Vec<String> = Vec::new();
        if !username.is_empty() {
            parts.push(username.to_string());
        }
        if !ip.is_empty() {
            parts.push(format!("[IP: {ip}]"));
        }
        parts.join(" ")
    };

    let (action, content) = match event_type {
        security_event::REGISTER_SUCCESS
        | security_event::LOGIN_SUCCESS
        | security_event::LOGOUT => (event_type.to_string(), format_user_ip(username, ip)),
        security_event::LOGIN_FAILED | security_event::RATE_LIMIT_EXCEEDED => {
            let mut parts: Vec<String> = Vec::new();
            if !username.is_empty() {
                parts.push(username.to_string());
            }
            if !reason.is_empty() {
                parts.push(format!("[原因: {reason}]"));
            }
            if !ip.is_empty() {
                parts.push(format!("[IP: {ip}]"));
            }
            (event_type.to_string(), parts.join(" "))
        }
        security_event::SUSPICIOUS_ACTIVITY => {
            let action = if details.action == Some("register") {
                "invalid_invite_code".to_string()
            } else {
                "suspicious_activity".to_string()
            };
            let mut parts: Vec<String> = Vec::new();
            if let Some(a) = details.action {
                parts.push(format!("[操作: {a}]"));
            }
            if !reason.is_empty() {
                parts.push(format!("[原因: {reason}]"));
            }
            if !username.is_empty() {
                parts.push(format!("[用户: {username}]"));
            }
            if !ip.is_empty() {
                parts.push(format!("[IP: {ip}]"));
            }
            let content = if parts.is_empty() {
                "可疑活动".to_string()
            } else {
                parts.join(" ")
            };
            (action, content)
        }
        _ => (event_type.to_string(), String::new()),
    };

    let result = if event_type.contains("failed")
        || event_type.contains("denied")
        || event_type == "rate_limit_exceeded"
        || event_type == "suspicious_activity"
    {
        "warning"
    } else {
        "success"
    };

    let insert = sqlx::query(
        "INSERT INTO logs (user_id, module, action, content, result) \
         VALUES ($1, 'security', $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&action)
    .bind(&content)
    .bind(result)
    .execute(&state.db)
    .await;
    if let Err(err) = insert {
        tracing::warn!("Security event log failed: {err}");
    }
}

// ===========================================================================
// notifier inbox part (port of lib/notifier.ts sendNotification: the inbox
// message is always created; the external channel fan-out is stubbed in
// libs/external.rs push_external_notification)
// ===========================================================================

async fn send_notification_inbox(
    state: &SharedAppState,
    user_id: i32,
    event_type: &str,
    title: &str,
    content: &str,
    data: Value,
) {
    let insert = sqlx::query(
        "INSERT INTO inbox_messages (user_id, event_type, title, content, data) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(event_type)
    .bind(title)
    .bind(content)
    .bind(data)
    .execute(&state.db)
    .await;
    if let Err(err) = insert {
        tracing::warn!("send_notification_inbox failed (ignored): {err}");
    }
    external::push_external_notification(user_id, event_type, title).await;
}

// ===========================================================================
// db helpers (port of the db/users.ts / db/login-records.ts pieces auth.ts uses)
// ===========================================================================

#[derive(Debug, FromRow)]
struct UserRow {
    id: i32,
    username: String,
    email: Option<String>,
    password_hash: String,
    role: String,
    status: String,
    ban_reason: Option<String>,
    avatar_style: String,
    avatar_badge_id: Option<String>,
    has_created_host_before: bool,
    two_factor_enabled: bool,
    two_factor_secret: Option<String>,
    two_factor_recovery_codes: Option<String>,
}

const USER_COLS: &str = "id, username, email, password_hash, role::text AS role, status::text AS status, \
     ban_reason, avatar_style, avatar_badge_id, has_created_host_before, \
     two_factor_enabled, two_factor_secret, two_factor_recovery_codes";

async fn find_user_by_username(pool: &PgPool, username: &str) -> Result<Option<UserRow>, ApiError> {
    let row = sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLS} FROM users WHERE username = $1"
    ))
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Port of db/users.ts findUserByUsernameOrEmail: exact username first, then a
/// case-insensitive email match (Prisma `mode: 'insensitive'` equals).
async fn find_user_by_username_or_email(
    pool: &PgPool,
    identifier: &str,
) -> Result<Option<UserRow>, ApiError> {
    if let Some(user) = find_user_by_username(pool, identifier).await? {
        return Ok(Some(user));
    }
    let trimmed = identifier.trim();
    let row = sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLS} FROM users \
         WHERE email IS NOT NULL AND LOWER(email) = LOWER($1) LIMIT 1"
    ))
    .bind(trimmed)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Port of db/users.ts findUserByEmail (case-insensitive, trimmed).
async fn find_user_by_email(pool: &PgPool, email: &str) -> Result<Option<UserRow>, ApiError> {
    let trimmed = email.trim();
    let row = sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLS} FROM users \
         WHERE email IS NOT NULL AND LOWER(email) = LOWER($1) LIMIT 1"
    ))
    .bind(trimmed)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

async fn find_user_by_id(pool: &PgPool, id: i32) -> Result<Option<UserRow>, ApiError> {
    let row = sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLS} FROM users WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Port of lib/hosting-access.ts getUserHostingFeatureStatus folded into the
/// auth user payload (auth.ts buildAuthUserPayload).
async fn build_auth_user_payload(state: &SharedAppState, user: &UserRow) -> Result<Value, ApiError> {
    let feature_enabled = get_system_config_boolean(state, "hosting_feature_enabled", true).await?;
    let can_access = if user.role == "admin" {
        true
    } else {
        feature_enabled || user.has_created_host_before
    };
    Ok(json!({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "avatarStyle": user.avatar_style,
        "avatarBadgeId": user.avatar_badge_id,
        "hasCreatedHostBefore": user.has_created_host_before,
        "canAccessHostingFeature": can_access,
    }))
}

/// Port of lib/security.ts detectNewLoginLocation (LoginRecord table, last 30
/// days / 50 records). Errors return (false, false) so login is never blocked.
async fn detect_new_login_location(
    state: &SharedAppState,
    user_id: i32,
    current_ip: &str,
    current_user_agent: &str,
) -> (bool, bool) {
    let thirty_days_ago = Utc::now() - chrono::Duration::seconds(30 * 24 * 60 * 60);
    let rows: Vec<(Option<String>, Option<String>)> = match sqlx::query_as(
        "SELECT ip, user_agent FROM login_records \
         WHERE user_id = $1 AND created_at >= $2 \
         ORDER BY created_at DESC LIMIT 50",
    )
    .bind(user_id)
    .bind(thirty_days_ago)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!("Failed to detect new login location: {err}");
            return (false, false);
        }
    };

    if rows.is_empty() {
        return (false, false);
    }

    let known_ips: HashSet<String> = rows.iter().filter_map(|(ip, _)| ip.clone()).collect();
    let is_new_ip = !known_ips.contains(current_ip);

    let known_fingerprints: HashSet<String> = rows
        .iter()
        .filter_map(|(_, ua)| ua.clone().map(|ua| normalize_user_agent(&ua)))
        .collect();
    let is_new_device = !known_fingerprints.contains(&normalize_user_agent(current_user_agent));

    (is_new_ip, is_new_device)
}

/// lib/security.ts normalizeUserAgent (browser|os|mobile/desktop).
fn normalize_user_agent(ua: &str) -> String {
    static BROWSER: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)(Chrome|Firefox|Safari|Edge|Opera|MSIE|Trident)").expect("valid regex")
    });
    let browser = BROWSER
        .captures(ua)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_lowercase())
        .unwrap_or_else(|| "unknown".to_string());

    let lower = ua.to_lowercase();
    let os = if lower.contains("windows") {
        "windows"
    } else if lower.contains("mac os x") || lower.contains("macintosh") {
        "macos"
    } else if lower.contains("iphone") || lower.contains("ipad") || lower.contains("ipod") {
        "ios"
    } else if lower.contains("android") {
        "android"
    } else if lower.contains("linux") {
        "linux"
    } else if lower.contains("cros") {
        "chromeos"
    } else {
        "unknown"
    };

    let is_mobile = lower.contains("mobile")
        || lower.contains("android")
        || lower.contains("iphone")
        || lower.contains("ipad");

    format!("{browser}|{os}|{}", if is_mobile { "mobile" } else { "desktop" })
}

/// Background login record with GeoIP (auth.ts: fire-and-forget; GeoIP failure
/// still records without geo fields because get_geo_ip_info never errors).
fn spawn_login_record(state: SharedAppState, user_id: i32, ip: String, user_agent: String) {
    tokio::spawn(async move {
        let geo = external::get_geo_ip_info(&ip).await;
        let insert = sqlx::query(
            "INSERT INTO login_records (user_id, ip, country, region, city, isp, timezone, user_agent) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(user_id)
        .bind(&ip)
        .bind(&geo.country)
        .bind(&geo.region)
        .bind(&geo.city)
        .bind(&geo.isp)
        .bind(&geo.timezone)
        .bind(&user_agent)
        .execute(&state.db)
        .await;
        if let Err(err) = insert {
            tracing::warn!("[Login Record] Failed to create login record: {err}");
        }
    });
}

// ===========================================================================
// email verification codes (port of db/email-verification.ts)
// ===========================================================================

const CODE_EXPIRATION_MINUTES: i64 = 10;
const MAX_CODES_PER_HOUR: i64 = 5;
const MAX_VERIFY_FAILURES: i64 = 5;
const VERIFY_FAILURE_KEY_PREFIX: &str = "email-verify-failure:";

fn generate_verification_code() -> String {
    let mut rng = rand::thread_rng();
    rng.gen_range(100000..=999999).to_string()
}

/// Port of createVerificationCode: None == rate limited (5 codes/hour/email).
async fn create_verification_code(
    state: &SharedAppState,
    email: &str,
) -> Result<Option<(String, DateTime<Utc>)>, ApiError> {
    let normalized = email.to_lowercase().trim().to_string();

    let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
    let (recent_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM email_verification_codes WHERE email = $1 AND created_at >= $2",
    )
    .bind(&normalized)
    .bind(one_hour_ago)
    .fetch_one(&state.db)
    .await?;
    if recent_count >= MAX_CODES_PER_HOUR {
        return Ok(None);
    }

    sqlx::query("DELETE FROM email_verification_codes WHERE email = $1")
        .bind(&normalized)
        .execute(&state.db)
        .await?;

    let code = generate_verification_code();
    let expires_at = Utc::now() + chrono::Duration::minutes(CODE_EXPIRATION_MINUTES);
    sqlx::query(
        "INSERT INTO email_verification_codes (email, code, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&normalized)
    .bind(&code)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    Ok(Some((code, expires_at)))
}

/// Port of verifyCode: atomic match-and-consume via DELETE; the per-email
/// failure counter lives in the shared store and invalidates all codes for the
/// email after MAX_VERIFY_FAILURES (brute-force protection).
async fn verify_code(state: &SharedAppState, email: &str, code: &str) -> Result<bool, ApiError> {
    let normalized = email.to_lowercase().trim().to_string();

    static SIX_DIGITS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d{6}$").expect("valid regex"));
    if code.is_empty() || !SIX_DIGITS.is_match(code) {
        return Ok(false);
    }

    let result = sqlx::query(
        "DELETE FROM email_verification_codes \
         WHERE email = $1 AND code = $2 AND expires_at > now()",
    )
    .bind(&normalized)
    .bind(code)
    .execute(&state.db)
    .await?;

    if result.rows_affected() > 0 {
        state
            .shared
            .del(&format!("{VERIFY_FAILURE_KEY_PREFIX}{normalized}"))
            .await;
        return Ok(true);
    }

    let (count, _) = state
        .shared
        .increment_window(
            &format!("{VERIFY_FAILURE_KEY_PREFIX}{normalized}"),
            Duration::from_secs(60 * 60),
        )
        .await;
    if count >= MAX_VERIFY_FAILURES {
        state
            .shared
            .del(&format!("{VERIFY_FAILURE_KEY_PREFIX}{normalized}"))
            .await;
        let _ = sqlx::query("DELETE FROM email_verification_codes WHERE email = $1")
            .bind(&normalized)
            .execute(&state.db)
            .await;
    }
    Ok(false)
}

// ===========================================================================
// email domain whitelist (port of lib/email-domain.ts)
// ===========================================================================

const DEFAULT_ALLOWED_DOMAINS: &[&str] = &[
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "yahoo.com",
    "zoho.com",
    "proton.me",
    "pm.me",
    "protonmail.com",
    "protonmail.ch",
    "fastmail.com",
    "tuta.com",
    "tutanota.com",
    "tuta.io",
    "keemail.me",
    "posteo.de",
    "posteo.net",
    "disroot.org",
    "riseup.net",
];

struct DomainValidation {
    valid: bool,
    domain: Option<String>,
}

async fn validate_email_domain(
    state: &SharedAppState,
    email: &str,
) -> Result<DomainValidation, ApiError> {
    let whitelist_enabled =
        get_system_config_boolean(state, "email_domain_whitelist_enabled", false).await?;
    if !whitelist_enabled {
        return Ok(DomainValidation {
            valid: true,
            domain: None,
        });
    }

    let Some(domain) = extract_email_domain(email) else {
        return Ok(DomainValidation {
            valid: false,
            domain: None,
        });
    };

    let allowed: Vec<String> = match get_system_config(state, "email_allowed_domains").await? {
        Some(domains) if !domains.is_empty() => domains
            .split(',')
            .map(|d| d.trim().to_lowercase())
            .filter(|d| !d.is_empty())
            .collect(),
        _ => DEFAULT_ALLOWED_DOMAINS.iter().map(|s| s.to_string()).collect(),
    };

    Ok(DomainValidation {
        valid: allowed.iter().any(|d| d == &domain),
        domain: Some(domain),
    })
}

fn extract_email_domain(email: &str) -> Option<String> {
    let at = email.rfind('@')?;
    if at == email.len() - 1 {
        return None;
    }
    Some(email[at + 1..].to_lowercase())
}

// ===========================================================================
// 2FA helpers (lib/security.ts generate2FASecret / verify2FAToken /
// generateRecoveryCodes via libs::crypto) + misc generators
// ===========================================================================

/// lib/security.ts generateRecoveryCodes: count codes of XXXX-XXXX over A-Z0-9.
fn generate_recovery_codes(count: usize) -> Vec<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let mut segment = || -> String {
        (0..4)
            .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
            .collect()
    };
    (0..count)
        .map(|_| format!("{}-{}", segment(), segment()))
        .collect()
}

/// lib/incus-config-container.ts generateRandomPassword(16).
fn generate_random_password(length: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// nanoid(12) with nanoid's default URL-safe alphabet.
fn nanoid_12() -> String {
    const ALPHABET: &[u8] = b"useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";
    let mut rng = rand::thread_rng();
    (0..12)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

/// decryptSensitiveData throws on tamper (P2-16 fail closed) => 500.
fn decrypt_2fa_secret(state: &SharedAppState, encrypted: &str) -> Result<String, ApiError> {
    crypto::decrypt_sensitive_data(&state.config.encryption_key, encrypted)
        .map_err(|_| ApiError::internal("sensitive data decryption failed"))
}

/// Single-use recovery-code consumption inside a SELECT FOR UPDATE
/// transaction (auth.ts recovery branch). Ok(None) == not consumed.
async fn consume_recovery_code(
    state: &SharedAppState,
    user_id: i32,
    recovery_code: &str,
) -> Result<Option<usize>, ApiError> {
    let mut tx = state.db.begin().await?;

    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT two_factor_recovery_codes FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(encrypted) = row.and_then(|(v,)| v) else {
        return Ok(None);
    };

    let plain = decrypt_2fa_secret(state, &encrypted)?;
    // JSON.parse failures inside the TS try block return null.
    let Ok(mut codes) = serde_json::from_str::<Vec<String>>(&plain) else {
        return Ok(None);
    };

    let target = recovery_code.trim().to_uppercase();
    let Some(index) = codes.iter().position(|c| *c == target) else {
        return Ok(None);
    };
    codes.remove(index);
    let remaining = codes.len();

    let re_encrypted = crypto::encrypt_sensitive_data(
        &state.config.encryption_key,
        &serde_json::to_string(&codes).unwrap_or_else(|_| "[]".to_string()),
    );
    sqlx::query("UPDATE users SET two_factor_recovery_codes = $2 WHERE id = $1")
        .bind(user_id)
        .bind(&re_encrypted)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(Some(remaining))
}

// ===========================================================================
// operation verification (port of the lib/operation-verification.ts pieces used
// by POST /2fa/disable)
// ===========================================================================

async fn is_operation_verified(
    state: &SharedAppState,
    user_id: i32,
    operation_type: &str,
) -> Result<bool, ApiError> {
    let ten_minutes_ago = Utc::now() - chrono::Duration::minutes(10);
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM operation_verifications \
         WHERE user_id = $1 AND operation_type = $2::\"OperationType\" AND resource_id IS NULL \
           AND verified = true AND verified_at > $3 \
         LIMIT 1",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(ten_minutes_ago)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.is_some())
}

/// Atomic claim (claimOperationVerification): deletes one verified record
/// within the window; concurrent requests cannot both succeed.
async fn claim_operation_verification(
    state: &SharedAppState,
    user_id: i32,
    operation_type: &str,
) -> Result<bool, ApiError> {
    let ten_minutes_ago = Utc::now() - chrono::Duration::minutes(10);
    let result = sqlx::query(
        "DELETE FROM operation_verifications \
         WHERE id = ( \
             SELECT id FROM operation_verifications \
             WHERE user_id = $1 AND operation_type = $2::\"OperationType\" AND resource_id IS NULL \
               AND verified = true AND verified_at > $3 \
             ORDER BY verified_at ASC LIMIT 1 \
         ) AND verified = true AND verified_at > $3",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(ten_minutes_ago)
    .execute(&state.db)
    .await?;
    Ok(result.rows_affected() == 1)
}

fn verification_required_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "Sensitive operation requires verification",
            "code": "VERIFICATION_REQUIRED",
            "operationType": "disable_2fa",
        })),
    )
        .into_response()
}

/// clearAuthCache (plugins/auth-decorators.ts): the Rust JWT extractor does not
/// populate these keys yet, but deleting them keeps shared state consistent
/// when a TS replica shares the same Redis.
async fn clear_auth_cache(state: &SharedAppState, user_id: i32) {
    state
        .shared
        .del(&format!("auth-cache:user:{user_id}"))
        .await;
    state
        .shared
        .del_prefix(&format!("auth-cache:tinv:{user_id}:"))
        .await;
}

// ===========================================================================
// registration support (db/users.ts AVATAR_STYLES / createRegisteredUser,
// lib/registration-role.ts)
// ===========================================================================

const AVATAR_STYLES: &[&str] = &[
    "adventurer",
    "adventurerNeutral",
    "avataaars",
    "avataaarsNeutral",
    "bigEars",
    "bigEarsNeutral",
    "bigSmile",
    "bottts",
    "botttsNeutral",
    "croodles",
    "croodlesNeutral",
    "dylan",
    "funEmoji",
    "glass",
    "icons",
    "identicon",
    "initials",
    "lorelei",
    "loreleiNeutral",
    "micah",
    "miniavs",
    "notionists",
    "notionistsNeutral",
    "openPeeps",
    "personas",
    "pixelArt",
    "pixelArtNeutral",
    "rings",
    "shapes",
    "thumbs",
];

fn random_avatar_style() -> &'static str {
    let mut rng = rand::thread_rng();
    AVATAR_STYLES[rng.gen_range(0..AVATAR_STYLES.len())]
}

/// lib/registration-role.ts parseAdminRegistrationEmailSuffixes.
fn parse_admin_registration_email_suffixes(value: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in value.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let item = item.trim().to_lowercase();
        if item.len() <= 1 || item[1..].contains('@') {
            continue;
        }
        let suffix = if item.starts_with('@') {
            item
        } else {
            format!("@{item}")
        };
        if seen.insert(suffix.clone()) {
            out.push(suffix);
        }
    }
    out
}

/// lib/registration-role.ts resolveRegistrationRole.
fn resolve_registration_role(
    email: Option<&str>,
    admin_registration_emails: Option<&str>,
    email_verified: bool,
) -> &'static str {
    let (Some(email), true, Some(configured)) = (email, email_verified, admin_registration_emails)
    else {
        return "user";
    };
    let normalized = email.trim().to_lowercase();
    if parse_admin_registration_email_suffixes(configured)
        .iter()
        .any(|suffix| normalized.ends_with(suffix.as_str()))
    {
        "admin"
    } else {
        "user"
    }
}

#[derive(Debug, FromRow)]
struct InviteCodeRow {
    id: i32,
    code: String,
    created_by: i32,
    used_by: Option<i32>,
    used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    cost_snapshot: Option<Value>,
    created_at: DateTime<Utc>,
    #[sqlx(default)]
    created_by_username: Option<String>,
    #[sqlx(default)]
    created_by_email: Option<String>,
    #[sqlx(default)]
    created_by_avatar_style: Option<String>,
    #[sqlx(default)]
    used_by_username: Option<String>,
    #[sqlx(default)]
    used_by_email: Option<String>,
    #[sqlx(default)]
    used_by_avatar_style: Option<String>,
}

async fn find_invite_code(
    state: &SharedAppState,
    code: &str,
) -> Result<Option<InviteCodeRow>, ApiError> {
    let row = sqlx::query_as::<_, InviteCodeRow>(
        "SELECT id, code, created_by, used_by, used_at, expires_at, cost_snapshot, created_at \
         FROM invite_codes WHERE code = $1 AND used_by IS NULL LIMIT 1",
    )
    .bind(code)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

async fn get_invite_code_by_id(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<InviteCodeRow>, ApiError> {
    let row = sqlx::query_as::<_, InviteCodeRow>(
        "SELECT id, code, created_by, used_by, used_at, expires_at, cost_snapshot, created_at \
         FROM invite_codes WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

// ---------------------------------------------------------------------------
// registration transaction (db/users.ts createRegisteredUser)
// ---------------------------------------------------------------------------

const MAX_REGISTER_GIFT_BALANCE: f64 = 999_999_999.99;
const MAX_REGISTER_GIFT_POINTS: i64 = 2_147_483_647;

struct RegisterContext {
    default_quota_host: i32,
    default_quota_friend: i32,
    default_quota_package: i32,
    gift_config: Option<GiftConfig>,
    admin_registration_emails: Option<String>,
}

struct GiftConfig {
    balance_amount: Decimal,
    points_amount: i64,
}

enum RegisterTxError {
    InviteUnavailable,
    UniqueViolation,
    Sql(sqlx::Error),
}

impl From<sqlx::Error> for RegisterTxError {
    fn from(err: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &err {
            // Unique violations (the (LOWER(email)) partial unique index, P2-10,
            // and others) surface as Prisma P2002 in TS.
            if db.code().map(|c| c.into_owned()).as_deref() == Some("23505") {
                return RegisterTxError::UniqueViolation;
            }
        }
        RegisterTxError::Sql(err)
    }
}

/// db/users.ts getFreeSiteRegisterGiftConfig.
async fn get_free_site_register_gift_config(
    state: &SharedAppState,
) -> Result<Option<GiftConfig>, ApiError> {
    let free_site_mode = get_system_config_boolean(state, "free_site_mode", false).await?;
    let gift_enabled =
        get_system_config_boolean(state, "free_site_register_gift_enabled", false).await?;
    if !free_site_mode || !gift_enabled {
        return Ok(None);
    }

    let raw_balance = get_system_config_float(state, "free_site_register_gift_balance", 0.0).await?;
    let raw_points = get_system_config_number(state, "free_site_register_gift_points", 0).await?;

    let balance = (raw_balance * 100.0).round() / 100.0;
    let balance = balance.clamp(0.0, MAX_REGISTER_GIFT_BALANCE);
    // raw_points is already an integer (getSystemConfigNumber); TS Math.floor
    // is a no-op there.
    let points = raw_points.clamp(0, MAX_REGISTER_GIFT_POINTS);

    if balance <= 0.0 && points <= 0 {
        return Ok(None);
    }

    Ok(Some(GiftConfig {
        balance_amount: Decimal::from_f64(balance).unwrap_or_default(),
        points_amount: points,
    }))
}

/// db/users.ts buildRegisterGiftMessage (content only is persisted; the
/// summary goes into the stubbed gift email).
fn build_register_gift_message(balance_amount: Decimal, points_amount: i64) -> String {
    let mut parts: Vec<String> = Vec::new();
    if balance_amount > Decimal::ZERO {
        parts.push(format!("余额 ¥{:.2}", balance_amount.to_f64().unwrap_or(0.0)));
    }
    if points_amount > 0 {
        parts.push(format!("{points_amount} 积分"));
    }
    let summary = parts.join(" + ");
    let arrival = if parts.len() > 1 {
        "余额和积分"
    } else {
        parts.first().map(|s| s.as_str()).unwrap_or("白嫖补给")
    };
    format!(
        "欢迎加入白嫖站！系统已经把 {summary} 塞进你的账户背包，{arrival}到账了。快去逛逛能薅点什么，优雅白嫖，从注册成功这一刻开始。"
    )
}

/// Returns (user_id, register_gift) with gift data
/// (balance_amount, points_amount, new_balance, new_points).
async fn create_registered_user(
    state: &SharedAppState,
    username: &str,
    email: &str,
    password_hash: &str,
    invite_code: Option<&str>,
    email_verified: bool,
    ctx: &RegisterContext,
) -> Result<(i32, Option<(Decimal, i64, Decimal, i64)>), RegisterTxError> {
    let role = resolve_registration_role(
        Some(email),
        ctx.admin_registration_emails.as_deref(),
        email_verified,
    );
    let avatar_style = random_avatar_style();

    let mut tx = state.db.begin().await.map_err(RegisterTxError::Sql)?;

    let (user_id,): (i32,) = sqlx::query_as(
        "INSERT INTO users (username, email, password_hash, role, avatar_style) \
         VALUES ($1, $2, $3, $4::\"UserRole\", $5) RETURNING id",
    )
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(role)
    .bind(avatar_style)
    .fetch_one(&mut *tx)
    .await
    .map_err(RegisterTxError::Sql)?;

    sqlx::query(
        "INSERT INTO user_quotas (user_id, host_limit, friend_limit, package_limit) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(ctx.default_quota_host)
    .bind(ctx.default_quota_friend)
    .bind(ctx.default_quota_package)
    .execute(&mut *tx)
    .await
    .map_err(RegisterTxError::Sql)?;

    if let Some(invite_code) = invite_code {
        let update = sqlx::query(
            "UPDATE invite_codes SET used_by = $2, used_at = now() \
             WHERE code = $1 AND used_by IS NULL \
               AND (expires_at IS NULL OR expires_at > now())",
        )
        .bind(invite_code)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(RegisterTxError::Sql)?;
        if update.rows_affected() != 1 {
            return Err(RegisterTxError::InviteUnavailable);
        }
    }

    let mut register_gift: Option<(Decimal, i64, Decimal, i64)> = None;
    if let Some(gift) = &ctx.gift_config {
        let (balance_before,): (Decimal,) =
            sqlx::query_as("SELECT balance FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(RegisterTxError::Sql)?;

        let new_balance;
        let new_points: i64;

        if gift.balance_amount > Decimal::ZERO {
            // Math.round((before + amount) * 100) / 100 — half away from zero.
            let balance_after = ((balance_before + gift.balance_amount)
                * Decimal::from(100))
            .round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
                / Decimal::from(100);
            sqlx::query("UPDATE users SET balance = $2 WHERE id = $1")
                .bind(user_id)
                .bind(balance_after)
                .execute(&mut *tx)
                .await
                .map_err(RegisterTxError::Sql)?;
            sqlx::query(
                "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, remark) \
                 VALUES ($1, 'gift'::\"BalanceLogType\", $2, $3, $4, $5)",
            )
            .bind(user_id)
            .bind(gift.balance_amount)
            .bind(balance_before)
            .bind(balance_after)
            .bind("白嫖站注册自动赠送：白嫖启动资金")
            .execute(&mut *tx)
            .await
            .map_err(RegisterTxError::Sql)?;
            new_balance = balance_after;
        } else {
            new_balance = balance_before;
        }

        if gift.points_amount > 0 {
            sqlx::query(
                "INSERT INTO user_points (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(RegisterTxError::Sql)?;
            let (points_before,): (i32,) =
                sqlx::query_as("SELECT points FROM user_points WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(RegisterTxError::Sql)?;
            let (points_after,): (i32,) = sqlx::query_as(
                "UPDATE user_points \
                 SET points = points + $2, total_earned = total_earned + $2 \
                 WHERE user_id = $1 RETURNING points",
            )
            .bind(user_id)
            .bind(gift.points_amount as i32)
            .fetch_one(&mut *tx)
            .await
            .map_err(RegisterTxError::Sql)?;
            sqlx::query(
                "INSERT INTO points_logs (user_id, type, points_before, points_after, remark) \
                 VALUES ($1, 'admin_adjust'::\"PointsLogType\", $2, $3, $4)",
            )
            .bind(user_id)
            .bind(points_before)
            .bind(points_after)
            .bind("白嫖站注册自动赠送：白嫖能量包")
            .execute(&mut *tx)
            .await
            .map_err(RegisterTxError::Sql)?;
            new_points = points_after as i64;
        } else {
            let existing: Option<(i32,)> =
                sqlx::query_as("SELECT points FROM user_points WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(RegisterTxError::Sql)?;
            new_points = existing.map(|(p,)| p as i64).unwrap_or(0);
        }

        let content = build_register_gift_message(gift.balance_amount, gift.points_amount);
        sqlx::query(
            "INSERT INTO inbox_messages (user_id, event_type, title, content, data) \
             VALUES ($1, 'free_site_register_gift', $2, $3, $4)",
        )
        .bind(user_id)
        .bind("白嫖补给到账啦")
        .bind(&content)
        .bind(json!({
            "balanceAmount": num(gift.balance_amount),
            "pointsAmount": gift.points_amount,
            "newBalance": num(new_balance),
            "newPoints": new_points,
        }))
        .execute(&mut *tx)
        .await
        .map_err(RegisterTxError::Sql)?;

        register_gift = Some((gift.balance_amount, gift.points_amount, new_balance, new_points));
    }

    tx.commit().await.map_err(RegisterTxError::Sql)?;
    Ok((user_id, register_gift))
}

// ===========================================================================
// POST /login (支持 2FA)
// ===========================================================================

struct LoginBody {
    username: String,
    password: String,
    totp_code: Option<String>,
    recovery_code: Option<String>,
    turnstile_token: Option<String>,
}

/// Body schema for /login (Fastify 5 does not validate `format` by default;
/// required/type/length rules reproduced in ajv evaluation order).
fn parse_login_body(body: &Value) -> Result<LoginBody, Response> {
    if body.get("username").is_none() {
        return Err(required_error("username"));
    }
    if body.get("password").is_none() {
        return Err(required_error("password"));
    }
    let username = require_string(body, "username")?;
    let password = require_string(body, "password")?;
    let totp_code = optional_string(body, "totpCode")?;
    let recovery_code = optional_string(body, "recoveryCode")?;
    let turnstile_token = optional_string(body, "turnstileToken")?;

    check_len("username", &username, Some(3), Some(254))?;
    check_len("password", &password, Some(6), Some(128))?;
    if let Some(code) = &totp_code {
        check_len("totpCode", code, Some(6), Some(6))?;
    }
    if let Some(code) = &recovery_code {
        check_len("recoveryCode", code, Some(8), Some(20))?;
    }

    Ok(LoginBody {
        username,
        password,
        totp_code,
        recovery_code,
        turnstile_token,
    })
}

async fn login(
    State(state): State<SharedAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let client_ip = client_ip_string(&headers, peer);
    let user_agent = request_user_agent(&headers);

    let Some(Json(body)) = body else {
        return Ok(must_be_object());
    };
    if !body.is_object() {
        return Ok(must_be_object());
    }
    let parsed = match parse_login_body(&body) {
        Ok(b) => b,
        Err(resp) => return Ok(resp),
    };

    // preHandler: turnstileVerifier (runs after body validation, like Fastify).
    if let Err(resp) = verify_turnstile(
        &state,
        parsed.turnstile_token.as_deref(),
        &query,
        &headers,
        &client_ip,
    )
    .await
    {
        return Ok(resp);
    }

    let user = find_user_by_username_or_email(&state.db, &parsed.username).await?;

    // Lock check keyed by user id when known, else lowercased identifier.
    let lock_identifier = match &user {
        Some(u) => format!("user:{}", u.id),
        None => parsed.username.to_lowercase().trim().to_string(),
    };
    if let Some(retry_after) = check_login_lock(&state, &client_ip, &lock_identifier) {
        log_security_event(
            &state,
            security_event::RATE_LIMIT_EXCEEDED,
            user.as_ref().map(|u| u.id),
            SecurityDetails {
                ip: Some(&client_ip),
                username: Some(
                    user.as_ref()
                        .map(|u| u.username.as_str())
                        .unwrap_or(&parsed.username),
                ),
                reason: Some("Account locked due to too many failed attempts"),
                action: Some("login"),
            },
        )
        .await;
        let minutes = retry_after.div_ceil(60);
        return Err(ApiError::new(code::TOO_MANY_ATTEMPTS, StatusCode::TOO_MANY_REQUESTS)
            .with_details(format!("{minutes} minutes")));
    }

    let Some(user) = user else {
        // TS records the RAW username key here (not lowercased/trimmed).
        record_login_failure(&state, &client_ip, &parsed.username);
        log_security_event(
            &state,
            security_event::LOGIN_FAILED,
            None,
            SecurityDetails {
                ip: Some(&client_ip),
                username: Some(&parsed.username),
                reason: Some("User not found"),
                action: None,
            },
        )
        .await;
        return Err(ApiError::unauthorized_code(code::INVALID_CREDENTIALS));
    };

    if user.status == "banned" {
        log_security_event(
            &state,
            security_event::LOGIN_FAILED,
            Some(user.id),
            SecurityDetails {
                ip: Some(&client_ip),
                username: Some(&parsed.username),
                reason: Some("Account banned"),
                action: None,
            },
        )
        .await;
        return Err(match user.ban_reason.as_deref().filter(|r| !r.is_empty()) {
            Some(reason) => {
                ApiError::with_message(code::ACCOUNT_BANNED, StatusCode::FORBIDDEN, reason)
            }
            None => ApiError::new(code::ACCOUNT_BANNED, StatusCode::FORBIDDEN),
        });
    }

    let valid_password = bcrypt::verify(&parsed.password, &user.password_hash)
        .map_err(|e| ApiError::internal(format!("bcrypt compare failed: {e}")))?;
    if !valid_password {
        record_login_failure(&state, &client_ip, &format!("user:{}", user.id));
        log_security_event(
            &state,
            security_event::LOGIN_FAILED,
            Some(user.id),
            SecurityDetails {
                ip: Some(&client_ip),
                username: Some(&user.username),
                reason: Some("Invalid password"),
                action: None,
            },
        )
        .await;
        return Err(ApiError::unauthorized_code(code::INVALID_CREDENTIALS));
    }

    // 2FA check (codes sent by non-2FA users are ignored, like TS).
    if user.two_factor_enabled {
        if parsed.totp_code.is_none() && parsed.recovery_code.is_none() {
            record_login_failure(&state, &client_ip, &format!("user:{}", user.id));
            log_security_event(
                &state,
                security_event::LOGIN_FAILED,
                Some(user.id),
                SecurityDetails {
                    ip: Some(&client_ip),
                    username: Some(&user.username),
                    reason: Some("2FA required but not provided"),
                    action: None,
                },
            )
            .await;
            return Err(ApiError::unauthorized_code(code::TWO_FA_REQUIRED));
        }

        let mut verified = false;

        // TOTP first.
        if let Some(totp_code) = &parsed.totp_code {
            if let Some(encrypted_secret) = &user.two_factor_secret {
                let secret = decrypt_2fa_secret(&state, encrypted_secret)?;
                if crypto::verify_totp(&secret, totp_code) {
                    verified = true;
                }
            }
        }

        // Recovery code fallback (single use, row locked against concurrent
        // logins reusing the same code).
        if !verified {
            if let Some(recovery_code) = &parsed.recovery_code {
                if let Some(remaining) =
                    consume_recovery_code(&state, user.id, recovery_code).await?
                {
                    verified = true;
                    log_security_event(
                        &state,
                        security_event::LOGIN_SUCCESS,
                        Some(user.id),
                        SecurityDetails {
                            ip: Some(&client_ip),
                            username: Some(&parsed.username),
                            reason: Some(&format!("Used recovery code, {remaining} remaining")),
                            action: None,
                        },
                    )
                    .await;
                }
            }
        }

        if !verified {
            record_login_failure(&state, &client_ip, &format!("user:{}", user.id));
            log_security_event(
                &state,
                security_event::LOGIN_FAILED,
                Some(user.id),
                SecurityDetails {
                    ip: Some(&client_ip),
                    username: Some(&user.username),
                    reason: Some("Invalid 2FA code or recovery code"),
                    action: None,
                },
            )
            .await;
            return Err(ApiError::unauthorized_code(code::INVALID_2FA_CODE));
        }
    }

    clear_login_failure(&state, &client_ip, &format!("user:{}", user.id));

    // Detect new location BEFORE creating the new session (TS timing fix).
    let login_alert_info = if user.email.is_some() {
        Some(detect_new_login_location(&state, user.id, &client_ip, &user_agent).await)
    } else {
        None
    };

    let refresh_token = generate_refresh_token();
    let mut conn = state.db.acquire().await?;
    create_refresh_token(
        &mut conn,
        &refresh_token,
        user.id,
        &user.username,
        &user.role,
        Some(&client_ip),
        Some(&user_agent),
    )
    .await?;
    drop(conn);

    // sid = first 20 chars of the refresh token.
    let session_id = &refresh_token[..refresh_token.len().min(20)];
    let access_token = sign_access_token(&state, user.id, &user.username, &user.role, session_id)?;

    log_security_event(
        &state,
        security_event::LOGIN_SUCCESS,
        Some(user.id),
        SecurityDetails {
            ip: Some(&client_ip),
            username: Some(&parsed.username),
            reason: None,
            action: None,
        },
    )
    .await;

    // Async login record (GeoIP + insert) — fire and forget.
    spawn_login_record(state.clone(), user.id, client_ip.clone(), user_agent.clone());

    // New IP / new device alert (stub email + inbox message, fire and forget).
    if let (Some(email), Some((is_new_ip, is_new_device))) = (user.email.clone(), login_alert_info)
    {
        if is_new_ip || is_new_device {
            let alert_state = state.clone();
            let alert_email = email.clone();
            let alert_username = user.username.clone();
            let alert_ua = user_agent.clone();
            let alert_ip = client_ip.clone();
            tokio::spawn(async move {
                let _ = external::send_login_alert_email(
                    &alert_email,
                    &alert_username,
                    &alert_ip,
                    &alert_ua,
                    is_new_ip,
                    is_new_device,
                )
                .await;

                let login_time = iso(Utc::now());
                send_notification_inbox(
                    &alert_state,
                    user.id,
                    "login_new_device",
                    "🔐 新设备登录提醒",
                    &format!(
                        "您的账户在新设备上登录\n设备: {alert_ua}\nIP: {alert_ip}\n时间: {login_time}\n如非本人操作，请立即修改密码"
                    ),
                    json!({
                        "instanceName": "",
                        "deviceInfo": alert_ua,
                        "ipAddress": alert_ip,
                        "loginTime": login_time,
                    }),
                )
                .await;
            });
        }
    }

    let user_payload = build_auth_user_payload(&state, &user).await?;
    let response = (
        StatusCode::OK,
        Json(json!({
            "token": access_token,
            "user": user_payload,
        })),
    )
        .into_response();
    Ok(with_set_cookie(
        response,
        &state.config.refresh_token_cookie(&refresh_token),
    ))
}

// ===========================================================================
// POST /send-verification-code
// ===========================================================================

async fn send_verification_code(
    State(state): State<SharedAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let client_ip = client_ip_string(&headers, peer);

    let Some(Json(body)) = body.filter(|b| b.is_object()) else {
        return Ok(must_be_object());
    };
    if body.get("email").is_none() {
        return Ok(required_error("email"));
    }
    let email = match require_string(&body, "email") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let turnstile_token = match optional_string(&body, "turnstileToken") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    // preHandler: strictTurnstileVerifier
    if let Err(resp) = verify_strict_turnstile(
        &state,
        turnstile_token.as_deref(),
        &query,
        &headers,
        &client_ip,
    )
    .await
    {
        return Ok(resp);
    }

    ensure_registration_enabled(&state).await?;

    if !is_smtp_enabled(&state).await? {
        return Err(ApiError::bad_request(code::EMAIL_VERIFICATION_DISABLED));
    }

    if email.is_empty() || !email.contains('@') {
        return Err(ApiError::bad_request(code::INVALID_EMAIL));
    }

    let email_without_allowed = email.replace('@', "").replace('.', "");
    if contains_dangerous_chars(&email_without_allowed) {
        return Err(ApiError::bad_request(code::EMAIL_CONTAINS_ILLEGAL));
    }

    if find_user_by_email(&state.db, &email).await?.is_some() {
        return Err(ApiError::bad_request(code::EMAIL_ALREADY_REGISTERED));
    }

    let domain_validation = validate_email_domain(&state, &email).await?;
    if !domain_validation.valid {
        let mut err = ApiError::bad_request(code::EMAIL_DOMAIN_NOT_ALLOWED);
        if let Some(domain) = domain_validation.domain {
            err = err.with_details(domain);
        }
        return Err(err);
    }

    let Some((code, expires_at)) = create_verification_code(&state, &email).await? else {
        return Err(ApiError::new(
            code::TOO_MANY_VERIFICATION_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
        ));
    };

    // Email delivery stub (TODO libs/external.rs / server/src/lib/mailer.ts:559).
    external::send_verification_email(&email, &code, CODE_EXPIRATION_MINUTES, "register").await;

    Ok(Json(json!({
        "message": "Verification code sent",
        "expiresAt": iso(expires_at),
    }))
    .into_response())
}

// ===========================================================================
// POST /register
// ===========================================================================

static REGISTER_USERNAME_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z][a-zA-Z0-9_-]*$").expect("valid regex"));

struct RegisterBody {
    username: String,
    password: String,
    email: String,
    invite_code: Option<String>,
    turnstile_token: Option<String>,
    email_code: Option<String>,
}

fn parse_register_body(body: &Value) -> Result<RegisterBody, Response> {
    for field in ["username", "password", "email"] {
        if body.get(field).is_none() {
            return Err(required_error(field));
        }
    }
    let username = require_string(body, "username")?;
    let password = require_string(body, "password")?;
    let email = require_string(body, "email")?;
    let invite_code = optional_string(body, "inviteCode")?;
    let turnstile_token = optional_string(body, "turnstileToken")?;
    let email_code = optional_string(body, "emailCode")?;

    check_len("username", &username, Some(3), Some(32))?;
    if !REGISTER_USERNAME_PATTERN.is_match(&username) {
        return Err(validation_error(
            "Username must start with a letter and contain only letters, numbers, underscores, and hyphens"
                .to_string(),
        ));
    }
    check_len("password", &password, Some(8), Some(128))?;
    if let Some(code) = &email_code {
        check_len("emailCode", code, Some(6), Some(6))?;
    }

    Ok(RegisterBody {
        username,
        password,
        email,
        invite_code,
        turnstile_token,
        email_code,
    })
}

async fn register(
    State(state): State<SharedAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let client_ip = client_ip_string(&headers, peer);
    let user_agent = request_user_agent(&headers);

    let Some(Json(body)) = body.filter(|b| b.is_object()) else {
        return Ok(must_be_object());
    };
    let parsed = match parse_register_body(&body) {
        Ok(b) => b,
        Err(resp) => return Ok(resp),
    };

    ensure_registration_enabled(&state).await?;

    let smtp_enabled = is_smtp_enabled(&state).await?;

    // shouldVerifyTurnstileForRegister(smtpEnabled): strict verifier only when
    // email verification is off (lib/register-turnstile.ts).
    if !smtp_enabled {
        if let Err(resp) = verify_strict_turnstile(
            &state,
            parsed.turnstile_token.as_deref(),
            &query,
            &headers,
            &client_ip,
        )
        .await
        {
            return Ok(resp);
        }
    }

    // Username validation (bare { error } on failure, like TS).
    let username_validation = validate_identifier(&parsed.username, "Username", 3, 32);
    if !username_validation.valid {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": username_validation
                    .message
                    .unwrap_or_else(|| "Invalid username".to_string()),
            })),
        )
            .into_response());
    }

    if contains_dangerous_chars(&parsed.username) {
        return Err(ApiError::bad_request(code::USERNAME_CONTAINS_ILLEGAL));
    }

    let password_check = validate_password(&parsed.password);
    if !password_check.valid {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": password_check
                    .message
                    .unwrap_or_else(|| "Password is too weak".to_string()),
            })),
        )
            .into_response());
    }

    if parsed.email.is_empty() || !parsed.email.contains('@') {
        return Err(ApiError::bad_request(code::INVALID_EMAIL));
    }

    let email_without_allowed = parsed.email.replace('@', "").replace('.', "");
    if contains_dangerous_chars(&email_without_allowed) {
        return Err(ApiError::bad_request(code::EMAIL_CONTAINS_ILLEGAL));
    }

    let domain_validation = validate_email_domain(&state, &parsed.email).await?;
    if !domain_validation.valid {
        let mut err = ApiError::bad_request(code::EMAIL_DOMAIN_NOT_ALLOWED);
        if let Some(domain) = domain_validation.domain {
            err = err.with_details(domain);
        }
        return Err(err);
    }

    // Email verification code when SMTP is on.
    if smtp_enabled {
        let Some(email_code) = &parsed.email_code else {
            return Err(ApiError::bad_request(code::EMAIL_CODE_REQUIRED));
        };
        if !verify_code(&state, &parsed.email, email_code).await? {
            return Err(ApiError::bad_request(code::INVALID_EMAIL_CODE));
        }
    }

    // Invite code (required depends on require_invite_code, default true).
    let require_invite = is_invite_code_required(&state).await?;
    let mut invite_found = false;
    if require_invite {
        let Some(invite_code) = &parsed.invite_code else {
            return Err(ApiError::bad_request(code::INVALID_INVITE_CODE));
        };
        let found = find_invite_code(&state, invite_code).await?;
        let Some(found) = found else {
            log_security_event(
                &state,
                security_event::SUSPICIOUS_ACTIVITY,
                None,
                SecurityDetails {
                    ip: Some(&client_ip),
                    username: Some(&parsed.username),
                    reason: Some("Invalid invite code"),
                    action: Some("register"),
                },
            )
            .await;
            return Err(ApiError::bad_request(code::INVALID_INVITE_CODE));
        };
        if found
            .expires_at
            .map(|expires| expires < Utc::now())
            .unwrap_or(false)
        {
            return Err(ApiError::bad_request(code::INVITE_CODE_EXPIRED));
        }
        invite_found = true;
    }

    if find_user_by_username(&state.db, &parsed.username)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request(code::USER_EXISTS));
    }

    if find_user_by_email(&state.db, &parsed.email).await?.is_some() {
        return Err(ApiError::bad_request(code::EMAIL_ALREADY_REGISTERED));
    }

    let password_hash = bcrypt::hash(&parsed.password, 12)
        .map_err(|e| ApiError::internal(format!("bcrypt hash failed: {e}")))?;

    let normalized_email = parsed.email.to_lowercase().trim().to_string();

    let ctx = RegisterContext {
        default_quota_host: get_system_config_number(&state, "default_quota_host", 0).await? as i32,
        default_quota_friend: get_system_config_number(&state, "default_quota_friend", 0).await?
            as i32,
        default_quota_package: get_system_config_number(&state, "default_quota_package", 0).await?
            as i32,
        gift_config: get_free_site_register_gift_config(&state).await?,
        admin_registration_emails: get_system_config(&state, "admin_registration_emails").await?,
    };

    let (user_id, register_gift) = match create_registered_user(
        &state,
        &parsed.username,
        &normalized_email,
        &password_hash,
        if invite_found { parsed.invite_code.as_deref() } else { None },
        smtp_enabled,
        &ctx,
    )
    .await
    {
        Ok(result) => result,
        Err(RegisterTxError::InviteUnavailable) => {
            return Err(ApiError::bad_request(code::INVALID_INVITE_CODE));
        }
        Err(RegisterTxError::UniqueViolation) => {
            return Err(ApiError::bad_request(code::EMAIL_ALREADY_REGISTERED));
        }
        Err(RegisterTxError::Sql(err)) => return Err(ApiError::from_sql(err)),
    };

    log_security_event(
        &state,
        security_event::REGISTER_SUCCESS,
        Some(user_id),
        SecurityDetails {
            ip: Some(&client_ip),
            username: Some(&parsed.username),
            reason: None,
            action: None,
        },
    )
    .await;

    let Some(new_user) = find_user_by_id(&state.db, user_id).await? else {
        return Err(ApiError::not_found(code::USER_NOT_FOUND));
    };

    if register_gift.is_some() {
        if let Some(email) = &new_user.email {
            // Email stub (TODO libs/external.rs / mailer.ts:1390); non-fatal.
            external::send_free_site_register_gift_email(email, &new_user.username).await;
        }
    }

    let refresh_token = generate_refresh_token();
    let mut conn = state.db.acquire().await?;
    create_refresh_token(
        &mut conn,
        &refresh_token,
        new_user.id,
        &new_user.username,
        &new_user.role,
        Some(&client_ip),
        Some(&user_agent),
    )
    .await?;
    drop(conn);

    let session_id = &refresh_token[..refresh_token.len().min(20)];
    let access_token =
        sign_access_token(&state, new_user.id, &new_user.username, &new_user.role, session_id)?;

    // Async login record (GeoIP + insert) — fire and forget.
    spawn_login_record(state.clone(), new_user.id, client_ip.clone(), user_agent.clone());

    let user_payload = build_auth_user_payload(&state, &new_user).await?;
    let response = (
        StatusCode::CREATED,
        Json(json!({
            "token": access_token,
            "user": user_payload,
        })),
    )
        .into_response();
    Ok(with_set_cookie(
        response,
        &state.config.refresh_token_cookie(&refresh_token),
    ))
}

// ===========================================================================
// GET /me
// ===========================================================================

async fn me(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let Some(found) = find_user_by_id(&state.db, user.id).await? else {
        return Err(ApiError::not_found(code::USER_NOT_FOUND));
    };

    let quota: Option<(i32, i32, i32, i32, i32, i32)> = sqlx::query_as(
        "SELECT host_limit, host_used, friend_limit, friend_used, package_limit, package_used \
         FROM user_quotas WHERE user_id = $1",
    )
    .bind(user.id)
    .fetch_optional(&state.db)
    .await?;

    let mut user_payload = build_auth_user_payload(&state, &found).await?;
    let quota_json = match quota {
        Some((host_limit, host_used, friend_limit, friend_used, package_limit, package_used)) => {
            json!({
                "hostLimit": host_limit,
                "hostUsed": host_used,
                "friendLimit": friend_limit,
                "friendUsed": friend_used,
                "packageLimit": package_limit,
                "packageUsed": package_used,
            })
        }
        None => Value::Null,
    };
    if let Value::Object(map) = &mut user_payload {
        map.insert("quota".to_string(), quota_json);
    }

    Ok(Json(json!({ "user": user_payload })))
}

// ===========================================================================
// POST /logout
// ===========================================================================

async fn logout(
    State(state): State<SharedAppState>,
    user: AuthUser,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let current_session_id = user.sid.clone();
    let refresh_token = get_cookie(&headers, "refreshToken");

    let mut session_ids_to_invalidate: Vec<String> = Vec::new();
    if let Some(rt) = &refresh_token {
        let sid: String = rt.chars().take(20).collect();
        if !session_ids_to_invalidate.contains(&sid) {
            session_ids_to_invalidate.push(sid);
        }
    }
    if let Some(sid) = &current_session_id {
        if !session_ids_to_invalidate.contains(sid) {
            session_ids_to_invalidate.push(sid.clone());
        }
    }

    // Revoke the refresh token; a DB failure must NOT fake a successful logout.
    // rows_affected == 0 (concurrent logout) counts as revoked, mirroring the
    // TS P2025 => true mapping.
    if let Some(rt) = &refresh_token {
        if let Err(err) = revoke_refresh_token(&state.db, rt).await {
            tracing::error!("Logout failed to revoke refresh token: {err}");
            return Err(ApiError::with_message(
                code::LOGOUT_FAILED,
                StatusCode::SERVICE_UNAVAILABLE,
                "Logout temporarily unavailable",
            ));
        }
    }

    for session_id in &session_ids_to_invalidate {
        invalidate_session_access_token(&state.db, user.id, session_id).await?;
        // Port of revokeActionTicketsForSession: the action-ticket subsystem is
        // not ported, so only the session index keys are cleared; any orphaned
        // `action-ticket:{token}` keys expire via their TTL.
        state
            .shared
            .del_prefix(&format!("action-ticket-session:{session_id}:"))
            .await;
        // closeSessionTerminalSessions: terminal proxy not ported — no-op.
    }

    clear_auth_cache(&state, user.id).await;

    log_security_event(
        &state,
        security_event::LOGOUT,
        Some(user.id),
        SecurityDetails {
            ip: None,
            username: Some(&user.username),
            reason: None,
            action: None,
        },
    )
    .await;

    let response = (StatusCode::OK, Json(json!({ "message": "Logged out" }))).into_response();
    Ok(with_set_cookie(
        response,
        &state.config.clear_refresh_token_cookie(),
    ))
}

// ===========================================================================
// POST /refresh
// ===========================================================================

async fn refresh(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let Some(refresh_token) = get_cookie(&headers, "refreshToken") else {
        return Err(ApiError::unauthorized_code(code::REFRESH_TOKEN_MISSING));
    };

    // verifyRefreshToken with one 100ms-delayed retry on DB errors (the TS
    // route retries once). Infrastructure failures keep the existing cookie and
    // map to the catch-all 500 'Internal server error'.
    let token_data = match verify_refresh_token(&state.db, &refresh_token).await {
        Ok(data) => data,
        Err(first_err) => {
            tracing::error!("Refresh token verification error: {first_err}");
            tokio::time::sleep(Duration::from_millis(100)).await;
            match verify_refresh_token(&state.db, &refresh_token).await {
                Ok(data) => data,
                Err(retry_err) => {
                    tracing::error!("Refresh token verification retry failed: {retry_err}");
                    return Err(ApiError::with_message(
                        code::INTERNAL_ERROR,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error",
                    ));
                }
            }
        }
    };

    let Some(token_data) = token_data else {
        let clear_cookie = state.config.clear_refresh_token_cookie();
        return Ok(error_with_cookie(
            ApiError::unauthorized_code(code::REFRESH_TOKEN_INVALID),
            &clear_cookie,
        ));
    };

    // Check user status.
    let user = find_user_by_id(&state.db, token_data.user_id).await?;
    if user.as_ref().map(|u| u.status == "banned").unwrap_or(true) {
        revoke_refresh_token(&state.db, &refresh_token)
            .await
            .map_err(|_| {
                ApiError::with_message(
                    code::INTERNAL_ERROR,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error",
                )
            })?;
        let clear_cookie = state.config.clear_refresh_token_cookie();
        let error = match user.and_then(|u| u.ban_reason.filter(|r| !r.is_empty())) {
            Some(reason) => {
                ApiError::with_message(code::ACCOUNT_BANNED, StatusCode::UNAUTHORIZED, reason)
            }
            None => ApiError::unauthorized_code(code::ACCOUNT_BANNED),
        };
        return Ok(error_with_cookie(error, &clear_cookie));
    }
    let user = user.expect("user checked above");

    let session_id = &refresh_token[..refresh_token.len().min(20)];

    // Slide the expiry forward; a failed update just skips the cookie refresh
    // (TS updateSessionActivity swallows its own errors).
    let session_update = update_session_activity(&state.db, &refresh_token).await.is_ok();

    let new_access_token =
        sign_access_token(&state, user.id, &user.username, &user.role, session_id)?;

    let response = (StatusCode::OK, Json(json!({ "token": new_access_token }))).into_response();
    if session_update {
        return Ok(with_set_cookie(
            response,
            &state.config.refresh_token_cookie(&refresh_token),
        ));
    }
    Ok(response)
}

// ===========================================================================
// POST /invite (admin)
// ===========================================================================

fn parse_integer_field(body: &Value, field: &str) -> Result<Option<i64>, Response> {
    match body.get(field) {
        None => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(Some)
            .ok_or_else(|| validation_error("must be integer".to_string())),
        Some(_) => Err(validation_error("must be integer".to_string())),
    }
}

async fn create_invite(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let Some(Json(body)) = body.filter(|b| b.is_object()) else {
        return Ok(must_be_object());
    };

    let expires_in_days = match parse_integer_field(&body, "expiresInDays") {
        Ok(Some(days)) if days < 1 => return Ok(validation_error("must be >= 1".to_string())),
        Ok(other) => other,
        Err(resp) => return Ok(resp),
    };
    let count = match parse_integer_field(&body, "count") {
        Ok(Some(count)) if count < 1 => return Ok(validation_error("must be >= 1".to_string())),
        Ok(Some(count)) if count > 100 => return Ok(validation_error("must be <= 100".to_string())),
        Ok(other) => other.unwrap_or(1),
        Err(resp) => return Ok(resp),
    };

    // TS: date.setDate(date.getDate() + expiresInDays); an overflow would be a
    // 500 in TS too (Invalid Date => toISOString throws). No expiresInDays =>
    // never expires (null).
    let expires_at: Option<DateTime<Utc>> = match expires_in_days {
        None => None,
        Some(days) => match days
            .checked_mul(24 * 60 * 60 * 1000)
            .and_then(|ms| Utc::now().checked_add_signed(chrono::Duration::milliseconds(ms)))
        {
            Some(at) => Some(at),
            None => return Err(ApiError::internal("expiresAt out of range")),
        },
    };
    let expires_at_json = expires_at.map(iso).map(Value::String).unwrap_or(Value::Null);

    let mut codes: Vec<String> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let code = nanoid_12();
        sqlx::query(
            "INSERT INTO invite_codes (code, created_by, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&code)
        .bind(admin.0.id)
        .bind(expires_at)
        .execute(&state.db)
        .await?;
        codes.push(code);
    }

    if count == 1 {
        let code = codes[0].clone();
        return Ok(Json(json!({
            "code": code,
            "expiresAt": expires_at_json,
            "url": format!("/register/{code}"),
        }))
        .into_response());
    }

    Ok(Json(json!({
        "codes": codes,
        "count": codes.len(),
        "expiresAt": expires_at_json,
    }))
    .into_response())
}

// ===========================================================================
// GET /invites (admin)
// ===========================================================================

async fn list_invites(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let pagination = parse_pagination(&params, 20, Some(100));
    let where_clause = match params.get("status").map(|s| s.as_str()) {
        Some("used") => "WHERE ic.used_by IS NOT NULL",
        Some("unused") => "WHERE ic.used_by IS NULL",
        _ => "",
    };

    let (total,): (i64,) =
        sqlx::query_as(&format!("SELECT COUNT(*) FROM invite_codes ic {where_clause}"))
            .fetch_one(&state.db)
            .await?;

    let invites = sqlx::query_as::<_, InviteCodeRow>(&format!(
        "SELECT ic.id, ic.code, ic.created_by, ic.used_by, ic.used_at, ic.expires_at, \
                ic.cost_snapshot, ic.created_at, \
                cu.username AS created_by_username, cu.email AS created_by_email, \
                cu.avatar_style AS created_by_avatar_style, \
                uu.username AS used_by_username, uu.email AS used_by_email, \
                uu.avatar_style AS used_by_avatar_style \
         FROM invite_codes ic \
         JOIN users cu ON cu.id = ic.created_by \
         LEFT JOIN users uu ON uu.id = ic.used_by \
         {where_clause} \
         ORDER BY ic.id DESC \
         OFFSET $1 LIMIT $2"
    ))
    .bind(pagination.skip)
    .bind(pagination.take)
    .fetch_all(&state.db)
    .await?;

    let items: Vec<Value> = invites
        .iter()
        .map(|i| {
            json!({
                "id": i.id,
                "code": i.code,
                "createdBy": i.created_by,
                // TS maps these through `|| null`, so '' becomes null too.
                "createdByUsername": i.created_by_username.clone().filter(|v| !v.is_empty()),
                "createdByEmail": i.created_by_email.clone().filter(|v| !v.is_empty()),
                "createdByAvatarStyle": i.created_by_avatar_style.clone().filter(|v| !v.is_empty()),
                "usedBy": i.used_by,
                "usedByUsername": i.used_by_username.clone().filter(|v| !v.is_empty()),
                "usedByEmail": i.used_by_email.clone().filter(|v| !v.is_empty()),
                "usedByAvatarStyle": i.used_by_avatar_style.clone().filter(|v| !v.is_empty()),
                "usedAt": iso_opt(i.used_at),
                "expiresAt": iso_opt(i.expires_at),
                "costSnapshot": i.cost_snapshot.clone(),
                "createdAt": iso(i.created_at),
            })
        })
        .collect();

    let total_pages = ((total + pagination.page_size - 1) / pagination.page_size).max(1);

    Ok(Json(json!({
        "invites": items,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
        "totalPages": total_pages,
    })))
}

// ===========================================================================
// DELETE /invites/{id} (admin)
// ===========================================================================

async fn delete_invite(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let invite_id: i32 = id
        .trim()
        .parse()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))?;

    if get_invite_code_by_id(&state, invite_id).await?.is_none() {
        return Err(ApiError::not_found(code::INVITE_CODE_NOT_FOUND));
    }

    sqlx::query("DELETE FROM invite_codes WHERE id = $1")
        .bind(invite_id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "message": "Invite code deleted" })))
}

// ===========================================================================
// 2FA endpoints
// ===========================================================================

async fn two_fa_status(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    // db.getUser2FAStatus => { enabled }
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT two_factor_enabled FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_optional(&state.db)
            .await?;
    let enabled = row.map(|(e,)| e).unwrap_or(false);
    Ok(Json(json!({ "enabled": enabled })))
}

async fn two_fa_setup(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let found = find_user_by_id(&state.db, user.id).await?;
    if found.as_ref().map(|u| u.two_factor_enabled).unwrap_or(false) {
        return Err(ApiError::bad_request(code::TWO_FA_ALREADY_ENABLED));
    }

    // Generate + persist the encrypted secret.
    let secret = crypto::generate_totp_secret();
    let encrypted_secret = crypto::encrypt_sensitive_data(&state.config.encryption_key, &secret);
    sqlx::query("UPDATE users SET two_factor_secret = $2 WHERE id = $1")
        .bind(user.id)
        .bind(&encrypted_secret)
        .execute(&state.db)
        .await?;

    // QR code image generation needs a `qrcode` crate which the shared
    // Cargo.toml does not have (dependency edits are out of scope). The
    // plaintext secret below still enables manual authenticator entry and the
    // frontend hides the <img> when qrCode is empty.
    // TODO: port lib/security.ts generate2FAQRCode
    // (server/src/lib/security.ts:1183: otpauth://totp/Incudal:{username}?secret=...&issuer=Incudal
    // rendered to a PNG data URL).
    let qr_code = "";
    tracing::warn!("2fa/setup: QR code generation unavailable in the Rust server (missing qrcode crate)");

    // Temporary recovery codes (take effect when 2FA is enabled).
    let recovery_codes = generate_recovery_codes(8);
    let encrypted_codes = crypto::encrypt_sensitive_data(
        &state.config.encryption_key,
        &serde_json::to_string(&recovery_codes).unwrap_or_else(|_| "[]".to_string()),
    );
    sqlx::query("UPDATE users SET two_factor_recovery_codes = $2 WHERE id = $1")
        .bind(user.id)
        .bind(&encrypted_codes)
        .execute(&state.db)
        .await?;

    create_log(&state, user.id, "security", "2fa.setup", "Started 2FA setup", "success").await;

    Ok(Json(json!({
        "secret": secret,
        "qrCode": qr_code,
        "recoveryCodes": recovery_codes,
    })))
}

async fn two_fa_enable(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let Some(Json(body)) = body.filter(|b| b.is_object()) else {
        return Ok(must_be_object());
    };
    if body.get("code").is_none() {
        return Ok(required_error("code"));
    }
    let code_value = match require_string(&body, "code") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = check_len("code", &code_value, Some(6), Some(6)) {
        return Ok(resp);
    }

    let encrypted_secret = find_user_by_id(&state.db, user.id)
        .await?
        .and_then(|u| u.two_factor_secret);
    let Some(encrypted_secret) = encrypted_secret else {
        return Err(ApiError::bad_request(code::TWO_FA_NOT_ENABLED));
    };

    let secret = decrypt_2fa_secret(&state, &encrypted_secret)?;
    if !crypto::verify_totp(&secret, &code_value) {
        return Err(ApiError::bad_request(code::INVALID_2FA_CODE));
    }

    sqlx::query("UPDATE users SET two_factor_enabled = TRUE WHERE id = $1")
        .bind(user.id)
        .execute(&state.db)
        .await?;

    create_log(
        &state,
        user.id,
        "security",
        "2fa.enable",
        "Enabled two-factor authentication",
        "success",
    )
    .await;

    send_notification_inbox(
        &state,
        user.id,
        "2fa_enabled",
        "🛡️ 两步验证已启用",
        "您的账户已成功启用两步验证，账户安全性已提升",
        json!({ "instanceName": "" }),
    )
    .await;

    Ok(Json(json!({ "message": "2FA enabled" })).into_response())
}

async fn two_fa_disable(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let Some(Json(body)) = body.filter(|b| b.is_object()) else {
        return Ok(must_be_object());
    };
    if body.get("password").is_none() {
        return Ok(required_error("password"));
    }
    if body.get("code").is_none() {
        return Ok(required_error("code"));
    }
    let password = match require_string(&body, "password") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let code_value = match require_string(&body, "code") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = check_len("code", &code_value, Some(6), Some(6)) {
        return Ok(resp);
    }

    // Sensitive-operation second verification.
    if !is_operation_verified(&state, user.id, "disable_2fa").await? {
        return Ok(verification_required_response());
    }

    let Some(found) = find_user_by_id(&state.db, user.id).await? else {
        return Err(ApiError::not_found(code::USER_NOT_FOUND));
    };

    let valid_password = bcrypt::verify(&password, &found.password_hash)
        .map_err(|e| ApiError::internal(format!("bcrypt compare failed: {e}")))?;
    if !valid_password {
        return Err(ApiError::unauthorized_code(code::INVALID_CREDENTIALS));
    }

    if let Some(encrypted_secret) = &found.two_factor_secret {
        let secret = decrypt_2fa_secret(&state, encrypted_secret)?;
        if !crypto::verify_totp(&secret, &code_value) {
            return Err(ApiError::bad_request(code::INVALID_2FA_CODE));
        }
    }

    // Atomic claim so concurrent requests cannot disable twice.
    if !claim_operation_verification(&state, user.id, "disable_2fa").await? {
        return Ok(verification_required_response());
    }

    // Disable 2FA and clear all 2FA data including recovery codes.
    sqlx::query(
        "UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL, \
         two_factor_recovery_codes = NULL WHERE id = $1",
    )
    .bind(user.id)
    .execute(&state.db)
    .await?;

    create_log(
        &state,
        user.id,
        "security",
        "2fa.disable",
        "Disabled two-factor authentication",
        "success",
    )
    .await;

    send_notification_inbox(
        &state,
        user.id,
        "2fa_disabled",
        "⚠️ 两步验证已禁用",
        "您的账户已禁用两步验证，建议重新启用以提高账户安全性",
        json!({ "instanceName": "" }),
    )
    .await;

    Ok(Json(json!({ "message": "2FA disabled" })).into_response())
}

async fn two_fa_recovery_codes(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let found = find_user_by_id(&state.db, user.id).await?;
    if !found.as_ref().map(|u| u.two_factor_enabled).unwrap_or(false) {
        return Err(ApiError::bad_request(code::TWO_FA_NOT_ENABLED));
    }

    let encrypted_codes = found.and_then(|u| u.two_factor_recovery_codes);
    let Some(encrypted_codes) = encrypted_codes else {
        return Ok(Json(json!({ "total": 8, "remaining": 0, "used": 8 })));
    };

    let decrypted = decrypt_2fa_secret(&state, &encrypted_codes)?;
    match serde_json::from_str::<Vec<String>>(&decrypted) {
        Ok(codes) => Ok(Json(json!({
            "total": 8,
            "remaining": codes.len(),
            "used": 8 - codes.len(),
        }))),
        Err(_) => Ok(Json(json!({ "total": 8, "remaining": 0, "used": 8 }))),
    }
}

async fn two_fa_regenerate_recovery_codes(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let Some(Json(body)) = body.filter(|b| b.is_object()) else {
        return Ok(must_be_object());
    };
    if body.get("password").is_none() {
        return Ok(required_error("password"));
    }
    if body.get("code").is_none() {
        return Ok(required_error("code"));
    }
    let password = match require_string(&body, "password") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let code_value = match require_string(&body, "code") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = check_len("code", &code_value, Some(6), Some(6)) {
        return Ok(resp);
    }

    let found = find_user_by_id(&state.db, user.id).await?;
    if !found.as_ref().map(|u| u.two_factor_enabled).unwrap_or(false) {
        return Err(ApiError::bad_request(code::TWO_FA_NOT_ENABLED));
    }
    let found = found.expect("2FA enabled implies user exists");

    let valid_password = bcrypt::verify(&password, &found.password_hash)
        .map_err(|e| ApiError::internal(format!("bcrypt compare failed: {e}")))?;
    if !valid_password {
        return Err(ApiError::unauthorized_code(code::INVALID_CREDENTIALS));
    }

    if let Some(encrypted_secret) = &found.two_factor_secret {
        let secret = decrypt_2fa_secret(&state, encrypted_secret)?;
        if !crypto::verify_totp(&secret, &code_value) {
            return Err(ApiError::bad_request(code::INVALID_2FA_CODE));
        }
    }

    let recovery_codes = generate_recovery_codes(8);
    let encrypted_codes = crypto::encrypt_sensitive_data(
        &state.config.encryption_key,
        &serde_json::to_string(&recovery_codes).unwrap_or_else(|_| "[]".to_string()),
    );
    sqlx::query("UPDATE users SET two_factor_recovery_codes = $2 WHERE id = $1")
        .bind(user.id)
        .bind(&encrypted_codes)
        .execute(&state.db)
        .await?;

    create_log(
        &state,
        user.id,
        "security",
        "2fa.recovery_reset",
        "Regenerated 2FA recovery codes",
        "success",
    )
    .await;

    Ok(Json(json!({ "recoveryCodes": recovery_codes })).into_response())
}

// ===========================================================================
// POST /forgot-password/send-code
// ===========================================================================

async fn forgot_password_send_code(
    State(state): State<SharedAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let client_ip = client_ip_string(&headers, peer);

    let Some(Json(body)) = body.filter(|b| b.is_object()) else {
        return Ok(must_be_object());
    };
    if body.get("email").is_none() {
        return Ok(required_error("email"));
    }
    let email = match require_string(&body, "email") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let turnstile_token = match optional_string(&body, "turnstileToken") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    // preHandler: turnstileVerifier
    if let Err(resp) = verify_turnstile(
        &state,
        turnstile_token.as_deref(),
        &query,
        &headers,
        &client_ip,
    )
    .await
    {
        return Ok(resp);
    }

    if !is_smtp_enabled(&state).await? {
        return Err(ApiError::bad_request(code::EMAIL_VERIFICATION_DISABLED));
    }

    if email.is_empty() || !email.contains('@') {
        return Err(ApiError::bad_request(code::INVALID_EMAIL));
    }

    let email_without_allowed = email.replace('@', "").replace('.', "");
    if contains_dangerous_chars(&email_without_allowed) {
        return Err(ApiError::bad_request(code::EMAIL_CONTAINS_ILLEGAL));
    }

    // Never reveal whether the email is registered.
    if find_user_by_email(&state.db, &email).await?.is_none() {
        let expires_at = iso(Utc::now() + chrono::Duration::minutes(10));
        return Ok(Json(json!({
            "message": "If the email is registered, a verification code will be sent",
            "expiresAt": expires_at,
        }))
        .into_response());
    }

    let Some((code, expires_at)) = create_verification_code(&state, &email).await? else {
        return Err(ApiError::new(
            code::TOO_MANY_VERIFICATION_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
        ));
    };

    // Email delivery stub (TODO libs/external.rs / mailer.ts:559),
    // purpose: reset_password.
    external::send_verification_email(&email, &code, CODE_EXPIRATION_MINUTES, "reset_password").await;

    Ok(Json(json!({
        "message": "Verification code sent",
        "expiresAt": iso(expires_at),
    }))
    .into_response())
}

// ===========================================================================
// POST /forgot-password/reset
// ===========================================================================

async fn forgot_password_reset(
    State(state): State<SharedAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Result<Response, ApiError> {
    let client_ip = client_ip_string(&headers, peer);

    let Some(Json(body)) = body.filter(|b| b.is_object()) else {
        return Ok(must_be_object());
    };
    if body.get("email").is_none() {
        return Ok(required_error("email"));
    }
    if body.get("code").is_none() {
        return Ok(required_error("code"));
    }
    let email = match require_string(&body, "email") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let code_value = match require_string(&body, "code") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let turnstile_token = match optional_string(&body, "turnstileToken") {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = check_len("code", &code_value, Some(6), Some(6)) {
        return Ok(resp);
    }

    // preHandler: turnstileVerifier
    if let Err(resp) = verify_turnstile(
        &state,
        turnstile_token.as_deref(),
        &query,
        &headers,
        &client_ip,
    )
    .await
    {
        return Ok(resp);
    }

    if !is_smtp_enabled(&state).await? {
        return Err(ApiError::bad_request(code::EMAIL_VERIFICATION_DISABLED));
    }

    if email.is_empty() || !email.contains('@') {
        return Err(ApiError::bad_request(code::INVALID_EMAIL));
    }

    if !verify_code(&state, &email, &code_value).await? {
        // Brute-force protection trail; never reveals user existence.
        log_security_event(
            &state,
            security_event::SUSPICIOUS_ACTIVITY,
            None,
            SecurityDetails {
                ip: Some(&client_ip),
                username: Some(&email),
                reason: Some("Invalid verification code"),
                action: Some("forgot_password_verify_code"),
            },
        )
        .await;
        return Err(ApiError::bad_request(code::INVALID_EMAIL_CODE));
    }

    let Some(user) = find_user_by_email(&state.db, &email).await? else {
        // Code verified but the user vanished (deleted): generic error.
        return Err(ApiError::bad_request(code::INVALID_EMAIL_CODE));
    };

    if user.status == "banned" {
        return Err(match user.ban_reason.as_deref().filter(|r| !r.is_empty()) {
            Some(reason) => {
                ApiError::with_message(code::ACCOUNT_BANNED, StatusCode::FORBIDDEN, reason)
            }
            None => ApiError::new(code::ACCOUNT_BANNED, StatusCode::FORBIDDEN),
        });
    }

    let new_password = generate_random_password(16);
    let password_hash = bcrypt::hash(&new_password, 12)
        .map_err(|e| ApiError::internal(format!("bcrypt hash failed: {e}")))?;

    let is_2fa_enabled = user.two_factor_enabled;

    // Send the new password BEFORE any irreversible state change (P2-15):
    // on delivery failure nothing changes and the old password still works.
    let send_ok = external::send_password_reset_email(
        &email,
        &user.username,
        &new_password,
        is_2fa_enabled,
    )
    .await;
    if !send_ok {
        return Err(ApiError::bad_request(code::EMAIL_SEND_FAILED).with_details(
            "密码重置邮件发送失败，账户密码未变更，请稍后重试",
        ));
    }

    // Atomic password update + revoke all refresh tokens + user-level access
    // token invalidation (lib/security.ts updateUserPasswordAndInvalidateSessions).
    let invalidated_at = Utc::now().timestamp();
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(user.id)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO token_invalidations (user_id, session_id, invalidated_at, created_at) \
         VALUES ($1, $2, $3, now()) \
         ON CONFLICT (user_id, session_id) \
         DO UPDATE SET invalidated_at = EXCLUDED.invalidated_at",
    )
    .bind(user.id)
    .bind(USER_LEVEL_SESSION_ID)
    .bind(invalidated_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let two_factor_disabled = is_2fa_enabled;

    // Clear 2FA after the password change; failures are non-fatal (TS logs).
    if is_2fa_enabled {
        match sqlx::query(
            "UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL, \
             two_factor_recovery_codes = NULL WHERE id = $1",
        )
        .bind(user.id)
        .execute(&state.db)
        .await
        {
            Ok(_) => {
                create_log(
                    &state,
                    user.id,
                    "security",
                    "2fa.disable",
                    "2FA disabled due to password reset",
                    "success",
                )
                .await;
            }
            Err(err) => {
                tracing::error!("Failed to disable 2FA after password reset: {err}");
            }
        }
    }

    // closeUserSessions: terminal proxy not ported — no-op.
    clear_auth_cache(&state, user.id).await;

    log_security_event(
        &state,
        security_event::SUSPICIOUS_ACTIVITY,
        Some(user.id),
        SecurityDetails {
            ip: Some(&client_ip),
            username: Some(&user.username),
            reason: Some("Password reset via forgot password"),
            action: Some("password_reset"),
        },
    )
    .await;

    Ok(Json(json!({
        "message": "Password reset successfully. Please check your email for the new password.",
        "twoFactorDisabled": two_factor_disabled,
    }))
    .into_response())
}

// ===========================================================================
// GET /login-history
// ===========================================================================

#[derive(Debug, FromRow)]
struct LoginRecordRow {
    id: i32,
    ip: String,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    timezone: Option<String>,
    user_agent: Option<String>,
    created_at: DateTime<Utc>,
}

async fn login_history(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    // TS: page default 1, pageSize default 20 capped at 50. Garbage input falls
    // back to defaults here instead of the TS NaN -> 5xx path.
    let pagination = parse_pagination(&params, 20, Some(50));

    let records = sqlx::query_as::<_, LoginRecordRow>(
        "SELECT id, ip, country, region, city, isp, timezone, user_agent, created_at \
         FROM login_records WHERE user_id = $1 \
         ORDER BY created_at DESC OFFSET $2 LIMIT $3",
    )
    .bind(user.id)
    .bind(pagination.skip)
    .bind(pagination.take)
    .fetch_all(&state.db)
    .await?;

    let (total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM login_records WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&state.db)
            .await?;

    let items: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "ip": r.ip,
                "country": r.country,
                "region": r.region,
                "city": r.city,
                "isp": r.isp,
                "timezone": r.timezone,
                "userAgent": r.user_agent,
                "createdAt": iso(r.created_at),
            })
        })
        .collect();

    Ok(Json(json!({
        "records": items,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
        "totalPages": (total + pagination.page_size - 1) / pagination.page_size,
    })))
}
