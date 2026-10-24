//! 用户路由 — port of server/src/routes/users.ts (mounted at /api/users).
//!
//! Endpoint map (TS decorator -> Rust extractor):
//! - GET    /                          authenticateAdmin -> AdminAuth
//! - POST   /create/send-verification-code  authenticateAdmin -> AdminAuth
//! - POST   /                          authenticateAdmin -> AdminAuth
//! - GET    /lookup                    authenticateAdmin -> AdminAuth
//! - GET    /{id}                      authenticate      -> AuthUser
//! - POST   /{id}/change-email/send-code    authenticate  -> AuthUser
//! - PATCH  /{id}                      authenticate      -> AuthUser
//! - PATCH  /{id}/role                 authenticateAdmin -> AdminAuth
//! - POST   /{id}/quota/recalculate    authenticateAdmin -> AdminAuth
//! - POST   /me/quota/increase         authenticateUser  -> UserOnlyAuth
//! - PATCH  /{id}/status               authenticateAdmin -> AdminAuth
//! - DELETE /{id}                      authenticateAdmin -> AdminAuth
//! - GET    /{id}/sessions             authenticateAdmin -> AdminAuth
//! - POST   /{id}/revoke-sessions      authenticateAdmin -> AdminAuth
//! - POST   /{id}/reset-password       authenticateAdmin -> AdminAuth
//! - POST   /{id}/disable-2fa          authenticateAdmin -> AdminAuth
//! - DELETE /{id}/oauth/{provider}     authenticateAdmin -> AdminAuth
//! - GET    /{id}/login-records        authenticateAdmin -> AdminAuth
//! - GET    /detect-linked-accounts    authenticateAdmin -> AdminAuth
//! - GET    /{id}/hosting-balance/logs authenticateAdmin -> AdminAuth
//! - POST   /{id}/hosting-balance/adjust    authenticateAdmin -> AdminAuth
//!
//! Reported deviations (all non-DB infra the Rust port has not got yet):
//! - closeUserSessions (lib/terminal-proxy.ts): in-memory WebSocket terminal
//!   registry; the terminal proxy is NOT_PORTED here, so the stub closes 0.
//! - clearAuthCache (plugins/auth-decorators.ts): the Rust auth layer reads the
//!   DB per request with no shared cache, so it is a no-op.
//! - sendAdminCreatedUserEmail / sendBanNotificationEmail: nodemailer stack not
//!   ported; stubs log and return success (same convention as libs/external.rs),
//!   keeping the TS success-path contracts (e.g. no user deletion on send).
//!   sendVerificationEmail reuses the existing libs::external stub.
//! - sendNotification external fan-out (Telegram/Discord/webhook): only the
//!   always-created inbox message part is ported (create_inbox_notification).

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rand::Rng;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::{Decimal, RoundingStrategy};
use serde_json::{json, Map, Value};
use sqlx::FromRow;

use crate::auth::{AdminAuth, AuthUser, UserOnlyAuth};
use crate::db::{advisory_lock_namespace, advisory_transaction_lock, try_advisory_transaction_lock};
use crate::error::{code, ApiError};
use crate::libs::security::{invalidate_user_access_tokens, revoke_all_user_refresh_tokens};
use crate::libs::validators::{contains_dangerous_chars, validate_password};
use crate::response::{num, parse_pagination};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route(
            "/create/send-verification-code",
            post(create_send_verification_code),
        )
        .route("/lookup", get(lookup_user))
        .route("/me/quota/increase", post(increase_own_quota))
        .route("/detect-linked-accounts", get(detect_linked_accounts))
        .route(
            "/{id}",
            get(get_user).patch(update_user).delete(delete_user),
        )
        .route("/{id}/change-email/send-code", post(change_email_send_code))
        .route("/{id}/role", patch(update_user_role))
        .route("/{id}/quota/recalculate", post(recalculate_quota))
        .route("/{id}/status", patch(update_user_status))
        .route("/{id}/sessions", get(list_user_sessions))
        .route("/{id}/revoke-sessions", post(revoke_user_sessions))
        .route("/{id}/reset-password", post(reset_password))
        .route("/{id}/disable-2fa", post(disable_2fa))
        .route("/{id}/oauth/{provider}", delete(unbind_oauth))
        .route("/{id}/login-records", get(list_login_records))
        .route("/{id}/hosting-balance/logs", get(hosting_balance_logs))
        .route("/{id}/hosting-balance/adjust", post(adjust_hosting_balance))
}

/// Port of db/logs.ts createLog: fire-and-forget audit log row. The TS helper
/// also infers an instanceId from content (inferLogInstanceId); callers that
/// know their instance pass it explicitly once that path is ported.
pub async fn create_log(
    state: &SharedAppState,
    user_id: i32,
    module: &str,
    action: &str,
    content: &str,
    result: &str,
) {
    let insert = sqlx::query(
        "INSERT INTO logs (user_id, module, action, content, result) \
         VALUES ($1, $2, $3, $4, $5)",
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

/// Port of db/inbox.ts createInboxMessage: insert one inbox row, fire-and-forget.
pub async fn create_inbox_notification(
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
        tracing::warn!("create_inbox_notification failed (ignored): {err}");
    }
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

/// JS `Number(id)` param semantics (used by GET/PATCH/DELETE /{id} and friends):
/// NaN -> 400 INVALID_ID; integral values cast to i32; non-integral/out-of-range
/// values would fail Prisma's Int validation -> 500.
fn js_number_id(raw: &str) -> Result<i32, ApiError> {
    let t = raw.trim();
    // Number('') === 0 in JS (an empty path param cannot match the route, but
    // keep the quirk for whitespace-only segments).
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

/// JS `parseInt(id, 10)` prefix semantics (used by /{id}/sessions, /reset-password,
/// /login-records, ...): leading digits win, no digits -> NaN -> 400 INVALID_ID.
fn js_parse_int_id(raw: &str) -> Result<i32, ApiError> {
    match js_parse_int(raw) {
        Some(v) if v >= i32::MIN as i64 && v <= i32::MAX as i64 => Ok(v as i32),
        Some(_) => Err(ApiError::internal("Prisma Int argument out of range")),
        None => Err(ApiError::bad_request(code::INVALID_ID)),
    }
}

/// JS parseInt base-10: optional sign + leading digits, else NaN.
fn js_parse_int(raw: &str) -> Option<i64> {
    let s = raw.trim_start();
    let bytes = s.as_bytes();
    let mut idx = 0usize;
    let mut sign = 1i64;
    if idx < bytes.len() && (bytes[idx] == b'+' || bytes[idx] == b'-') {
        if bytes[idx] == b'-' {
            sign = -1;
        }
        idx += 1;
    }
    let start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == start {
        return None;
    }
    s[start..idx].parse::<i64>().ok().map(|v| sign * v)
}

/// Mirrors the TS setErrorHandler validation branch:
/// `400 { error: messages[0], code: 'VALIDATION_ERROR', details?: messages }`
/// (details array only when more than one message).
fn validation_error(messages: Vec<String>) -> Response {
    let mut body = Map::new();
    body.insert(
        "error".into(),
        json!(messages
            .first()
            .cloned()
            .unwrap_or_else(|| "Validation failed".to_string())),
    );
    body.insert("code".into(), json!("VALIDATION_ERROR"));
    if messages.len() > 1 {
        body.insert("details".into(), json!(messages));
    }
    (StatusCode::BAD_REQUEST, Json(Value::Object(body))).into_response()
}

/// 403 body the TS sends for the sensitive-operation double-verification gate.
fn verification_required(operation_type: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "Sensitive operation requires verification",
            "code": "VERIFICATION_REQUIRED",
            "operationType": operation_type,
        })),
    )
        .into_response()
}

/// JS Number -> rust_decimal (bodies arrive as serde_json numbers).
fn decimal_from_number(n: &serde_json::Number) -> Option<Decimal> {
    if let Some(i) = n.as_i64() {
        return Some(Decimal::from(i));
    }
    if let Some(u) = n.as_u64() {
        return Some(Decimal::from(u));
    }
    Decimal::from_f64(n.as_f64()?)
}

/// JS `n.toFixed(2)` (round half away from zero approximation).
fn to_fixed_2(d: Decimal) -> String {
    d.round_dp_with_strategy(2, RoundingStrategy::MidpointAwayFromZero)
        .to_string()
}

/// JS template literal `${amount}` on a number: shortest round-trip repr,
/// which serde_json::Number's Display matches.
fn js_num_display(n: &serde_json::Number) -> String {
    n.to_string()
}

// ===========================================================================
// no-op infra stubs (see module docs)
// ===========================================================================

/// lib/terminal-proxy.ts closeUserSessions — the terminal WebSocket registry is
/// not ported, so nothing to close (TS returns the number of closed sessions).
fn close_user_sessions(_user_id: i32, _reason: &str) -> i32 {
    0
}

/// plugins/auth-decorators.ts clearAuthCache — the Rust auth layer has no shared
/// auth cache (DB is re-read per request), so there is nothing to evict.
async fn clear_auth_cache(_user_id: i32) {}

/// lib/mailer.ts sendAdminCreatedUserEmail — SMTP stack not ported (same stub
/// convention as libs/external.rs). Returns success to preserve the TS
/// SMTP-configured flow (failure would delete the just-created user).
async fn send_admin_created_user_email(email: &str, username: &str, initial_password: &str) -> bool {
    tracing::warn!(
        "[email stub] sendAdminCreatedUserEmail not implemented in the Rust server \
         (TODO server/src/lib/mailer.ts:990): to={email} user={username}"
    );
    let _ = initial_password;
    true
}

/// lib/mailer.ts sendBanNotificationEmail — SMTP stub, fire-and-forget in TS.
async fn send_ban_notification_email(email: &str, username: &str, reason: &str) {
    tracing::warn!(
        "[email stub] sendBanNotificationEmail not implemented in the Rust server \
         (TODO server/src/lib/mailer.ts:1603): to={email} user={username} reason={reason}"
    );
}

/// lib/notifier.ts sendNotification external-channel fan-out stub (the inbox
/// message part is real, via create_inbox_notification).
fn push_external_notification_stub(user_id: i32, event_type: &str, title: &str) {
    tracing::warn!(
        "[notifier stub] external channel push not implemented in the Rust server \
         (TODO server/src/lib/notifier.ts): user={user_id} event={event_type} title={title}"
    );
}

// ===========================================================================
// lib/security.ts audit-log helper (logAdminAction -> logAuditEvent)
// ===========================================================================

/// Port of logAuditEvent's content builder: only targetUsername,
/// resourceType+resourceName and reason reach the DB `content` column; ip /
/// userAgent / metadata are only printed to the console when
/// AUDIT_LOG_VERBOSE=true, which the Rust port does not replicate.
struct AdminAudit<'a> {
    target_username: Option<&'a str>,
    resource_type: Option<&'a str>,
    resource_name: Option<&'a str>,
    reason: Option<&'a str>,
}

async fn log_admin_action(state: &SharedAppState, admin_id: i32, action: &str, details: AdminAudit<'_>) {
    let mut parts: Vec<String> = Vec::new();
    if let Some(u) = details.target_username {
        parts.push(format!("target: {u}"));
    }
    if let (Some(rt), Some(rn)) = (details.resource_type, details.resource_name) {
        parts.push(format!("{rt}: {rn}"));
    }
    if let Some(r) = details.reason {
        parts.push(format!("reason: {r}"));
    }
    let content = parts.join(", ");
    create_log(state, admin_id, "admin", action, &content, "success").await;
}

// ===========================================================================
// db helpers (port of db/users.ts + pieces of db/index re-exports)
// ===========================================================================

#[derive(Debug, FromRow)]
struct UserRow {
    id: i32,
    username: String,
    email: Option<String>,
    password_hash: String,
    role: String,
    status: String,
    avatar_style: String,
    avatar_badge_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const USER_COLS: &str = "id, username, email, password_hash, role::text AS role, \
     status::text AS status, avatar_style, avatar_badge_id, created_at, updated_at";

async fn find_user_by_id(state: &SharedAppState, id: i32) -> Result<Option<UserRow>, ApiError> {
    let row = sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLS} FROM users WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

async fn find_user_by_username(
    state: &SharedAppState,
    username: &str,
) -> Result<Option<UserRow>, ApiError> {
    let row = sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLS} FROM users WHERE username = $1"
    ))
    .bind(username)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// findUserByEmail: case-insensitive match to tolerate legacy mixed-case rows.
async fn find_user_by_email(
    state: &SharedAppState,
    email: &str,
) -> Result<Option<UserRow>, ApiError> {
    let normalized = email.trim();
    let row = sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLS} FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1"
    ))
    .bind(normalized)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

/// db/users.ts deleteUser: prisma.user.delete (FK ON DELETE CASCADE handles
/// quotas, sessions, friendships, ...).
async fn delete_user_by_id(state: &SharedAppState, id: i32) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(())
}

#[derive(Debug, FromRow)]
struct QuotaRow {
    host_limit: i32,
    host_used: i32,
    friend_limit: i32,
    friend_used: i32,
    package_limit: i32,
    package_used: i32,
    monthly_traffic_limit: Option<i64>,
    monthly_traffic_used: i64,
    extra_traffic_quota: i64,
    traffic_status: String,
}

async fn get_user_quota(
    executor: impl sqlx::PgExecutor<'_>,
    user_id: i32,
) -> Result<Option<QuotaRow>, ApiError> {
    let row = sqlx::query_as::<_, QuotaRow>(
        "SELECT host_limit, host_used, friend_limit, friend_used, \
                package_limit, package_used, monthly_traffic_limit, \
                monthly_traffic_used, extra_traffic_quota, traffic_status::text AS traffic_status \
         FROM user_quotas WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// db/instances.ts getInstancesByUserId is only ever used for `.length` here.
async fn count_instances_by_user_id(state: &SharedAppState, user_id: i32) -> Result<i64, ApiError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instances WHERE user_id = $1 AND status <> 'deleted'",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(count)
}

async fn is_2fa_enabled(state: &SharedAppState, user_id: i32) -> Result<bool, ApiError> {
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT two_factor_enabled FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(row.map(|(v,)| v).unwrap_or(false))
}

/// db/users.ts disable2FAComplete: clear all 2FA data.
async fn disable_2fa_complete(state: &SharedAppState, user_id: i32) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL, \
         two_factor_recovery_codes = NULL WHERE id = $1",
    )
    .bind(user_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn has_oauth_binding(
    state: &SharedAppState,
    user_id: i32,
    provider: &str,
) -> Result<bool, ApiError> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM user_oauth_bindings WHERE user_id = $1 AND provider = $2::\"OAuthProvider\"",
    )
    .bind(user_id)
    .bind(provider)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.is_some())
}

async fn delete_oauth_binding(
    state: &SharedAppState,
    user_id: i32,
    provider: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM user_oauth_bindings WHERE user_id = $1 AND provider = $2::\"OAuthProvider\"",
    )
    .bind(user_id)
    .bind(provider)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// db/users.ts updateUser (email / passwordHash / avatarStyle subset).
async fn update_user_fields(
    state: &SharedAppState,
    user_id: i32,
    email: Option<&str>,
    password_hash: Option<&str>,
    avatar_style: Option<&str>,
) -> Result<(), ApiError> {
    if email.is_none() && password_hash.is_none() && avatar_style.is_none() {
        return Ok(());
    }
    let mut sets: Vec<&str> = Vec::new();
    if email.is_some() {
        sets.push("email = $2");
    }
    if password_hash.is_some() {
        sets.push(if sets.is_empty() {
            "password_hash = $3"
        } else {
            "password_hash = $3"
        });
    }
    if avatar_style.is_some() {
        sets.push("avatar_style = $4");
    }
    let sql = format!("UPDATE users SET {} WHERE id = $1", sets.join(", "));
    sqlx::query(&sql)
        .bind(user_id)
        .bind(email)
        .bind(password_hash)
        .bind(avatar_style)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// lib/security.ts updateUserPasswordAndInvalidateSessions: password (plus
/// optional email/avatar), refresh-token revocation and the user-level token
/// invalidation marker commit atomically.
async fn update_user_password_and_invalidate_sessions(
    state: &SharedAppState,
    user_id: i32,
    password_hash: &str,
    email: Option<&str>,
    avatar_style: Option<&str>,
) -> Result<(), ApiError> {
    let mut tx = state.db.begin().await?;
    let mut sets: Vec<&str> = vec!["password_hash = $2"];
    if email.is_some() {
        sets.push("email = $3");
    }
    if avatar_style.is_some() {
        sets.push("avatar_style = $4");
    }
    let sql = format!("UPDATE users SET {} WHERE id = $1", sets.join(", "));
    sqlx::query(&sql)
        .bind(user_id)
        .bind(password_hash)
        .bind(email)
        .bind(avatar_style)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    let invalidated_at = Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO token_invalidations (user_id, session_id, invalidated_at, created_at) \
         VALUES ($1, $2, $3, now()) \
         ON CONFLICT (user_id, session_id) \
         DO UPDATE SET invalidated_at = EXCLUDED.invalidated_at",
    )
    .bind(user_id)
    .bind(crate::libs::security::USER_LEVEL_SESSION_ID)
    .bind(invalidated_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// system config reads (port of db/system-config.ts getters; no cache layer —
// the auth.rs port keeps a cache but its helpers are module-private, so this
// module reads the table directly; semantics are identical)
// ---------------------------------------------------------------------------

async fn get_system_config(
    state: &SharedAppState,
    key: &str,
) -> Result<Option<String>, ApiError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM system_configs WHERE key = $1")
        .bind(key)
        .fetch_optional(&state.db)
        .await?;
    Ok(row.map(|(v,)| v))
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

/// db/system-config.ts getDefaultQuotaConfig (defaults 0 = feature closed).
async fn get_default_quota_config(state: &SharedAppState) -> Result<(i64, i64, i64), ApiError> {
    let host = get_system_config_number(state, "default_quota_host", 0).await?;
    let friend = get_system_config_number(state, "default_quota_friend", 0).await?;
    let package = get_system_config_number(state, "default_quota_package", 0).await?;
    Ok((host, friend, package))
}

/// lib/mailer.ts isSmtpEnabled: pure system-config check.
async fn is_smtp_enabled(state: &SharedAppState) -> Result<bool, ApiError> {
    let enabled = get_system_config_boolean(state, "smtp_enabled", false).await?;
    let host = get_system_config(state, "smtp_host").await?;
    let username = get_system_config(state, "smtp_username").await?;
    let password = get_system_config(state, "smtp_password").await?;
    let non_empty = |v: Option<String>| v.map(|s| !s.is_empty()).unwrap_or(false);
    Ok(enabled && non_empty(host) && non_empty(username) && non_empty(password))
}

// ---------------------------------------------------------------------------
// lib/email-domain.ts (email domain whitelist)
// ---------------------------------------------------------------------------

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

fn extract_email_domain(email: &str) -> Option<String> {
    let at = email.rfind('@')?;
    if at == email.len() - 1 {
        return None;
    }
    Some(email[at + 1..].to_lowercase())
}

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

// ---------------------------------------------------------------------------
// db/email-verification.ts (email verification codes)
// ---------------------------------------------------------------------------

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

/// Port of verifyCode: atomic match-and-consume via DELETE; per-email failure
/// counter lives in the shared store and invalidates all codes for the email
/// after MAX_VERIFY_FAILURES (brute-force protection).
async fn verify_code(state: &SharedAppState, email: &str, code: &str) -> Result<bool, ApiError> {
    let normalized = email.to_lowercase().trim().to_string();

    static SIX_DIGITS: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^\d{6}$").expect("valid regex")
    });
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
            std::time::Duration::from_secs(60 * 60),
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

// ---------------------------------------------------------------------------
// lib/operation-verification.ts (sensitive-operation double verification)
// ---------------------------------------------------------------------------

/// isOperationVerified: a verified record newer than 10 minutes authorizes once.
async fn is_operation_verified(
    state: &SharedAppState,
    user_id: i32,
    operation_type: &str,
) -> Result<bool, ApiError> {
    let ten_minutes_ago = Utc::now() - chrono::Duration::minutes(10);
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM operation_verifications \
         WHERE user_id = $1 AND operation_type = $2::\"OperationType\" \
           AND resource_id IS NULL AND verified = TRUE AND verified_at > $3 \
         LIMIT 1",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(ten_minutes_ago)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.is_some())
}

/// claimOperationVerification: atomically consumes one verified record
/// (find first by verified_at asc, delete with the same predicate).
async fn claim_operation_verification(
    state: &SharedAppState,
    user_id: i32,
    operation_type: &str,
) -> Result<bool, ApiError> {
    let ten_minutes_ago = Utc::now() - chrono::Duration::minutes(10);
    let mut tx = state.db.begin().await?;
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM operation_verifications \
         WHERE user_id = $1 AND operation_type = $2::\"OperationType\" \
           AND resource_id IS NULL AND verified = TRUE AND verified_at > $3 \
         ORDER BY verified_at ASC LIMIT 1",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(ten_minutes_ago)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id,)) = row else {
        tx.rollback().await?;
        return Ok(false);
    };
    let result = sqlx::query(
        "DELETE FROM operation_verifications \
         WHERE id = $1 AND verified = TRUE AND verified_at > $2",
    )
    .bind(id)
    .bind(ten_minutes_ago)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result.rows_affected() == 1)
}

// ---------------------------------------------------------------------------
// users list (db/pagination.ts getUsersPaginated + route aggregates)
// ---------------------------------------------------------------------------

const USER_SEARCH_FIELDS: &[&str] = &["username", "id", "email"];

fn parse_user_search_fields(raw: Option<&str>) -> Vec<&'static str> {
    let Some(raw) = raw else {
        return USER_SEARCH_FIELDS.iter().copied().collect();
    };
    let requested: Vec<&str> = raw
        .split(',')
        .map(|f| f.trim())
        .filter(|f| USER_SEARCH_FIELDS.contains(f))
        .collect();
    if requested.is_empty() {
        return USER_SEARCH_FIELDS.iter().copied().collect();
    }
    // TS normalizes back to the canonical USER_SEARCH_FIELDS order.
    USER_SEARCH_FIELDS
        .iter()
        .copied()
        .filter(|f| requested.contains(f))
        .collect()
}

fn parse_boolean_query(raw: Option<&str>) -> bool {
    matches!(raw, Some(v) if ["1", "true", "yes", "on"].contains(&v.to_lowercase().as_str()))
}

fn escape_sql_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 4);
    for c in value.chars() {
        if c == '\\' || c == '%' || c == '_' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// buildUserSearchWhereClause: OR-combined per-field clauses. Returns the SQL
/// fragment using $1 (fuzzy pattern) and $2 (raw search) when a clause exists.
fn build_user_search_clause(
    raw_search: &str,
    fields: &[&str],
    exact_match: bool,
) -> Option<(String, String, String)> {
    let search = raw_search.trim();
    if search.is_empty() {
        return None;
    }
    let fuzzy = format!("%{}%", escape_sql_like(search));
    let mut clauses: Vec<String> = Vec::new();
    if fields.contains(&"username") {
        clauses.push(if exact_match {
            "LOWER(u.username) = LOWER($2)".to_string()
        } else {
            "u.username ILIKE $1 ESCAPE '\\'".to_string()
        });
    }
    if fields.contains(&"id") {
        clauses.push(if exact_match {
            "CAST(u.id AS TEXT) = $2".to_string()
        } else {
            "CAST(u.id AS TEXT) ILIKE $1 ESCAPE '\\'".to_string()
        });
    }
    if fields.contains(&"email") {
        clauses.push(if exact_match {
            "u.email IS NOT NULL AND LOWER(u.email) = LOWER($2)".to_string()
        } else {
            "u.email IS NOT NULL AND u.email ILIKE $1 ESCAPE '\\'".to_string()
        });
    }
    if clauses.is_empty() {
        return None;
    }
    Some((format!("({})", clauses.join(" OR ")), fuzzy, search.to_string()))
}

#[derive(Debug, FromRow)]
struct UserListRow {
    id: i32,
    username: String,
    email: Option<String>,
    role: String,
    status: String,
    avatar_style: String,
    avatar_badge_id: Option<String>,
    created_at: DateTime<Utc>,
    host_limit: Option<i32>,
    host_used: Option<i32>,
    friend_limit: Option<i32>,
    friend_used: Option<i32>,
    package_limit: Option<i32>,
    package_used: Option<i32>,
    monthly_traffic_limit: Option<i64>,
    monthly_traffic_used: Option<i64>,
    extra_traffic_quota: Option<i64>,
    traffic_status: Option<String>,
    hosting_balance: Decimal,
}

const USER_LIST_COLS: &str =
    "u.id, u.username, u.email, u.role::text AS role, u.status::text AS status, \
     u.avatar_style, u.avatar_badge_id, u.created_at, \
     q.host_limit, q.host_used, q.friend_limit, q.friend_used, \
     q.package_limit, q.package_used, q.monthly_traffic_limit, \
     q.monthly_traffic_used, q.extra_traffic_quota, q.traffic_status::text AS traffic_status, \
     u.hosting_balance";

/// Port of db/pagination.ts getUsersPaginated. The TS search path (count + id
/// page + re-fetch + reorder) reduces to one query ordered by created_at DESC
/// with LIMIT/OFFSET, which is what both branches produce.
async fn get_users_paginated(
    state: &SharedAppState,
    page: i64,
    page_size: i64,
    search: &str,
    search_fields: &[&str],
    exact_match: bool,
) -> Result<(Vec<UserListRow>, i64), ApiError> {
    let clause = build_user_search_clause(search, search_fields, exact_match);
    let where_sql = clause
        .as_ref()
        .map(|(fragment, _, _)| format!(" WHERE {fragment}"))
        .unwrap_or_default();

    let total: i64 = if let Some((_, fuzzy, search)) = &clause {
        let (count,): (i64,) = sqlx::query_as(&format!(
            "SELECT COUNT(*)::bigint FROM users u{where_sql}"
        ))
        .bind(fuzzy)
        .bind(search)
        .fetch_one(&state.db)
        .await?;
        count
    } else {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*)::bigint FROM users u")
                .fetch_one(&state.db)
                .await?;
        count
    };

    let skip = (page - 1) * page_size;
    let list_sql = format!(
        "SELECT {USER_LIST_COLS} FROM users u \
         LEFT JOIN user_quotas q ON q.user_id = u.id{where_sql} \
         ORDER BY u.created_at DESC LIMIT $3 OFFSET $4"
    );
    let mut query = sqlx::query_as::<_, UserListRow>(&list_sql);
    if let Some((_, fuzzy, search)) = &clause {
        query = query.bind(fuzzy).bind(search);
    } else {
        // Keep placeholder numbering consistent even without search params.
        query = query.bind(Option::<String>::None).bind(Option::<String>::None);
    }
    let rows = query
        .bind(page_size)
        .bind(skip)
        .fetch_all(&state.db)
        .await?;
    Ok((rows, total))
}

/// db/balance.ts getUsersTotalConsumeMap: prefer balanceBefore->After deltas to
/// stay compatible with historical consume rows signed inconsistently.
async fn get_users_total_consume_map(
    state: &SharedAppState,
    user_ids: &[i32],
) -> Result<HashMap<i32, Decimal>, ApiError> {
    if user_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(i32, Decimal)> = sqlx::query_as(
        "SELECT user_id, \
                COALESCE(SUM(\
                  CASE WHEN balance_before > balance_after \
                       THEN balance_before - balance_after \
                       ELSE ABS(amount) END), 0)::numeric AS total_consume \
         FROM balance_logs \
         WHERE user_id = ANY($1) AND type IN ('consume', 'hourly_consume') \
         GROUP BY user_id",
    )
    .bind(user_ids)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().collect())
}

/// db/login-records.ts getLastLoginRecordsForUsers: latest record per user.
async fn get_last_login_records_for_users(
    state: &SharedAppState,
    user_ids: &[i32],
) -> Result<HashMap<i32, (String, Option<String>, Option<String>, DateTime<Utc>)>, ApiError> {
    if user_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(i32, String, Option<String>, Option<String>, DateTime<Utc>)> =
        sqlx::query_as(
            "SELECT DISTINCT ON (user_id) user_id, ip, country, city, created_at \
             FROM login_records WHERE user_id = ANY($1) \
             ORDER BY user_id, created_at DESC",
        )
        .bind(user_ids)
        .fetch_all(&state.db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(uid, ip, country, city, created_at)| (uid, (ip, country, city, created_at)))
        .collect())
}

// ---------------------------------------------------------------------------
// sessions (lib/security.ts getUserSessions)
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct SessionTokenRow {
    token: String,
    ip: Option<String>,
    user_agent: Option<String>,
    created_at: DateTime<Utc>,
    last_active_at: DateTime<Utc>,
}

async fn get_user_sessions(
    state: &SharedAppState,
    user_id: i32,
) -> Result<Vec<SessionTokenRow>, ApiError> {
    let rows = sqlx::query_as::<_, SessionTokenRow>(
        "SELECT token, ip, user_agent, created_at, last_active_at \
         FROM refresh_tokens WHERE user_id = $1 AND expires_at > now() \
         ORDER BY last_active_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// quota usage calculation (db/quota-operations.ts calculateUserQuotaUsed)
// ---------------------------------------------------------------------------

async fn calculate_user_quota_used(
    state: &SharedAppState,
    user_id: i32,
) -> Result<(i64, i64, i64), ApiError> {
    let (host_used,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM hosts WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    let (friend_used,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM friendships \
         WHERE (user_id = $1 AND status = 'accepted') \
            OR (friend_id = $1 AND status = 'accepted')",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    let (package_used,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM packages WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    Ok((host_used, friend_used, package_used))
}

/// quota-operations.ts updateUserQuotaUsed — prisma.userQuota.update throws
/// (P2025 -> 500) when the row is missing; mirrored via rows_affected.
async fn update_user_quota_used(
    state: &SharedAppState,
    user_id: i32,
    host_used: i64,
    friend_used: i64,
    package_used: i64,
) -> Result<(), ApiError> {
    let result = sqlx::query(
        "UPDATE user_quotas SET host_used = $2, friend_used = $3, package_used = $4 \
         WHERE user_id = $1",
    )
    .bind(user_id)
    .bind(host_used as i32)
    .bind(friend_used as i32)
    .bind(package_used as i32)
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::internal(
            "userQuota record not found (prisma P2025)",
        ));
    }
    Ok(())
}

/// quota-operations.ts updateUserQuotaLimits.
async fn update_user_quota_limits(
    state: &SharedAppState,
    user_id: i32,
    host_limit: Option<i64>,
    friend_limit: Option<i64>,
) -> Result<(), ApiError> {
    let mut sets: Vec<&str> = Vec::new();
    if host_limit.is_some() {
        sets.push("host_limit = $2");
    }
    if friend_limit.is_some() {
        sets.push("friend_limit = $3");
    }
    if sets.is_empty() {
        return Ok(());
    }
    let sql = format!("UPDATE user_quotas SET {} WHERE user_id = $1", sets.join(", "));
    let result = sqlx::query(&sql)
        .bind(user_id)
        .bind(host_limit.map(|v| v as i32))
        .bind(friend_limit.map(|v| v as i32))
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::internal(
            "userQuota record not found (prisma P2025)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// random password (lib/incus-config-container.ts generateRandomPassword)
// ---------------------------------------------------------------------------

fn generate_random_password(length: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// users.ts getAdminCreateEmailLockKey: 32-bit FNV-1a over UTF-16 code units,
/// `hash | 0` reinterprets as i32.
fn admin_create_email_lock_key(email: &str) -> i32 {
    let mut hash: u32 = 0x811c_9dc5;
    for unit in email.encode_utf16() {
        hash ^= unit as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash as i32
}

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

/// db/users.ts createUser: random avatar + default quota row.
async fn create_user_with_quota(
    tx: &mut sqlx::PgConnection,
    username: &str,
    email: &str,
    password_hash: &str,
    role: &str,
    default_quota: (i64, i64, i64),
) -> Result<i32, sqlx::Error> {
    let avatar_style = AVATAR_STYLES[rand::thread_rng().gen_range(0..AVATAR_STYLES.len())];
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
    .await?;
    sqlx::query(
        "INSERT INTO user_quotas (user_id, host_limit, friend_limit, package_limit) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(default_quota.0 as i32)
    .bind(default_quota.1 as i32)
    .bind(default_quota.2 as i32)
    .execute(&mut *tx)
    .await?;
    Ok(user_id)
}

// ===========================================================================
// Email validation targets (route-local TS helpers)
// ===========================================================================

async fn validate_email_change_target(
    state: &SharedAppState,
    raw_email: &str,
    current_email: Option<&str>,
    user_id: i32,
) -> Result<Result<String, ApiError>, ApiError> {
    if raw_email.is_empty() || !raw_email.contains('@') {
        return Ok(Err(ApiError::bad_request(code::INVALID_EMAIL)));
    }

    // TS: rawEmail.replace(/@/g, '').replace(/\./g, '') then dangerous chars.
    let email_without_allowed: String = raw_email
        .chars()
        .filter(|c| *c != '@' && *c != '.')
        .collect();
    if contains_dangerous_chars(&email_without_allowed) {
        return Ok(Err(ApiError::bad_request(code::EMAIL_CONTAINS_ILLEGAL)));
    }

    let normalized_email = raw_email.to_lowercase().trim().to_string();
    let normalized_current = current_email
        .map(|e| e.to_lowercase().trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(current) = &normalized_current {
        if &normalized_email == current {
            return Ok(Err(ApiError::with_message(
                code::INVALID_PARAMS,
                StatusCode::BAD_REQUEST,
                "New email must be different from current email",
            )));
        }
    }

    let domain_validation = validate_email_domain(state, &normalized_email).await?;
    if !domain_validation.valid {
        let mut err = ApiError::bad_request(code::EMAIL_DOMAIN_NOT_ALLOWED);
        if let Some(domain) = domain_validation.domain {
            err = err.with_details(domain);
        }
        return Ok(Err(err));
    }

    if let Some(existing) = find_user_by_email(state, &normalized_email).await? {
        if existing.id != user_id {
            return Ok(Err(ApiError::bad_request(code::EMAIL_ALREADY_REGISTERED)));
        }
    }

    Ok(Ok(normalized_email))
}

/// Same as above but the existing-user check does not exclude anyone
/// (validateAdminCreateEmailTarget).
async fn validate_admin_create_email_target(
    state: &SharedAppState,
    raw_email: &str,
) -> Result<Result<String, ApiError>, ApiError> {
    if raw_email.is_empty() || !raw_email.contains('@') {
        return Ok(Err(ApiError::bad_request(code::INVALID_EMAIL)));
    }
    let email_without_allowed: String = raw_email
        .chars()
        .filter(|c| *c != '@' && *c != '.')
        .collect();
    if contains_dangerous_chars(&email_without_allowed) {
        return Ok(Err(ApiError::bad_request(code::EMAIL_CONTAINS_ILLEGAL)));
    }
    let normalized_email = raw_email.to_lowercase().trim().to_string();
    let domain_validation = validate_email_domain(state, &normalized_email).await?;
    if !domain_validation.valid {
        let mut err = ApiError::bad_request(code::EMAIL_DOMAIN_NOT_ALLOWED);
        if let Some(domain) = domain_validation.domain {
            err = err.with_details(domain);
        }
        return Ok(Err(err));
    }
    if find_user_by_email(state, &normalized_email).await?.is_some() {
        return Ok(Err(ApiError::bad_request(code::EMAIL_ALREADY_REGISTERED)));
    }
    Ok(Ok(normalized_email))
}

// ===========================================================================
// GET / — 获取用户列表 (管理员，支持分页和搜索)
// ===========================================================================

async fn list_users(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    // TS: `page = '1'` default then parseInt — an unparsable explicit value
    // yields NaN which Prisma rejects -> 500 in the TS server too.
    let page = match params.get("page") {
        None => 1i64,
        Some(raw) => match js_parse_int(raw) {
            Some(v) => v,
            None => {
                return Err(ApiError::internal("Prisma rejects NaN skip/take"));
            }
        },
    };
    let page_size = match params.get("pageSize") {
        None => 20i64,
        Some(raw) => match js_parse_int(raw) {
            Some(v) => v,
            None => {
                return Err(ApiError::internal("Prisma rejects NaN skip/take"));
            }
        },
    };
    let search = params.get("search").map(|s| s.as_str()).unwrap_or("");
    let search_fields = parse_user_search_fields(params.get("searchFields").map(|s| s.as_str()));
    let exact_match = parse_boolean_query(params.get("exact").map(|s| s.as_str()));

    let (users, total) =
        get_users_paginated(&state, page, page_size, search, &search_fields, exact_match).await?;

    let user_ids: Vec<i32> = users.iter().map(|u| u.id).collect();

    // 2FA 状态
    let mut two_fa_map: HashMap<i32, bool> = HashMap::new();
    if !user_ids.is_empty() {
        let rows: Vec<(i32, bool)> =
            sqlx::query_as("SELECT id, two_factor_enabled FROM users WHERE id = ANY($1)")
                .bind(&user_ids)
                .fetch_all(&state.db)
                .await?;
        two_fa_map.extend(rows);
    }

    // 实例数量
    let mut instance_count_map: HashMap<i32, i64> = HashMap::new();
    if !user_ids.is_empty() {
        let rows: Vec<(i32, i64)> = sqlx::query_as(
            "SELECT user_id, COUNT(*) FROM instances \
             WHERE user_id = ANY($1) AND status <> 'deleted' GROUP BY user_id",
        )
        .bind(&user_ids)
        .fetch_all(&state.db)
        .await?;
        instance_count_map.extend(rows);
    }

    // GitHub 绑定状态
    let mut github_map: HashMap<i32, bool> = HashMap::new();
    if !user_ids.is_empty() {
        let rows: Vec<(i32, i64)> = sqlx::query_as(
            "SELECT user_id, COUNT(*) FROM user_oauth_bindings \
             WHERE user_id = ANY($1) AND provider = 'github' GROUP BY user_id",
        )
        .bind(&user_ids)
        .fetch_all(&state.db)
        .await?;
        github_map.extend(rows.into_iter().map(|(id, c)| (id, c > 0)));
    }

    // 最后登录记录
    let last_login_map = get_last_login_records_for_users(&state, &user_ids).await?;

    // 余额
    let mut balance_map: HashMap<i32, Decimal> = HashMap::new();
    if !user_ids.is_empty() {
        let rows: Vec<(i32, Decimal)> =
            sqlx::query_as("SELECT id, balance FROM users WHERE id = ANY($1)")
                .bind(&user_ids)
                .fetch_all(&state.db)
                .await?;
        balance_map.extend(rows);
    }

    // 实际消费统计
    let consume_map = get_users_total_consume_map(&state, &user_ids).await?;

    // 积分
    let mut points_map: HashMap<i32, (i32, i32)> = HashMap::new();
    if !user_ids.is_empty() {
        let rows: Vec<(i32, i32, i32)> = sqlx::query_as(
            "SELECT user_id, points, total_earned FROM user_points WHERE user_id = ANY($1)",
        )
        .bind(&user_ids)
        .fetch_all(&state.db)
        .await?;
        points_map.extend(rows.into_iter().map(|(id, p, t)| (id, (p, t))));
    }

    // 冻结托管余额
    let mut frozen_map: HashMap<i32, Decimal> = HashMap::new();
    if !user_ids.is_empty() {
        let rows: Vec<(i32, Decimal)> = sqlx::query_as(
            "SELECT user_id, COALESCE(SUM(amount), 0) FROM hosting_balance_logs \
             WHERE user_id = ANY($1) AND frozen = TRUE GROUP BY user_id",
        )
        .bind(&user_ids)
        .fetch_all(&state.db)
        .await?;
        frozen_map.extend(rows);
    }

    let items: Vec<Value> = users
        .iter()
        .map(|u| {
            let quota = json!({
                "hostLimit": u.host_limit.unwrap_or(0),
                "hostUsed": u.host_used.unwrap_or(0),
                "friendLimit": u.friend_limit.unwrap_or(0),
                "friendUsed": u.friend_used.unwrap_or(0),
                "packageLimit": u.package_limit.unwrap_or(0),
                "packageUsed": u.package_used.unwrap_or(0),
                "monthlyTrafficLimit": match u.monthly_traffic_limit {
                    Some(v) => json!(v.to_string()),
                    None => Value::Null,
                },
                "monthlyTrafficUsed": u.monthly_traffic_used.map(|v| v.to_string()).unwrap_or_else(|| "0".to_string()),
                "extraTrafficQuota": u.extra_traffic_quota.map(|v| v.to_string()).unwrap_or_else(|| "0".to_string()),
                "trafficStatus": u.traffic_status.clone().unwrap_or_else(|| "NORMAL".to_string()),
            });
            let last_login = last_login_map.get(&u.id).map(|(ip, country, city, created_at)| {
                json!({
                    "ip": ip,
                    "country": country,
                    "city": city,
                    "createdAt": iso(*created_at),
                })
            });
            json!({
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "status": u.status,
                "avatarStyle": u.avatar_style,
                "avatarBadgeId": u.avatar_badge_id.clone(),
                "twoFAEnabled": two_fa_map.get(&u.id).copied().unwrap_or(false),
                "instanceCount": instance_count_map.get(&u.id).copied().unwrap_or(0),
                "hasGithubBinding": github_map.get(&u.id).copied().unwrap_or(false),
                "quota": quota,
                "createdAt": iso(u.created_at),
                "lastLogin": last_login,
                "balance": balance_map
                    .get(&u.id)
                    .map(|b| json!(num(*b)))
                    .unwrap_or_else(|| json!(0)),
                "totalConsume": consume_map
                    .get(&u.id)
                    .map(|c| json!(num(*c)))
                    .unwrap_or_else(|| json!(0)),
                "points": points_map.get(&u.id).map(|(p, _)| *p).unwrap_or(0),
                "totalEarnedPoints": points_map.get(&u.id).map(|(_, t)| *t).unwrap_or(0),
                "hostingBalance": num(u.hosting_balance),
                "hostingBalanceFrozen": frozen_map
                    .get(&u.id)
                    .map(|f| json!(num(*f)))
                    .unwrap_or_else(|| json!(0)),
            })
        })
        .collect();

    Ok(Json(json!({
        "users": items,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "totalPages": (total as f64 / page_size as f64).ceil() as i64,
    })))
}

// ===========================================================================
// POST /create/send-verification-code — 管理员创建用户：发送邮箱验证码
// ===========================================================================

async fn create_send_verification_code(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    // Fastify schema: email required, format email.
    let Some(email_value) = body.get("email") else {
        return Ok(validation_error(vec!["email is required".to_string()]));
    };
    let Some(email) = email_value.as_str() else {
        return Ok(validation_error(vec!["body/email must be string".to_string()]));
    };
    if !is_email_format(email) {
        return Ok(validation_error(vec![
            "Please enter a valid email address".to_string(),
        ]));
    }

    if !is_smtp_enabled(&state).await? {
        return Err(ApiError::bad_request(code::EMAIL_VERIFICATION_DISABLED));
    }

    let normalized_email = match validate_admin_create_email_target(&state, email).await? {
        Ok(email) => email,
        Err(err) => return Ok(err.into_response()),
    };

    let Some((code_value, expires_at)) = create_verification_code(&state, &normalized_email).await?
    else {
        return Err(ApiError::new(
            code::TOO_MANY_VERIFICATION_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
        ));
    };

    // lib/mailer.ts sendVerificationEmail — stubbed success in the Rust port.
    let sent = crate::libs::external::send_verification_email(
        &normalized_email,
        &code_value,
        10,
        "register",
    )
    .await;
    if !sent {
        return Err(ApiError::new(code::EMAIL_SEND_FAILED, StatusCode::INTERNAL_SERVER_ERROR));
    }

    Ok(Json(json!({
        "message": "Verification code sent",
        "expiresAt": iso(expires_at),
    }))
    .into_response())
}

/// Lightweight ajv-formats 'email' check (full RFC 5322 validation is not the
/// TS behavior either — ajv-formats uses a practical subset).
fn is_email_format(s: &str) -> bool {
    static EMAIL: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").expect("valid regex")
    });
    EMAIL.is_match(s)
}

// ===========================================================================
// POST / — 管理员创建用户
// ===========================================================================

/// Port of lib/admin-create-user.ts normalizeAdminCreateUserInput plus the
/// Fastify schema pre-checks (schema errors take precedence, exactly like AJV).
fn normalize_admin_create_user_input(
    body: &Value,
) -> Result<Result<AdminCreateInput, Vec<String>>, Response> {
    let mut schema_errors: Vec<String> = Vec::new();

    // Schema: username string 3..32 pattern ^[a-zA-Z][a-zA-Z0-9_-]*$
    let username_raw = body.get("username");
    if username_raw.is_none() {
        schema_errors.push("username is required".to_string());
    } else if !username_raw.unwrap().is_string() {
        schema_errors.push("body/username must be string".to_string());
    } else {
        let username = username_raw.unwrap().as_str().unwrap();
        if username.chars().count() < 3 {
            schema_errors.push("Username must be at least 3 characters".to_string());
        } else if username.chars().count() > 32 {
            schema_errors.push("username is too long".to_string());
        }
        static PATTERN: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
            regex::Regex::new(r"^[a-zA-Z][a-zA-Z0-9_-]*$").expect("valid regex")
        });
        if !PATTERN.is_match(username) {
            schema_errors.push(
                "Username must start with a letter and contain only letters, numbers, underscores, and hyphens"
                    .to_string(),
            );
        }
    }

    // Schema: email string format email
    let email_raw = body.get("email");
    if email_raw.is_none() {
        schema_errors.push("email is required".to_string());
    } else if !email_raw.unwrap().is_string() {
        schema_errors.push("body/email must be string".to_string());
    } else if !is_email_format(email_raw.unwrap().as_str().unwrap()) {
        schema_errors.push("Please enter a valid email address".to_string());
    }

    // Schema: role enum
    let role_raw = body.get("role");
    let role_valid = matches!(role_raw, Some(Value::String(s)) if s == "admin" || s == "user");
    if role_raw.is_none() {
        schema_errors.push("role is required".to_string());
    } else if !role_raw.unwrap().is_string() {
        schema_errors.push("body/role must be string".to_string());
    } else if !role_valid {
        schema_errors.push("must be equal to one of the allowed values".to_string());
    }

    // Schema: status enum
    let status_raw = body.get("status");
    let status_valid =
        matches!(status_raw, Some(Value::String(s)) if s == "active" || s == "banned");
    if status_raw.is_none() {
        schema_errors.push("status is required".to_string());
    } else if !status_raw.unwrap().is_string() {
        schema_errors.push("body/status must be string".to_string());
    } else if !status_valid {
        schema_errors.push("must be equal to one of the allowed values".to_string());
    }

    // Schema: verifyEmail boolean
    let verify_email_raw = body.get("verifyEmail");
    let verify_email_valid = matches!(verify_email_raw, Some(Value::Bool(_)));
    if verify_email_raw.is_none() {
        schema_errors.push("verifyEmail is required".to_string());
    } else if !verify_email_valid {
        schema_errors.push("body/verifyEmail must be boolean".to_string());
    }

    // Schema: emailCode string 6..6 (optional)
    let email_code_raw = body.get("emailCode");
    if let Some(code_raw) = email_code_raw {
        if !code_raw.is_string() {
            schema_errors.push("body/emailCode must be string".to_string());
        } else {
            let code = code_raw.as_str().unwrap().chars().count();
            if code < 6 {
                schema_errors.push("emailCode is too short".to_string());
            } else if code > 6 {
                schema_errors.push("emailCode is too long".to_string());
            }
        }
    }

    if !schema_errors.is_empty() {
        return Err(validation_error(schema_errors));
    }

    // normalizeAdminCreateUserInput re-checks on trimmed values.
    let username = body["username"].as_str().unwrap_or("").trim().to_string();
    if username.chars().count() < 3
        || username.chars().count() > 32
        || !regex::Regex::new(r"^[A-Za-z][A-Za-z0-9_-]*$")
            .expect("valid regex")
            .is_match(&username)
    {
        return Err(validation_error(vec![format!(
            "Username must be 3-32 characters, start with a letter, and contain only letters, numbers, hyphens or underscores"
        )]));
    }

    let email = body["email"]
        .as_str()
        .unwrap_or("")
        .to_lowercase()
        .trim()
        .to_string();
    if email.is_empty() || !email.contains('@') {
        return Err(validation_error(vec!["Please enter a valid email address".to_string()]));
    }

    let role = body["role"].as_str().unwrap_or("");
    let role = if role == "admin" {
        "admin"
    } else if role == "user" {
        "user"
    } else {
        return Err(validation_error(vec!["Invalid role".to_string()]));
    };

    let status = body["status"].as_str().unwrap_or("");
    let status = if status == "banned" {
        "banned"
    } else if status == "active" {
        "active"
    } else {
        return Err(validation_error(vec!["Invalid status".to_string()]));
    };

    // normalizeBoolean: true | 'true' | 1 | '1' (schema already required boolean).
    let verify_email = matches!(body["verifyEmail"], Value::Bool(true));

    let email_code = body["emailCode"].as_str().map(|s| s.trim().to_string());
    if verify_email {
        let Some(code_value) = &email_code else {
            return Err(ApiError::bad_request(code::EMAIL_CODE_REQUIRED).into_response());
        };
        static SIX_DIGITS: once_cell::sync::Lazy<regex::Regex> =
            once_cell::sync::Lazy::new(|| regex::Regex::new(r"^\d{6}$").expect("valid regex"));
        if !SIX_DIGITS.is_match(code_value) {
            return Err(ApiError::bad_request(code::INVALID_EMAIL_CODE).into_response());
        }
    }

    Ok(Ok(AdminCreateInput {
        username,
        email,
        role: role.to_string(),
        status: status.to_string(),
        verify_email,
        email_code,
    }))
}

struct AdminCreateInput {
    username: String,
    email: String,
    role: String,
    status: String,
    verify_email: bool,
    email_code: Option<String>,
}

async fn create_user(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let input = match normalize_admin_create_user_input(&body) {
        Ok(Ok(input)) => input,
        Ok(Err(messages)) => return Ok(validation_error(messages)),
        Err(response) => return Ok(response),
    };

    if contains_dangerous_chars(&input.username) {
        return Err(ApiError::bad_request(code::USERNAME_CONTAINS_ILLEGAL));
    }

    let normalized_email = match validate_admin_create_email_target(&state, &input.email).await? {
        Ok(email) => email,
        Err(err) => return Ok(err.into_response()),
    };

    if find_user_by_username(&state, &input.username).await?.is_some() {
        return Err(ApiError::bad_request(code::USER_EXISTS));
    }

    if input.verify_email {
        if !is_smtp_enabled(&state).await? {
            return Err(ApiError::bad_request(code::EMAIL_VERIFICATION_DISABLED));
        }
        let code_value = input.email_code.clone().unwrap_or_default();
        let valid = verify_code(&state, &normalized_email, &code_value).await?;
        if !valid {
            return Err(ApiError::bad_request(code::INVALID_EMAIL_CODE));
        }
    }

    let default_quota = get_default_quota_config(&state).await?;
    let lock_key = admin_create_email_lock_key(&normalized_email);

    enum CreateTxError {
        Sql(sqlx::Error),
        UsernameExists,
        EmailExists,
        UniqueViolation,
    }
    impl From<sqlx::Error> for CreateTxError {
        fn from(err: sqlx::Error) -> Self {
            // TS maps a P2002 unique violation to USER_EXISTS.
            if let sqlx::Error::Database(db) = &err {
                if db.code().map(|c| c.into_owned()).as_deref() == Some("23505") {
                    return CreateTxError::UniqueViolation;
                }
            }
            CreateTxError::Sql(err)
        }
    }

    let initial_password = generate_random_password(16);
    let password_hash = bcrypt::hash(&initial_password, 12)
        .map_err(|e| ApiError::internal(format!("bcrypt hash failed: {e}")))?;

    let created: (i32, String) = {
        let result: Result<(i32, String), CreateTxError> = async {
            let mut tx = state.db.begin().await?;
            advisory_transaction_lock(
                &mut *tx,
                advisory_lock_namespace::USER_CREATE_EMAIL,
                lock_key as i64,
            )
            .await
            .map_err(CreateTxError::Sql)?;

            let username_exists: Option<(i32,)> =
                sqlx::query_as("SELECT id FROM users WHERE username = $1")
                    .bind(&input.username)
                    .fetch_optional(&mut *tx)
                    .await?;
            if username_exists.is_some() {
                return Err(CreateTxError::UsernameExists);
            }
            let email_exists: Option<(i32,)> =
                sqlx::query_as("SELECT id FROM users WHERE email = $1")
                    .bind(&normalized_email)
                    .fetch_optional(&mut *tx)
                    .await?;
            if email_exists.is_some() {
                return Err(CreateTxError::EmailExists);
            }

            let user_id = create_user_with_quota(
                &mut *tx,
                &input.username,
                &normalized_email,
                &password_hash,
                &input.role,
                default_quota,
            )
            .await
            .map_err(CreateTxError::Sql)?;

            if input.status == "banned" {
                sqlx::query(
                    "UPDATE users SET status = 'banned'::\"UserStatus\", \
                     ban_reason = 'Admin created banned user' WHERE id = $1",
                )
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            }

            Ok((user_id, initial_password))
        }
        .await;
        match result {
            Ok(value) => value,
            Err(CreateTxError::UsernameExists) | Err(CreateTxError::UniqueViolation) => {
                return Err(ApiError::bad_request(code::USER_EXISTS))
            }
            Err(CreateTxError::EmailExists) => {
                return Err(ApiError::bad_request(code::EMAIL_ALREADY_REGISTERED))
            }
            Err(CreateTxError::Sql(err)) => return Err(ApiError::from_sql(err)),
        }
    };

    let (user_id, initial_password) = created;

    let Some(created_user) = find_user_by_id(&state, user_id).await? else {
        delete_user_by_id(&state, user_id).await?;
        return Err(ApiError::not_found(code::USER_NOT_FOUND));
    };

    let password_delivery = if input.verify_email { "email" } else { "display" };
    if password_delivery == "email" {
        let sent = send_admin_created_user_email(
            &normalized_email,
            &input.username,
            &initial_password,
        )
        .await;
        if !sent {
            delete_user_by_id(&state, user_id).await?;
            return Err(ApiError::new(
                code::EMAIL_SEND_FAILED,
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }

    create_log(
        &state,
        admin.0.id,
        "user",
        "user.create",
        &format!(
            "Admin created user \"{}\" (ID: {}, email: {}, role: {}, status: {}, passwordDelivery: {})",
            input.username, user_id, normalized_email, input.role, input.status, password_delivery
        ),
        "success",
    )
    .await;

    log_admin_action(
        &state,
        admin.0.id,
        "user.create",
        AdminAudit {
            target_username: Some(&input.username),
            resource_type: Some("user"),
            resource_name: None,
            reason: Some("Admin created user account"),
        },
    )
    .await;

    let response = json!({
        "user": {
            "id": created_user.id,
            "username": created_user.username,
            "email": created_user.email,
            "role": created_user.role,
            "status": created_user.status,
            "avatarStyle": created_user.avatar_style,
            "avatarBadgeId": created_user.avatar_badge_id.clone(),
            "created_at": iso(created_user.created_at),
            "updated_at": iso(created_user.updated_at),
            "createdAt": iso(created_user.created_at),
        },
        "passwordDelivery": password_delivery,
    });
    let response = if password_delivery == "display" {
        let mut map = response.as_object().cloned().unwrap_or_default();
        map.insert("initialPassword".into(), json!(initial_password));
        Value::Object(map)
    } else {
        response
    };

    Ok(Json(response).into_response())
}

// ===========================================================================
// GET /lookup — 按用户名精确查找用户
// ===========================================================================

async fn lookup_user(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let Some(username) = params.get("username").map(|s| s.trim()) else {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "Username is required",
        ));
    };
    if username.is_empty() {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "Username is required",
        ));
    }

    let row: Option<(i32, String, Option<String>, String, String, Decimal)> = sqlx::query_as(
        "SELECT id, username, email, role::text AS role, status::text AS status, balance \
         FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(&state.db)
    .await?;

    let Some((id, found_username, email, role, status, balance)) = row else {
        return Err(ApiError::not_found(code::USER_NOT_FOUND));
    };

    let (ssh_key_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM ssh_keys WHERE user_id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;

    Ok(Json(json!({
        "user": {
            "id": id,
            "username": found_username,
            "email": email,
            "role": role,
            "status": status,
            "balance": num(balance),
            "hasSshKey": ssh_key_count > 0,
        }
    })))
}

// ===========================================================================
// GET /{id} — 获取用户详情
// ===========================================================================

async fn get_user(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_number_id(&id)?;

    // 普通用户只能查看自己
    if user.role != "admin" && user.id != user_id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    let quota = get_user_quota(&state.db, found.id).await?;
    let instance_count = count_instances_by_user_id(&state, found.id).await?;

    let quota_json = quota.map(|q| {
        json!({
            "hostLimit": q.host_limit,
            "hostUsed": q.host_used,
            "friendLimit": q.friend_limit,
            "friendUsed": q.friend_used,
            "packageLimit": q.package_limit,
            "packageUsed": q.package_used,
            "monthlyTrafficLimit": q.monthly_traffic_limit.map(|v| v.to_string()),
            "monthlyTrafficUsed": q.monthly_traffic_used.to_string(),
            "extraTrafficQuota": q.extra_traffic_quota.to_string(),
            "trafficStatus": q.traffic_status,
        })
    });

    Ok(Json(json!({
        "user": {
            "id": found.id,
            "username": found.username,
            "email": found.email,
            "role": found.role,
            "status": found.status,
            "avatarStyle": found.avatar_style,
            "avatarBadgeId": found.avatar_badge_id,
            "quota": quota_json,
            "instanceCount": instance_count,
            "createdAt": iso(found.created_at),
        }
    })))
}

// ===========================================================================
// POST /{id}/change-email/send-code — 发送修改邮箱验证码
// ===========================================================================

async fn change_email_send_code(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let user_id = js_number_id(&id)?;

    // Fastify schema: email required, format email.
    let Some(email_value) = body.get("email") else {
        return Ok(validation_error(vec!["email is required".to_string()]));
    };
    let Some(raw_email) = email_value.as_str() else {
        return Ok(validation_error(vec!["body/email must be string".to_string()]));
    };
    if !is_email_format(raw_email) {
        return Ok(validation_error(vec![
            "Please enter a valid email address".to_string(),
        ]));
    }

    if user.id != user_id {
        return Ok(ApiError::forbidden(code::FORBIDDEN).into_response());
    }

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    if !is_smtp_enabled(&state).await? {
        return Err(ApiError::bad_request(code::EMAIL_VERIFICATION_DISABLED));
    }

    if found.email.is_some() {
        let verified = is_operation_verified(&state, user_id, "change_email").await?;
        if !verified {
            return Ok(verification_required("change_email"));
        }
    }

    let normalized_email =
        match validate_email_change_target(&state, raw_email, found.email.as_deref(), user_id)
            .await?
        {
            Ok(email) => email,
            Err(err) => return Ok(err.into_response()),
        };

    let Some((code_value, expires_at)) = create_verification_code(&state, &normalized_email).await?
    else {
        return Err(ApiError::new(
            code::TOO_MANY_VERIFICATION_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
        ));
    };

    let sent = crate::libs::external::send_verification_email(
        &normalized_email,
        &code_value,
        10,
        "change_email",
    )
    .await;
    if !sent {
        return Err(ApiError::new(code::EMAIL_SEND_FAILED, StatusCode::INTERNAL_SERVER_ERROR));
    }

    Ok(Json(json!({
        "message": "Verification code sent",
        "expiresAt": iso(expires_at),
    }))
    .into_response())
}

// ===========================================================================
// PATCH /{id} — 更新用户信息
// ===========================================================================

fn validate_update_user_schema(body: &Value) -> Option<Response> {
    let mut messages: Vec<String> = Vec::new();

    if let Some(email) = body.get("email") {
        match email.as_str() {
            Some(s) if is_email_format(s) => {}
            Some(_) => messages.push("Please enter a valid email address".to_string()),
            None => messages.push("body/email must be string".to_string()),
        }
    }

    if let Some(password) = body.get("password") {
        match password.as_str() {
            // setErrorHandler special-cases minLength on field 'password'.
            Some(s) if s.chars().count() >= 6 => {}
            Some(_) => messages.push("Password must be at least 8 characters".to_string()),
            None => messages.push("body/password must be string".to_string()),
        }
    }

    if let Some(email_code) = body.get("emailCode") {
        match email_code.as_str() {
            Some(s) => {
                let len = s.chars().count();
                if len < 6 {
                    messages.push("emailCode is too short".to_string());
                } else if len > 6 {
                    messages.push("emailCode is too long".to_string());
                }
            }
            None => messages.push("body/emailCode must be string".to_string()),
        }
    }

    if let Some(avatar_style) = body.get("avatarStyle") {
        match avatar_style.as_str() {
            Some(s) if AVATAR_STYLES.contains(&s) => {}
            Some(_) => {
                messages.push("must be equal to one of the allowed values".to_string())
            }
            None => messages.push("body/avatarStyle must be string".to_string()),
        }
    }

    if messages.is_empty() {
        None
    } else {
        Some(validation_error(messages))
    }
}

async fn update_user(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    if let Some(response) = validate_update_user_schema(&body) {
        return Ok(response);
    }

    let user_id = js_number_id(&id)?;

    // 只能修改自己或管理员可修改任意用户
    if user.role != "admin" && user.id != user_id {
        return Ok(ApiError::forbidden(code::FORBIDDEN).into_response());
    }

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    let body_email = body.get("email").and_then(Value::as_str);
    let body_password = body.get("password").and_then(Value::as_str);
    let body_avatar_style = body.get("avatarStyle").and_then(Value::as_str);
    let body_current_password = body.get("currentPassword").and_then(Value::as_str);
    let body_email_code = body.get("emailCode").and_then(Value::as_str);

    let is_self = user.id == user_id;
    let is_changing_password = is_self && body_password.map(|p| !p.is_empty()).unwrap_or(false);
    let is_changing_email = is_self
        && body_email.is_some()
        && Some(body_email.unwrap_or("")) != found.email.as_deref()
        && found.email.is_some();

    // 敏感操作二次验证：修改密码或邮箱时需要验证（管理员修改他人时跳过）
    if is_self {
        if is_changing_password {
            // 验证当前密码（防止会话劫持）
            let Some(current_password) = body_current_password else {
                return Err(ApiError::with_message(
                    code::INVALID_PARAMS,
                    StatusCode::BAD_REQUEST,
                    "Current password is required",
                ));
            };
            let valid_password = bcrypt::verify(current_password, &found.password_hash)
                .map_err(|e| ApiError::internal(format!("bcrypt compare failed: {e}")))?;
            if !valid_password {
                return Err(ApiError::with_message(
                    code::INVALID_CREDENTIALS,
                    StatusCode::UNAUTHORIZED,
                    "Current password is incorrect",
                ));
            }
            let verified = is_operation_verified(&state, user_id, "change_password").await?;
            if !verified {
                return Ok(verification_required("change_password"));
            }
        }
        if let Some(email) = body_email {
            if Some(email) != found.email.as_deref() {
                if is_changing_email {
                    let verified =
                        is_operation_verified(&state, user_id, "change_email").await?;
                    if !verified {
                        return Ok(verification_required("change_email"));
                    }
                }
                if body_email_code.is_none() {
                    return Err(ApiError::bad_request(code::EMAIL_CODE_REQUIRED));
                }
            }
        }
    }

    let mut new_email: Option<String> = None;
    if let Some(email) = body_email {
        let normalized_email =
            match validate_email_change_target(&state, email, found.email.as_deref(), user_id)
                .await?
            {
                Ok(email) => email,
                Err(err) => return Ok(err.into_response()),
            };

        if is_self && Some(email) != found.email.as_deref() {
            let verified = verify_code(
                &state,
                &normalized_email,
                body_email_code.unwrap_or_default(),
            )
            .await?;
            if !verified {
                return Err(ApiError::bad_request(code::INVALID_EMAIL_CODE));
            }
        }

        new_email = Some(normalized_email);
    }

    let mut new_password_hash: Option<String> = None;
    if let Some(password) = body_password.filter(|p| !p.is_empty()) {
        let password_check = validate_password(password);
        if !password_check.valid {
            let mut err = ApiError::bad_request(code::PASSWORD_TOO_WEAK);
            if let Some(message) = password_check.message {
                err = err.with_details(message);
            }
            return Ok(err.into_response());
        }
        new_password_hash = Some(
            bcrypt::hash(password, 12)
                .map_err(|e| ApiError::internal(format!("bcrypt hash failed: {e}")))?,
        );
    }

    // `if (avatarStyle)` truthy check: empty string is skipped.
    let new_avatar_style: Option<&str> = body_avatar_style.filter(|s| !s.is_empty());

    let has_updates =
        new_email.is_some() || new_password_hash.is_some() || new_avatar_style.is_some();

    if has_updates {
        // 在真正修改前原子领取验证记录，避免并发请求复用同一份二次验证。
        if is_changing_password {
            let claimed = claim_operation_verification(&state, user_id, "change_password").await?;
            if !claimed {
                return Ok(verification_required("change_password"));
            }
        }
        if is_changing_email {
            let claimed = claim_operation_verification(&state, user_id, "change_email").await?;
            if !claimed {
                return Ok(verification_required("change_email"));
            }
        }

        if let Some(password_hash) = &new_password_hash {
            update_user_password_and_invalidate_sessions(
                &state,
                user_id,
                password_hash,
                new_email.as_deref(),
                new_avatar_style,
            )
            .await?;
        } else {
            update_user_fields(
                &state,
                user_id,
                new_email.as_deref(),
                None,
                new_avatar_style,
            )
            .await?;
        }

        if new_password_hash.is_some() {
            close_user_sessions(user_id, "Password updated");
            clear_auth_cache(user_id).await;
        }

        let mut update_actions: Vec<&str> = Vec::new();
        if body_email.is_some() {
            update_actions.push("email");
        }
        if body_password.is_some() && !body_password.unwrap().is_empty() {
            update_actions.push("password");
        }
        if !new_avatar_style.unwrap_or("").is_empty() {
            update_actions.push("avatarStyle");
        }

        let admin_prefix = if user.role == "admin" && !is_self {
            format!("Admin updated user \"{}\":", found.username)
        } else {
            String::new()
        };
        // TS keeps the leading space between the (possibly empty) prefix and
        // the joined action list — preserved verbatim.
        create_log(
            &state,
            user.id,
            "personal",
            "profile.update",
            &format!("{admin_prefix} {}", update_actions.join(", ")),
            "success",
        )
        .await;

        if is_self && new_password_hash.is_some() {
            // lib/notifier.ts sendNotification('password_changed') — inbox part.
            let title = "🔑 密码已修改";
            let message = "您的账户密码已成功修改\n如非本人操作，请立即联系管理员";
            create_inbox_notification(
                &state,
                user_id,
                "password_changed",
                title,
                message,
                json!({ "instanceName": "" }),
            )
            .await;
            push_external_notification_stub(user_id, "password_changed", title);
        }
    }

    let reauth_required = new_password_hash.is_some() && is_self;
    Ok(Json(json!({
        "message": "User info updated",
        "reauthRequired": reauth_required,
    }))
    .into_response())
}

// ===========================================================================
// PATCH /{id}/role — Change user role (admin)
// ===========================================================================

enum TxError {
    Sql(sqlx::Error),
    Sentinel(&'static str),
}

impl From<sqlx::Error> for TxError {
    fn from(err: sqlx::Error) -> Self {
        TxError::Sql(err)
    }
}

async fn update_user_role(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    // Fastify schema: role required, enum ['admin', 'user'].
    let role = match body.get("role") {
        None => {
            return Ok(validation_error(vec!["role is required".to_string()]));
        }
        Some(Value::String(s)) if s == "admin" || s == "user" => s.clone(),
        Some(_) => {
            return Ok(validation_error(vec![
                "must be equal to one of the allowed values".to_string(),
            ]));
        }
    };

    let user_id = js_number_id(&id)?;

    if admin.0.id == user_id {
        return Err(ApiError::bad_request(code::CANNOT_MODIFY_SELF));
    }

    struct RoleUpdate {
        changed: bool,
        username: String,
        previous_role: String,
        role: String,
        revoked_sessions: i64,
    }

    let role_update: RoleUpdate = {
        let result: Result<RoleUpdate, TxError> = async {
            let mut tx = state.db.begin().await?;
            let locked = try_advisory_transaction_lock(
                &mut *tx,
                advisory_lock_namespace::USER_ADMIN_ROLE,
                1,
            )
            .await?;
            if !locked {
                return Err(TxError::Sentinel("USER_ADMIN_ROLE_LOCK_BUSY"));
            }

            let actor: Option<(String, String)> = sqlx::query_as(
                "SELECT role::text, status::text FROM users WHERE id = $1",
            )
            .bind(admin.0.id)
            .fetch_optional(&mut *tx)
            .await?;
            match &actor {
                Some((role, status)) if role == "admin" && status == "active" => {}
                _ => return Err(TxError::Sentinel("ADMIN_PERMISSION_REVOKED")),
            }

            let target: Option<(String, String, String)> = sqlx::query_as(
                "SELECT username, role::text, status::text FROM users WHERE id = $1",
            )
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((username, target_role, target_status)) = target else {
                return Err(TxError::Sentinel("USER_NOT_FOUND"));
            };

            if role == target_role {
                return Ok(RoleUpdate {
                    changed: false,
                    username,
                    previous_role: target_role,
                    role,
                    revoked_sessions: 0,
                });
            }

            if role == "admin" && target_status != "active" {
                return Err(TxError::Sentinel("TARGET_NOT_ACTIVE"));
            }

            if target_role == "admin" && role == "user" && target_status == "active" {
                let (active_admin_count,): (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'",
                )
                .fetch_one(&mut *tx)
                .await?;
                if active_admin_count <= 1 {
                    return Err(TxError::Sentinel("LAST_ACTIVE_ADMIN"));
                }
            }

            sqlx::query("UPDATE users SET role = $2::\"UserRole\" WHERE id = $1")
                .bind(user_id)
                .bind(&role)
                .execute(&mut *tx)
                .await?;

            let revoked = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;

            let invalidated_at = Utc::now().timestamp();
            sqlx::query(
                "INSERT INTO token_invalidations (user_id, session_id, invalidated_at, created_at) \
                 VALUES ($1, $2, $3, now()) \
                 ON CONFLICT (user_id, session_id) \
                 DO UPDATE SET invalidated_at = EXCLUDED.invalidated_at",
            )
            .bind(user_id)
            .bind(crate::libs::security::USER_LEVEL_SESSION_ID)
            .bind(invalidated_at)
            .execute(&mut *tx)
            .await?;

            Ok(RoleUpdate {
                changed: true,
                username,
                previous_role: target_role,
                role,
                revoked_sessions: revoked.rows_affected() as i64,
            })
        }
        .await;
        match result {
            Ok(value) => value,
            Err(TxError::Sql(err)) => return Err(ApiError::from_sql(err)),
            Err(TxError::Sentinel("ADMIN_PERMISSION_REVOKED")) => {
                return Err(ApiError::forbidden(code::FORBIDDEN))
            }
            Err(TxError::Sentinel("USER_NOT_FOUND")) => {
                return Err(ApiError::not_found(code::USER_NOT_FOUND))
            }
            Err(TxError::Sentinel("TARGET_NOT_ACTIVE")) => {
                return Err(ApiError::with_message(
                    code::INVALID_PARAMS,
                    StatusCode::BAD_REQUEST,
                    "Only active users can be promoted to admin",
                ));
            }
            Err(TxError::Sentinel("LAST_ACTIVE_ADMIN")) => {
                return Err(ApiError::with_message(
                    code::INVALID_PARAMS,
                    StatusCode::BAD_REQUEST,
                    "Cannot remove the last active admin",
                ));
            }
            Err(TxError::Sentinel("USER_ADMIN_ROLE_LOCK_BUSY")) => {
                return Err(ApiError::with_message(
                    code::INVALID_PARAMS,
                    StatusCode::CONFLICT,
                    "Another admin role update is in progress, please retry",
                ));
            }
            Err(TxError::Sentinel(other)) => {
                return Err(ApiError::internal(format!("unexpected sentinel: {other}")));
            }
        }
    };

    if !role_update.changed {
        return Ok(Json(json!({
            "message": "User role unchanged",
            "role": role_update.role,
        }))
        .into_response());
    }

    // 清除认证缓存，确保角色变更立即生效（Rust 端为 no-op）
    clear_auth_cache(user_id).await;

    let closed_terminals = close_user_sessions(user_id, "User role changed by admin");
    if closed_terminals > 0 {
        tracing::info!(
            "[Role] Closed {closed_terminals} terminal session(s) for user {user_id}"
        );
    }

    create_log(
        &state,
        admin.0.id,
        "user",
        "user.role.update",
        &format!(
            "Changed user \"{}\" (ID: {}) role from {} to {}",
            role_update.username, user_id, role_update.previous_role, role_update.role
        ),
        "success",
    )
    .await;

    log_admin_action(
        &state,
        admin.0.id,
        "user.role.update",
        AdminAudit {
            target_username: Some(&role_update.username),
            resource_type: Some("user"),
            resource_name: None,
            reason: Some(&format!(
                "Admin changed user role from {} to {}",
                role_update.previous_role, role_update.role
            )),
        },
    )
    .await;

    Ok(Json(json!({
        "message": "User role updated",
        "role": role_update.role,
        "revokedSessions": role_update.revoked_sessions,
    }))
    .into_response())
}

// ===========================================================================
// POST /{id}/quota/recalculate — 重算用户配额使用量 (管理员)
// ===========================================================================

async fn recalculate_quota(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_number_id(&id)?;

    find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    // 新配额系统：重新计算用户的资源使用量（不再计算实例配额）
    let (host_used, friend_used, package_used) = calculate_user_quota_used(&state, user_id).await?;
    update_user_quota_used(&state, user_id, host_used, friend_used, package_used).await?;

    Ok(Json(json!({
        "message": "Quota recalculated",
        "quota": {
            "hostUsed": host_used,
            "friendUsed": friend_used,
            "packageUsed": package_used,
        }
    })))
}

// ===========================================================================
// POST /me/quota/increase — 用户自行增加配额
// ===========================================================================

async fn increase_own_quota(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    // Fastify schema: integer >= 0 properties (both optional). AJV rejects with
    // a VALIDATION_ERROR whose message list comes from the setErrorHandler.
    fn parse_quota_limit(body: &Value, key: &str) -> Result<Option<i64>, Response> {
        match body.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => {
                let n = value
                    .as_i64()
                    .or_else(|| value.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64));
                match n {
                    None => Err(validation_error(vec!["must be integer".to_string()])),
                    Some(v) if v < 0 => {
                        Err(validation_error(vec!["must be >= 0".to_string()]))
                    }
                    Some(v) => Ok(Some(v)),
                }
            }
        }
    }
    let host_limit = match parse_quota_limit(&body, "hostLimit") {
        Ok(v) => v,
        Err(response) => return Ok(response),
    };
    let friend_limit = match parse_quota_limit(&body, "friendLimit") {
        Ok(v) => v,
        Err(response) => return Ok(response),
    };

    let user_id = user.0.id;

    // 检查是否只提供了一种配额类型
    let provided_types = [host_limit.is_some(), friend_limit.is_some()]
        .iter()
        .filter(|p| **p)
        .count();
    if provided_types != 1 {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "每次只能增加一种配额类型",
        ));
    }

    // 获取当前配额
    let Some(current_quota) = get_user_quota(&state.db, user_id).await? else {
        return Err(ApiError::with_message(
            code::USER_NOT_FOUND,
            StatusCode::NOT_FOUND,
            "配额信息不存在",
        ));
    };

    let (quota_type, increase_amount, current_used, current_limit, expected_increase, new_limit) =
        if let Some(host_limit) = host_limit {
            (
                "host",
                host_limit - current_quota.host_limit as i64,
                current_quota.host_used as i64,
                current_quota.host_limit as i64,
                5i64,
                host_limit,
            )
        } else {
            let friend_limit = friend_limit.unwrap_or(0);
            (
                "friend",
                friend_limit - current_quota.friend_limit as i64,
                current_quota.friend_used as i64,
                current_quota.friend_limit as i64,
                10i64,
                friend_limit,
            )
        };

    // 验证增加数量是否正确
    if increase_amount != expected_increase {
        let type_name = if quota_type == "host" { "宿主机" } else { "好友" };
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            format!("{type_name}每次只能增加 {expected_increase} 个"),
        ));
    }

    // 检查使用率是否达到50%
    if current_limit == 0 {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "配额限制为0，无法计算使用率",
        ));
    }

    let usage_percent = (current_used as f64 / current_limit as f64) * 100.0;
    if usage_percent < 50.0 {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            format!(
                "当前使用率为 {}%，需要达到50%（含）才能增加配额",
                usage_percent.round() as i64
            ),
        ));
    }

    // 更新配额
    if quota_type == "host" {
        update_user_quota_limits(&state, user_id, Some(new_limit), None).await?;
    } else {
        update_user_quota_limits(&state, user_id, None, Some(new_limit)).await?;
    }

    // 记录日志
    let type_name = if quota_type == "host" { "宿主机" } else { "好友" };
    create_log(
        &state,
        user_id,
        "personal",
        "quota.increase",
        &format!("用户自行增加{type_name}配额：{current_limit} → {new_limit}"),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "配额增加成功" })).into_response())
}

// ===========================================================================
// PATCH /{id}/status — 封禁/解封用户 (管理员)
// ===========================================================================

async fn update_user_status(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    // Fastify schema: status required enum; reason optional string maxLength 500.
    let status = match body.get("status") {
        None => {
            return Ok(validation_error(vec!["status is required".to_string()]));
        }
        Some(Value::String(s)) if s == "active" || s == "banned" => s.clone(),
        Some(_) => {
            return Ok(validation_error(vec![
                "must be equal to one of the allowed values".to_string(),
            ]));
        }
    };
    let reason = match body.get("reason") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            if s.chars().count() > 500 {
                return Ok(validation_error(vec!["reason is too long".to_string()]));
            }
            Some(s.clone())
        }
        Some(_) => {
            return Ok(validation_error(vec!["body/reason must be string".to_string()]));
        }
    };

    let user_id = js_number_id(&id)?;

    // 不能封禁自己
    if admin.0.id == user_id {
        return Err(ApiError::bad_request(code::CANNOT_MODIFY_SELF));
    }

    struct StatusTarget {
        username: String,
        email: Option<String>,
    }

    let target: StatusTarget = {
        let result: Result<StatusTarget, TxError> = async {
            let mut tx = state.db.begin().await?;
            let locked = try_advisory_transaction_lock(
                &mut *tx,
                advisory_lock_namespace::USER_ADMIN_ROLE,
                1,
            )
            .await?;
            if !locked {
                return Err(TxError::Sentinel("USER_ADMIN_ROLE_LOCK_BUSY"));
            }
            let actor: Option<(String, String)> = sqlx::query_as(
                "SELECT role::text, status::text FROM users WHERE id = $1",
            )
            .bind(admin.0.id)
            .fetch_optional(&mut *tx)
            .await?;
            match &actor {
                Some((role, status)) if role == "admin" && status == "active" => {}
                _ => return Err(TxError::Sentinel("ADMIN_PERMISSION_REVOKED")),
            }
            let target: Option<(String, String, Option<String>)> = sqlx::query_as(
                "SELECT username, role::text, email FROM users WHERE id = $1",
            )
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((username, target_role, email)) = target else {
                return Err(TxError::Sentinel("USER_NOT_FOUND"));
            };
            if target_role == "admin" && status == "banned" {
                return Err(TxError::Sentinel("CANNOT_BAN_ADMIN"));
            }

            sqlx::query(
                "UPDATE users SET status = $2::\"UserStatus\", ban_reason = $3 WHERE id = $1",
            )
            .bind(user_id)
            .bind(&status)
            .bind(if status == "banned" {
                reason.clone().filter(|r| !r.is_empty())
            } else {
                None
            })
            .execute(&mut *tx)
            .await?;

            if status == "banned" {
                sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?;
                let invalidated_at = Utc::now().timestamp();
                sqlx::query(
                    "INSERT INTO token_invalidations (user_id, session_id, invalidated_at, created_at) \
                     VALUES ($1, $2, $3, now()) \
                     ON CONFLICT (user_id, session_id) \
                     DO UPDATE SET invalidated_at = EXCLUDED.invalidated_at",
                )
                .bind(user_id)
                .bind(crate::libs::security::USER_LEVEL_SESSION_ID)
                .bind(invalidated_at)
                .execute(&mut *tx)
                .await?;
            }

            Ok(StatusTarget { username, email })
        }
        .await;
        match result {
            Ok(value) => value,
            Err(TxError::Sql(err)) => return Err(ApiError::from_sql(err)),
            Err(TxError::Sentinel("ADMIN_PERMISSION_REVOKED")) => {
                return Err(ApiError::forbidden(code::FORBIDDEN))
            }
            Err(TxError::Sentinel("USER_NOT_FOUND")) => {
                return Err(ApiError::not_found(code::USER_NOT_FOUND))
            }
            Err(TxError::Sentinel("CANNOT_BAN_ADMIN")) => {
                return Err(ApiError::bad_request(code::CANNOT_BAN_ADMIN))
            }
            Err(TxError::Sentinel("USER_ADMIN_ROLE_LOCK_BUSY")) => {
                return Err(ApiError::with_message(
                    code::INVALID_PARAMS,
                    StatusCode::CONFLICT,
                    "Another user permission update is in progress, please retry",
                ));
            }
            Err(TxError::Sentinel(other)) => {
                return Err(ApiError::internal(format!("unexpected sentinel: {other}")));
            }
        }
    };

    // Evict legacy caches only after account state and revocation commit (no-op).
    clear_auth_cache(user_id).await;

    if status == "banned" {
        let closed_sessions = close_user_sessions(user_id, "User account banned");
        if closed_sessions > 0 {
            tracing::info!(
                "[Ban] Closed {closed_sessions} terminal session(s) for user {user_id}"
            );
        }
    }

    let banned = status == "banned";
    create_log(
        &state,
        admin.0.id,
        "user",
        if banned { "user.ban" } else { "user.unban" },
        &format!(
            "{} user \"{}\" (ID: {}, email: {}){}",
            if banned { "Banned" } else { "Unbanned" },
            target.username,
            user_id,
            target.email.clone().unwrap_or_else(|| "N/A".to_string()),
            reason
                .as_ref()
                .map(|r| format!(" - Reason: {r}"))
                .unwrap_or_default(),
        ),
        "success",
    )
    .await;

    // AUTH003: 管理员操作审计日志
    log_admin_action(
        &state,
        admin.0.id,
        if banned { "user.ban" } else { "user.unban" },
        AdminAudit {
            target_username: Some(&target.username),
            resource_type: Some("user"),
            resource_name: None,
            reason: Some(if banned {
                reason.as_deref().unwrap_or("Admin banned user")
            } else {
                "Admin unbanned user"
            }),
        },
    )
    .await;

    // 如果是封禁且提供了原因，发送封禁邮件通知（fire-and-forget；SMTP stub）
    if banned {
        if let (Some(reason), Some(email)) = (reason.as_deref(), target.email.as_deref()) {
            send_ban_notification_email(email, &target.username, reason).await;
        }
    }

    Ok(Json(json!({
        "message": if banned { "User banned" } else { "User unbanned" },
    }))
    .into_response())
}

// ===========================================================================
// DELETE /{id} — 删除用户 (管理员)
// ===========================================================================

async fn delete_user(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_number_id(&id)?;

    // 不能删除自己
    if admin.0.id == user_id {
        return Err(ApiError::bad_request(code::CANNOT_DELETE_SELF));
    }

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    // 不能删除管理员
    if found.role == "admin" {
        return Err(ApiError::bad_request(code::CANNOT_DELETE_ADMIN));
    }

    // 检查是否有实例
    let instance_count = count_instances_by_user_id(&state, user_id).await?;
    if instance_count > 0 {
        return Err(
            ApiError::bad_request(code::USER_HAS_INSTANCES).with_details(format!(
                "{}",
                instance_count
            )),
        );
    }

    delete_user_by_id(&state, user_id).await?;

    create_log(
        &state,
        admin.0.id,
        "user",
        "user.delete",
        &format!(
            "Deleted user \"{}\" (ID: {}, email: {}, role: {})",
            found.username,
            user_id,
            found.email.clone().unwrap_or_else(|| "N/A".to_string()),
            found.role
        ),
        "success",
    )
    .await;

    // AUTH003: 管理员操作审计日志 - 删除用户是高危操作
    log_admin_action(
        &state,
        admin.0.id,
        "user.delete",
        AdminAudit {
            target_username: Some(&found.username),
            resource_type: Some("user"),
            resource_name: None,
            reason: Some("Admin deleted user account"),
        },
    )
    .await;

    Ok(Json(json!({ "message": "User deleted" })))
}

// ===========================================================================
// GET /{id}/sessions — 管理员获取指定用户的所有会话
// ===========================================================================

async fn list_user_sessions(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_parse_int_id(&id)?;

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    let tokens = get_user_sessions(&state, found.id).await?;
    let sessions: Vec<Value> = tokens
        .iter()
        .map(|t| {
            json!({
                "token": format!("{}...", &t.token.chars().take(20).collect::<String>()),
                "ip": t.ip.clone().unwrap_or_else(|| "unknown".to_string()),
                "userAgent": t.user_agent.clone().unwrap_or_else(|| "unknown".to_string()),
                "createdAt": t.created_at.timestamp_millis(),
                "lastActiveAt": t.last_active_at.timestamp_millis(),
                "isCurrent": false,
            })
        })
        .collect();

    Ok(Json(json!({ "sessions": sessions })))
}

// ===========================================================================
// POST /{id}/revoke-sessions — 管理员撤销指定用户的所有会话
// ===========================================================================

async fn revoke_user_sessions(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_parse_int_id(&id)?;

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    let count = revoke_all_user_refresh_tokens(&state.db, user_id)
        .await
        .map_err(ApiError::from_sql)?;
    invalidate_user_access_tokens(&state.db, user_id)
        .await
        .map_err(ApiError::from_sql)?;
    // 清除认证缓存，确保令牌失效立即生效（no-op）
    clear_auth_cache(user_id).await;

    // 关闭该用户的所有终端连接（terminal proxy 未移植，返回 0）
    let closed_terminals = close_user_sessions(user_id, "Sessions revoked by admin");
    if closed_terminals > 0 {
        tracing::info!(
            "[RevokeSession] Closed {closed_terminals} terminal session(s) for user {user_id}"
        );
    }

    create_log(
        &state,
        admin.0.id,
        "user",
        "user.revoke_sessions",
        &format!(
            "Revoked {} sessions for user \"{}\" (ID: {})",
            count, found.username, user_id
        ),
        "success",
    )
    .await;

    log_admin_action(
        &state,
        admin.0.id,
        "user.revoke_sessions",
        AdminAudit {
            target_username: Some(&found.username),
            resource_type: Some("session"),
            resource_name: None,
            reason: None,
        },
    )
    .await;

    Ok(Json(json!({ "message": format!("已撤销 {count} 个会话") })))
}

// ===========================================================================
// POST /{id}/reset-password — 管理员重置用户密码（自动生成随机密码）
// ===========================================================================

async fn reset_password(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_parse_int_id(&id)?;

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    // 生成随机密码：12位，包含大小写字母和数字（密码学安全随机数）
    let new_password = generate_random_password(12);
    let password_hash = bcrypt::hash(&new_password, 12)
        .map_err(|e| ApiError::internal(format!("bcrypt hash failed: {e}")))?;

    // 原子更新密码并撤销所有会话；任一步骤失败都会回滚密码更新。
    update_user_password_and_invalidate_sessions(&state, user_id, &password_hash, None, None)
        .await?;

    close_user_sessions(user_id, "Password reset by admin");
    clear_auth_cache(user_id).await;

    create_log(
        &state,
        admin.0.id,
        "user",
        "user.reset_password",
        &format!(
            "Admin reset password for user \"{}\" (ID: {}) - new password generated",
            found.username, user_id
        ),
        "success",
    )
    .await;

    log_admin_action(
        &state,
        admin.0.id,
        "user.reset_password",
        AdminAudit {
            target_username: Some(&found.username),
            resource_type: Some("credential"),
            resource_name: None,
            reason: Some("Admin initiated password reset"),
        },
    )
    .await;

    Ok(Json(json!({
        "message": "Password reset successfully",
        "newPassword": new_password,
        "username": found.username,
    })))
}

// ===========================================================================
// POST /{id}/disable-2fa — 管理员取消用户的 2FA
// ===========================================================================

async fn disable_2fa(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_parse_int_id(&id)?;

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    // 检查用户是否启用了 2FA
    let enabled = is_2fa_enabled(&state, user_id).await?;
    if !enabled {
        return Err(ApiError::bad_request(code::TWO_FA_NOT_ENABLED));
    }

    // 禁用 2FA（清除所有 2FA 数据）
    disable_2fa_complete(&state, user_id).await?;

    create_log(
        &state,
        admin.0.id,
        "user",
        "user.disable_2fa",
        &format!(
            "Admin disabled 2FA for user \"{}\" (ID: {})",
            found.username, user_id
        ),
        "success",
    )
    .await;

    log_admin_action(
        &state,
        admin.0.id,
        "user.disable_2fa",
        AdminAudit {
            target_username: Some(&found.username),
            resource_type: Some("2fa"),
            resource_name: None,
            reason: Some("Admin disabled user 2FA"),
        },
    )
    .await;

    Ok(Json(json!({ "message": "2FA disabled successfully" })))
}

// ===========================================================================
// DELETE /{id}/oauth/{provider} — 管理员解除用户的 OAuth 绑定
// ===========================================================================

async fn unbind_oauth(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path((id, provider)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_parse_int_id(&id)?;

    // 验证 provider 参数
    if provider != "github" && provider != "google" {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "Invalid OAuth provider",
        ));
    }

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    // 检查用户是否绑定了该 OAuth
    let has_bound = has_oauth_binding(&state, user_id, &provider).await?;
    if !has_bound {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "User has not bound this OAuth provider",
        ));
    }

    // 删除 OAuth 绑定
    delete_oauth_binding(&state, user_id, &provider).await?;

    create_log(
        &state,
        admin.0.id,
        "user",
        "user.unbind_oauth",
        &format!(
            "Admin unbound {provider} OAuth for user \"{}\" (ID: {})",
            found.username, user_id
        ),
        "success",
    )
    .await;

    log_admin_action(
        &state,
        admin.0.id,
        "user.unbind_oauth",
        AdminAudit {
            target_username: Some(&found.username),
            resource_type: Some("oauth"),
            resource_name: None,
            reason: Some(&format!("Admin unbound {provider} OAuth")),
        },
    )
    .await;

    Ok(Json(json!({
        "message": format!("{provider} OAuth binding removed successfully"),
    })))
}

// ===========================================================================
// GET /{id}/login-records — 管理员获取用户登录记录
// ===========================================================================

async fn list_login_records(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_parse_int_id(&id)?;

    let found = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    let pagination = parse_pagination(&params, 20, None);

    #[derive(FromRow)]
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

    let records: Vec<LoginRecordRow> = sqlx::query_as(
        "SELECT id, ip, country, region, city, isp, timezone, user_agent, created_at \
         FROM login_records WHERE user_id = $1 \
         ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(found.id)
    .bind(pagination.take)
    .bind(pagination.skip)
    .fetch_all(&state.db)
    .await?;

    let (total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM login_records WHERE user_id = $1")
            .bind(found.id)
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
        "totalPages": (total as f64 / pagination.page_size as f64).ceil() as i64,
    })))
}

// ===========================================================================
// GET /detect-linked-accounts — 管理员检测关联账号
// ===========================================================================

#[derive(Debug, Clone)]
struct IpGroupUser {
    id: i32,
    username: String,
    email: Option<String>,
    status: String,
    login_count: i64,
    last_login: DateTime<Utc>,
}

struct IpGroup {
    ip: String,
    users: Vec<IpGroupUser>,
    total_logins: i64,
}

/// db/login-records.ts getSharedIPGroups: IPs used by >= minUsers distinct
/// users within the window.
async fn get_shared_ip_groups(
    state: &SharedAppState,
    days: i64,
    min_users: i64,
) -> Result<Vec<IpGroup>, ApiError> {
    let since = Utc::now() - chrono::Duration::days(days);

    let shared_ips: Vec<(String,)> = sqlx::query_as(
        "SELECT ip FROM login_records WHERE created_at >= $1 \
         GROUP BY ip HAVING COUNT(user_id) >= $2",
    )
    .bind(since)
    .bind(min_users)
    .fetch_all(&state.db)
    .await?;

    let mut groups: Vec<IpGroup> = Vec::new();
    for (ip,) in shared_ips {
        let records: Vec<(i32, String, Option<String>, String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT lr.user_id, u.username, u.email, u.status::text AS status, lr.created_at \
             FROM login_records lr JOIN users u ON u.id = lr.user_id \
             WHERE lr.ip = $1 AND lr.created_at >= $2 \
             ORDER BY lr.created_at DESC",
        )
        .bind(&ip)
        .bind(since)
        .fetch_all(&state.db)
        .await?;

        // 按用户分组统计：首次出现即最新登录（记录按时间倒序）。
        let mut user_map: Vec<IpGroupUser> = Vec::new();
        for (user_id, username, email, status, created_at) in &records {
            if let Some(existing) = user_map.iter_mut().find(|u| &u.username == username) {
                existing.login_count += 1;
            } else {
                user_map.push(IpGroupUser {
                    id: *user_id,
                    username: username.clone(),
                    email: email.clone(),
                    status: status.clone(),
                    login_count: 1,
                    last_login: *created_at,
                });
            }
        }

        // 只有真正被多个不同用户使用的IP才加入结果
        if user_map.len() as i64 >= min_users {
            user_map.sort_by(|a, b| b.last_login.cmp(&a.last_login));
            groups.push(IpGroup {
                ip,
                total_logins: records.len() as i64,
                users: user_map,
            });
        }
    }

    // 按关联用户数降序排列
    groups.sort_by(|a, b| b.users.len().cmp(&a.users.len()));
    Ok(groups)
}

#[derive(Debug, Clone)]
struct SimilarUser {
    id: i32,
    username: String,
    email: Option<String>,
    status: String,
    created_at: DateTime<Utc>,
}

struct SimilarGroup {
    pattern: String,
    users: Vec<SimilarUser>,
}

/// Shared prefix-group detection for getSimilarEmailGroups /
/// getSimilarUsernameGroups: strip trailing digits/underscores/hyphens,
/// lowercase, group, keep groups with >= 2 users, sort stably by size desc and
/// users by createdAt desc.
async fn get_similar_prefix_groups(
    state: &SharedAppState,
    keyed_by_email: bool,
) -> Result<Vec<SimilarGroup>, ApiError> {
    static TRAILING: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"[\d_-]+$").expect("valid regex")
    });

    let rows: Vec<(i32, String, Option<String>, String, DateTime<Utc>)> = if keyed_by_email {
        sqlx::query_as(
            "SELECT id, username, email, status::text AS status, created_at FROM users \
             WHERE email IS NOT NULL",
        )
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, username, email, status::text AS status, created_at FROM users",
        )
        .fetch_all(&state.db)
        .await?
    };

    // Insertion-ordered map (mirrors JS Map iteration order).
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<SimilarUser>> = HashMap::new();

    for (id, username, email, status, created_at) in rows {
        let (local, domain): (String, String) = if keyed_by_email {
            let email = email.clone().unwrap_or_default();
            let mut parts = email.split('@');
            let local = parts.next().unwrap_or("").to_string();
            let domain = parts.next().unwrap_or("").to_string();
            if local.is_empty() || domain.is_empty() {
                continue;
            }
            let local = TRAILING.replace_all(&local, "").to_lowercase();
            if local.chars().count() < 2 {
                continue; // 前缀太短无意义
            }
            (local, domain)
        } else {
            let local = TRAILING.replace_all(&username, "").to_lowercase();
            if local.chars().count() < 2 {
                continue;
            }
            (local, String::new())
        };

        let key = if keyed_by_email {
            format!("{local}*@{domain}")
        } else {
            format!("{local}*")
        };

        let entry = groups.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Vec::new()
        });
        entry.push(SimilarUser {
            id,
            username,
            email,
            status,
            created_at,
        });
    }

    let mut result: Vec<SimilarGroup> = order
        .into_iter()
        .filter_map(|key| {
            let mut users = groups.remove(&key)?;
            if users.len() < 2 {
                return None;
            }
            // sort((a, b) => b.createdAt - a.createdAt) — descending, stable.
            users.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            Some(SimilarGroup { pattern: key, users })
        })
        .collect();

    // 按用户数降序排列
    result.sort_by(|a, b| b.users.len().cmp(&a.users.len()));
    Ok(result)
}

async fn detect_linked_accounts(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let started_at = std::time::Instant::now();
    // 参数校验：限制检测范围在 1-365 天之间，防止查询性能问题
    let raw_days = js_parse_int(params.get("days").map(|s| s.as_str()).unwrap_or("90"))
        .unwrap_or(90);
    let days = raw_days.clamp(1, 365);

    // 并行执行三种检测（Rust 端顺序执行，结果一致）
    let ip_groups = get_shared_ip_groups(&state, days, 2).await?;
    let email_groups = get_similar_prefix_groups(&state, true).await?;
    let username_groups = get_similar_prefix_groups(&state, false).await?;

    let duration_ms = started_at.elapsed().as_millis() as i64;

    // 记录管理员操作日志
    create_log(
        &state,
        admin.0.id,
        "user",
        "admin.detect_linked_accounts",
        &format!(
            "Admin detected linked accounts: {} IP groups, {} email groups, {} username groups ({}ms)",
            ip_groups.len(),
            email_groups.len(),
            username_groups.len(),
            duration_ms
        ),
        "success",
    )
    .await;

    let ip_groups_json: Vec<Value> = ip_groups
        .iter()
        .map(|g| {
            json!({
                "ip": g.ip,
                "userCount": g.users.len(),
                "totalLogins": g.total_logins,
                "users": g.users.iter().map(|u| json!({
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "status": u.status,
                    "loginCount": u.login_count,
                    "lastLogin": iso(u.last_login),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let email_groups_json: Vec<Value> = email_groups
        .iter()
        .map(|g| {
            json!({
                "pattern": g.pattern,
                "userCount": g.users.len(),
                "users": g.users.iter().map(|u| json!({
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "status": u.status,
                    "createdAt": iso(u.created_at),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let username_groups_json: Vec<Value> = username_groups
        .iter()
        .map(|g| {
            json!({
                "pattern": g.pattern,
                "userCount": g.users.len(),
                "users": g.users.iter().map(|u| json!({
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "status": u.status,
                    "createdAt": iso(u.created_at),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    Ok(Json(json!({
        "detectedAt": iso(Utc::now()),
        "durationMs": duration_ms,
        "days": days,
        "summary": {
            "ipGroups": ip_groups_json.len(),
            "emailGroups": email_groups_json.len(),
            "usernameGroups": username_groups_json.len(),
        },
        "ipGroups": ip_groups_json,
        "emailGroups": email_groups_json,
        "usernameGroups": username_groups_json,
    })))
}

// ===========================================================================
// GET /{id}/hosting-balance/logs — 获取用户托管余额明细（管理员）
// ===========================================================================

async fn hosting_balance_logs(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_parse_int_id(&id).map_err(|_| {
        ApiError::with_message(code::INVALID_PARAMS, StatusCode::BAD_REQUEST, "Invalid user ID")
    })?;

    let pagination = parse_pagination(&params, 20, Some(100));

    let user: Option<(i32, String, Decimal)> = sqlx::query_as(
        "SELECT id, username, hosting_balance FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((found_id, username, hosting_balance)) = user else {
        return Err(ApiError::with_message(
            code::USER_NOT_FOUND,
            StatusCode::NOT_FOUND,
            "User not found",
        ));
    };

    #[derive(FromRow)]
    struct HostingLogRow {
        id: i32,
        log_type: String,
        action_type: Option<String>,
        amount: Decimal,
        frozen: bool,
        unfreeze_at: Option<DateTime<Utc>>,
        remark: Option<String>,
        created_at: DateTime<Utc>,
    }

    let logs: Vec<HostingLogRow> = sqlx::query_as(
        "SELECT id, type::text AS log_type, action_type::text AS action_type, \
                amount, frozen, unfreeze_at, remark, created_at \
         FROM hosting_balance_logs WHERE user_id = $1 \
         ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(found_id)
    .bind(pagination.take)
    .bind(pagination.skip)
    .fetch_all(&state.db)
    .await?;

    let (total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM hosting_balance_logs WHERE user_id = $1")
            .bind(found_id)
            .fetch_one(&state.db)
            .await?;

    // 获取冻结余额总额
    let (frozen_sum,): (Option<Decimal>,) = sqlx::query_as(
        "SELECT SUM(amount) FROM hosting_balance_logs WHERE user_id = $1 AND frozen = TRUE",
    )
    .bind(found_id)
    .fetch_one(&state.db)
    .await?;

    let logs_json: Vec<Value> = logs
        .iter()
        .map(|log| {
            json!({
                "id": log.id,
                "type": log.log_type,
                "actionType": log.action_type,
                "amount": num(log.amount),
                "frozen": log.frozen,
                "unfreezeAt": iso_opt(log.unfreeze_at),
                "description": log.remark,
                "createdAt": iso(log.created_at),
            })
        })
        .collect();

    Ok(Json(json!({
        "user": {
            "id": found_id,
            "username": username,
        },
        "available": num(hosting_balance),
        "frozen": num(frozen_sum.unwrap_or(Decimal::ZERO)),
        "logs": logs_json,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
        "totalPages": (total as f64 / pagination.page_size as f64).ceil() as i64,
    })))
}

// ===========================================================================
// POST /{id}/hosting-balance/adjust — 调整用户托管余额（管理员）
// ===========================================================================

async fn adjust_hosting_balance(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let user_id = js_parse_int_id(&id).map_err(|_| {
        ApiError::with_message(code::INVALID_PARAMS, StatusCode::BAD_REQUEST, "Invalid user ID")
    })?;

    let adjust_type = body.get("type").and_then(Value::as_str);
    let Some(adjust_type) = adjust_type else {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "Invalid type, must be \"available\" or \"frozen\"",
        ));
    };
    if adjust_type != "available" && adjust_type != "frozen" {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "Invalid type, must be \"available\" or \"frozen\"",
        ));
    }

    let amount_value = body.get("amount");
    let amount_number = amount_value.and_then(Value::as_number);
    let Some(amount_number) = amount_number else {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "Amount must be a non-zero number",
        ));
    };
    let amount_f64 = amount_number.as_f64().unwrap_or(0.0);
    if amount_f64 == 0.0 {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "Amount must be a non-zero number",
        ));
    }

    let Some(reason) = body.get("reason").and_then(Value::as_str).map(str::to_string) else {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "Reason is required",
        ));
    };
    if reason.trim().is_empty() {
        return Err(ApiError::with_message(
            code::INVALID_PARAMS,
            StatusCode::BAD_REQUEST,
            "Reason is required",
        ));
    }

    // 检查用户是否存在
    let user: Option<(i32, String, Decimal)> = sqlx::query_as(
        "SELECT id, username, hosting_balance FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((found_id, _username, _hosting_balance)) = user else {
        return Err(ApiError::with_message(
            code::USER_NOT_FOUND,
            StatusCode::NOT_FOUND,
            "User not found",
        ));
    };

    let is_add = amount_f64 > 0.0;
    let Some(abs_amount) = decimal_from_number(amount_number).map(|d| d.abs()) else {
        return Err(ApiError::internal("amount is not a finite number"));
    };
    let trimmed_reason = reason.trim().to_string();

    enum AdjustError {
        Sql(sqlx::Error),
        Busy,
        InsufficientHosting,
        InsufficientFrozen,
    }
    impl From<sqlx::Error> for AdjustError {
        fn from(err: sqlx::Error) -> Self {
            AdjustError::Sql(err)
        }
    }

    let run_adjustment = || async {
        let mut tx = state.db.begin().await?;
        let locked = try_advisory_transaction_lock(
            &mut *tx,
            advisory_lock_namespace::HOSTING_BALANCE_LOG,
            found_id as i64,
        )
        .await?;
        if !locked {
            return Err(AdjustError::Busy);
        }

        if adjust_type == "available" {
            // 更新用户托管余额（扣减时带下界条件）
            let result = if is_add {
                sqlx::query(
                    "UPDATE users SET hosting_balance = hosting_balance + $1 WHERE id = $2",
                )
                .bind(abs_amount)
                .bind(found_id)
                .execute(&mut *tx)
                .await?
            } else {
                sqlx::query(
                    "UPDATE users SET hosting_balance = hosting_balance - $1 \
                     WHERE id = $2 AND hosting_balance >= $1",
                )
                .bind(abs_amount)
                .bind(found_id)
                .execute(&mut *tx)
                .await?
            };
            if result.rows_affected() == 0 {
                return Err(AdjustError::InsufficientHosting);
            }

            // 记录日志
            sqlx::query(
                "INSERT INTO hosting_balance_logs \
                 (user_id, type, action_type, amount, frozen, remark) \
                 VALUES ($1, $2::\"HostingBalanceType\", 'admin_adjust'::\"HostingActionType\", \
                         $3, FALSE, $4)",
            )
            .bind(found_id)
            .bind(if is_add { "income" } else { "deduction" })
            .bind(abs_amount)
            .bind(format!("[Admin] {trimmed_reason}"))
            .execute(&mut *tx)
            .await?;
        } else if is_add {
            // 增加冻结余额：创建一条冻结记录（30天后解冻）
            sqlx::query(
                "INSERT INTO hosting_balance_logs \
                 (user_id, type, action_type, amount, frozen, unfreeze_at, remark) \
                 VALUES ($1, 'income'::\"HostingBalanceType\", \
                         'admin_adjust'::\"HostingActionType\", $2, TRUE, $3, $4)",
            )
            .bind(found_id)
            .bind(abs_amount)
            .bind(Utc::now() + chrono::Duration::days(30))
            .bind(format!("[Admin Frozen] {trimmed_reason}"))
            .execute(&mut *tx)
            .await?;
        } else {
            // 扣减冻结余额：从冻结记录中扣除
            let frozen_logs: Vec<(i32, Decimal)> = sqlx::query_as(
                "SELECT id, amount FROM hosting_balance_logs \
                 WHERE user_id = $1 AND frozen = TRUE AND amount > 0 \
                 ORDER BY created_at ASC",
            )
            .bind(found_id)
            .fetch_all(&mut *tx)
            .await?;
            let frozen_total = frozen_logs.iter().map(|(_, a)| *a).sum::<Decimal>();
            if frozen_total < abs_amount {
                return Err(AdjustError::InsufficientFrozen);
            }

            // 从最早的冻结记录开始扣减
            let mut remaining = abs_amount;
            for (log_id, log_amount) in frozen_logs {
                if remaining <= Decimal::ZERO {
                    break;
                }
                if log_amount <= remaining {
                    // 完全扣除这条记录
                    sqlx::query("DELETE FROM hosting_balance_logs WHERE id = $1")
                        .bind(log_id)
                        .execute(&mut *tx)
                        .await?;
                    remaining -= log_amount;
                } else {
                    // 部分扣除
                    sqlx::query(
                        "UPDATE hosting_balance_logs SET amount = amount - $1 WHERE id = $2",
                    )
                    .bind(remaining)
                    .bind(log_id)
                    .execute(&mut *tx)
                    .await?;
                    remaining = Decimal::ZERO;
                }
            }

            // 记录扣减日志（不计入实际余额，仅作为记录）
            sqlx::query(
                "INSERT INTO hosting_balance_logs \
                 (user_id, type, action_type, amount, frozen, remark) \
                 VALUES ($1, 'deduction'::\"HostingBalanceType\", \
                         'admin_adjust'::\"HostingActionType\", 0, FALSE, $2)",
            )
            .bind(found_id)
            .bind(format!(
                "[Admin Frozen Deduct] {trimmed_reason} (¥{})",
                to_fixed_2(abs_amount)
            ))
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    };

    if let Err(err) = run_adjustment().await {
        return match err {
            AdjustError::Sql(e) => Err(ApiError::from_sql(e)),
            AdjustError::Busy => Err(ApiError::with_message(
                "HOSTING_BALANCE_BUSY",
                StatusCode::CONFLICT,
                "托管余额正在处理，请稍后重试",
            )),
            AdjustError::InsufficientHosting => Err(ApiError::with_message(
                code::BALANCE_INSUFFICIENT,
                StatusCode::BAD_REQUEST,
                "Insufficient hosting balance",
            )),
            AdjustError::InsufficientFrozen => Err(ApiError::with_message(
                code::BALANCE_INSUFFICIENT,
                StatusCode::BAD_REQUEST,
                "Insufficient frozen hosting balance",
            )),
        };
    }

    // 记录管理员操作日志
    create_log(
        &state,
        admin.0.id,
        "user",
        "admin.adjust_hosting_balance",
        &format!(
            "Admin adjusted user #{} hosting balance: type={}, amount={}, reason={}",
            user_id,
            adjust_type,
            js_num_display(amount_number),
            reason
        ),
        "success",
    )
    .await;

    // 返回更新后的托管余额信息
    let updated: Option<(Decimal,)> =
        sqlx::query_as("SELECT hosting_balance FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    let (frozen_sum,): (Option<Decimal>,) = sqlx::query_as(
        "SELECT SUM(amount) FROM hosting_balance_logs WHERE user_id = $1 AND frozen = TRUE",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(json!({
        "success": true,
        "available": num(updated.map(|(b,)| b).unwrap_or(Decimal::ZERO)),
        "frozen": num(frozen_sum.unwrap_or(Decimal::ZERO)),
    }))
    .into_response())
}
