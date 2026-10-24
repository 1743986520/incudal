//! 敏感操作二次验证路由 — port of server/src/routes/verification.ts, with the
//! server/src/lib/operation-verification.ts service ported inline (request /
//! verify / isVerified / consume / claim).
//!
//! Endpoint map (TS decorator -> Rust extractor), mounted at /api/verification:
//! - POST /request          authenticate -> AuthUser
//! - POST /verify           authenticate -> AuthUser
//! - GET  /check            authenticate -> AuthUser
//! - GET  /operation-types  authenticate -> AuthUser
//!
//! The TS route files declare no inline config.rateLimit for these; they rely
//! on the global 300/min limit only (no per-route rules to add).
//!
//! Email delivery (sendOperationVerificationEmail) and channel push
//! (sendVerificationNotification) are warn-stubs that report success, matching
//! the libs/external.rs convention: a TS send failure would delete the code
//! and return SEND_FAILED, but the stub never fails so the code stays valid
//! (see the report note).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sqlx::PgPool;
use std::collections::HashMap;

use crate::auth::AuthUser;
use crate::error::{code, ApiError};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/request", post(request_code))
        .route("/verify", post(verify_code))
        .route("/check", get(check))
        .route("/operation-types", get(operation_types))
}

// ===========================================================================
// port of lib/operation-verification.ts — constants
// ===========================================================================

/// 有效的操作类型列表 (routes/verification.ts).
const VALID_OPERATION_TYPES: [&str; 9] = [
    "change_password",
    "disable_2fa",
    "change_email",
    "delete_account",
    "reinstall_instance",
    "recreate_instance",
    "transfer_instance",
    "delete_snapshot",
    "delete_backup",
];

const ACCOUNT_OPERATIONS: [&str; 4] = [
    "change_password",
    "disable_2fa",
    "change_email",
    "delete_account",
];

const RESOURCE_OPERATIONS: [&str; 5] = [
    "reinstall_instance",
    "recreate_instance",
    "transfer_instance",
    "delete_snapshot",
    "delete_backup",
];

const CODE_LENGTH: usize = 6;
const EXPIRES_IN_MINUTES: i64 = 10;
const MAX_ATTEMPTS: u32 = 5;

/// Attempts counter encoded into the stored code (schema has no column).
const FAILED_ATTEMPTS_SUFFIX: &str = ":attempts:";

fn is_valid_operation_type(value: &str) -> bool {
    VALID_OPERATION_TYPES.contains(&value)
}

pub fn is_account_operation(operation_type: &str) -> bool {
    ACCOUNT_OPERATIONS.contains(&operation_type)
}

pub fn is_resource_operation(operation_type: &str) -> bool {
    RESOURCE_OPERATIONS.contains(&operation_type)
}

/// OPERATION_NAMES — (zh, en).
pub fn get_operation_name(operation_type: &str, lang: &str) -> String {
    let names: &[(&str, (&str, &str))] = &[
        ("change_password", ("修改密码", "Change Password")),
        ("disable_2fa", ("禁用双因素认证", "Disable 2FA")),
        ("change_email", ("修改邮箱地址", "Change Email")),
        ("delete_account", ("删除账户", "Delete Account")),
        ("delete_instance", ("删除实例", "Delete Instance")),
        ("reinstall_instance", ("重装实例", "Reinstall Instance")),
        ("recreate_instance", ("重建实例", "Recreate Instance")),
        ("transfer_instance", ("转移实例", "Transfer Instance")),
        ("delete_snapshot", ("删除快照", "Delete Snapshot")),
        ("delete_backup", ("删除备份", "Delete Backup")),
    ];
    let entry = names
        .iter()
        .find(|(op, _)| *op == operation_type)
        .map(|(_, names)| *names);
    match entry {
        Some((zh, en)) if lang == "en" => en.to_string(),
        Some((zh, _)) => zh.to_string(),
        // TS: OPERATION_NAMES[type]?.[lang] || type
        None => operation_type.to_string(),
    }
}

fn decode_verification_code(stored: &str) -> (String, u32) {
    let Some(index) = stored.rfind(FAILED_ATTEMPTS_SUFFIX) else {
        return (stored.to_string(), 0);
    };
    let attempts_raw = &stored[index + FAILED_ATTEMPTS_SUFFIX.len()..];
    match attempts_raw.parse::<f64>() {
        Ok(n) if n.is_finite() && n.fract() == 0.0 && (0.0..=MAX_ATTEMPTS as f64).contains(&n) => {
            (stored[..index].to_string(), n as u32)
        }
        _ => (stored.to_string(), 0),
    }
}

fn encode_verification_code(code: &str, attempts: u32) -> String {
    format!("{code}{FAILED_ATTEMPTS_SUFFIX}{attempts}")
}

/// crypto.randomInt(100000, 1000000) — 6 digits, inclusive-exclusive.
fn generate_verification_code() -> String {
    use rand::Rng;
    rand::thread_rng().gen_range(100000..1000000).to_string()
}

/// JS slice(0, n) by UTF-16 code units.
fn js_slice(s: &str, n: usize) -> String {
    let mut units = 0usize;
    let mut end = s.len();
    for (idx, ch) in s.char_indices() {
        if units >= n {
            end = idx;
            break;
        }
        units += ch.len_utf16();
    }
    if units < n {
        s.to_string()
    } else {
        s[..end].to_string()
    }
}

// ===========================================================================
// notification channel resolution
// ===========================================================================

struct NotificationChannelInfo {
    channel: String,
    #[allow(dead_code)]
    channel_id: i32,
    target: String,
}

/// getUserNotificationChannel — first enabled channel (createdAt asc).
async fn get_user_notification_channel(
    db: &PgPool,
    user_id: i32,
) -> Result<Option<NotificationChannelInfo>, ApiError> {
    let row: Option<(i32, String, Value)> = sqlx::query_as(
        "SELECT id, type::text AS type, config FROM notification_channels \
         WHERE user_id = $1 AND enabled = true ORDER BY created_at ASC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    let Some((channel_id, channel_type, raw_config)) = row else {
        return Ok(None);
    };

    // TS: JSON.parse when the column holds a JSON string, else use as-is.
    let config: Map<String, Value> = match raw_config {
        Value::String(text) => serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default(),
        Value::Object(map) => map,
        _ => Map::new(),
    };

    // TS chatId?.substring(0, 6): a missing/non-string chatId renders
    // "undefined" in the template (a numeric chatId would crash TS with a
    // TypeError -> 500; the port degrades to the same display as missing).
    let target = match channel_type.as_str() {
        "telegram" => {
            let prefix = match config.get("chatId").and_then(|v| v.as_str()) {
                Some(chat_id) => js_slice(chat_id, 6),
                None => "undefined".to_string(),
            };
            format!("Telegram ({prefix}***)")
        }
        "discord" => "Discord Webhook".to_string(),
        "webhook" => "Webhook".to_string(),
        other => other.to_string(),
    };

    Ok(Some(NotificationChannelInfo {
        channel: channel_type,
        channel_id,
        target,
    }))
}

/// isResourceVerificationRequired — any enabled channel means required.
async fn is_resource_verification_required(
    db: &PgPool,
    user_id: i32,
) -> Result<bool, ApiError> {
    Ok(get_user_notification_channel(db, user_id).await?.is_some())
}

// ===========================================================================
// delivery stubs
// ===========================================================================

/// TODO: port of lib/mailer.ts sendOperationVerificationEmail. Returns
/// success; a TS failure deletes the code and returns SEND_FAILED.
async fn send_operation_verification_email(
    email: &str,
    username: &str,
    operation_name: &str,
    code: &str,
) -> Result<(), String> {
    tracing::warn!(
        "[email stub] sendOperationVerificationEmail not implemented in the Rust server \
         (TODO server/src/lib/mailer.ts): to={email} user={username} op={operation_name} \
         code={code} ttl={EXPIRES_IN_MINUTES}m"
    );
    Ok(())
}

/// TODO: port of lib/notifier.ts sendVerificationNotification (channel push).
async fn send_verification_notification(
    user_id: i32,
    operation_name: &str,
    code: &str,
) -> Result<(), String> {
    tracing::warn!(
        "[notifier stub] sendVerificationNotification not implemented in the Rust server \
         (TODO server/src/lib/notifier.ts): user={user_id} op={operation_name} code={code}"
    );
    Ok(())
}

// ===========================================================================
// requestOperationVerification
// ===========================================================================

struct RequestVerificationResult {
    success: bool,
    channel: Option<String>,
    masked_target: Option<String>,
    expires_in: Option<i64>,
    error: Option<String>,
    error_code: Option<String>,
}

fn verification_failure(error: &str, error_code: &str) -> RequestVerificationResult {
    RequestVerificationResult {
        success: false,
        channel: None,
        masked_target: None,
        expires_in: None,
        error: Some(error.to_string()),
        error_code: Some(error_code.to_string()),
    }
}

async fn request_operation_verification(
    db: &PgPool,
    user_id: i32,
    operation_type: &str,
    resource_id: Option<i32>,
    resource_type: Option<&str>,
) -> Result<RequestVerificationResult, ApiError> {
    // 1. 用户信息
    let user: Option<(Option<String>, String)> =
        sqlx::query_as("SELECT email, username FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    let Some((email, username)) = user else {
        return Ok(verification_failure("User not found", "USER_NOT_FOUND"));
    };

    // 2. 验证渠道
    let (channel, masked_target) = if is_account_operation(operation_type) {
        let Some(email_ref) = email.as_deref() else {
            return Ok(verification_failure(
                "Email not configured",
                "EMAIL_NOT_CONFIGURED",
            ));
        };
        // localPart.substring(0,2)***@domain (JS split('@') destructuring:
        // domain = second segment, "undefined" when absent).
        let parts: Vec<&str> = email_ref.split('@').collect();
        let local_part = parts.first().copied().unwrap_or("");
        let domain = parts.get(1).copied().unwrap_or("undefined");
        (
            "email".to_string(),
            format!("{}***@{domain}", js_slice(local_part, 2)),
        )
    } else {
        let Some(info) = get_user_notification_channel(db, user_id).await? else {
            return Ok(verification_failure(
                "No notification channel configured",
                "NO_NOTIFICATION_CHANNEL",
            ));
        };
        let target = if info.target.is_empty() {
            info.channel.clone()
        } else {
            info.target
        };
        (info.channel, target)
    };

    // 3. 清理过期的验证码
    sqlx::query("DELETE FROM operation_verifications WHERE user_id = $1 AND expires_at < NOW()")
        .bind(user_id)
        .execute(db)
        .await?;

    // 4. 未过期的同类型验证码（防频繁请求）
    let existing: Option<(i32, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, created_at, expires_at FROM operation_verifications \
         WHERE user_id = $1 AND operation_type = $2::\"OperationType\" \
         AND resource_id IS NOT DISTINCT FROM $3 AND verified = false \
         AND expires_at > NOW() LIMIT 1",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(resource_id)
    .fetch_optional(db)
    .await?;

    if let Some((existing_id, created_at, expires_at)) = existing {
        let two_minutes_ago = Utc::now() - chrono::Duration::minutes(2);
        if created_at > two_minutes_ago {
            // TS returns success:true + remaining seconds; the route surfaces
            // it as the normal success shape.
            let remaining = ((expires_at - Utc::now()).num_milliseconds() as f64 / 1000.0).ceil()
                as i64;
            return Ok(RequestVerificationResult {
                success: true,
                channel: Some(channel),
                masked_target: Some(masked_target),
                expires_in: Some(remaining),
                error: Some("Verification code already sent, please wait".to_string()),
                error_code: None,
            });
        }
        sqlx::query("DELETE FROM operation_verifications WHERE id = $1")
            .bind(existing_id)
            .execute(db)
            .await?;
    }

    // 5-6. 生成并存储新验证码
    let verification_code = generate_verification_code();
    sqlx::query(
        "INSERT INTO operation_verifications \
         (user_id, operation_type, code, channel, resource_id, resource_type, expires_at) \
         VALUES ($1, $2::\"OperationType\", $3, $4::\"VerificationChannel\", $5, $6, $7)",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(&verification_code)
    .bind(&channel)
    .bind(resource_id)
    .bind(resource_type)
    .bind(Utc::now() + chrono::Duration::minutes(EXPIRES_IN_MINUTES))
    .execute(db)
    .await?;

    // 7. 发送验证码 (stubs — see module docs)
    let send_result = if channel == "email" {
        let email = email.unwrap_or_default();
        send_operation_verification_email(
            &email,
            &username,
            &get_operation_name(operation_type, "zh"),
            &verification_code,
        )
        .await
    } else {
        send_verification_notification(
            user_id,
            &get_operation_name(operation_type, "zh"),
            &verification_code,
        )
        .await
    };
    if let Err(error) = send_result {
        sqlx::query(
            "DELETE FROM operation_verifications \
             WHERE user_id = $1 AND operation_type = $2::\"OperationType\" AND code = $3",
        )
        .bind(user_id)
        .bind(operation_type)
        .bind(&verification_code)
        .execute(db)
        .await?;
        return Ok(verification_failure(&error, "SEND_FAILED"));
    }

    Ok(RequestVerificationResult {
        success: true,
        channel: Some(channel),
        masked_target: Some(masked_target),
        expires_in: Some(EXPIRES_IN_MINUTES * 60),
        error: None,
        error_code: None,
    })
}

// ===========================================================================
// verifyOperationCode
// ===========================================================================

struct VerifyOperationResult {
    success: bool,
    verified: bool,
    error: Option<String>,
    error_code: Option<String>,
}

fn invalid_code_result() -> VerifyOperationResult {
    VerifyOperationResult {
        success: false,
        verified: false,
        error: Some("Invalid or expired verification code".to_string()),
        error_code: Some("INVALID_CODE".to_string()),
    }
}

async fn verify_operation_code(
    db: &PgPool,
    user_id: i32,
    operation_type: &str,
    input_code: &str,
    resource_id: Option<i32>,
) -> Result<VerifyOperationResult, ApiError> {
    let mut tx = db.begin().await?;

    let verification: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM operation_verifications \
         WHERE user_id = $1 AND operation_type = $2::\"OperationType\" \
         AND resource_id IS NOT DISTINCT FROM $3 AND verified = false \
         AND expires_at > NOW() \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(resource_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((verification_id,)) = verification else {
        let _ = tx.rollback().await;
        return Ok(invalid_code_result());
    };

    // FOR UPDATE serializes concurrent attempts on the same code.
    sqlx::query("SELECT id FROM operation_verifications WHERE id = $1 AND verified = false FOR UPDATE")
        .bind(verification_id)
        .execute(&mut *tx)
        .await?;

    let locked: Option<(String, DateTime<Utc>, bool)> = sqlx::query_as(
        "SELECT code, expires_at, verified FROM operation_verifications WHERE id = $1",
    )
    .bind(verification_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((stored, expires_at, verified)) = locked else {
        let _ = tx.rollback().await;
        return Ok(invalid_code_result());
    };
    let now = Utc::now();
    if verified || expires_at <= now {
        let _ = tx.rollback().await;
        return Ok(invalid_code_result());
    }

    let (code, attempts) = decode_verification_code(&stored);

    // 达到上限：立即删除验证码。
    if attempts >= MAX_ATTEMPTS {
        sqlx::query(
            "DELETE FROM operation_verifications \
             WHERE user_id = $1 AND operation_type = $2::\"OperationType\" \
             AND resource_id IS NOT DISTINCT FROM $3 AND verified = false",
        )
        .bind(user_id)
        .bind(operation_type)
        .bind(resource_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(invalid_code_result());
    }

    if code != input_code {
        let next_attempts = attempts + 1;
        if next_attempts >= MAX_ATTEMPTS {
            sqlx::query(
                "DELETE FROM operation_verifications \
                 WHERE user_id = $1 AND operation_type = $2::\"OperationType\" \
                 AND resource_id IS NOT DISTINCT FROM $3 AND verified = false",
            )
            .bind(user_id)
            .bind(operation_type)
            .bind(resource_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query("UPDATE operation_verifications SET code = $2 WHERE id = $1")
                .bind(verification_id)
                .bind(encode_verification_code(&code, next_attempts))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        return Ok(invalid_code_result());
    }

    sqlx::query("UPDATE operation_verifications SET verified = true, verified_at = $2 WHERE id = $1")
        .bind(verification_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(VerifyOperationResult {
        success: true,
        verified: true,
        error: None,
        error_code: None,
    })
}

// ===========================================================================
// isOperationVerified / consume / claim
// ===========================================================================

pub async fn is_operation_verified(
    db: &PgPool,
    user_id: i32,
    operation_type: &str,
    resource_id: Option<i32>,
) -> Result<bool, ApiError> {
    let ten_minutes_ago = Utc::now() - chrono::Duration::minutes(10);
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM operation_verifications \
         WHERE user_id = $1 AND operation_type = $2::\"OperationType\" \
         AND resource_id IS NOT DISTINCT FROM $3 AND verified = true \
         AND verified_at > $4 LIMIT 1",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(resource_id)
    .bind(ten_minutes_ago)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

pub async fn consume_operation_verification(
    db: &PgPool,
    user_id: i32,
    operation_type: &str,
    resource_id: Option<i32>,
) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM operation_verifications \
         WHERE user_id = $1 AND operation_type = $2::\"OperationType\" \
         AND resource_id IS NOT DISTINCT FROM $3 AND verified = true",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(resource_id)
    .execute(db)
    .await?;
    Ok(())
}

/// claimOperationVerification — atomic single consume for sensitive gates.
pub async fn claim_operation_verification(
    db: &PgPool,
    user_id: i32,
    operation_type: &str,
    resource_id: Option<i32>,
) -> Result<bool, ApiError> {
    let ten_minutes_ago = Utc::now() - chrono::Duration::minutes(10);
    let mut tx = db.begin().await?;

    let verification: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM operation_verifications \
         WHERE user_id = $1 AND operation_type = $2::\"OperationType\" \
         AND resource_id IS NOT DISTINCT FROM $3 AND verified = true \
         AND verified_at > $4 ORDER BY verified_at ASC LIMIT 1",
    )
    .bind(user_id)
    .bind(operation_type)
    .bind(resource_id)
    .bind(ten_minutes_ago)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((verification_id,)) = verification else {
        let _ = tx.rollback().await;
        return Ok(false);
    };

    let result = sqlx::query(
        "DELETE FROM operation_verifications \
         WHERE id = $1 AND verified = true AND verified_at > $2",
    )
    .bind(verification_id)
    .bind(ten_minutes_ago)
    .execute(&mut *tx)
    .await?;

    let claimed = result.rows_affected() == 1;
    tx.commit().await?;
    Ok(claimed)
}

/// claimOperationVerificationIfRequired — resource ops without a channel skip
/// verification entirely.
pub async fn claim_operation_verification_if_required(
    db: &PgPool,
    user_id: i32,
    operation_type: &str,
    resource_id: Option<i32>,
) -> Result<bool, ApiError> {
    if is_resource_operation(operation_type)
        && !is_resource_verification_required(db, user_id).await?
    {
        return Ok(true);
    }
    claim_operation_verification(db, user_id, operation_type, resource_id).await
}

/// cleanupExpiredVerifications (scheduler helper).
pub async fn cleanup_expired_verifications(db: &PgPool) -> Result<u64, ApiError> {
    let result = sqlx::query("DELETE FROM operation_verifications WHERE expires_at < NOW()")
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}

// ===========================================================================
// body/query validation (Fastify AJV schemas)
// ===========================================================================

fn validation_error(messages: Vec<String>) -> ApiError {
    let first = messages
        .first()
        .cloned()
        .unwrap_or_else(|| "Validation failed".to_string());
    let mut err = ApiError::with_message(code::VALIDATION_ERROR, StatusCode::BAD_REQUEST, first);
    if messages.len() > 1 {
        err = err.with_details(messages.join(", "));
    }
    err
}

/// AJV enum message.
const ENUM_MESSAGE: &str = "must be equal to one of the allowed values";

fn validate_operation_type(value: Option<&Value>, messages: &mut Vec<String>) -> Option<String> {
    match value {
        None | Some(Value::Null) => {
            messages.push("operationType is required".to_string());
            None
        }
        Some(Value::String(s)) => {
            if !is_valid_operation_type(s) {
                messages.push(ENUM_MESSAGE.to_string());
                None
            } else {
                Some(s.clone())
            }
        }
        Some(_) => {
            messages.push(ENUM_MESSAGE.to_string());
            None
        }
    }
}

/// AJV `{ resourceId?: number }` type check (rejects null / non-numbers with
/// "must be number"); returns whether the value passed the schema.
fn ajv_check_resource_id(value: Option<&Value>, messages: &mut Vec<String>) -> bool {
    match value {
        None => true,
        Some(v) if v.is_number() => true,
        Some(_) => {
            messages.push("must be number".to_string());
            false
        }
    }
}

/// After AJV: convert the number to Prisma Int semantics — non-integer or
/// out-of-i32 values fail Prisma validation -> 500.
fn prisma_resource_id(value: Option<&Value>) -> Result<Option<i32>, ApiError> {
    match value {
        None => Ok(None),
        Some(v) => {
            let n = v.as_f64().unwrap_or(f64::NAN);
            if n.is_finite()
                && n.fract() == 0.0
                && (i32::MIN as f64..=i32::MAX as f64).contains(&n)
            {
                Ok(Some(n as i32))
            } else {
                Err(ApiError::internal("Prisma Int argument out of range"))
            }
        }
    }
}

// ===========================================================================
// POST /request — 请求二次验证码
// ===========================================================================

async fn request_code(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let mut messages: Vec<String> = Vec::new();
    let Some(obj) = body.as_object() else {
        return Err(validation_error(vec!["must be object".to_string()]));
    };
    let operation_type = validate_operation_type(obj.get("operationType"), &mut messages);
    let resource_id_ajv_ok = ajv_check_resource_id(obj.get("resourceId"), &mut messages);
    if let Some(v) = obj.get("resourceType") {
        // AJV `type: string` rejects null and non-strings.
        if !v.is_string() {
            messages.push("must be string".to_string());
        }
    }
    if !messages.is_empty() {
        return Err(validation_error(messages));
    }
    let operation_type = operation_type.expect("validated above");
    let resource_id = if resource_id_ajv_ok {
        prisma_resource_id(obj.get("resourceId"))?
    } else {
        None
    };
    let resource_type = obj.get("resourceType").and_then(|v| v.as_str());

    // 资源操作：检查是否需要二次验证
    if is_resource_operation(&operation_type)
        && !is_resource_verification_required(&state.db, user.id).await?
    {
        return Ok(Json(json!({
            "success": true,
            "required": false,
            "message": "No notification channel configured, verification not required"
        }))
        .into_response());
    }

    let result = request_operation_verification(
        &state.db,
        user.id,
        &operation_type,
        resource_id,
        resource_type,
    )
    .await?;

    if !result.success {
        // Dead branch in TS (failures never carry expiresIn), kept for parity.
        if let Some(expires_in) = result.expires_in {
            return Ok(Json(json!({
                "success": true,
                "channel": result.channel,
                "maskedTarget": result.masked_target,
                "expiresIn": expires_in,
                "message": "Verification code already sent"
            }))
            .into_response());
        }
        return Err(ApiError::with_message(
            result.error_code.as_deref().unwrap_or("VERIFICATION_FAILED"),
            StatusCode::BAD_REQUEST,
            result.error.as_deref().unwrap_or_default(),
        ));
    }

    Ok(Json(json!({
        "success": true,
        "required": true,
        "channel": result.channel,
        "maskedTarget": result.masked_target,
        "expiresIn": result.expires_in,
        "operationName": get_operation_name(&operation_type, "zh"),
    }))
    .into_response())
}

// ===========================================================================
// POST /verify — 验证二次验证码
// ===========================================================================

async fn verify_code(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let mut messages: Vec<String> = Vec::new();
    let Some(obj) = body.as_object() else {
        return Err(validation_error(vec!["must be object".to_string()]));
    };
    let operation_type = validate_operation_type(obj.get("operationType"), &mut messages);
    let verify_code_value = match obj.get("code") {
        None | Some(Value::Null) => {
            messages.push("code is required".to_string());
            None
        }
        Some(Value::String(s)) => {
            let len: usize = s.chars().map(|c| c.len_utf16()).sum();
            if len < CODE_LENGTH {
                messages.push("code is too short".to_string());
            } else if len > CODE_LENGTH {
                messages.push("code is too long".to_string());
            }
            Some(s.clone())
        }
        Some(_) => {
            messages.push("must be string".to_string());
            None
        }
    };
    let resource_id_ajv_ok = ajv_check_resource_id(obj.get("resourceId"), &mut messages);
    if !messages.is_empty() {
        return Err(validation_error(messages));
    }
    let operation_type = operation_type.expect("validated above");
    let verify_code_value = verify_code_value.expect("validated above");
    let resource_id = if resource_id_ajv_ok {
        prisma_resource_id(obj.get("resourceId"))?
    } else {
        None
    };

    let result = verify_operation_code(
        &state.db,
        user.id,
        &operation_type,
        &verify_code_value,
        resource_id,
    )
    .await?;

    if !result.success || !result.verified {
        return Err(ApiError::with_message(
            result.error_code.as_deref().unwrap_or("INVALID_CODE"),
            StatusCode::BAD_REQUEST,
            result
                .error
                .as_deref()
                .unwrap_or("Verification failed"),
        ));
    }

    Ok(Json(json!({
        "success": true,
        "verified": true,
        "message": "Verification successful"
    }))
    .into_response())
}

// ===========================================================================
// GET /check — 检查操作是否已通过验证
// ===========================================================================

async fn check(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let mut messages: Vec<String> = Vec::new();
    let operation_type = match params.get("operationType") {
        Some(v) => {
            if !is_valid_operation_type(v) {
                messages.push(ENUM_MESSAGE.to_string());
                None
            } else {
                Some(v.clone())
            }
        }
        None => {
            messages.push("operationType is required".to_string());
            None
        }
    };
    if !messages.is_empty() {
        return Err(validation_error(messages));
    }
    let operation_type = operation_type.expect("validated above");

    // 资源操作：检查是否需要二次验证
    if is_resource_operation(&operation_type)
        && !is_resource_verification_required(&state.db, user.id).await?
    {
        return Ok(Json(json!({ "required": false, "verified": true })).into_response());
    }

    // `resourceId ? parseInt(resourceId, 10) : undefined`; NaN -> null via
    // the `resourceId || null` guards downstream.
    let resource_id: Option<i32> = match params.get("resourceId") {
        Some(s) if !s.is_empty() => {
            let trimmed = s.trim_start();
            let bytes = trimmed.as_bytes();
            let mut end = 0usize;
            if bytes.first().map(|b| *b == b'-' || *b == b'+').unwrap_or(false) {
                end += 1;
            }
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end == 0 || (end == 1 && (bytes[0] == b'-' || bytes[0] == b'+')) {
                // parseInt -> NaN -> falsy -> null
                None
            } else {
                let parsed: f64 = trimmed[..end].parse().unwrap_or(f64::NAN);
                if !parsed.is_finite() || parsed.fract() != 0.0 {
                    None
                } else if !(i32::MIN as f64..=i32::MAX as f64).contains(&parsed) {
                    return Err(ApiError::internal("Prisma Int argument out of range"));
                } else {
                    Some(parsed as i32)
                }
            }
        }
        _ => None,
    };

    let verified = is_operation_verified(&state.db, user.id, &operation_type, resource_id).await?;
    let required = is_account_operation(&operation_type)
        || is_resource_verification_required(&state.db, user.id).await?;

    Ok(Json(json!({ "required": required, "verified": verified })).into_response())
}

// ===========================================================================
// GET /operation-types — 获取操作类型信息
// ===========================================================================

async fn operation_types(_user: AuthUser) -> Json<Value> {
    let account_operations: Vec<Value> = VALID_OPERATION_TYPES
        .iter()
        .filter(|op| is_account_operation(op))
        .map(|op| {
            json!({
                "type": op,
                "name": get_operation_name(op, "zh"),
                "nameEn": get_operation_name(op, "en"),
                "channel": "email",
            })
        })
        .collect();
    let resource_operations: Vec<Value> = VALID_OPERATION_TYPES
        .iter()
        .filter(|op| is_resource_operation(op))
        .map(|op| {
            json!({
                "type": op,
                "name": get_operation_name(op, "zh"),
                "nameEn": get_operation_name(op, "en"),
                "channel": "notification",
            })
        })
        .collect();

    Json(json!({
        "accountOperations": account_operations,
        "resourceOperations": resource_operations,
    }))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_suffix_round_trip() {
        let (code, attempts) = decode_verification_code("123456");
        assert_eq!((code.as_str(), attempts), ("123456", 0));

        let (code, attempts) = decode_verification_code("123456:attempts:3");
        assert_eq!((code.as_str(), attempts), ("123456", 3));

        // Out-of-range attempts decode as the whole literal with 0 attempts.
        let (code, attempts) = decode_verification_code("123456:attempts:9");
        assert_eq!(attempts, 0);
        assert_eq!(code, "123456:attempts:9");

        assert_eq!(encode_verification_code("123456", 2), "123456:attempts:2");
    }

    #[test]
    fn operation_classification() {
        assert!(is_account_operation("change_password"));
        assert!(!is_account_operation("delete_instance"));
        assert!(is_resource_operation("delete_snapshot"));
        // delete_instance exists in the enum but is NOT offered by the routes.
        assert!(!is_valid_operation_type("delete_instance"));
        assert_eq!(get_operation_name("reinstall_instance", "zh"), "重装实例");
        assert_eq!(get_operation_name("reinstall_instance", "en"), "Reinstall Instance");
        assert_eq!(get_operation_name("unknown_op", "zh"), "unknown_op");
    }

    #[test]
    fn masked_email_matches_js_substring() {
        // "ab***@example.com"
        let parts: Vec<&str> = "abcd@example.com".split('@').collect();
        let masked = format!("{}***@{}", js_slice(parts[0], 2), parts[1]);
        assert_eq!(masked, "ab***@example.com");

        // UTF-16 substring on a CJK local part keeps whole surrogate pairs.
        let parts: Vec<&str> = "测试账户@example.com".split('@').collect();
        assert_eq!(js_slice(parts[0], 2), "测试");
    }

    #[test]
    fn router_builds() {
        let _ = router();
    }
}
