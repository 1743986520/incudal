//! 用户邀请码管理路由 — port of server/src/routes/user-invites.ts (mounted at
//! /api/user-invites), including the lib/invite-pricing.ts port used only by
//! this module (cost options, quotes, charging balance/points).
//!
//! Endpoint map (TS decorator -> Rust extractor):
//! - GET  /summary  authenticateUser -> UserOnlyAuth
//! - GET  /         authenticateUser -> UserOnlyAuth
//! - POST /         authenticateUser -> UserOnlyAuth (+20/min inline rate limit)
//!
//! Inline rate limit NOT in rate_limit.rs: POST / 20 per minute.
//!
//! The POST body goes through the Fastify schema
//! `{ costResource: string 1..64 required, count: integer 1..10 }` — failures
//! map to the app error handler's `400 { error, code: VALIDATION_ERROR,
//! details? }` shape. Charge failures map to the TS message/code pairs
//! (INVITE_COST_OPTION_UNAVAILABLE / INVITE_COST_RESOURCE_UNSUPPORTED /
//! INSUFFICIENT_BALANCE / INSUFFICIENT_POINTS / USER_NOT_FOUND 404).

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::auth::UserOnlyAuth;
use crate::error::{code, ApiError};
use crate::libs::vip::{js_num_json, js_num_to_string, js_round, round_money_f64};
use crate::response::num;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/summary", get(summary))
        .route("/", get(list).post(generate))
}

// ===========================================================================
// small helpers
// ===========================================================================

fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// nanoid(12) with nanoid's default URL-safe alphabet (same as auth.rs).
fn nanoid_12() -> String {
    const ALPHABET: &[u8] = b"useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";
    let mut rng = rand::thread_rng();
    use rand::Rng;
    (0..12)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

// ===========================================================================
// lib/invite-pricing.ts port
// ===========================================================================

#[derive(Debug, Clone)]
struct InviteCostOption {
    resource: String,
    amount: f64,
    enabled: bool,
}

const DEFAULT_COST_OPTIONS: [(&str, f64, bool); 2] =
    [("balance", 0.0, false), ("points", 0.0, false)];

fn default_cost_options() -> Vec<InviteCostOption> {
    DEFAULT_COST_OPTIONS
        .iter()
        .map(|(resource, amount, enabled)| InviteCostOption {
            resource: resource.to_string(),
            amount: *amount,
            enabled: *enabled,
        })
        .collect()
}

/// Handler metadata for supported resources.
fn cost_handler(resource: &str) -> Option<(&'static str, &'static str)> {
    // (label, unit)
    match resource {
        "balance" => Some(("余额", "元")),
        "points" => Some(("积分", "积分")),
        _ => None,
    }
}

fn normalize_cost_amount(resource: &str, amount: f64) -> f64 {
    match resource {
        "balance" => round_money_f64(0.0f64.max(amount)),
        "points" => 0.0f64.max(amount).floor(),
        _ => 0.0f64.max(amount),
    }
}

/// parseInviteCostConfig — invalid JSON / non-array falls back to defaults.
fn parse_invite_cost_config(raw: Option<&str>) -> Vec<InviteCostOption> {
    let Some(raw) = raw else {
        return default_cost_options();
    };
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw) else {
        return default_cost_options();
    };

    let mut options = Vec::new();
    for item in items {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let resource = obj
            .get("resource")
            .map(|v| {
                // TS String(item.resource || '').trim()
                if v.is_null() || v == &Value::Bool(false) || v == &json!(0) {
                    String::new()
                } else if let Some(s) = v.as_str() {
                    s.to_string()
                } else {
                    v.to_string()
                }
            })
            .unwrap_or_default()
            .trim()
            .to_string();
        if resource.is_empty() {
            continue;
        }
        let amount = obj
            .get("amount")
            .and_then(crate::libs::vip::js_to_number)
            .filter(|v| v.is_finite())
            .unwrap_or(0.0);
        let amount = normalize_cost_amount(&resource, amount);
        options.push(InviteCostOption {
            resource,
            amount,
            enabled: obj.get("enabled") == Some(&Value::Bool(true)),
        });
    }
    options
}

/// ensureDefaultCostOptions — parsed options first, missing defaults appended
/// (TS Map insertion order).
fn ensure_default_cost_options(options: Vec<InviteCostOption>) -> Vec<InviteCostOption> {
    let mut merged = options;
    for (resource, amount, enabled) in DEFAULT_COST_OPTIONS {
        if !merged.iter().any(|option| option.resource == resource) {
            merged.push(InviteCostOption {
                resource: resource.to_string(),
                amount,
                enabled,
            });
        }
    }
    merged
}

fn normalize_cost_options(options: Vec<InviteCostOption>) -> Vec<InviteCostOption> {
    ensure_default_cost_options(options)
        .into_iter()
        .map(|option| InviteCostOption {
            amount: normalize_cost_amount(&option.resource, option.amount),
            ..option
        })
        .collect()
}

/// getSystemConfig(key) for non-sensitive keys: raw string or null.
async fn get_system_config_string(
    db: &PgPool,
    key: &str,
) -> Result<Option<String>, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT value FROM system_configs WHERE key = $1")
            .bind(key)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(v,)| v))
}

/// getSystemConfigNumber: parseInt(value, 10) with default fallback.
async fn get_system_config_int(
    db: &PgPool,
    key: &str,
    default_value: i64,
) -> Result<i64, ApiError> {
    let Some(value) = get_system_config_string(db, key).await? else {
        return Ok(default_value);
    };
    // JS parseInt: leading integer prefix; NaN -> default.
    let trimmed = value.trim_start();
    let bytes = trimmed.as_bytes();
    let mut end = 0usize;
    if bytes.first().map(|b| *b == b'-' || *b == b'+').unwrap_or(false) {
        end += 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && (bytes[0] == b'-' || bytes[0] == b'+')) {
        return Ok(default_value);
    }
    trimmed[..end]
        .parse::<i64>()
        .map(|v| v as i64)
        .or(Ok(default_value))
}

async fn get_invite_cost_options(db: &PgPool) -> Result<Vec<InviteCostOption>, ApiError> {
    let raw = get_system_config_string(db, "invite_generation_costs").await?;
    Ok(normalize_cost_options(parse_invite_cost_config(raw.as_deref())))
}

/// getInviteExpiryDays: Math.max(0, getSystemConfigNumber(...)).
async fn get_invite_expiry_days(db: &PgPool) -> Result<i64, ApiError> {
    Ok(0i64.max(get_system_config_int(db, "invite_default_expire_days", 0).await?))
}

/// getInviteCostQuotes — options with display metadata.
fn invite_cost_quotes(options: &[InviteCostOption]) -> Vec<Value> {
    options
        .iter()
        .map(|option| {
            let (label, unit, display_amount) = match cost_handler(&option.resource) {
                Some((label, unit)) => {
                    let display = if option.resource == "balance" {
                        format!("¥{:.2}", option.amount)
                    } else if option.resource == "points" {
                        format!("{} 积分", option.amount.floor() as i64)
                    } else {
                        unreachable!()
                    };
                    (label, unit, display)
                }
                None => {
                    let unit = "";
                    let display = js_num_to_string(option.amount);
                    (option.resource.as_str(), unit, display)
                }
            };
            json!({
                "resource": option.resource,
                "amount": js_num_json(option.amount),
                "enabled": option.enabled,
                "label": label,
                "unit": unit,
                "displayAmount": display_amount,
            })
        })
        .collect()
}

/// getUserInviteBalances — balance + upserted points row.
async fn get_user_invite_balances(
    db: &PgPool,
    user_id: i32,
) -> Result<(Decimal, i32), ApiError> {
    let balance: Option<(Decimal,)> =
        sqlx::query_as("SELECT balance FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    sqlx::query("INSERT INTO user_points (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING")
        .bind(user_id)
        .execute(db)
        .await?;
    let (points,): (i32,) = sqlx::query_as("SELECT points FROM user_points WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?;
    Ok((balance.map(|(b,)| b).unwrap_or(Decimal::ZERO), points))
}

/// Charge-step errors thrown as Error(message) in the TS and matched by the
/// route's catch block.
enum InviteChargeError {
    OptionUnavailable,
    ResourceUnsupported,
    InsufficientBalance,
    InsufficientPoints,
    UserNotFound,
    Db(ApiError),
}

impl From<ApiError> for InviteChargeError {
    fn from(e: ApiError) -> Self {
        Self::Db(e)
    }
}

/// chargeInviteGenerationCost — returns the cost snapshot JSON.
async fn charge_invite_generation_cost(
    tx: &mut sqlx::PgConnection,
    user_id: i32,
    invite_code: &str,
    resource: &str,
    cost_options: &[InviteCostOption],
) -> Result<Value, InviteChargeError> {
    let Some(option) = cost_options
        .iter()
        .find(|cost| cost.resource == resource && cost.enabled)
    else {
        return Err(InviteChargeError::OptionUnavailable);
    };
    let Some((label, unit)) = cost_handler(&option.resource) else {
        return Err(InviteChargeError::ResourceUnsupported);
    };

    if option.resource == "balance" {
        charge_balance(tx, user_id, option.amount, invite_code).await?;
    } else if option.resource == "points" {
        charge_points(tx, user_id, option.amount, invite_code).await?;
    }

    let display_amount = if option.resource == "balance" {
        format!("¥{:.2}", option.amount)
    } else {
        format!("{} 积分", option.amount.floor() as i64)
    };

    Ok(json!({
        "resource": option.resource,
        "amount": js_num_json(option.amount),
        "label": label,
        "unit": unit,
        "displayAmount": display_amount,
        "chargedAt": iso(Utc::now()),
    }))
}

async fn charge_balance(
    tx: &mut sqlx::PgConnection,
    user_id: i32,
    amount: f64,
    invite_code: &str,
) -> Result<(), InviteChargeError> {
    if amount <= 0.0 {
        return Ok(());
    }
    let amount_dec = crate::libs::vip::dec2(amount);

    let rows: Vec<(Decimal, Decimal)> = sqlx::query_as(
        "UPDATE users SET balance = balance - $2 \
         WHERE id = $1 AND balance >= $2 \
         RETURNING (balance + $2) AS balance_before, balance AS balance_after",
    )
    .bind(user_id)
    .bind(amount_dec)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| InviteChargeError::Db(ApiError::from_sql(e)))?;

    if rows.len() != 1 {
        let user_exists: Option<(i32,)> =
            sqlx::query_as("SELECT id FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| InviteChargeError::Db(ApiError::from_sql(e)))?;
        if user_exists.is_none() {
            return Err(InviteChargeError::UserNotFound);
        }
        return Err(InviteChargeError::InsufficientBalance);
    }

    let (balance_before, balance_after) = rows[0];
    sqlx::query(
        "INSERT INTO balance_logs \
         (user_id, type, amount, balance_before, balance_after, remark) \
         VALUES ($1, 'invite_generate'::\"BalanceLogType\", $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(-amount_dec)
    .bind(balance_before)
    .bind(balance_after)
    .bind(format!("生成邀请码 {invite_code}"))
    .execute(&mut *tx)
    .await
    .map_err(|e| InviteChargeError::Db(ApiError::from_sql(e)))?;
    Ok(())
}

async fn charge_points(
    tx: &mut sqlx::PgConnection,
    user_id: i32,
    amount: f64,
    invite_code: &str,
) -> Result<(), InviteChargeError> {
    if amount <= 0.0 {
        return Ok(());
    }
    let amount_int = amount.floor() as i32;

    sqlx::query("INSERT INTO user_points (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| InviteChargeError::Db(ApiError::from_sql(e)))?;

    let rows: Vec<(i32, i32)> = sqlx::query_as(
        "UPDATE user_points SET points = points - $2, total_spent = total_spent + $2, \
         updated_at = NOW() \
         WHERE user_id = $1 AND points >= $2 \
         RETURNING points + $2 AS points_before, points AS points_after",
    )
    .bind(user_id)
    .bind(amount_int)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| InviteChargeError::Db(ApiError::from_sql(e)))?;

    if rows.len() != 1 {
        return Err(InviteChargeError::InsufficientPoints);
    }

    let (points_before, points_after) = rows[0];
    sqlx::query(
        "INSERT INTO points_logs \
         (user_id, type, amount, points_before, points_after, remark) \
         VALUES ($1, 'invite_generate'::\"PointsLogType\", $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(-amount_int)
    .bind(points_before)
    .bind(points_after)
    .bind(format!("生成邀请码 {invite_code}"))
    .execute(&mut *tx)
    .await
    .map_err(|e| InviteChargeError::Db(ApiError::from_sql(e)))?;
    Ok(())
}

// ===========================================================================
// invite payloads
// ===========================================================================

#[derive(Debug, sqlx::FromRow)]
struct InviteRow {
    id: i32,
    code: String,
    created_by: i32,
    used_by: Option<i32>,
    used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    cost_snapshot: Option<Value>,
    // joined user (used_by target)
    user_id: Option<i32>,
    username: Option<String>,
    email: Option<String>,
    avatar_style: Option<String>,
    avatar_badge_id: Option<String>,
    user_created_at: Option<DateTime<Utc>>,
}

const INVITE_SELECT: &str = "SELECT i.id, i.code, i.created_by, i.used_by, i.used_at, \
    i.expires_at, i.created_at, i.cost_snapshot, \
    u.id AS user_id, u.username, u.email, u.avatar_style, u.avatar_badge_id, u.created_at AS user_created_at \
    FROM invite_codes i LEFT JOIN users u ON u.id = i.used_by";

fn to_invite_payload(invite: &InviteRow) -> Value {
    let used_by_user = match (
        invite.user_id,
        &invite.username,
        &invite.email,
        &invite.avatar_style,
        &invite.avatar_badge_id,
        invite.user_created_at,
    ) {
        (Some(id), Some(username), email, avatar_style, avatar_badge_id, Some(created_at)) => {
            json!({
                "id": id,
                "username": username,
                "email": email,
                "avatarStyle": avatar_style,
                "avatarBadgeId": avatar_badge_id,
                "createdAt": iso(created_at),
            })
        }
        _ => Value::Null,
    };
    json!({
        "id": invite.id,
        "code": invite.code,
        "createdBy": invite.created_by,
        "usedBy": invite.used_by,
        "usedAt": invite.used_at.map(|t| Value::String(iso(t))).unwrap_or(Value::Null),
        "expiresAt": invite.expires_at.map(|t| Value::String(iso(t))).unwrap_or(Value::Null),
        "createdAt": iso(invite.created_at),
        "costSnapshot": invite.cost_snapshot.clone().unwrap_or(Value::Null),
        "registerUrl": format!("/register/{}", invite.code),
        "usedByUser": used_by_user,
    })
}

// ===========================================================================
// GET /summary — 邀请码统计与生成方式报价
// ===========================================================================

async fn summary(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    let user_id = user.0.id;

    let cost_options = get_invite_cost_options(&state.db).await?;
    let (balance, points) = get_user_invite_balances(&state.db, user_id).await?;
    let (total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM invite_codes WHERE created_by = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    let (used,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM invite_codes WHERE created_by = $1 AND used_by IS NOT NULL",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;

    // usageRate: total > 0 ? Math.round((used / total) * 1000) / 10 : 0
    let usage_rate = if total > 0 {
        js_round((used as f64 / total as f64) * 1000.0) / 10.0
    } else {
        0.0
    };

    Ok(Json(json!({
        "costOptions": invite_cost_quotes(&cost_options),
        "balances": {
            "balance": num(balance),
            "points": points,
        },
        "stats": {
            "total": total,
            "used": used,
            "unused": total - used,
            "usageRate": js_num_json(usage_rate),
        }
    })))
}

// ===========================================================================
// GET / — 邀请码列表
// ===========================================================================

async fn list(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let pagination = crate::response::parse_pagination(&params, 20, Some(100));
    let user_id = user.0.id;

    let (total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM invite_codes WHERE created_by = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    let invites = sqlx::query_as::<_, InviteRow>(&format!(
        "{INVITE_SELECT} WHERE i.created_by = $1 ORDER BY i.id DESC OFFSET $2 LIMIT $3"
    ))
    .bind(user_id)
    .bind(pagination.skip)
    .bind(pagination.take)
    .fetch_all(&state.db)
    .await?;

    let total_pages = 1i64.max(total.saturating_add(pagination.page_size - 1) / pagination.page_size.max(1));
    Ok(Json(json!({
        "invites": invites.iter().map(to_invite_payload).collect::<Vec<_>>(),
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
        "totalPages": total_pages,
    })))
}

// ===========================================================================
// POST / — 生成邀请码
// ===========================================================================

/// Fastify schema validation (body): costResource required string 1..64,
/// count optional integer 1..10. Messages follow the app error handler.
fn validate_generate_body(body: &Value) -> Result<(String, i64), ApiError> {
    let invalid = |messages: Vec<String>| -> ApiError {
        let first = messages.first().cloned().unwrap_or_else(|| "Validation failed".into());
        let mut err = ApiError::with_message(code::VALIDATION_ERROR, StatusCode::BAD_REQUEST, first);
        if messages.len() > 1 {
            err = err.with_details(messages.join(", "));
        }
        err
    };

    let Some(obj) = body.as_object() else {
        return Err(invalid(vec!["must be object".to_string()]));
    };

    let mut messages: Vec<String> = Vec::new();

    let cost_resource = match obj.get("costResource") {
        None | Some(Value::Null) => {
            messages.push("costResource is required".to_string());
            None
        }
        Some(Value::String(s)) => {
            let len: usize = s.chars().count();
            if len < 1 {
                messages.push("costResource is too short".to_string());
            } else if len > 64 {
                messages.push("costResource is too long".to_string());
            }
            Some(s.clone())
        }
        Some(_) => {
            messages.push("must be string".to_string());
            None
        }
    };

    let count = match obj.get("count") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_f64() {
            Some(n) if n.fract() == 0.0 && n >= 1.0 && n <= 10.0 => Some(n as i64),
            Some(n) if n.fract() != 0.0 => {
                messages.push("must be integer".to_string());
                None
            }
            Some(_) => {
                messages.push(if v.as_f64().unwrap_or(0.0) < 1.0 {
                    "must be >= 1".to_string()
                } else {
                    "must be <= 10".to_string()
                });
                None
            }
            None => {
                messages.push("must be integer".to_string());
                None
            }
        },
    };

    if !messages.is_empty() {
        return Err(invalid(messages));
    }
    Ok((cost_resource.unwrap_or_default(), count.unwrap_or(1)))
}

/// The TS catch block: charge-step error messages -> wire responses.
fn invite_charge_error_response(err: InviteChargeError) -> Response {
    let (status, error, error_code) = match err {
        InviteChargeError::OptionUnavailable => (
            StatusCode::BAD_REQUEST,
            "当前邀请码生成方式不可用".to_string(),
            "INVITE_COST_OPTION_UNAVAILABLE",
        ),
        InviteChargeError::ResourceUnsupported => (
            StatusCode::BAD_REQUEST,
            "暂不支持该生成方式".to_string(),
            "INVITE_COST_RESOURCE_UNSUPPORTED",
        ),
        InviteChargeError::InsufficientBalance => (
            StatusCode::BAD_REQUEST,
            "余额不足".to_string(),
            "INSUFFICIENT_BALANCE",
        ),
        InviteChargeError::InsufficientPoints => (
            StatusCode::BAD_REQUEST,
            "积分不足".to_string(),
            "INSUFFICIENT_POINTS",
        ),
        InviteChargeError::UserNotFound => {
            return ApiError::not_found(code::USER_NOT_FOUND).into_response();
        }
        InviteChargeError::Db(api_err) => return api_err.into_response(),
    };
    (
        status,
        Json(json!({ "error": error, "code": error_code })),
    )
        .into_response()
}

async fn generate(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let user_id = user.0.id;
    let (cost_resource, count) = validate_generate_body(&body)?;

    let expiry_days = get_invite_expiry_days(&state.db).await?;
    let cost_options = get_invite_cost_options(&state.db).await?;
    let expires_at: Option<DateTime<Utc>> = if expiry_days > 0 {
        Some(Utc::now() + chrono::Duration::days(expiry_days))
    } else {
        None
    };

    let mut tx = state.db.begin().await?;

    let created: Result<Vec<InviteRow>, InviteChargeError> = async {
        let mut results = Vec::new();
        for _ in 0..count {
            let code = nanoid_12();
            let cost_snapshot =
                charge_invite_generation_cost(&mut *tx, user_id, &code, &cost_resource, &cost_options)
                    .await?;
            let invite = sqlx::query_as::<_, InviteRow>(
                "INSERT INTO invite_codes (code, created_by, expires_at, cost_snapshot) \
                 VALUES ($1, $2, $3, $4) \
                 RETURNING id, code, created_by, used_by, used_at, expires_at, created_at, \
                 cost_snapshot, NULL AS user_id, NULL AS username, NULL AS email, \
                 NULL AS avatar_style, NULL AS avatar_badge_id, NULL AS user_created_at",
            )
            .bind(&code)
            .bind(user_id)
            .bind(expires_at)
            .bind(&cost_snapshot)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| InviteChargeError::Db(ApiError::from_sql(e)))?;
            results.push(invite);
        }
        Ok(results)
    }
    .await;

    let created = match created {
        Ok(rows) => rows,
        Err(err) => {
            let _ = tx.rollback().await;
            return Ok(invite_charge_error_response(err));
        }
    };
    tx.commit().await?;

    Ok(Json(json!({
        "invites": created.iter().map(to_invite_payload).collect::<Vec<_>>(),
        "count": created.len(),
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_config_parsing_falls_back_to_defaults() {
        let options = parse_invite_cost_config(Some("not json"));
        assert_eq!(options.len(), 2);
        assert_eq!(options[0].resource, "balance");
        assert!(!options[0].enabled);

        let options = parse_invite_cost_config(Some(
            r#"[{"resource":"balance","amount":1.005,"enabled":true},{"resource":"points","amount":2.6,"enabled":false}]"#,
        ));
        let options = normalize_cost_options(options);
        // JS: Math.round(1.005 * 100) / 100 -> 100.49999... -> 100 -> 1.0
        assert_eq!(options[0].amount, 1.0);
        assert!(options[0].enabled);
        assert_eq!(options[1].amount, 2.0);
    }

    #[test]
    fn quotes_format_amounts() {
        let options = vec![
            InviteCostOption { resource: "balance".into(), amount: 12.5, enabled: true },
            InviteCostOption { resource: "points".into(), amount: 30.0, enabled: true },
        ];
        let quotes = invite_cost_quotes(&options);
        assert_eq!(quotes[0]["displayAmount"], json!("¥12.50"));
        assert_eq!(quotes[0]["label"], json!("余额"));
        assert_eq!(quotes[1]["displayAmount"], json!("30 积分"));
    }

    #[test]
    fn generate_body_validation() {
        assert!(
            validate_generate_body(&json!({ "costResource": "balance", "count": 3 })).is_ok()
        );
        assert!(validate_generate_body(&json!({})).is_err());
        assert!(validate_generate_body(&json!({ "costResource": "" })).is_err());
        assert!(
            validate_generate_body(&json!({ "costResource": "balance", "count": 11 })).is_err()
        );
        assert!(
            validate_generate_body(&json!({ "costResource": "balance", "count": 1.5 })).is_err()
        );
    }
}
