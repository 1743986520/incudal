//! 余额管理路由 — port of server/src/routes/balance.ts (mounted at /api/balance).
//!
//! Endpoint map (TS decorator -> Rust extractor):
//! - GET  /me                     authenticate     -> AuthUser
//! - GET  /me/logs                authenticate     -> AuthUser
//! - GET  /me/billing             authenticate     -> AuthUser
//! - GET  /transfer/recipient     authenticateUser -> UserOnlyAuth (+rate limit in rate_limit.rs)
//! - POST /transfer/preview       authenticateUser -> UserOnlyAuth (+rate limit)
//! - POST /transfer               authenticateUser -> UserOnlyAuth (+rate limit)
//! - GET  /admin/{userId}         authenticate+requireAdmin -> AdminAuth
//! - GET  /admin/{userId}/logs    authenticate+requireAdmin -> AdminAuth
//! - POST /admin/{userId}/adjust  authenticate+requireAdmin -> AdminAuth (+rate limit)
//! - POST /admin/{userId}/gift    authenticate+requireAdmin -> AdminAuth (+rate limit)
//!
//! Reported deviations:
//! - sendBalanceAdjustedEmail (nodemailer) is not ported: adjust/gift log a
//!   warning where the TS sends the email; email failures never affect the
//!   response in TS either.
//! - Per-route rate limits (transfer 30/10 per minute, adjust/gift 20 per
//!   minute) live in rate_limit.rs, which is outside this module.
//! - changeBalance's catch-all maps unexpected DB failures to
//!   `400 { error: <message> }` exactly like the TS (it does NOT rethrow);
//!   transient serialization/deadlock failures are retried inside the
//!   transaction like runBalanceTransaction does.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::{AdminAuth, AuthUser, UserOnlyAuth};
use crate::db;
use crate::error::{code, ApiError};
use crate::response::num;
use crate::routes::users::create_log;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/me", get(me_balance))
        .route("/me/logs", get(me_logs))
        .route("/me/billing", get(me_billing))
        .route("/transfer/recipient", get(transfer_recipient))
        .route("/transfer/preview", post(transfer_preview))
        .route("/transfer", post(transfer_submit))
        .route("/admin/{user_id}", get(admin_balance))
        .route("/admin/{user_id}/logs", get(admin_logs))
        .route("/admin/{user_id}/adjust", post(admin_adjust))
        .route("/admin/{user_id}/gift", post(admin_gift))
}

// ===========================================================================
// small shared helpers
// ===========================================================================

/// TS `Date` fields serialize as ISO strings through Fastify's JSON encoder.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// JS `Number(str)` for route params: NaN -> 400 INVALID_ID, non-integral or
/// out-of-i32 values mirror the Prisma Int validation failure (500).
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

/// JS String(number) for log interpolation (integers print without ".0").
fn js_num_string(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    format!("{v}")
}

/// JS Math.round: halves round toward +Infinity.
fn js_round(v: f64) -> f64 {
    (v + 0.5).floor()
}

/// lib/balance-transfer.ts roundMoney: round to cents avoiding float drift.
fn round_money(value: f64) -> f64 {
    js_round((value + f64::EPSILON) * 100.0) / 100.0
}

/// Exact Decimal from an already-rounded money f64 (string round-trip so the
/// binary float never leaks extra digits).
fn dec_from_money(value: f64) -> Option<Decimal> {
    use std::str::FromStr;
    Decimal::from_str(&format!("{value:.2}")).ok()
}

fn has_at_most_two_decimal_places(value: f64) -> bool {
    (value * 100.0 - js_round(value * 100.0)).abs() < 1e-9
}

pub const MAX_USER_BALANCE: f64 = 99999999.99;

/// lib/balance-transfer.ts normalizeBalanceTransferAmount.
fn normalize_transfer_amount(value: f64) -> Result<f64, &'static str> {
    if !value.is_finite()
        || value < 0.01
        || value > MAX_USER_BALANCE
        || !has_at_most_two_decimal_places(value)
    {
        return Err("BALANCE_TRANSFER_AMOUNT_INVALID");
    }
    Ok(round_money(value))
}

/// lib/balance-transfer.ts normalizeBalanceTransferFee.
fn normalize_transfer_fee(value: f64) -> Result<f64, &'static str> {
    if !value.is_finite()
        || value < 0.0
        || value > MAX_USER_BALANCE
        || !has_at_most_two_decimal_places(value)
    {
        return Err("BALANCE_TRANSFER_AMOUNT_INVALID");
    }
    Ok(round_money(value))
}

/// Decimal roundMoney (inputs are already 2dp; kept for TS parity).
fn round_money_dec(value: Decimal) -> Decimal {
    use rust_decimal::RoundingStrategy;
    value.round_dp_with_strategy(2, RoundingStrategy::MidpointAwayFromZero)
}

/// lib/balance-transfer.ts createBalanceTransferNo:
/// `BT` + base36 timestamp + 8 base36 random chars, uppercased.
fn create_transfer_no() -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut n = Utc::now().timestamp_millis() as u64;
    let mut ts36 = Vec::new();
    while n > 0 {
        ts36.push(CHARS[(n % 36) as usize] as char);
        n /= 36;
    }
    if ts36.is_empty() {
        ts36.push('0');
    }
    let mut random = String::with_capacity(8);
    for _ in 0..8 {
        random.push(CHARS[(rand::random::<u8>() % 36) as usize] as char);
    }
    let ts36: String = ts36.into_iter().rev().collect();
    format!("BT{ts36}{random}")
}

/// routes/balance.ts mapBalanceTransferError: thrown message -> status + code.
fn transfer_api_error(message: &str) -> ApiError {
    match message {
        "USER_NOT_FOUND" => ApiError::not_found(code::USER_NOT_FOUND),
        "BALANCE_TRANSFER_DISABLED" => ApiError::forbidden(code::BALANCE_TRANSFER_DISABLED),
        "BALANCE_TRANSFER_TO_SELF" => ApiError::bad_request(code::BALANCE_TRANSFER_TO_SELF),
        "BALANCE_TRANSFER_RECIPIENT_BANNED" => {
            ApiError::bad_request(code::BALANCE_TRANSFER_RECIPIENT_BANNED)
        }
        "BALANCE_TRANSFER_AMOUNT_INVALID" => {
            ApiError::bad_request(code::BALANCE_TRANSFER_AMOUNT_INVALID)
        }
        "BALANCE_TRANSFER_INSUFFICIENT_BALANCE" => {
            ApiError::bad_request(code::BALANCE_TRANSFER_INSUFFICIENT_BALANCE)
        }
        "BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED" => {
            ApiError::bad_request(code::BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED)
        }
        _ => ApiError::internal("balance transfer failed"),
    }
}

/// sqlx error inside transferBalanceBetweenUsers: the TS route catches it and
/// mapBalanceTransferError falls through to 500; transient conflicts retry.
fn transfer_sql_err(err: sqlx::Error) -> ApiError {
    if db::is_transient_db_error(&err) {
        ApiError::from_sql(err).retryable()
    } else {
        ApiError::internal("balance transfer failed")
    }
}

/// sqlx error inside changeBalance: the TS catch-all turns it into
/// `{ success: false, error: <message> }` -> `400 { error }`; transient
/// conflicts still retry via runBalanceTransaction.
fn change_sql_err(err: sqlx::Error) -> ApiError {
    if db::is_transient_db_error(&err) {
        ApiError::from_sql(err).retryable()
    } else {
        ApiError::bare(StatusCode::BAD_REQUEST, format!("{err}"))
    }
}

// ===========================================================================
// db helpers (port of db/balance.ts + db/users.ts + db/billing-records.ts)
// ===========================================================================

async fn get_user_balance(state: &SharedAppState, user_id: i32) -> Result<f64, ApiError> {
    let row: Option<(Decimal,)> = sqlx::query_as("SELECT balance FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(row
        .map(|(b,)| b.to_f64().unwrap_or(0.0))
        .unwrap_or(0.0))
}

#[derive(Debug, sqlx::FromRow)]
struct TargetUser {
    id: i32,
    username: String,
    email: Option<String>,
}

/// db/users.ts findUserById (only the fields the routes use).
async fn find_user_by_id(state: &SharedAppState, id: i32) -> Result<Option<TargetUser>, ApiError> {
    let row =
        sqlx::query_as::<_, TargetUser>("SELECT id, username, email FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    Ok(row)
}

/// db/users.ts findUserByUsername: exact (case-sensitive) username match.
async fn find_user_by_username(
    state: &SharedAppState,
    username: &str,
) -> Result<Option<TargetUser>, ApiError> {
    let row =
        sqlx::query_as::<_, TargetUser>("SELECT id, username, email FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&state.db)
            .await?;
    Ok(row)
}

// ---- balance logs (db/balance.ts getBalanceLogs) ----

#[derive(Debug, FromRow)]
struct BalanceLogRow {
    id: i32,
    #[sqlx(rename = "type")]
    log_type: String,
    amount: Decimal,
    balance_before: Decimal,
    balance_after: Decimal,
    order_id: Option<String>,
    instance_id: Option<i32>,
    remark: Option<String>,
    created_at: DateTime<Utc>,
    instance_name: Option<String>,
}

const BALANCE_LOG_SELECT: &str = "SELECT bl.id, bl.type::text AS type, bl.amount, \
    bl.balance_before, bl.balance_after, bl.order_id, bl.instance_id, bl.remark, bl.created_at, \
    i.name AS instance_name \
    FROM balance_logs bl LEFT JOIN instances i ON i.id = bl.instance_id";

fn balance_log_json(row: &BalanceLogRow) -> Value {
    json!({
        "id": row.id,
        "type": row.log_type,
        "amount": num(row.amount),
        "balanceBefore": num(row.balance_before),
        "balanceAfter": num(row.balance_after),
        "orderId": row.order_id,
        "instanceId": row.instance_id,
        "instanceName": row.instance_name,
        "remark": row.remark,
        "createdAt": iso(row.created_at),
    })
}

async fn get_balance_logs(
    state: &SharedAppState,
    user_id: i32,
    pagination: crate::response::Pagination,
    log_type: Option<&str>,
    lottery_gift: Option<&str>,
) -> Result<(Vec<BalanceLogRow>, i64), ApiError> {
    // where: userId + optional type + lottery-gift filter. The lottery marker
    // is type='gift' AND remark contains '抽奖中奖'.
    let mut sql = format!("{BALANCE_LOG_SELECT} WHERE bl.user_id = $1");
    let mut count_sql =
        String::from("SELECT COUNT(*) FROM balance_logs bl WHERE bl.user_id = $1");
    let mut param_idx = 1usize;
    if log_type.is_some() {
        param_idx += 1;
        let idx = format!("${param_idx}");
        sql.push_str(&format!(" AND bl.type = {idx}::\"BalanceLogType\""));
        count_sql.push_str(&format!(" AND bl.type = {idx}::\"BalanceLogType\""));
    }
    if lottery_gift.is_some() {
        param_idx += 1;
        let idx = format!("${param_idx}");
        let clause = match lottery_gift {
            Some("exclude") => format!(" AND NOT (bl.type = 'gift' AND bl.remark LIKE {idx})"),
            _ => format!(" AND bl.type = 'gift' AND bl.remark LIKE {idx}"),
        };
        sql.push_str(&clause);
        count_sql.push_str(&clause);
    }
    param_idx += 1;
    sql.push_str(&format!(
        " ORDER BY bl.created_at DESC OFFSET ${param_idx} LIMIT ${} ",
        param_idx + 1
    ));

    let mut q = sqlx::query_as::<_, BalanceLogRow>(sql.trim_end()).bind(user_id);
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(user_id);
    if let Some(t) = log_type {
        q = q.bind(t);
        cq = cq.bind(t);
    }
    if lottery_gift.is_some() {
        q = q.bind("%抽奖中奖%");
        cq = cq.bind("%抽奖中奖%");
    }
    q = q.bind(pagination.skip).bind(pagination.take);

    let logs = q.fetch_all(&state.db).await?;
    let total = cq.fetch_one(&state.db).await?;
    Ok((logs, total))
}

// ---- consume stats (db/balance.ts getUserConsumeStats) ----

#[derive(Debug, Clone)]
struct ConsumeStats {
    total_recharge: f64,
    total_consume: f64,
    total_refund: f64,
    total_destroyed_value: f64,
}

async fn get_user_consume_stats(
    state: &SharedAppState,
    user_id: i32,
) -> Result<ConsumeStats, ApiError> {
    let groups: Vec<(String, Decimal)> = sqlx::query_as(
        "SELECT type::text AS type, COALESCE(SUM(amount), 0) \
         FROM balance_logs WHERE user_id = $1 GROUP BY type",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;

    let destroyed: (Decimal,) = sqlx::query_as(
        "SELECT COALESCE(SUM(amount), 0) FROM balance_logs \
         WHERE user_id = $1 AND type = 'refund' AND amount > 0 \
         AND remark LIKE '%用户销毁实例退款%'",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;

    // getUsersTotalConsumeMap: prefer the before/after delta because historic
    // consume rows may store a positive amount.
    let total_consume: (Decimal,) = sqlx::query_as(
        "SELECT COALESCE(SUM( \
            CASE WHEN balance_before > balance_after \
                 THEN balance_before - balance_after \
                 ELSE ABS(amount) END), 0) \
         FROM balance_logs WHERE user_id = $1 AND type IN ('consume', 'hourly_consume')",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;

    let mut stats = ConsumeStats {
        total_recharge: 0.0,
        total_consume: total_consume.0.to_f64().unwrap_or(0.0),
        total_refund: 0.0,
        total_destroyed_value: destroyed.0.to_f64().unwrap_or(0.0),
    };
    for (t, sum) in groups {
        let amount = sum.to_f64().unwrap_or(0.0);
        match t.as_str() {
            "recharge" => stats.total_recharge = amount,
            "refund" => stats.total_refund = amount,
            _ => {}
        }
    }
    Ok(stats)
}

fn stats_json(stats: &ConsumeStats) -> Value {
    json!({
        "totalRecharge": stats.total_recharge,
        "totalConsume": stats.total_consume,
        "totalRefund": stats.total_refund,
        "totalDestroyedValue": stats.total_destroyed_value,
    })
}

// ---- billing records (db/billing-records.ts) ----

#[derive(Debug, FromRow)]
struct BillingRecordRow {
    id: i32,
    instance_id: i32,
    #[sqlx(rename = "type")]
    record_type: String,
    amount: Decimal,
    months: i32,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    remark: Option<String>,
    created_at: DateTime<Utc>,
    inst_id: Option<i32>,
    inst_name: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct RawPage {
    skip: i64,
    take: i64,
    page: f64,
    page_size: f64,
}

/// routes/balance.ts /me/billing parses page/pageSize with raw Number() (not
/// parsePagination) and feeds them to Prisma skip/take: only finite integral
/// non-negative skip/take survive; anything else throws -> 500.
fn parse_raw_page(
    page_str: Option<&String>,
    size_str: Option<&String>,
) -> Result<RawPage, ApiError> {
    let js_number = |s: &str| -> f64 {
        let t = s.trim();
        if t.is_empty() {
            0.0
        } else {
            t.parse::<f64>().unwrap_or(f64::NAN)
        }
    };
    let page = page_str.map(|s| js_number(s)).unwrap_or(1.0);
    let page_size = size_str.map(|s| js_number(s)).unwrap_or(20.0);
    let skip = (page - 1.0) * page_size;
    if !skip.is_finite()
        || !page_size.is_finite()
        || skip.fract() != 0.0
        || page_size.fract() != 0.0
        || skip < 0.0
        || page_size < 0.0
        || skip > i64::MAX as f64
        || page_size > i64::MAX as f64
    {
        return Err(ApiError::internal(
            "Prisma argument validation failed: skip/take must be non-negative integers",
        ));
    }
    Ok(RawPage {
        skip: skip as i64,
        take: page_size as i64,
        page,
        page_size,
    })
}

async fn get_user_billing_records(
    state: &SharedAppState,
    user_id: i32,
    page: RawPage,
    record_type: Option<&str>,
) -> Result<(Vec<BillingRecordRow>, i64), ApiError> {
    let mut sql = String::from(
        "SELECT r.id, r.instance_id, r.type::text AS type, r.amount, r.months, \
         r.period_start, r.period_end, r.remark, r.created_at, \
         i.id AS inst_id, i.name AS inst_name \
         FROM instance_billing_records r LEFT JOIN instances i ON i.id = r.instance_id \
         WHERE r.user_id = $1",
    );
    let mut count_sql = String::from(
        "SELECT COUNT(*) FROM instance_billing_records r WHERE r.user_id = $1",
    );
    if record_type.is_some() {
        sql.push_str(" AND r.type = $2::\"BillingRecordType\"");
        count_sql.push_str(" AND r.type = $2::\"BillingRecordType\"");
    }
    sql.push_str(if record_type.is_some() {
        " ORDER BY r.created_at DESC OFFSET $3 LIMIT $4"
    } else {
        " ORDER BY r.created_at DESC OFFSET $2 LIMIT $3"
    });

    let mut q = sqlx::query_as::<_, BillingRecordRow>(&sql).bind(user_id);
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(user_id);
    if let Some(t) = record_type {
        q = q.bind(t);
        cq = cq.bind(t);
    }
    q = q.bind(page.skip).bind(page.take);

    let records = q.fetch_all(&state.db).await?;
    let total = cq.fetch_one(&state.db).await?;
    Ok((records, total))
}

fn billing_record_json(record: &BillingRecordRow) -> Value {
    json!({
        "id": record.id,
        "instanceId": record.instance_id,
        "instance": match record.inst_id {
            Some(id) => json!({ "id": id, "name": record.inst_name }),
            None => Value::Null,
        },
        "type": record.record_type,
        "amount": num(record.amount),
        "months": record.months,
        "periodStart": iso(record.period_start),
        "periodEnd": iso(record.period_end),
        "remark": record.remark,
        "createdAt": iso(record.created_at),
    })
}

/// db/billing-records.ts getUserBillingStats.
async fn get_user_billing_stats(state: &SharedAppState, user_id: i32) -> Result<Value, ApiError> {
    let spent: (Decimal,) = sqlx::query_as(
        "SELECT COALESCE(SUM(amount), 0) FROM instance_billing_records \
         WHERE user_id = $1 AND type IN ('newPurchase', 'renew', 'upgrade')",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    let refunded: (Decimal,) = sqlx::query_as(
        "SELECT COALESCE(SUM(ABS(amount)), 0) FROM instance_billing_records \
         WHERE user_id = $1 AND type = 'refund'",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    let purchase: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instance_billing_records WHERE user_id = $1 AND type = 'newPurchase'",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    let renew: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instance_billing_records WHERE user_id = $1 AND type = 'renew'",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;

    Ok(json!({
        "totalSpent": spent.0.to_f64().unwrap_or(0.0),
        "totalRefunded": refunded.0.to_f64().unwrap_or(0.0),
        "purchaseCount": purchase.0,
        "renewCount": renew.0,
    }))
}

// ---- system config (db/system-config.ts) ----

async fn get_system_config_boolean(
    state: &SharedAppState,
    key: &str,
    default_value: bool,
) -> Result<bool, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT value FROM system_configs WHERE key = $1")
            .bind(key)
            .fetch_optional(&state.db)
            .await?;
    let Some((Some(value),)) = row else {
        return Ok(default_value);
    };
    Ok(value == "true" || value == "1")
}

async fn get_system_config_float(
    state: &SharedAppState,
    key: &str,
    default_value: f64,
) -> Result<f64, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT value FROM system_configs WHERE key = $1")
            .bind(key)
            .fetch_optional(&state.db)
            .await?;
    let Some((Some(value),)) = row else {
        return Ok(default_value);
    };
    // JS parseFloat: leading float parse; non-finite -> default.
    let trimmed = value.trim_start();
    let end = trimmed
        .find(|c: char| !matches!(c, '0'..='9' | '.' | 'e' | 'E' | '+' | '-'))
        .unwrap_or(trimmed.len());
    Ok(trimmed[..end]
        .parse::<f64>()
        .ok()
        .filter(|n| n.is_finite())
        .unwrap_or(default_value))
}

// ===========================================================================
// balance transfer core (db/balance.ts)
// ===========================================================================

struct TransferParty {
    id: i32,
    username: String,
    avatar_style: String,
    avatar_badge_id: Option<String>,
}

struct TransferCore {
    recipient: TransferParty,
    amount: Decimal,
    fee: Decimal,
    total_deduction: Decimal,
    current_balance: Decimal,
    balance_after: Decimal,
}

struct SenderRow {
    balance: Decimal,
    username: String,
}

struct RecipientRow {
    id: i32,
    username: String,
    avatar_style: String,
    avatar_badge_id: Option<String>,
    status: String,
    balance: Decimal,
}

async fn fetch_sender<'e, E>(
    exec: E,
    from_user_id: i32,
) -> Result<Option<SenderRow>, ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row: Option<(Decimal, String)> =
        sqlx::query_as("SELECT balance, username FROM users WHERE id = $1")
            .bind(from_user_id)
            .fetch_optional(exec)
            .await
            .map_err(transfer_sql_err)?;
    Ok(row.map(|(balance, username)| SenderRow { balance, username }))
}

async fn fetch_recipient<'e, E>(
    exec: E,
    recipient_id: i32,
) -> Result<Option<RecipientRow>, ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row: Option<(i32, String, String, Option<String>, String, Decimal)> = sqlx::query_as(
        "SELECT id, username, avatar_style, avatar_badge_id, status::text AS status, balance \
         FROM users WHERE id = $1",
    )
    .bind(recipient_id)
    .fetch_optional(exec)
    .await
    .map_err(transfer_sql_err)?;
    Ok(row.map(
        |(id, username, avatar_style, avatar_badge_id, status, balance)| RecipientRow {
            id,
            username,
            avatar_style,
            avatar_badge_id,
            status,
            balance,
        },
    ))
}

/// db/balance.ts buildBalanceTransferPreview. Errors are returned already
/// mapped through mapBalanceTransferError.
async fn build_transfer_preview(
    state: &SharedAppState,
    from_user_id: i32,
    recipient_id: i32,
    amount_f64: f64,
    fee_f64: f64,
) -> Result<TransferCore, ApiError> {
    let amount_f64 = normalize_transfer_amount(amount_f64).map_err(transfer_api_error)?;
    let fee_f64 = normalize_transfer_fee(fee_f64).map_err(transfer_api_error)?;
    let amount = dec_from_money(amount_f64).ok_or_else(|| transfer_api_error("INTERNAL"))?;
    let fee = dec_from_money(fee_f64).ok_or_else(|| transfer_api_error("INTERNAL"))?;

    if from_user_id == recipient_id {
        return Err(transfer_api_error("BALANCE_TRANSFER_TO_SELF"));
    }

    let sender = fetch_sender(&state.db, from_user_id)
        .await?
        .ok_or_else(|| transfer_api_error("USER_NOT_FOUND"))?;
    let recipient = fetch_recipient(&state.db, recipient_id)
        .await?
        .ok_or_else(|| transfer_api_error("USER_NOT_FOUND"))?;

    if recipient.status == "banned" {
        return Err(transfer_api_error("BALANCE_TRANSFER_RECIPIENT_BANNED"));
    }

    let max_balance = dec_from_money(MAX_USER_BALANCE).unwrap_or(Decimal::ZERO);
    // TS: roundMoney(Number(recipient.balance) + amount) > MAX_USER_BALANCE.
    let recipient_after = round_money_dec(recipient.balance + amount);
    if recipient_after > max_balance {
        return Err(transfer_api_error("BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED"));
    }

    let current_balance = sender.balance;
    let total_deduction = round_money_dec(amount + fee);
    let balance_after = round_money_dec(current_balance - total_deduction);
    if balance_after < Decimal::ZERO {
        return Err(transfer_api_error("BALANCE_TRANSFER_INSUFFICIENT_BALANCE"));
    }

    Ok(TransferCore {
        recipient: TransferParty {
            id: recipient.id,
            username: recipient.username,
            avatar_style: recipient.avatar_style,
            avatar_badge_id: recipient.avatar_badge_id,
        },
        amount,
        fee,
        total_deduction,
        current_balance,
        balance_after,
    })
}

/// db/balance.ts transferBalanceBetweenUsers: Serializable tx with retries.
async fn transfer_balance_between_users(
    state: &SharedAppState,
    from_user_id: i32,
    recipient_id: i32,
    amount_f64: f64,
    fee_f64: f64,
) -> Result<(TransferCore, String /* transferNo */), ApiError> {
    let amount_f64 = normalize_transfer_amount(amount_f64).map_err(transfer_api_error)?;
    let fee_f64 = normalize_transfer_fee(fee_f64).map_err(transfer_api_error)?;
    let amount = dec_from_money(amount_f64).ok_or_else(|| transfer_api_error("INTERNAL"))?;
    let fee = dec_from_money(fee_f64).ok_or_else(|| transfer_api_error("INTERNAL"))?;

    if from_user_id == recipient_id {
        return Err(transfer_api_error("BALANCE_TRANSFER_TO_SELF"));
    }

    let max_balance = dec_from_money(MAX_USER_BALANCE).unwrap_or(Decimal::ZERO);

    crate::balance_tx!(&state.db, tx, {
        (async {
            let Some(sender) = fetch_sender(&mut *tx, from_user_id).await? else {                return Err(transfer_api_error("USER_NOT_FOUND"));
            };
            let Some(recipient) = fetch_recipient(&mut *tx, recipient_id).await? else {
                return Err(transfer_api_error("USER_NOT_FOUND"));
            };
            if recipient.status == "banned" {
                return Err(transfer_api_error("BALANCE_TRANSFER_RECIPIENT_BANNED"));
            }

            let total_deduction = round_money_dec(amount + fee);
            let sender_balance_before = sender.balance;
            let sender_after_transfer = round_money_dec(sender_balance_before - amount);
            let sender_after_fee = round_money_dec(sender_after_transfer - fee);
            if sender_after_fee < Decimal::ZERO {
                return Err(transfer_api_error("BALANCE_TRANSFER_INSUFFICIENT_BALANCE"));
            }

            let recipient_balance_before = recipient.balance;
            let recipient_balance_after = round_money_dec(recipient_balance_before + amount);
            if recipient_balance_after > max_balance {
                return Err(transfer_api_error("BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED"));
            }

            let transfer_no = create_transfer_no();

            sqlx::query("UPDATE users SET balance = $2 WHERE id = $1")
                .bind(from_user_id)
                .bind(sender_after_fee)
                .execute(&mut *tx)
                .await
                .map_err(transfer_sql_err)?;
            sqlx::query("UPDATE users SET balance = $2 WHERE id = $1")
                .bind(recipient.id)
                .bind(recipient_balance_after)
                .execute(&mut *tx)
                .await
                .map_err(transfer_sql_err)?;

            sqlx::query(
                "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, order_id, remark) \
                 VALUES ($1, 'balance_transfer_out'::\"BalanceLogType\", $2, $3, $4, $5, $6)",
            )
            .bind(from_user_id)
            .bind(-amount)
            .bind(sender_balance_before)
            .bind(sender_after_transfer)
            .bind(&transfer_no)
            .bind(format!("转账给 {}", recipient.username))
            .execute(&mut *tx)
            .await
            .map_err(transfer_sql_err)?;

            if fee > Decimal::ZERO {
                sqlx::query(
                    "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, order_id, remark) \
                     VALUES ($1, 'balance_transfer_fee'::\"BalanceLogType\", $2, $3, $4, $5, '余额转账手续费')",
                )
                .bind(from_user_id)
                .bind(-fee)
                .bind(sender_after_transfer)
                .bind(sender_after_fee)
                .bind(&transfer_no)
                .execute(&mut *tx)
                .await
                .map_err(transfer_sql_err)?;
            }

            sqlx::query(
                "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, order_id, remark) \
                 VALUES ($1, 'balance_transfer_in'::\"BalanceLogType\", $2, $3, $4, $5, $6)",
            )
            .bind(recipient.id)
            .bind(amount)
            .bind(recipient_balance_before)
            .bind(recipient_balance_after)
            .bind(&transfer_no)
            .bind(format!("收到 {} 转账", sender.username))
            .execute(&mut *tx)
            .await
            .map_err(transfer_sql_err)?;

            Ok((
                TransferCore {
                    recipient: TransferParty {
                        id: recipient.id,
                        username: recipient.username,
                        avatar_style: recipient.avatar_style,
                        avatar_badge_id: recipient.avatar_badge_id,
                    },
                    amount,
                    fee,
                    total_deduction,
                    current_balance: sender_balance_before,
                    balance_after: sender_after_fee,
                },
                transfer_no,
            ))
        })
        .await
    })
}

// ===========================================================================
// changeBalance (db/balance.ts) — used by admin adjust + gift
// ===========================================================================

struct BalanceChangeResult {
    balance_log_id: i32,
    log_type: String,
    amount: Decimal,
    balance_before: Decimal,
    balance_after: Decimal,
    new_balance: Decimal,
}

async fn change_balance(
    state: &SharedAppState,
    user_id: i32,
    log_type: &str,
    amount: Decimal,
    order_id: Option<String>,
    instance_id: Option<i32>,
    remark: Option<String>,
) -> Result<BalanceChangeResult, ApiError> {
    crate::balance_tx!(&state.db, tx, {
        (async {
            let row: Option<(Decimal,)> =
                sqlx::query_as("SELECT balance FROM users WHERE id = $1")
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(change_sql_err)?;
            let Some((balance_before,)) = row else {
                // TS throws Error('用户不存在') inside the tx.
                return Err(ApiError::bare(StatusCode::BAD_REQUEST, "用户不存在"));
            };

            let balance_after = round_money_dec(balance_before + amount);
            if amount < Decimal::ZERO && balance_after < Decimal::ZERO {
                return Err(ApiError::bare(StatusCode::BAD_REQUEST, "余额不足"));
            }

            sqlx::query("UPDATE users SET balance = $2 WHERE id = $1")
                .bind(user_id)
                .bind(balance_after)
                .execute(&mut *tx)
                .await
                .map_err(change_sql_err)?;

            let log: (i32,) = sqlx::query_as(
                "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, order_id, instance_id, remark) \
                 VALUES ($1, $2::\"BalanceLogType\", $3, $4, $5, $6, $7, $8) RETURNING id",
            )
            .bind(user_id)
            .bind(log_type)
            .bind(amount)
            .bind(balance_before)
            .bind(balance_after)
            .bind(order_id.clone())
            .bind(instance_id)
            .bind(remark.clone())
            .fetch_one(&mut *tx)
            .await
            .map_err(change_sql_err)?;

            Ok(BalanceChangeResult {
                balance_log_id: log.0,
                log_type: log_type.to_string(),
                amount,
                balance_before,
                balance_after,
                new_balance: balance_after,
            })
        })
        .await
    })
}

// ===========================================================================
// GET /me — 获取当前用户余额
// ===========================================================================

async fn me_balance(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let row: Option<(Decimal, Decimal)> = sqlx::query_as(
        "SELECT balance, hourly_reserved_balance FROM users WHERE id = $1",
    )
    .bind(user.id)
    .fetch_optional(&state.db)
    .await?;
    let (balance_amount, hourly_reserved) = row.unwrap_or((Decimal::ZERO, Decimal::ZERO));
    let balance_f64 = balance_amount.to_f64().unwrap_or(0.0);
    let reserved_f64 = hourly_reserved.to_f64().unwrap_or(0.0);
    let stats = get_user_consume_stats(&state, user.id).await?;

    Ok(Json(json!({
        "balance": {
            "balance": balance_f64,
            "frozen": reserved_f64,
            "hourlyReserved": reserved_f64,
            "totalBalance": balance_f64 + reserved_f64,
            "totalRecharge": stats.total_recharge,
            "totalConsume": stats.total_consume,
            "destroyedValue": stats.total_destroyed_value,
        }
    })))
}

// ===========================================================================
// GET /me/logs — 当前用户余额变动日志
// ===========================================================================

async fn me_logs(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let log_type = params.get("type").map(|s| s.as_str());
    let lottery_gift = match params.get("lotteryGift").map(|s| s.as_str()) {
        Some("exclude") | Some("only") => params.get("lotteryGift").map(|s| s.as_str()),
        _ => None,
    };

    let pagination = crate::response::parse_pagination(&params, 20, Some(100));
    let (logs, total) =
        get_balance_logs(&state, user.id, pagination, log_type, lottery_gift).await?;

    let records: Vec<Value> = logs.iter().map(balance_log_json).collect();
    Ok(Json(json!({
        "records": records,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
    })))
}

// ===========================================================================
// GET /me/billing — 当前用户计费记录
// ===========================================================================

#[allow(dead_code)]
#[derive(Deserialize)]
struct _UnusedQuery {
    _t: Option<String>,
}

async fn me_billing(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let page = parse_raw_page(params.get("page"), params.get("pageSize"))?;
    let record_type = params.get("type").map(|s| s.as_str());

    let (records, total) = get_user_billing_records(&state, user.id, page, record_type).await?;
    let stats = get_user_billing_stats(&state, user.id).await?;

    let items: Vec<Value> = records.iter().map(billing_record_json).collect();
    Ok(Json(json!({
        "records": items,
        "total": total,
        // The route echoes the raw Number() values.
        "page": js_json_number(page.page),
        "pageSize": js_json_number(page.page_size),
        "stats": stats,
    })))
}

/// JS Number -> JSON number (non-finite never reaches here: parse_raw_page
/// already returned 500 for Prisma-invalid values).
fn js_json_number(v: f64) -> Value {
    serde_json::Number::from_f64(v)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

// ===========================================================================
// GET /transfer/recipient — 解析余额转账收款人
// ===========================================================================

async fn transfer_recipient(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let transfer_enabled =
        get_system_config_boolean(&state, "balance_transfer_enabled", false).await?;
    if !transfer_enabled {
        return Err(ApiError::forbidden(code::BALANCE_TRANSFER_DISABLED));
    }

    let username = params
        .get("username")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    // JS string length (UTF-16 code units).
    let js_len: usize = username.chars().map(|c| c.len_utf16()).sum();
    if username.is_empty() || js_len < 2 {
        return Err(ApiError::bad_request(code::INVALID_PARAMS)
            .with_details("Username must be at least 2 characters"));
    }

    let recipient = find_user_by_username(&state, &username)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;
    if recipient.id == user.0.id {
        return Err(ApiError::bad_request(code::BALANCE_TRANSFER_TO_SELF));
    }

    let (avatar_style, avatar_badge_id, status): (String, Option<String>, String) = sqlx::query_as(
        "SELECT avatar_style, avatar_badge_id, status::text AS status FROM users WHERE id = $1",
    )
    .bind(recipient.id)
    .fetch_one(&state.db)
    .await?;
    if status == "banned" {
        return Err(ApiError::bad_request(code::BALANCE_TRANSFER_RECIPIENT_BANNED));
    }

    Ok(Json(json!({
        "recipient": {
            "id": recipient.id,
            "username": recipient.username,
            "avatarStyle": avatar_style,
            "avatarBadgeId": avatar_badge_id,
        }
    })))
}

// ===========================================================================
// shared body validation for /transfer/preview + /transfer
// ===========================================================================

/// Fastify schema { recipientId: integer minimum 1, amount: number minimum
/// 0.01 }; failures go through the app error handler ->
/// 400 { error, code: VALIDATION_ERROR, details? }.
fn validate_transfer_body(body: &Value) -> Result<(i32, f64), ApiError> {
    let obj = match body.as_object() {
        Some(o) => o,
        None => {
            return Err(ApiError::with_message(
                code::VALIDATION_ERROR,
                StatusCode::BAD_REQUEST,
                "body must be object",
            ))
        }
    };

    let mut messages: Vec<String> = Vec::new();
    for field in ["recipientId", "amount"] {
        if !obj.contains_key(field) {
            messages.push(format!("{field} is required"));
        }
    }
    if let Some(v) = obj.get("recipientId") {
        match v.as_i64() {
            Some(n) if n >= 1 => {}
            Some(_) => messages.push("recipientId must be >= 1".to_string()),
            None => messages.push("recipientId must be integer".to_string()),
        }
    }
    if let Some(v) = obj.get("amount") {
        match v.as_f64() {
            Some(n) if n >= 0.01 => {}
            Some(_) => messages.push("amount must be >= 0.01".to_string()),
            None => messages.push("amount must be number".to_string()),
        }
    }

    if !messages.is_empty() {
        let first = messages[0].clone();
        let mut err =
            ApiError::with_message(code::VALIDATION_ERROR, StatusCode::BAD_REQUEST, first);
        if messages.len() > 1 {
            err = err.with_details(messages.join(", "));
        }
        return Err(err);
    }

    let recipient_id = obj["recipientId"].as_i64().unwrap_or(0);
    if recipient_id > i32::MAX as i64 {
        return Err(ApiError::internal("Prisma Int argument out of range"));
    }
    Ok((recipient_id as i32, obj["amount"].as_f64().unwrap_or(0.0)))
}

fn recipient_json(recipient: &TransferParty) -> Value {
    json!({
        "id": recipient.id,
        "username": recipient.username,
        "avatarStyle": recipient.avatar_style,
        "avatarBadgeId": recipient.avatar_badge_id,
    })
}

// ===========================================================================
// POST /transfer/preview — 预览余额转账
// ===========================================================================

async fn transfer_preview(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let transfer_enabled =
        get_system_config_boolean(&state, "balance_transfer_enabled", false).await?;
    if !transfer_enabled {
        return Err(ApiError::forbidden(code::BALANCE_TRANSFER_DISABLED));
    }

    let (recipient_id, amount) = validate_transfer_body(&body)?;
    let fee = get_system_config_float(&state, "balance_transfer_fee", 0.0).await?;

    let preview = build_transfer_preview(&state, user.0.id, recipient_id, amount, fee).await?;

    Ok(Json(json!({
        "preview": {
            "recipient": recipient_json(&preview.recipient),
            "amount": num(preview.amount),
            "fee": num(preview.fee),
            "totalDeduction": num(preview.total_deduction),
            "currentBalance": num(preview.current_balance),
            "balanceAfter": num(preview.balance_after),
        }
    })))
}

// ===========================================================================
// POST /transfer — 提交余额转账
// ===========================================================================

async fn transfer_submit(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let transfer_enabled =
        get_system_config_boolean(&state, "balance_transfer_enabled", false).await?;
    if !transfer_enabled {
        return Err(ApiError::forbidden(code::BALANCE_TRANSFER_DISABLED));
    }

    let (recipient_id, amount) = validate_transfer_body(&body)?;
    let fee = get_system_config_float(&state, "balance_transfer_fee", 0.0).await?;

    let (result, transfer_no) =
        transfer_balance_between_users(&state, user.0.id, recipient_id, amount, fee).await?;

    create_log(
        &state,
        user.0.id,
        "balance",
        "balance.transfer",
        &format!(
            "Transferred {} to user {}, fee {}, transferNo {}",
            js_num_string(result.amount.to_f64().unwrap_or(0.0)),
            result.recipient.username,
            js_num_string(result.fee.to_f64().unwrap_or(0.0)),
            transfer_no
        ),
        "success",
    )
    .await;

    Ok(Json(json!({
        "transfer": {
            "transferNo": transfer_no,
            "recipient": recipient_json(&result.recipient),
            "amount": num(result.amount),
            "fee": num(result.fee),
            "totalDeduction": num(result.total_deduction),
            "currentBalance": num(result.current_balance),
            "balanceAfter": num(result.balance_after),
        }
    })))
}

// ===========================================================================
// GET /admin/{userId} — 获取用户余额（管理员）
// ===========================================================================

async fn admin_balance(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_number_id(&user_id)?;

    let target_user = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    let balance = get_user_balance(&state, user_id).await?;
    let stats = get_user_consume_stats(&state, user_id).await?;

    let mut body = json!({
        "userId": user_id,
        "username": target_user.username,
        "balance": balance,
    });
    if let (Some(obj), Some(Value::Object(stats_obj))) = (body.as_object_mut(), Some(stats_json(&stats)))
    {
        for (k, v) in stats_obj {
            obj.insert(k, v);
        }
    }
    Ok(Json(body))
}

// ===========================================================================
// GET /admin/{userId}/logs — 获取用户余额日志（管理员）
// ===========================================================================

async fn admin_logs(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(user_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let user_id = js_number_id(&user_id)?;

    let log_type = params.get("type").map(|s| s.as_str());
    let lottery_gift = match params.get("lotteryGift").map(|s| s.as_str()) {
        Some("exclude") | Some("only") => params.get("lotteryGift").map(|s| s.as_str()),
        _ => None,
    };

    let pagination = crate::response::parse_pagination(&params, 20, Some(100));
    let (logs, total) =
        get_balance_logs(&state, user_id, pagination, log_type, lottery_gift).await?;

    let items: Vec<Value> = logs.iter().map(balance_log_json).collect();
    Ok(Json(json!({
        "logs": items,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
    })))
}

// ===========================================================================
// POST /admin/{userId}/adjust — 管理员调整用户余额
// ===========================================================================

/// Bare `{ error }` 400 (the adjust/gift handlers send raw error objects
/// without a code).
fn bare_bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({ "error": message.into() })),
    )
        .into_response()
}

/// f64 -> Decimal preserving the JS number's literal digits (no forced 2dp;
/// the stored column is Decimal(20,8)).
fn dec_from_money_precise(value: f64) -> Option<Decimal> {
    use std::str::FromStr;
    let mut d = Decimal::from_str(&format!("{value}")).ok()?;
    d = d.round_dp(8);
    Some(d)
}

async fn admin_adjust(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let user_id = js_number_id(&user_id)?;

    // 参数校验 (the TS route has no Fastify schema here).
    let Some(amount_value) = body.get("amount") else {
        return Ok(bare_bad_request("调整金额必须是有效的数字"));
    };
    let amount = match amount_value.as_f64() {
        Some(a) if a.is_nan() => return Ok(bare_bad_request("调整金额必须是有效的数字")),
        Some(a) => a,
        None => return Ok(bare_bad_request("调整金额必须是有效的数字")),
    };
    if amount == 0.0 {
        return Ok(bare_bad_request("调整金额不能为 0"));
    }

    let remark = match body.get("remark") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => return Ok(bare_bad_request("必须填写调整原因")),
        // TS: remark.trim() on a non-string throws -> 500.
        Some(_) => return Err(ApiError::internal("remark.trim is not a function")),
    };
    if remark.trim().is_empty() {
        return Ok(bare_bad_request("必须填写调整原因"));
    }
    if remark.trim().chars().map(|c| c.len_utf16()).sum::<usize>() > 500 {
        return Ok(bare_bad_request("调整原因不能超过 500 字符"));
    }

    let target_user = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    let amount_dec = match dec_from_money_precise(amount) {
        Some(d) => d,
        None => {
            // TS: an absurd amount fails Prisma Decimal serialization inside
            // changeBalance -> catch-all -> 400 { error }.
            return Ok(bare_bad_request("余额变动失败"));
        }
    };

    let result = change_balance(
        &state,
        user_id,
        "admin_adjust",
        amount_dec,
        None,
        None,
        Some(format!("[管理员 {}] {}", admin.0.username, remark)),
    )
    .await?;

    create_log(
        &state,
        admin.0.id,
        "admin",
        "balance.adjust",
        &format!(
            "Adjusted balance for user {}: {}{}, reason: {}",
            target_user.username,
            if amount > 0.0 { "+" } else { "" },
            js_num_string(amount),
            remark
        ),
        "success",
    )
    .await;

    // 发送余额调整邮件通知 — nodemailer stack not ported; failures never
    // affect the flow in TS either.
    if target_user.email.is_some() {
        tracing::warn!(
            "[余额调整] sendBalanceAdjustedEmail not ported (nodemailer); skipped for user #{user_id}"
        );
    }

    Ok(axum::Json(json!({
        "message": "余额调整成功",
        "newBalance": num(result.new_balance),
        "balanceLog": {
            "id": result.balance_log_id,
            "type": result.log_type,
            "amount": num(result.amount),
            "balanceBefore": num(result.balance_before),
            "balanceAfter": num(result.balance_after),
        }
    }))
    .into_response())
}

// ===========================================================================
// POST /admin/{userId}/gift — 管理员赠送余额
// ===========================================================================

async fn admin_gift(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let user_id = js_number_id(&user_id)?;

    let Some(amount_value) = body.get("amount") else {
        return Ok(bare_bad_request("赠送金额必须是有效的数字"));
    };
    let amount = match amount_value.as_f64() {
        Some(a) if a.is_nan() => return Ok(bare_bad_request("赠送金额必须是有效的数字")),
        Some(a) => a,
        None => return Ok(bare_bad_request("赠送金额必须是有效的数字")),
    };
    if amount <= 0.0 {
        return Ok(bare_bad_request("赠送金额必须大于 0"));
    }

    let remark = match body.get("remark") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Null) | None => None,
        // TS: `remark || fallback` accepts any truthy value; a truthy
        // non-string remark would fail Prisma validation -> 400 catch-all.
        // Keep the common path exact and treat exotic values as the fallback.
        Some(_) => None,
    };
    let remark = remark.unwrap_or_else(|| format!("管理员 {} 赠送", admin.0.username));

    let target_user = find_user_by_id(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::USER_NOT_FOUND))?;

    let amount_dec = match dec_from_money_precise(amount) {
        Some(d) => d,
        None => return Ok(bare_bad_request("余额变动失败")),
    };

    let result = change_balance(&state, user_id, "gift", amount_dec, None, None, Some(remark))
        .await?;

    create_log(
        &state,
        admin.0.id,
        "admin",
        "balance.gift",
        &format!(
            "Gifted {} to user {}",
            js_num_string(amount),
            target_user.username
        ),
        "success",
    )
    .await;

    // 发送余额赠送邮件通知 — not ported (see adjust).
    if target_user.email.is_some() {
        tracing::warn!(
            "[余额赠送] sendBalanceAdjustedEmail not ported (nodemailer); skipped for user #{user_id}"
        );
    }

    Ok(axum::Json(json!({
        "message": "赠送成功",
        "newBalance": num(result.new_balance),
    }))
    .into_response())
}
