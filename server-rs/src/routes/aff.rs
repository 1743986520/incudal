//! AFF 推荐计划路由 — port of server/src/routes/aff.ts (+ db/aff.ts helpers).
//!
//! Fixed 5%/5% rates; global codes (packagePlanId null, multiple allowed) and
//! per-plan codes (unique per user+plan, purchase required); withdrawals are
//! auto-approved at creation inside a USER_BALANCE-locked transaction; admin
//! approve/reject still handle legacy pending rows.
//!
//! Deviation: generateAffCode random suffix uses [A-Za-z0-9] (TS nanoid also
//! allows '-'/'_'); available-plans ordering is by plan id (TS ordering not
//! visible in ported excerpt).

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rand::Rng;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::{AdminAuth, AuthUser};
use crate::db::{advisory_lock_namespace, advisory_transaction_lock};
use crate::error::{code, ApiError};
use crate::libs::instance_common::iso;
use crate::state::SharedAppState;

const AFF_REBATE_DISABLED_ERROR: &str = "AFF 返利暂未开启，暂时无法使用优惠码";

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/me", get(me))
        .route("/me/codes", get(my_codes).post(create_code))
        .route("/me/codes/{codeId}", axum::routing::delete(delete_code))
        .route("/me/available-plans", get(available_plans))
        .route("/me/logs", get(logs))
        .route("/me/convert", post(convert))
        .route("/me/withdrawals", get(my_withdrawals))
        .route("/leaderboard", get(leaderboard))
        .route("/validate", post(validate))
        .route("/admin/withdrawals", get(admin_withdrawals))
        .route("/admin/withdrawals/{withdrawalId}/approve", post(admin_approve))
        .route("/admin/withdrawals/{withdrawalId}/reject", post(admin_reject))
}

fn bad(message: impl Into<String>) -> ApiError {
    ApiError::bare(axum::http::StatusCode::BAD_REQUEST, message)
}

fn parse_id(raw: &str) -> Result<i32, ApiError> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))
}

fn pagination(params: &HashMap<String, String>) -> crate::response::Pagination {
    crate::response::parse_pagination(params, 20, None)
}

/// db isAffActivated → isAffRebateEnabled → system_configs aff_rebate_enabled.
async fn is_aff_activated(state: &SharedAppState) -> bool {
    let value: Option<String> =
        sqlx::query_scalar("SELECT value FROM system_configs WHERE key = 'aff_rebate_enabled'")
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    value.as_deref().map(|v| v == "true" || v == "1").unwrap_or(false)
}

/// db generateAffCode: AFF-{userId}-{8 random uppercase}.
fn generate_aff_code(user_id: i32) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..8)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect();
    format!("AFF-{user_id}-{suffix}")
}

// ===========================================================================
// GET /me — 状态与统计
// ===========================================================================

async fn me(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let activated = is_aff_activated(&state).await;

    let (aff_balance,): (Option<Decimal>,) = sqlx::query_as(
        "SELECT aff_balance FROM users WHERE id = $1",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;
    let (total_codes, total_used): (i64, Option<i64>) = sqlx::query_as(
        "SELECT COUNT(*), SUM(used_count) FROM aff_codes WHERE user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;
    let (earnings,): (Option<Decimal>,) = sqlx::query_as(
        "SELECT SUM(amount) FROM aff_logs WHERE user_id = $1 \
         AND type::text IN ('new_purchase','renew','refund')",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;
    let (converted,): (Option<Decimal>,) = sqlx::query_as(
        "SELECT SUM(amount) FROM aff_logs WHERE user_id = $1 AND type::text = 'convert'",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    let num = |d: Option<Decimal>| crate::response::num(d.unwrap_or_default());

    Ok(Json(json!({
        "activated": activated,
        "totalEarnings": num(earnings),
        "totalConverted": num(converted.map(|d| d.abs())),
        "currentBalance": num(aff_balance),
        "totalCodes": total_codes,
        "totalUsed": total_used.unwrap_or(0),
    })))
}

// ===========================================================================
// GET /me/codes — 我的优惠码（含全局码）
// ===========================================================================

#[derive(Debug, FromRow)]
struct CodeRow {
    id: i32,
    code: String,
    package_plan_id: Option<i32>,
    discount_rate: Decimal,
    commission_rate: Decimal,
    used_count: i32,
    total_earnings: Decimal,
    created_at: DateTime<Utc>,
    plan_name: Option<String>,
    package_name: Option<String>,
    plan_price: Option<Decimal>,
}

async fn my_codes(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query_as::<_, CodeRow>(
        "SELECT a.id, a.code, a.package_plan_id, a.discount_rate, a.commission_rate, \
                a.used_count, a.total_earnings, a.created_at, \
                pp.name AS plan_name, p.name AS package_name, pp.price AS plan_price \
         FROM aff_codes a \
         LEFT JOIN package_plans pp ON pp.id = a.package_plan_id \
         LEFT JOIN packages p ON p.id = pp.package_id \
         WHERE a.user_id = $1 ORDER BY a.created_at DESC",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;

    let codes: Vec<Value> = rows
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "code": c.code,
                "packagePlanId": c.package_plan_id,
                "planName": c.plan_name,
                "packageName": c.package_name,
                "price": c.plan_price.map(crate::response::num),
                "isGlobal": c.package_plan_id.is_none(),
                "discountRate": crate::response::num(c.discount_rate),
                "commissionRate": crate::response::num(c.commission_rate),
                "usedCount": c.used_count,
                "totalEarnings": crate::response::num(c.total_earnings),
                "createdAt": iso(c.created_at),
            })
        })
        .collect();
    Ok(Json(json!({ "codes": codes })))
}

// ===========================================================================
// GET /me/available-plans — 可创建优惠码的方案
// ===========================================================================

async fn available_plans(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    if !is_aff_activated(&state).await {
        return Err(bad("AFF 返利暂未开启，暂时无法创建优惠码"));
    }

    let (global_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM aff_codes WHERE user_id = $1 AND package_plan_id IS NULL",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;
    let has_global_code = global_count > 0;

    let rows: Vec<(i32, String, Decimal, String, bool)> = sqlx::query_as(
        "SELECT DISTINCT pp.id, pp.name, pp.price, p.name, \
                EXISTS(SELECT 1 FROM aff_codes a WHERE a.user_id = $1 AND a.package_plan_id = pp.id) \
         FROM package_plans pp \
         JOIN packages p ON p.id = pp.package_id \
         WHERE pp.price > 0 AND pp.is_active = true \
           AND EXISTS(SELECT 1 FROM instances i WHERE i.user_id = $1 AND i.package_plan_id = pp.id) \
         ORDER BY pp.id ASC",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;

    let plans: Vec<Value> = rows
        .iter()
        .map(|(id, name, price, package_name, has_code)| {
            json!({
                "id": id,
                "name": name,
                "price": crate::response::num(*price),
                "packageName": package_name,
                "hasCode": has_code,
            })
        })
        .collect();
    Ok(Json(json!({ "plans": plans, "hasGlobalCode": has_global_code })))
}

// ===========================================================================
// POST /me/codes — 创建优惠码（固定 5%/5%）
// ===========================================================================

#[derive(Deserialize)]
struct CreateCodeBody {
    #[serde(rename = "packagePlanId")]
    package_plan_id: Option<serde_json::Value>,
}

async fn create_code(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<CreateCodeBody>>,
) -> Result<Json<Value>, ApiError> {
    let package_plan_id = body.and_then(|Json(b)| b.package_plan_id);

    // undefined → 全局码；提供时必须是正整数。
    let plan_id = match package_plan_id {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => {
            let as_f = n.as_f64().unwrap_or(0.0);
            if as_f.fract() != 0.0 || as_f <= 0.0 {
                return Err(bad("方案 ID 无效"));
            }
            Some(as_f as i64)
        }
        Some(_) => return Err(bad("方案 ID 无效")),
    };

    if !is_aff_activated(&state).await {
        return Err(bad(AFF_REBATE_DISABLED_ERROR));
    }

    let aff_code = match plan_id {
        None => {
            // 全局码：允许创建多个。
            let code = generate_aff_code(user.id);
            let row: (i32, String, DateTime<Utc>) = sqlx::query_as(
                "INSERT INTO aff_codes (code, user_id, package_plan_id, discount_rate, commission_rate) \
                 VALUES ($1, $2, NULL, 0.05, 0.05) RETURNING id, code, created_at",
            )
            .bind(&code)
            .bind(user.id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| bad("创建全局优惠码失败"))?;
            row
        }
        Some(plan_id) => {
            let plan: Option<(Decimal, bool)> = sqlx::query_as(
                "SELECT price, is_active FROM package_plans WHERE id = $1",
            )
            .bind(plan_id as i32)
            .fetch_optional(&state.db)
            .await?;
            let Some((price, is_active)) = plan else {
                return Err(bad("方案不存在或不是付费方案"));
            };
            if price <= Decimal::ZERO {
                return Err(bad("方案不存在或不是付费方案"));
            }
            if !is_active {
                return Err(bad("方案已下架"));
            }
            let (purchased,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM instances WHERE user_id = $1 AND package_plan_id = $2",
            )
            .bind(user.id)
            .bind(plan_id as i32)
            .fetch_one(&state.db)
            .await?;
            if purchased == 0 {
                return Err(bad("您尚未购买过此方案，无法创建优惠码"));
            }
            let existing: Option<i32> = sqlx::query_scalar(
                "SELECT id FROM aff_codes WHERE user_id = $1 AND package_plan_id = $2",
            )
            .bind(user.id)
            .bind(plan_id as i32)
            .fetch_optional(&state.db)
            .await?;
            if existing.is_some() {
                return Err(bad("该方案已创建过优惠码"));
            }
            let code = generate_aff_code(user.id);
            let row: (i32, String, DateTime<Utc>) = sqlx::query_as(
                "INSERT INTO aff_codes (code, user_id, package_plan_id, discount_rate, commission_rate) \
                 VALUES ($1, $2, $3, 0.05, 0.05) RETURNING id, code, created_at",
            )
            .bind(&code)
            .bind(user.id)
            .bind(plan_id as i32)
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                if e.as_database_error()
                    .and_then(|d| d.code().map(|c| c.into_owned()))
                    .map(|c| c == "23505")
                    .unwrap_or(false)
                {
                    bad("该方案已创建过优惠码")
                } else {
                    ApiError::from_sql(e)
                }
            })?;
            row
        }
    };

    let is_global = plan_id.is_none();
    crate::routes::users::create_log(
        &state,
        user.id,
        "user",
        "aff.create_code",
        &if is_global {
            format!("Created global AFF code {}", aff_code.1)
        } else {
            format!("Created AFF code {} for plan #{plan_id:?}", aff_code.1)
        },
        "success",
    )
    .await;

    Ok(Json(json!({
        "message": if is_global { "全局优惠码创建成功" } else { "优惠码创建成功" },
        "code": {
            "id": aff_code.0,
            "code": aff_code.1,
            "packagePlanId": plan_id,
            "isGlobal": is_global,
            "discountRate": 0.05,
            "commissionRate": 0.05,
            "createdAt": iso(aff_code.2),
        }
    })))
}

// ===========================================================================
// DELETE /me/codes/:codeId
// ===========================================================================

async fn delete_code(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(code_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let code_id = parse_id(&code_id)?;

    let row: Option<(String, i32, i32)> = sqlx::query_as(
        "SELECT code, user_id, used_count FROM aff_codes WHERE id = $1",
    )
    .bind(code_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((code, owner_id, used_count)) = row else {
        return Err(bad("优惠码不存在"));
    };
    if owner_id != user.id {
        return Err(bad("无权删除此优惠码"));
    }
    if used_count > 0 {
        return Err(bad("该优惠码已被使用，无法删除"));
    }
    let (bindings,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM aff_bindings WHERE aff_code_id = $1")
            .bind(code_id)
            .fetch_one(&state.db)
            .await?;
    if bindings > 0 {
        return Err(bad("该优惠码已绑定订阅，无法删除"));
    }

    sqlx::query("DELETE FROM aff_codes WHERE id = $1")
        .bind(code_id)
        .execute(&state.db)
        .await?;

    crate::routes::users::create_log(
        &state,
        user.id,
        "user",
        "aff.delete_code",
        &format!("Deleted AFF code {code}"),
        "success",
    )
    .await;
    Ok(Json(json!({ "message": "优惠码已删除" })))
}

// ===========================================================================
// GET /me/logs — 收益日志
// ===========================================================================

#[derive(Deserialize)]
struct LogsQuery {
    page: Option<String>,
    #[serde(rename = "pageSize")]
    page_size: Option<String>,
    #[serde(rename = "type")]
    log_type: Option<String>,
}

#[derive(Debug, FromRow)]
struct AffLogRow {
    id: i32,
    #[sqlx(rename = "type")]
    log_type: String,
    amount: Decimal,
    original_amount: Option<Decimal>,
    balance_before: Decimal,
    balance_after: Decimal,
    aff_code_id: Option<i32>,
    instance_id: Option<i32>,
    remark: Option<String>,
    created_at: DateTime<Utc>,
    code: Option<String>,
}

async fn logs(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Value>, ApiError> {
    let mut params: HashMap<String, String> = HashMap::new();
    if let Some(p) = query.page {
        params.insert("page".into(), p);
    }
    if let Some(ps) = query.page_size {
        params.insert("pageSize".into(), ps);
    }
    let pagination = pagination(&params);
    let log_type = query.log_type.as_deref().filter(|t|
        ["new_purchase", "renew", "refund", "convert"].contains(t));

    let rows = sqlx::query_as::<_, AffLogRow>(
        "SELECT l.id, l.type::text AS \"type\", l.amount, l.original_amount, l.balance_before, \
                l.balance_after, l.aff_code_id, l.instance_id, l.remark, l.created_at, \
                a.code \
         FROM aff_logs l LEFT JOIN aff_codes a ON a.id = l.aff_code_id \
         WHERE l.user_id = $1 AND ($2::text IS NULL OR l.type::text = $2) \
         ORDER BY l.created_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(user.id)
    .bind(log_type)
    .bind(pagination.take)
    .bind(pagination.skip)
    .fetch_all(&state.db)
    .await?;

    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM aff_logs WHERE user_id = $1 \
         AND ($2::text IS NULL OR type::text = $2)",
    )
    .bind(user.id)
    .bind(log_type)
    .fetch_one(&state.db)
    .await?;

    let logs: Vec<Value> = rows
        .iter()
        .map(|l| {
            json!({
                "id": l.id,
                "type": l.log_type,
                "amount": crate::response::num(l.amount),
                "originalAmount": l.original_amount.map(crate::response::num),
                "balanceBefore": crate::response::num(l.balance_before),
                "balanceAfter": crate::response::num(l.balance_after),
                "affCodeId": l.aff_code_id,
                "affCode": l.code,
                "instanceId": l.instance_id,
                "remark": l.remark,
                "createdAt": iso(l.created_at),
            })
        })
        .collect();

    Ok(Json(json!({
        "logs": logs,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
    })))
}

// ===========================================================================
// GET /leaderboard — TOP 10
// ===========================================================================

/// db maskUsername: ≤4 chars → first char + '***'; else first2 + '***' + last2.
fn mask_username(username: &str) -> String {
    let chars: Vec<char> = username.chars().collect();
    if chars.len() <= 4 {
        return format!("{}***", chars.first().copied().unwrap_or_default());
    }
    format!(
        "{}***{}",
        chars[..2].iter().collect::<String>(),
        chars[chars.len() - 2..].iter().collect::<String>()
    )
}

async fn leaderboard(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(i32, String, Decimal)> = sqlx::query_as(
        "SELECT l.user_id, u.username, SUM(l.amount) AS total \
         FROM aff_logs l JOIN users u ON u.id = l.user_id \
         WHERE l.amount > 0 GROUP BY l.user_id, u.username \
         ORDER BY total DESC LIMIT 10",
    )
    .fetch_all(&state.db)
    .await?;

    let entries: Vec<Value> = rows
        .iter()
        .enumerate()
        .map(|(index, (uid, username, total))| {
            json!({
                "rank": index + 1,
                "username": mask_username(username),
                "totalEarnings": crate::response::num(*total),
                "isCurrentUser": uid == &user.id,
            })
        })
        .collect();
    Ok(Json(json!({ "leaderboard": entries })))
}

// ===========================================================================
// POST /validate — 验证优惠码
// ===========================================================================

#[derive(Deserialize)]
struct ValidateBody {
    code: Option<String>,
    #[serde(rename = "packagePlanId")]
    package_plan_id: Option<serde_json::Value>,
}

async fn validate(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<ValidateBody>>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.ok_or_else(|| bad("请输入优惠码"))?;
    let Some(code) = body.code.as_deref().map(str::trim).filter(|c| !c.is_empty()) else {
        return Err(bad("请输入优惠码"));
    };
    let Some(plan_id) = body.package_plan_id.as_ref().and_then(Value::as_i64) else {
        return Err(bad("方案 ID 无效"));
    };

    if !is_aff_activated(&state).await {
        return Err(bad(AFF_REBATE_DISABLED_ERROR));
    }

    let row: Option<(bool, Option<i32>, i32, Decimal, Decimal)> = sqlx::query_as(
        "SELECT enabled, package_plan_id, user_id, discount_rate, commission_rate \
         FROM aff_codes WHERE code = $1",
    )
    .bind(code.to_uppercase())
    .fetch_optional(&state.db)
    .await?;
    let Some((enabled, code_plan_id, owner_id, discount, commission)) = row else {
        return Err(bad("优惠码不存在"));
    };
    if !enabled {
        return Err(bad("优惠码已停用"));
    }
    if let Some(code_plan) = code_plan_id {
        if code_plan as i64 != plan_id {
            return Err(bad("优惠码不适用于此方案"));
        }
    }
    if owner_id == user.id {
        return Err(bad("不能使用自己的优惠码"));
    }

    Ok(Json(json!({
        "valid": true,
        "discountRate": crate::response::num(discount),
        "commissionRate": crate::response::num(commission),
    })))
}

// ===========================================================================
// POST /me/convert — 转化（自动审批）
// ===========================================================================

#[derive(Deserialize)]
struct ConvertBody {
    amount: Option<serde_json::Value>,
}

#[derive(Debug, FromRow)]
struct WithdrawalRow {
    id: i32,
    user_id: i32,
    amount: Decimal,
    #[sqlx(rename = "status")]
    w_status: String,
    reject_reason: Option<String>,
    reviewed_by: Option<i32>,
    reviewed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    username: Option<String>,
    aff_balance: Option<Decimal>,
}

const WITHDRAWAL_COLUMNS: &str =
    "id, user_id, amount, status::text AS status, reject_reason, reviewed_by, reviewed_at, created_at";

async fn convert(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<ConvertBody>>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.ok_or_else(|| bad("请输入有效的转化金额"))?;
    let amount = body
        .amount
        .as_ref()
        .and_then(Value::as_f64)
        .filter(|a| a.is_finite() && *a > 0.0)
        .ok_or_else(|| bad("请输入有效的转化金额"))?;
    // 两位小数规范化
    let amount = (amount * 100.0).round() / 100.0;
    let amount = Decimal::try_from(amount).unwrap_or_default();

    let withdrawal = balance_tx_withdrawal(&state, user.id, amount).await?;

    crate::routes::users::create_log(
        &state,
        user.id,
        "user",
        "aff.convert_request",
        &format!("AFF balance converted: {amount}"),
        "success",
    )
    .await;

    Ok(Json(json!({
        "message": "转化成功，已转入账户余额",
        "withdrawal": {
            "id": withdrawal.id,
            "amount": crate::response::num(withdrawal.amount),
            "status": withdrawal.w_status,
            "createdAt": iso(withdrawal.created_at),
        }
    })))
}

/// db createAffWithdrawal: locked tx — create approved withdrawal, deduct AFF
/// balance (+ aff log), increment main balance (+ balance log).
async fn balance_tx_withdrawal(
    state: &SharedAppState,
    user_id: i32,
    amount: Decimal,
) -> Result<WithdrawalRow, ApiError> {
    if amount < Decimal::new(1, 1) {
        return Err(bad("最低转化金额为 0.1 元"));
    }

    let mut tx = state.db.begin().await?;
    advisory_transaction_lock(
        &mut tx,
        advisory_lock_namespace::USER_BALANCE,
        user_id as i64,
    )
    .await?;

    let (aff_balance_before, balance_before): (Decimal, Decimal) = sqlx::query_as(
        "SELECT aff_balance, balance FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| bad("用户不存在"))?;

    if aff_balance_before < amount {
        let _ = tx.rollback().await;
        return Err(bad("AFF 余额不足"));
    }

    let withdrawal: WithdrawalRow = sqlx::query_as(&format!(
        "INSERT INTO aff_withdrawals (user_id, amount, status, reviewed_at) \
         VALUES ($1, $2, 'approved', now()) RETURNING {WITHDRAWAL_COLUMNS}"
    ))
    .bind(user_id)
    .bind(amount)
    .fetch_one(&mut *tx)
    .await?;

    let aff_balance_after = aff_balance_before - amount;
    sqlx::query("UPDATE users SET aff_balance = aff_balance - $2 WHERE id = $1")
        .bind(user_id)
        .bind(amount)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO aff_logs (user_id, type, amount, balance_before, balance_after, remark) \
         VALUES ($1, 'convert'::\"AffLogType\", $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(-amount)
    .bind(aff_balance_before)
    .bind(aff_balance_after)
    .bind(format!("转化申请 #{} 审核通过", withdrawal.id))
    .execute(&mut *tx)
    .await?;

    let balance_after = balance_before + amount;
    sqlx::query("UPDATE users SET balance = balance + $2 WHERE id = $1")
        .bind(user_id)
        .bind(amount)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, remark) \
         VALUES ($1, 'gift'::\"BalanceLogType\", $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(amount)
    .bind(balance_before)
    .bind(balance_after)
    .bind(format!("AFF 余额转化 #{}", withdrawal.id))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(withdrawal)
}

// ===========================================================================
// GET /me/withdrawals — 我的转化申请
// ===========================================================================

#[derive(Deserialize)]
struct WithdrawalsQuery {
    page: Option<String>,
    #[serde(rename = "pageSize")]
    page_size: Option<String>,
    status: Option<String>,
}

async fn my_withdrawals(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(query): Query<WithdrawalsQuery>,
) -> Result<Json<Value>, ApiError> {
    let mut params: HashMap<String, String> = HashMap::new();
    if let Some(p) = query.page {
        params.insert("page".into(), p);
    }
    if let Some(ps) = query.page_size {
        params.insert("pageSize".into(), ps);
    }
    let pagination = pagination(&params);
    let status = query
        .status
        .as_deref()
        .filter(|s| ["pending", "approved", "rejected"].contains(s));

    let rows = sqlx::query_as::<_, WithdrawalRow>(&format!(
        "SELECT {WITHDRAWAL_COLUMNS}, NULL AS username, NULL AS aff_balance \
         FROM aff_withdrawals WHERE user_id = $1 AND ($2::text IS NULL OR status::text = $2) \
         ORDER BY created_at DESC LIMIT $3 OFFSET $4"
    ))
    .bind(user.id)
    .bind(status)
    .bind(pagination.take)
    .bind(pagination.skip)
    .fetch_all(&state.db)
    .await?;
    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM aff_withdrawals WHERE user_id = $1 \
         AND ($2::text IS NULL OR status::text = $2)",
    )
    .bind(user.id)
    .bind(status)
    .fetch_one(&state.db)
    .await?;

    let withdrawals: Vec<Value> = rows
        .iter()
        .map(|w| {
            json!({
                "id": w.id,
                "amount": crate::response::num(w.amount),
                "status": w.w_status,
                "rejectReason": w.reject_reason,
                "reviewedAt": w.reviewed_at.map(iso).unwrap_or(Value::Null),
                "createdAt": iso(w.created_at),
            })
        })
        .collect();
    Ok(Json(json!({
        "withdrawals": withdrawals,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
    })))
}

// ===========================================================================
// GET /admin/withdrawals — 所有转化申请（管理员）
// ===========================================================================

async fn admin_withdrawals(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Query(query): Query<WithdrawalsQuery>,
) -> Result<Json<Value>, ApiError> {
    let mut params: HashMap<String, String> = HashMap::new();
    if let Some(p) = query.page {
        params.insert("page".into(), p);
    }
    if let Some(ps) = query.page_size {
        params.insert("pageSize".into(), ps);
    }
    let pagination = pagination(&params);
    let status = query
        .status
        .as_deref()
        .filter(|s| ["pending", "approved", "rejected"].contains(s));

    let rows = sqlx::query_as::<_, WithdrawalRow>(&format!(
        "SELECT w.id, w.user_id, w.amount, w.status::text AS status, w.reject_reason, \
                w.reviewed_by, w.reviewed_at, w.created_at, u.username, u.aff_balance \
         FROM aff_withdrawals w JOIN users u ON u.id = w.user_id \
         WHERE ($1::text IS NULL OR w.status::text = $1) \
         ORDER BY w.created_at DESC LIMIT $2 OFFSET $3"
    ))
    .bind(status)
    .bind(pagination.take)
    .bind(pagination.skip)
    .fetch_all(&state.db)
    .await?;
    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM aff_withdrawals WHERE ($1::text IS NULL OR status::text = $1)",
    )
    .bind(status)
    .fetch_one(&state.db)
    .await?;

    let withdrawals: Vec<Value> = rows
        .iter()
        .map(|w| {
            json!({
                "id": w.id,
                "userId": w.user_id,
                "username": w.username,
                "userAffBalance": w.aff_balance.map(crate::response::num),
                "amount": crate::response::num(w.amount),
                "status": w.w_status,
                "rejectReason": w.reject_reason,
                "reviewedBy": w.reviewed_by,
                "reviewedAt": w.reviewed_at.map(iso).unwrap_or(Value::Null),
                "createdAt": iso(w.created_at),
            })
        })
        .collect();
    Ok(Json(json!({
        "withdrawals": withdrawals,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
    })))
}

// ===========================================================================
// POST /admin/withdrawals/:id/approve | reject
// ===========================================================================

async fn get_withdrawal_by_id(
    state: &SharedAppState,
    withdrawal_id: i32,
) -> Result<Option<(i32, Decimal)>, ApiError> {
    Ok(sqlx::query_as::<_, (i32, Decimal)>(
        "SELECT user_id, amount FROM aff_withdrawals WHERE id = $1",
    )
    .bind(withdrawal_id)
    .fetch_optional(&state.db)
    .await?)
}

async fn admin_approve(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(withdrawal_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let withdrawal_id = parse_id(&withdrawal_id)?;

    let withdrawal = get_withdrawal_by_id(&state, withdrawal_id)
        .await?
        .ok_or_else(|| bad("申请不存在"))?;
    let (owner_id, amount) = withdrawal;

    // db approveAffWithdrawal: USER_BALANCE lock on owner, re-read pending.
    let mut tx = state.db.begin().await?;
    advisory_transaction_lock(
        &mut tx,
        advisory_lock_namespace::USER_BALANCE,
        owner_id as i64,
    )
    .await?;

    let row: Option<(String, Decimal, Decimal, Decimal)> = sqlx::query_as(
        "SELECT w.status::text, u.aff_balance, u.balance, w.amount \
         FROM aff_withdrawals w JOIN users u ON u.id = w.user_id WHERE w.id = $1",
    )
    .bind(withdrawal_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((status, aff_before, balance_before, amount)) = row else {
        let _ = tx.rollback().await;
        return Err(bad("申请不存在"));
    };
    if status != "pending" {
        let _ = tx.rollback().await;
        return Err(bad("申请已处理"));
    }
    if aff_before < amount {
        let _ = tx.rollback().await;
        return Err(bad("AFF 余额不足"));
    }

    let aff_after = aff_before - amount;
    sqlx::query("UPDATE users SET aff_balance = aff_balance - $2 WHERE id = $1")
        .bind(owner_id)
        .bind(amount)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO aff_logs (user_id, type, amount, balance_before, balance_after, remark) \
         VALUES ($1, 'convert'::\"AffLogType\", $2, $3, $4, $5)",
    )
    .bind(owner_id)
    .bind(-amount)
    .bind(aff_before)
    .bind(aff_after)
    .bind(format!("转化申请 #{withdrawal_id} 审核通过"))
    .execute(&mut *tx)
    .await?;

    let balance_after = balance_before + amount;
    sqlx::query("UPDATE users SET balance = balance + $2 WHERE id = $1")
        .bind(owner_id)
        .bind(amount)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, remark) \
         VALUES ($1, 'gift'::\"BalanceLogType\", $2, $3, $4, $5)",
    )
    .bind(owner_id)
    .bind(amount)
    .bind(balance_before)
    .bind(balance_after)
    .bind(format!("AFF 余额转化 #{withdrawal_id}"))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE aff_withdrawals SET status = 'approved', reviewed_by = $2, reviewed_at = now() \
         WHERE id = $1",
    )
    .bind(withdrawal_id)
    .bind(admin.0.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    crate::routes::users::create_log(
        &state,
        admin.0.id,
        "admin",
        "aff.approve_convert",
        &format!("Approved AFF convert request #{withdrawal_id}"),
        "success",
    )
    .await;
    crate::routes::users::create_inbox_notification(
        &state,
        owner_id,
        "aff_convert_approved",
        "AFF 转化审核通过",
        &format!(
            "您的 AFF 余额转化申请已审核通过，¥{amount:.2} 已转入您的账户余额。",
            amount = amount
        ),
        json!({ "withdrawalId": withdrawal_id, "amount": crate::response::num(amount) }),
    )
    .await;

    Ok(Json(json!({ "message": "审核通过，已转入用户余额" })))
}

#[derive(Deserialize)]
struct RejectBody {
    reason: Option<String>,
}

async fn admin_reject(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(withdrawal_id): Path<String>,
    body: Option<Json<RejectBody>>,
) -> Result<Json<Value>, ApiError> {
    let withdrawal_id = parse_id(&withdrawal_id)?;
    let reason = body
        .and_then(|Json(b)| b.reason)
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .ok_or_else(|| bad("请填写拒绝原因"))?;

    let withdrawal = get_withdrawal_by_id(&state, withdrawal_id)
        .await?
        .ok_or_else(|| bad("申请不存在"))?;
    let (owner_id, amount) = withdrawal;

    let result = sqlx::query(
        "UPDATE aff_withdrawals SET status = 'rejected', reject_reason = $2, \
         reviewed_by = $3, reviewed_at = now() WHERE id = $1 AND status::text = 'pending'",
    )
    .bind(withdrawal_id)
    .bind(&reason)
    .bind(admin.0.id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() != 1 {
        return Err(bad("申请已处理"));
    }

    crate::routes::users::create_log(
        &state,
        admin.0.id,
        "admin",
        "aff.reject_convert",
        &format!("Rejected AFF convert request #{withdrawal_id}: {reason}"),
        "success",
    )
    .await;
    crate::routes::users::create_inbox_notification(
        &state,
        owner_id,
        "aff_convert_rejected",
        "AFF 转化申请被拒绝",
        &format!(
            "您的 AFF 余额转化申请（¥{amount:.2}）已被拒绝。\n拒绝原因：{reason}",
            amount = amount
        ),
        json!({ "withdrawalId": withdrawal_id, "amount": crate::response::num(amount), "reason": reason }),
    )
    .await;

    Ok(Json(json!({ "message": "已拒绝" })))
}
