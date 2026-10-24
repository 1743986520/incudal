//! Port of server/src/services/vip-benefits.ts — admin reward CRUD, the user
//! benefit overview, and the claim flows (single + bulk).
//!
//! Notes on the port:
//! - `VipBenefitError { code, statusCode }` maps to the wire shape
//!   `{ error, code }` with its own status via `ApiError::with_message`.
//! - The claim transaction is a plain (read-committed) transaction exactly
//!   like the TS `prisma.$transaction`; the balance grant serializes through
//!   the USER_BALANCE advisory lock (namespace 4110), and the per-user claimNo
//!   uniqueness is enforced by the `vip_benefit_claims` unique constraint
//!   (Prisma P2002 -> CLAIM_CONFLICT, ported as PG error 23505).
//! - Instance-type rewards only create a `pending` claim row; the provisioning
//!   worker that fulfils them is not ported (instances routes are TS-only so
//!   far), which matches the TS data flow for this service.

use std::collections::HashMap;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde_json::{json, Map, Value};
use sqlx::PgPool;

use crate::db::advisory_lock_namespace;
use crate::error::ApiError;
use crate::libs::vip::{
    calculate_user_vip_level_by_metric, dec2, get_user_vip_metric, get_user_vip_stats_tx,
    get_vip_badge_style_for_level, get_vip_rules_tx, js_num_json, js_to_number, round_amount_dec,
    round_money_f64, UserVipMetric, VipRuleType, MAX_VIP_LEVEL,
};
use crate::response::num;

const MAX_MONEY_AMOUNT: f64 = 99999999.99;
const MAX_POINTS_AMOUNT: f64 = 1000000000.0;
const MAX_CLAIM_LIMIT: f64 = 100.0;
const MAX_SORT_ORDER: f64 = 1000000.0;
const MAX_INSTANCE_DAYS: f64 = 3650.0;
const MAX_INSTANCE_QUANTITY: f64 = 10.0;
const MAX_TITLE_LENGTH: usize = 80;
const MAX_DESCRIPTION_LENGTH: usize = 300;
const MAX_BULK_CLAIMS: usize = 1000;

/// TS VipBenefitError — code + custom status, message is the `error` field.
#[derive(Debug, Clone)]
pub struct VipBenefitError {
    pub code: String,
    pub message: String,
    pub status: StatusCode,
}

impl VipBenefitError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    pub fn with_status(code: &str, message: impl Into<String>, status: StatusCode) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            status,
        }
    }
}

impl From<VipBenefitError> for ApiError {
    fn from(e: VipBenefitError) -> Self {
        ApiError::with_message(&e.code, e.status, e.message)
    }
}

/// Error surface of the service functions: VipBenefitError or a DB failure.
pub enum BenefitError {
    Benefit(VipBenefitError),
    Db(ApiError),
}

impl From<VipBenefitError> for BenefitError {
    fn from(e: VipBenefitError) -> Self {
        Self::Benefit(e)
    }
}

impl From<ApiError> for BenefitError {
    fn from(e: ApiError) -> Self {
        Self::Db(e)
    }
}

impl From<sqlx::Error> for BenefitError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(ApiError::from_sql(e))
    }
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db)
        if db.code().map(|c| c.into_owned()).as_deref() == Some("23505"))
}

// ===========================================================================
// JS helpers
// ===========================================================================

fn to_number(value: &Value) -> f64 {
    js_to_number(value).filter(|v| v.is_finite()).unwrap_or(0.0)
}

fn get_record(value: &Value) -> Map<String, Value> {
    match value.as_object() {
        Some(map) => map.clone(),
        _ => Map::new(),
    }
}

/// JS `a ?? b`: absent or JSON null falls through to the base value.
fn coalesce<'a>(input: &'a Value, key: &str, base: &'a Value, base_key: &str) -> &'a Value {
    match input.get(key) {
        Some(Value::Null) | None => &base[base_key],
        Some(v) => v,
    }
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

fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ===========================================================================
// Normalization
// ===========================================================================

fn normalize_level(value: &Value) -> Result<i32, VipBenefitError> {
    let level = js_to_number(value);
    let valid = matches!(level, Some(v) if v.is_finite()
        && v.fract() == 0.0
        && (1.0..=MAX_VIP_LEVEL as f64).contains(&v));
    if !valid {
        return Err(VipBenefitError::new(
            "INVALID_LEVEL",
            format!("VIP level must be between 1 and {MAX_VIP_LEVEL}"),
        ));
    }
    Ok(level.unwrap() as i32)
}

fn normalize_reward_type(value: &Value) -> Result<String, VipBenefitError> {
    match value.as_str() {
        Some(t) if matches!(t, "balance" | "points" | "instance") => Ok(t.to_string()),
        _ => Err(VipBenefitError::new(
            "INVALID_REWARD_TYPE",
            "Invalid VIP benefit reward type",
        )),
    }
}

fn normalize_title(value: &Value) -> Result<String, VipBenefitError> {
    let Some(s) = value.as_str() else {
        return Err(VipBenefitError::new(
            "INVALID_TITLE",
            "Reward title is required",
        ));
    };
    let title = s.trim();
    if title.is_empty() {
        return Err(VipBenefitError::new(
            "INVALID_TITLE",
            "Reward title is required",
        ));
    }
    let len: usize = title.chars().map(|c| c.len_utf16()).sum();
    if len > MAX_TITLE_LENGTH {
        return Err(VipBenefitError::new(
            "INVALID_TITLE",
            format!("Reward title cannot exceed {MAX_TITLE_LENGTH} characters"),
        ));
    }
    Ok(title.to_string())
}

fn normalize_description(value: &Value) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let Some(s) = value.as_str() else {
        return None;
    };
    let description = s.trim();
    if description.is_empty() {
        None
    } else {
        Some(js_slice(description, MAX_DESCRIPTION_LENGTH))
    }
}

fn normalize_positive_integer(value: &Value, field: &str, max: f64) -> Result<i64, VipBenefitError> {
    let parsed = js_to_number(value);
    let valid =
        matches!(parsed, Some(v) if v.is_finite() && v.fract() == 0.0 && v > 0.0 && v <= max);
    if !valid {
        return Err(VipBenefitError::new(
            "INVALID_NUMBER",
            format!("{field} must be an integer between 1 and {max}"),
        ));
    }
    Ok(parsed.unwrap() as i64)
}

fn normalize_optional_positive_integer(
    value: &Value,
    fallback: i64,
    field: &str,
    max: f64,
) -> Result<i64, VipBenefitError> {
    if value.is_null() || value.as_str() == Some("") {
        return Ok(fallback);
    }
    normalize_positive_integer(value, field, max)
}

fn normalize_money(value: &Value, field: &str) -> Result<f64, VipBenefitError> {
    let parsed = js_to_number(value);
    let valid = matches!(parsed, Some(v) if v.is_finite() && v > 0.0 && v <= MAX_MONEY_AMOUNT);
    if !valid {
        return Err(VipBenefitError::new(
            "INVALID_AMOUNT",
            format!("{field} must be between 0.01 and {MAX_MONEY_AMOUNT}"),
        ));
    }
    Ok(round_money_f64(parsed.unwrap()))
}

fn normalize_sort_order(value: &Value) -> Result<i64, VipBenefitError> {
    let parsed = js_to_number(value).unwrap_or(0.0);
    if !parsed.is_finite() || parsed.fract() != 0.0 || !(0.0..=MAX_SORT_ORDER).contains(&parsed) {
        return Err(VipBenefitError::new(
            "INVALID_SORT_ORDER",
            format!("Sort order must be an integer between 0 and {MAX_SORT_ORDER}"),
        ));
    }
    Ok(parsed as i64)
}

fn normalize_label(value: &Value) -> Option<String> {
    let s = value.as_str()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(js_slice(trimmed, 100))
    }
}

/// normalizeRewardConfig — strict, for admin input.
fn normalize_reward_config(reward_type: &str, value: &Value) -> Result<Value, VipBenefitError> {
    let config = get_record(value);
    if reward_type == "balance" {
        let amount = normalize_money(config.get("amount").unwrap_or(&Value::Null), "Balance reward amount")?;
        return Ok(json!({ "amount": js_num_json(amount) }));
    }
    if reward_type == "points" {
        let amount =
            normalize_positive_integer(config.get("amount").unwrap_or(&Value::Null), "Points reward amount", MAX_POINTS_AMOUNT)?;
        return Ok(json!({ "amount": amount }));
    }
    Ok(json!({
        "packageId": normalize_positive_integer(config.get("packageId").unwrap_or(&Value::Null), "Package ID", 2147483647.0)?,
        "packageName": normalize_label(config.get("packageName").unwrap_or(&Value::Null)),
        "planId": normalize_positive_integer(config.get("planId").unwrap_or(&Value::Null), "Plan ID", 2147483647.0)?,
        "planName": normalize_label(config.get("planName").unwrap_or(&Value::Null)),
        "days": normalize_optional_positive_integer(
            config.get("days").unwrap_or(&Value::Null), 30, "Instance reward days", MAX_INSTANCE_DAYS)?,
        "quantity": normalize_optional_positive_integer(
            config.get("quantity").unwrap_or(&Value::Null), 1, "Instance reward quantity", MAX_INSTANCE_QUANTITY)?,
    }))
}

/// normalizeStoredRewardConfig — lenient, for DB rows.
fn normalize_stored_reward_config(reward_type: &str, value: &Value) -> Value {
    let config = get_record(value);
    if reward_type == "balance" {
        let amount = round_money_f64(0.0f64.max(to_number(config.get("amount").unwrap_or(&Value::Null))));
        return json!({ "amount": js_num_json(amount) });
    }
    if reward_type == "points" {
        let amount = 0.0f64.max(to_number(config.get("amount").unwrap_or(&Value::Null))).floor();
        return json!({ "amount": js_num_json(amount) });
    }
    // TS: Number.isInteger(Number(v)) ? Number(v) : null
    let int_or_null = |v: &Value| match js_to_number(v) {
        Some(n) if n.is_finite() && n.fract() == 0.0 => js_num_json(n),
        _ => Value::Null,
    };
    // TS days: Math.max(1, Math.min(MAX, Math.floor(toNumber(v) || 30)))
    let days = match to_number(config.get("days").unwrap_or(&Value::Null)) {
        0.0 => 30.0,
        v => 1.0f64.max(MAX_INSTANCE_DAYS.min(v.floor())),
    };
    let quantity = match to_number(config.get("quantity").unwrap_or(&Value::Null)) {
        0.0 => 1.0,
        v => 1.0f64.max(MAX_INSTANCE_QUANTITY.min(v.floor())),
    };
    json!({
        "packageId": int_or_null(config.get("packageId").unwrap_or(&Value::Null)),
        "packageName": normalize_label(config.get("packageName").unwrap_or(&Value::Null)),
        "planId": int_or_null(config.get("planId").unwrap_or(&Value::Null)),
        "planName": normalize_label(config.get("planName").unwrap_or(&Value::Null)),
        "days": js_num_json(days),
        "quantity": js_num_json(quantity),
    })
}

// ===========================================================================
// DB rows
// ===========================================================================

#[derive(Debug, sqlx::FromRow)]
pub struct RewardRow {
    pub id: i32,
    pub level: i32,
    #[sqlx(rename = "type")]
    pub reward_type: String,
    pub title: String,
    pub description: Option<String>,
    pub claim_limit: i32,
    pub sort_order: i32,
    pub enabled: bool,
    pub config: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const REWARD_SELECT: &str = "SELECT id, level, type::text AS type, title, description, \
    claim_limit, sort_order, enabled, config, created_at, updated_at FROM vip_benefit_rewards";

#[derive(Debug, sqlx::FromRow)]
pub struct ClaimRow {
    pub id: i32,
    pub reward_id: i32,
    pub level: i32,
    #[sqlx(rename = "status")]
    pub status: String,
    pub claim_no: i32,
    pub snapshot: Value,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const CLAIM_SELECT: &str = "SELECT id, reward_id, level, status::text AS status, claim_no, \
    snapshot, delivered_at, created_at FROM vip_benefit_claims";

fn claim_to_view(claim: &ClaimRow) -> Value {
    json!({
        "id": claim.id,
        "rewardId": claim.reward_id,
        "level": claim.level,
        "status": claim.status,
        "claimNo": claim.claim_no,
        "snapshot": if claim.snapshot.is_object() {
            claim.snapshot.clone()
        } else {
            json!({})
        },
        "deliveredAt": claim.delivered_at.map(|t| Value::String(iso(t))).unwrap_or(Value::Null),
        "createdAt": iso(claim.created_at),
    })
}

fn reward_to_admin_view(reward: &RewardRow) -> Value {
    json!({
        "id": reward.id,
        "level": reward.level,
        "type": reward.reward_type,
        "title": reward.title,
        "description": reward.description,
        "claimLimit": reward.claim_limit,
        "sortOrder": reward.sort_order,
        "enabled": reward.enabled,
        "config": normalize_stored_reward_config(&reward.reward_type, &reward.config),
        "createdAt": iso(reward.created_at),
        "updatedAt": iso(reward.updated_at),
        "claimedCount": 0,
        "remainingClaims": reward.claim_limit,
        "state": "locked",
        "blockedByLevel": Value::Null,
        "claims": [],
    })
}

/// validateInstanceConfig — package/plan must exist, be active and belong
/// together; missing labels fall back to the DB names.
async fn validate_instance_config(db: &PgPool, config: &Value) -> Result<Value, BenefitError> {
    let (package_id, plan_id) = (
        config["packageId"].as_i64(),
        config["planId"].as_i64(),
    );
    let (Some(package_id), Some(plan_id)) = (package_id, plan_id) else {
        return Err(VipBenefitError::new(
            "INVALID_INSTANCE_REWARD",
            "Instance reward requires a package and plan",
        )
        .into());
    };

    let pkg: Option<(Option<String>,)> =
        sqlx::query_as("SELECT name FROM packages WHERE id = $1 AND active = true")
            .bind(package_id)
            .fetch_optional(db)
            .await?;
    let plan: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT name FROM package_plans WHERE id = $1 AND package_id = $2 AND is_active = true",
    )
    .bind(plan_id)
    .bind(package_id)
    .fetch_optional(db)
    .await?;

    let Some((Some(package_name),)) = pkg else {
        return Err(VipBenefitError::new(
            "INVALID_INSTANCE_REWARD",
            "Selected package does not exist or is disabled",
        )
        .into());
    };
    let Some((Some(plan_name),)) = plan else {
        return Err(VipBenefitError::new(
            "INVALID_INSTANCE_REWARD",
            "Selected plan does not exist, is disabled, or does not belong to the package",
        )
        .into());
    };

    let mut merged = config.clone();
    if merged["packageName"].as_str().map(|s| !s.is_empty()) != Some(true) {
        merged["packageName"] = json!(package_name);
    }
    if merged["planName"].as_str().map(|s| !s.is_empty()) != Some(true) {
        merged["planName"] = json!(plan_name);
    }
    Ok(merged)
}

/// normalizeRewardData — `input` fields fall back to `base` with JS `??`
/// semantics (absent or null), except `config`, which falls back only when the
/// key is absent (JSON null passes through, exactly like `!== undefined`).
async fn normalize_reward_data(
    db: &PgPool,
    input: &Value,
    base: Option<&RewardRow>,
) -> Result<Value, BenefitError> {
    let base_value = match base {
        Some(row) => json!({
            "level": row.level,
            "type": row.reward_type,
            "title": row.title,
            "description": row.description,
            "claimLimit": row.claim_limit,
            "sortOrder": row.sort_order,
            "enabled": row.enabled,
            "config": row.config,
        }),
        None => json!({}),
    };

    let reward_type = normalize_reward_type(coalesce(input, "type", &base_value, "type"))?;

    // `input.config !== undefined ? input.config : base?.config`
    let raw_config = match input.get("config") {
        Some(v) => v.clone(),
        None => base_value["config"].clone(),
    };
    let mut config = normalize_reward_config(&reward_type, &raw_config)?;
    if reward_type == "instance" {
        config = validate_instance_config(db, &config).await?;
    }

    let level = normalize_level(coalesce(input, "level", &base_value, "level"))?;
    let title = normalize_title(coalesce(input, "title", &base_value, "title"))?;
    let description =
        normalize_description(coalesce(input, "description", &base_value, "description"));
    let claim_limit = normalize_optional_positive_integer(
        coalesce(input, "claimLimit", &base_value, "claimLimit"),
        1,
        "Claim limit",
        MAX_CLAIM_LIMIT,
    )?;
    // `input.sortOrder ?? base?.sortOrder ?? 0` — double nullish chain.
    let sort_order_value = match input.get("sortOrder") {
        Some(Value::Null) | None => base_value["sortOrder"].clone(),
        Some(v) => v.clone(),
    };
    let sort_order = normalize_sort_order(&sort_order_value)?;
    let enabled = match input.get("enabled") {
        None => base.map(|row| row.enabled).unwrap_or(true),
        Some(v) => *v == Value::Bool(true),
    };

    Ok(json!({
        "level": level,
        "type": reward_type,
        "title": title,
        "description": description,
        "claimLimit": claim_limit,
        "sortOrder": sort_order,
        "enabled": enabled,
        "config": config,
    }))
}

// ===========================================================================
// Admin CRUD
// ===========================================================================

pub async fn list_admin_vip_benefit_rewards(db: &PgPool) -> Result<Vec<Value>, ApiError> {
    let rewards =
        sqlx::query_as::<_, RewardRow>(&format!("{REWARD_SELECT} ORDER BY level ASC, sort_order ASC, id ASC"))
            .fetch_all(db)
            .await?;
    Ok(rewards.iter().map(reward_to_admin_view).collect())
}

pub async fn create_vip_benefit_reward(db: &PgPool, input: &Value) -> Result<Value, BenefitError> {
    let data = normalize_reward_data(db, input, None).await?;
    let reward = sqlx::query_as::<_, RewardRow>(
        "INSERT INTO vip_benefit_rewards \
         (level, type, title, description, claim_limit, sort_order, enabled, config) \
         VALUES ($1, $2::\"VipBenefitRewardType\", $3, $4, $5, $6, $7, $8) \
         RETURNING id, level, type::text AS type, title, description, claim_limit, \
         sort_order, enabled, config, created_at, updated_at",
    )
    .bind(data["level"].as_i64().unwrap_or(0) as i32)
    .bind(data["type"].as_str().unwrap_or(""))
    .bind(data["title"].as_str().unwrap_or(""))
    .bind(data["description"].as_str())
    .bind(data["claimLimit"].as_i64().unwrap_or(0) as i32)
    .bind(data["sortOrder"].as_i64().unwrap_or(0) as i32)
    .bind(data["enabled"].as_bool().unwrap_or(true))
    .bind(&data["config"])
    .fetch_one(db)
    .await?;
    Ok(reward_to_admin_view(&reward))
}

pub async fn update_vip_benefit_reward(
    db: &PgPool,
    id: i32,
    input: &Value,
) -> Result<Value, BenefitError> {
    let existing = sqlx::query_as::<_, RewardRow>(&format!("{REWARD_SELECT} WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?;
    let Some(existing) = existing else {
        return Err(VipBenefitError::with_status(
            "REWARD_NOT_FOUND",
            "VIP benefit reward not found",
            StatusCode::NOT_FOUND,
        )
        .into());
    };

    let data = normalize_reward_data(db, input, Some(&existing)).await?;
    let reward = sqlx::query_as::<_, RewardRow>(
        "UPDATE vip_benefit_rewards SET \
         level = $2, type = $3::\"VipBenefitRewardType\", title = $4, description = $5, \
         claim_limit = $6, sort_order = $7, enabled = $8, config = $9, updated_at = NOW() \
         WHERE id = $1 \
         RETURNING id, level, type::text AS type, title, description, claim_limit, \
         sort_order, enabled, config, created_at, updated_at",
    )
    .bind(id)
    .bind(data["level"].as_i64().unwrap_or(0) as i32)
    .bind(data["type"].as_str().unwrap_or(""))
    .bind(data["title"].as_str().unwrap_or(""))
    .bind(data["description"].as_str())
    .bind(data["claimLimit"].as_i64().unwrap_or(0) as i32)
    .bind(data["sortOrder"].as_i64().unwrap_or(0) as i32)
    .bind(data["enabled"].as_bool().unwrap_or(true))
    .bind(&data["config"])
    .fetch_one(db)
    .await?;
    Ok(reward_to_admin_view(&reward))
}

pub async fn delete_vip_benefit_reward(db: &PgPool, id: i32) -> Result<(), BenefitError> {
    let result = sqlx::query("DELETE FROM vip_benefit_rewards WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    if result.rows_affected() == 0 {
        // Prisma P2025 -> REWARD_NOT_FOUND 404.
        return Err(VipBenefitError::with_status(
            "REWARD_NOT_FOUND",
            "VIP benefit reward not found",
            StatusCode::NOT_FOUND,
        )
        .into());
    }
    Ok(())
}

// ===========================================================================
// Overview
// ===========================================================================

struct CurrentUserVip {
    level: i32,
    metric: UserVipMetric,
    total_recharge: Decimal,
    total_consume: Decimal,
    badge_style: Option<Value>,
}

async fn get_current_user_vip(
    db: &PgPool,
    conn: &mut sqlx::PgConnection,
    user_id: i32,
) -> Result<CurrentUserVip, ApiError> {
    // TS reads the metric from the global prisma client even inside the claim
    // transaction; rules/stats use the passed client.
    let metric = get_user_vip_metric(db).await?;
    let rules = get_vip_rules_tx(conn, VipRuleType::User).await?;
    let stats = get_user_vip_stats_tx(conn, user_id).await?;
    let level = calculate_user_vip_level_by_metric(&rules, &stats, metric);
    Ok(CurrentUserVip {
        level,
        metric,
        total_recharge: stats.total_recharge,
        total_consume: stats.total_consume,
        badge_style: get_vip_badge_style_for_level(&rules, VipRuleType::User, level)
            .map(|b| b.to_json()),
    })
}

/// addRewardAmount — mutates the (balance, points, instances) accumulators.
fn add_reward_amount(summary: &mut (f64, i64, i64), reward: &Value, multiplier: i64) {
    if multiplier <= 0 {
        return;
    }
    let amount = to_number(&reward["config"]["amount"]);
    match reward["type"].as_str() {
        Some("balance") => {
            summary.0 = round_money_f64(summary.0 + amount * multiplier as f64)
        }
        Some("points") => summary.1 += amount.floor() as i64 * multiplier,
        Some("instance") => {
            let quantity = to_number(&reward["config"]["quantity"]);
            summary.2 += 1i64.max(quantity.floor() as i64) * multiplier;
        }
        _ => {}
    }
}

pub async fn get_vip_benefit_overview(db: &PgPool, user_id: i32) -> Result<Value, ApiError> {
    let mut conn = db.acquire().await?;
    let vip = get_current_user_vip(db, &mut *conn, user_id).await?;
    let rewards = sqlx::query_as::<_, RewardRow>(&format!(
        "{REWARD_SELECT} WHERE enabled = true ORDER BY level ASC, sort_order ASC, id ASC"
    ))
    .fetch_all(&mut *conn)
    .await?;
    let claims = sqlx::query_as::<_, ClaimRow>(&format!(
        "{CLAIM_SELECT} WHERE user_id = $1 ORDER BY level ASC, reward_id ASC, claim_no ASC"
    ))
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    drop(conn);

    let mut claims_by_reward: HashMap<i32, Vec<&ClaimRow>> = HashMap::new();
    for claim in &claims {
        claims_by_reward
            .entry(claim.reward_id)
            .or_default()
            .push(claim);
    }

    // First pass: claimed counts, remaining claims and the outstanding levels.
    let mut outstanding_levels: Vec<i32> = Vec::new();
    let mut prepared: Vec<(Value, i64, i64, Vec<&ClaimRow>)> = Vec::new();
    for reward in &rewards {
        let reward_claims = claims_by_reward
            .get(&reward.id)
            .cloned()
            .unwrap_or_default();
        let claimed_count = reward_claims.len() as i64;
        let remaining = 0i64.max(reward.claim_limit as i64 - claimed_count);
        if reward.level <= vip.level && remaining > 0 && !outstanding_levels.contains(&reward.level)
        {
            outstanding_levels.push(reward.level);
        }
        prepared.push((reward_to_view_base(reward), reward.claim_limit as i64, remaining, reward_claims));
    }

    // Second pass: states, blockedByLevel, claims.
    let mut reward_views: Vec<Value> = Vec::new();
    let mut entitlement = (0.0f64, 0i64, 0i64);
    let mut remaining_summary = (0.0f64, 0i64, 0i64);
    for (mut view, claim_limit, remaining, reward_claims) in prepared {
        let level = view["level"].as_i64().unwrap_or(0);
        let lower_outstanding = outstanding_levels
            .iter()
            .copied()
            .filter(|l| (*l as i64) < level)
            .min();
        let state = if remaining <= 0 {
            "claimed"
        } else if level > vip.level as i64 {
            "locked"
        } else if lower_outstanding.is_some() {
            "blocked"
        } else {
            "claimable"
        };
        if level <= vip.level as i64 {
            add_reward_amount(&mut entitlement, &view, claim_limit);
            add_reward_amount(&mut remaining_summary, &view, remaining);
        }
        view["claimedCount"] = json!(reward_claims.len());
        view["remainingClaims"] = json!(remaining);
        view["state"] = json!(state);
        view["blockedByLevel"] = match lower_outstanding {
            Some(l) if state == "blocked" => json!(l),
            _ => Value::Null,
        };
        view["claims"] = Value::Array(
            reward_claims
                .iter()
                .map(|claim| claim_to_view(claim))
                .collect(),
        );
        reward_views.push(view);
    }

    let total_rewards = reward_views.len();
    let unlocked_rewards = reward_views
        .iter()
        .filter(|r| r["level"].as_i64().unwrap_or(0) <= vip.level as i64)
        .count();
    let count_state = |state: &str| {
        reward_views
            .iter()
            .filter(|r| r["state"] == json!(state))
            .count()
    };

    Ok(json!({
        "currentLevel": vip.level,
        "userVipMetric": vip.metric.as_str(),
        "userStats": {
            "totalRecharge": num(vip.total_recharge),
            "totalConsume": num(vip.total_consume),
        },
        "userVipBadgeStyle": vip.badge_style.clone().unwrap_or(Value::Null),
        "rewards": reward_views,
        "summary": {
            "totalRewards": total_rewards,
            "unlockedRewards": unlocked_rewards,
            "claimableRewards": count_state("claimable"),
            "claimedRewards": count_state("claimed"),
            "lockedRewards": count_state("locked"),
            "blockedRewards": count_state("blocked"),
            "pendingRewards": claims
                .iter()
                .filter(|c| c.status == "pending")
                .count(),
            "entitlement": {
                "balanceAmount": js_num_json(entitlement.0),
                "pointsAmount": entitlement.1,
                "instanceQuantity": entitlement.2,
            },
            "remaining": {
                "balanceAmount": js_num_json(remaining_summary.0),
                "pointsAmount": remaining_summary.1,
                "instanceQuantity": remaining_summary.2,
            },
        }
    }))
}

fn reward_to_view_base(reward: &RewardRow) -> Value {
    json!({
        "id": reward.id,
        "level": reward.level,
        "type": reward.reward_type,
        "title": reward.title,
        "description": reward.description,
        "claimLimit": reward.claim_limit,
        "sortOrder": reward.sort_order,
        "enabled": reward.enabled,
        "config": normalize_stored_reward_config(&reward.reward_type, &reward.config),
        "createdAt": iso(reward.created_at),
        "updatedAt": iso(reward.updated_at),
    })
}

// ===========================================================================
// Claim flows
// ===========================================================================

fn build_claim_snapshot(reward: &RewardRow, config: &Value) -> Value {
    json!({
        "rewardId": reward.id,
        "level": reward.level,
        "type": reward.reward_type,
        "title": reward.title,
        "description": reward.description,
        "claimLimit": reward.claim_limit,
        "config": config.clone(),
    })
}

pub async fn claim_vip_benefit_reward(
    db: &PgPool,
    user_id: i32,
    reward_id: i64,
) -> Result<(Value, Value), BenefitError> {
    // Service-side re-validation (the route already parses the id).
    if reward_id <= 0 {
        return Err(VipBenefitError::new(
            "INVALID_REWARD_ID",
            "Invalid VIP benefit reward ID",
        )
        .into());
    }

    let mut tx = db.begin().await?;
    let inner = claim_tx_inner(db, &mut *tx, user_id, reward_id).await;
    let created = match inner {
        Ok(claim) => {
            tx.commit().await?;
            claim
        }
        Err(err) => {
            let _ = tx.rollback().await;
            return Err(err);
        }
    };

    let overview = get_vip_benefit_overview(db, user_id).await?;
    Ok((claim_to_view(&created), overview))
}

async fn claim_tx_inner(
    db: &PgPool,
    tx: &mut sqlx::PgConnection,
    user_id: i32,
    reward_id: i64,
) -> Result<ClaimRow, BenefitError> {
    let vip = get_current_user_vip(db, tx, user_id)
        .await
        .map_err(BenefitError::Db)?;

    let reward = sqlx::query_as::<_, RewardRow>(&format!(
        "{REWARD_SELECT} WHERE id = $1 AND enabled = true"
    ))
    .bind(reward_id as i32)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(reward) = reward else {
        return Err(VipBenefitError::with_status(
            "REWARD_NOT_FOUND",
            "VIP benefit reward not found",
            StatusCode::NOT_FOUND,
        )
        .into());
    };
    if reward.level > vip.level {
        return Err(VipBenefitError::with_status(
            "VIP_LEVEL_REQUIRED",
            format!("VIP{} is required to claim this reward", reward.level),
            StatusCode::FORBIDDEN,
        )
        .into());
    }

    // Lower enabled rewards at or below the user's level must be fully claimed
    // first (Prisma `level: { lt: reward.level, lte: vip.level }` is an AND).
    let lower_rewards = sqlx::query_as::<_, RewardRow>(
        "SELECT id, level, type::text AS type, title, description, claim_limit, \
         sort_order, enabled, config, created_at, updated_at \
         FROM vip_benefit_rewards \
         WHERE enabled = true AND level < $1 AND level <= $2 \
         ORDER BY level ASC, sort_order ASC, id ASC",
    )
    .bind(reward.level)
    .bind(vip.level)
    .fetch_all(&mut *tx)
    .await?;

    let mut ids_to_check: Vec<i32> = lower_rewards.iter().map(|r| r.id).collect();
    ids_to_check.push(reward.id);
    let relevant: Vec<(i32,)> = sqlx::query_as(
        "SELECT reward_id FROM vip_benefit_claims \
         WHERE user_id = $1 AND reward_id = ANY($2)",
    )
    .bind(user_id)
    .bind(&ids_to_check)
    .fetch_all(&mut *tx)
    .await?;
    let mut claim_counts: HashMap<i32, i64> = HashMap::new();
    for (rid,) in relevant {
        *claim_counts.entry(rid).or_insert(0) += 1;
    }

    if let Some(blocking) = lower_rewards
        .iter()
        .find(|r| claim_counts.get(&r.id).copied().unwrap_or(0) < r.claim_limit as i64)
    {
        return Err(VipBenefitError::with_status(
            "LOWER_LEVEL_REWARD_REQUIRED",
            format!("Please claim all VIP{} rewards first", blocking.level),
            StatusCode::CONFLICT,
        )
        .into());
    }

    let existing_count = claim_counts.get(&reward.id).copied().unwrap_or(0);
    if existing_count >= reward.claim_limit as i64 {
        return Err(VipBenefitError::with_status(
            "CLAIM_LIMIT_REACHED",
            "This VIP benefit reward has already been fully claimed",
            StatusCode::CONFLICT,
        )
        .into());
    }

    let config = normalize_stored_reward_config(&reward.reward_type, &reward.config);
    let status = if reward.reward_type == "instance" {
        "pending"
    } else {
        "delivered"
    };
    let insert = sqlx::query_as::<_, ClaimRow>(
        "INSERT INTO vip_benefit_claims \
         (user_id, reward_id, level, status, claim_no, snapshot, delivered_at) \
         VALUES ($1, $2, $3, $4::\"VipBenefitClaimStatus\", $5, $6, $7) \
         RETURNING id, reward_id, level, status::text AS status, claim_no, \
         snapshot, delivered_at, created_at",
    )
    .bind(user_id)
    .bind(reward.id)
    .bind(reward.level)
    .bind(status)
    .bind((existing_count + 1) as i32)
    .bind(build_claim_snapshot(&reward, &config))
    .bind(if reward.reward_type == "instance" {
        None
    } else {
        Some(Utc::now())
    })
    .fetch_one(&mut *tx)
    .await;

    let claim = match insert {
        Ok(claim) => claim,
        Err(err) if is_unique_violation(&err) => {
            // Prisma P2002 -> CLAIM_CONFLICT.
            return Err(VipBenefitError::with_status(
                "CLAIM_CONFLICT",
                "This VIP benefit reward was already claimed, please refresh and try again",
                StatusCode::CONFLICT,
            )
            .into());
        }
        Err(err) => return Err(BenefitError::Db(ApiError::from_sql(err))),
    };

    if reward.reward_type == "balance" {
        let amount = normalize_money(config.get("amount").unwrap_or(&Value::Null), "Balance reward amount")?;
        let amount_dec = dec2(amount);
        // Serialize every balance read/log/write for this user (namespace 4110).
        crate::db::advisory_transaction_lock(
            tx,
            advisory_lock_namespace::USER_BALANCE,
            user_id as i64,
        )
        .await
        .map_err(|e| BenefitError::Db(ApiError::from_sql(e)))?;
        let row: Option<(Decimal,)> = sqlx::query_as("SELECT balance FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| BenefitError::Db(ApiError::from_sql(e)))?;
        let Some((balance_before,)) = row else {
            return Err(VipBenefitError::with_status(
                "USER_NOT_FOUND",
                "User not found",
                StatusCode::NOT_FOUND,
            )
            .into());
        };
        let balance_after = round_amount_dec(balance_before + amount_dec);
        // TS increments the balance by the exact amount but logs the rounded
        // before/after pair; keep both behaviors.
        sqlx::query("UPDATE users SET balance = balance + $2 WHERE id = $1")
            .bind(user_id)
            .bind(amount_dec)
            .execute(&mut *tx)
            .await
            .map_err(|e| BenefitError::Db(ApiError::from_sql(e)))?;
        sqlx::query(
            "INSERT INTO balance_logs \
             (user_id, type, amount, balance_before, balance_after, remark) \
             VALUES ($1, 'gift'::\"BalanceLogType\", $2, $3, $4, $5)",
        )
        .bind(user_id)
        .bind(amount_dec)
        .bind(balance_before)
        .bind(balance_after)
        .bind(format!("VIP benefit: {}", reward.title))
        .execute(&mut *tx)
        .await
        .map_err(|e| BenefitError::Db(ApiError::from_sql(e)))?;
    } else if reward.reward_type == "points" {
        let amount = normalize_positive_integer(
            config.get("amount").unwrap_or(&Value::Null),
            "Points reward amount",
            MAX_POINTS_AMOUNT,
        )?;
        // Prisma upsert (no-op update) ensures the row exists.
        sqlx::query("INSERT INTO user_points (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| BenefitError::Db(ApiError::from_sql(e)))?;
        let (points_before,): (i32,) =
            sqlx::query_as("SELECT points FROM user_points WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| BenefitError::Db(ApiError::from_sql(e)))?;
        let (points_after,): (i32,) = sqlx::query_as(
            "UPDATE user_points SET points = points + $2, \
             total_earned = total_earned + $2, updated_at = NOW() \
             WHERE user_id = $1 RETURNING points",
        )
        .bind(user_id)
        .bind(amount as i32)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| BenefitError::Db(ApiError::from_sql(e)))?;
        sqlx::query(
            "INSERT INTO points_logs \
             (user_id, type, amount, points_before, points_after, related_id, remark) \
             VALUES ($1, 'vip_benefit'::\"PointsLogType\", $2, $3, $4, $5, $6)",
        )
        .bind(user_id)
        .bind(amount as i32)
        .bind(points_before)
        .bind(points_after)
        .bind(claim.id)
        .bind(format!("VIP benefit: {}", reward.title))
        .execute(&mut *tx)
        .await
        .map_err(|e| BenefitError::Db(ApiError::from_sql(e)))?;
    }

    Ok(claim)
}

pub async fn claim_all_available_vip_benefit_rewards(
    db: &PgPool,
    user_id: i32,
) -> Result<(Vec<Value>, Value), BenefitError> {
    let mut claims: Vec<Value> = Vec::new();
    let mut overview = get_vip_benefit_overview(db, user_id)
        .await
        .map_err(BenefitError::Db)?;

    for _ in 0..MAX_BULK_CLAIMS {
        let next_reward = overview["rewards"]
            .as_array()
            .and_then(|rewards| {
                rewards
                    .iter()
                    .filter(|r| r["state"] == json!("claimable"))
                    .min_by_key(|r| {
                        (
                            r["level"].as_i64().unwrap_or(0),
                            r["sortOrder"].as_i64().unwrap_or(0),
                            r["id"].as_i64().unwrap_or(0),
                        )
                    })
            })
            .cloned();
        let Some(next_reward) = next_reward else {
            return Ok((claims, overview));
        };

        let (claim, new_overview) =
            claim_vip_benefit_reward(db, user_id, next_reward["id"].as_i64().unwrap_or(0)).await?;
        claims.push(claim);
        overview = new_overview;
    }

    Err(VipBenefitError::with_status(
        "BULK_CLAIM_LIMIT_EXCEEDED",
        "Too many VIP benefit rewards to claim at once",
        StatusCode::CONFLICT,
    )
    .into())
}

// ===========================================================================
// Tests (pure normalization logic; no DB)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_config_normalization() {
        let config = normalize_reward_config("balance", &json!({ "amount": 12.345 })).unwrap();
        assert_eq!(config, json!({ "amount": 12.35 }));

        assert!(normalize_reward_config("balance", &json!({})).is_err());
        assert!(normalize_reward_config("balance", &json!({ "amount": "abc" })).is_err());

        let points = normalize_reward_config("points", &json!({ "amount": 500 })).unwrap();
        assert_eq!(points, json!({ "amount": 500 }));

        // TS: days=0 is NOT the fallback path (only null/undefined/'''' are)
        // and normalizePositiveInteger(0) throws.
        assert!(normalize_reward_config(
            "instance",
            &json!({ "packageId": 3, "planId": 9, "days": 0, "quantity": 99 }),
        )
        .is_err());
        let instance = normalize_reward_config(
            "instance",
            &json!({ "packageId": 3, "planId": 9, "days": null, "quantity": 5 }),
        )
        .unwrap();
        assert_eq!(instance["days"], json!(30));
        assert_eq!(instance["quantity"], json!(5));
    }

    #[test]
    fn stored_config_is_lenient() {
        let config = normalize_stored_reward_config(
            "instance",
            &json!({ "packageId": "x", "days": -5, "quantity": 0 }),
        );
        assert_eq!(config["packageId"], Value::Null);
        assert_eq!(config["days"], json!(1));
        assert_eq!(config["quantity"], json!(1));

        let balance = normalize_stored_reward_config("balance", &json!({ "amount": -1 }));
        assert_eq!(balance["amount"], json!(0));
    }

    #[test]
    fn title_validation_matches_js_length() {
        assert!(normalize_title(&json!(123)).is_err());
        assert!(normalize_title(&json!("  ")).is_err());
        let long = "字".repeat(80);
        assert!(normalize_title(&json!(long)).is_ok());
        let longer = "字".repeat(81);
        assert!(normalize_title(&json!(longer)).is_err());
    }

    #[test]
    fn sort_order_validation() {
        assert_eq!(normalize_sort_order(&Value::Null).unwrap(), 0);
        assert!(normalize_sort_order(&json!(1000001)).is_err());
        assert!(normalize_sort_order(&json!(1.5)).is_err());
    }

    #[test]
    fn coalesce_uses_js_nullish_semantics() {
        let base = json!({ "level": 5 });
        // Absent falls back.
        assert_eq!(coalesce(&json!({}), "level", &base, "level"), &json!(5));
        // JSON null falls back too (?? treats null as nullish).
        assert_eq!(
            coalesce(&json!({ "level": null }), "level", &base, "level"),
            &json!(5)
        );
        // Present values win.
        assert_eq!(
            coalesce(&json!({ "level": 3 }), "level", &base, "level"),
            &json!(3)
        );
    }

    #[test]
    fn claim_snapshot_shape() {
        let reward = RewardRow {
            id: 7,
            level: 4,
            reward_type: "points".to_string(),
            title: "T".to_string(),
            description: None,
            claim_limit: 2,
            sort_order: 0,
            enabled: true,
            config: json!({ "amount": 10 }),
            created_at: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let snapshot = build_claim_snapshot(&reward, &json!({ "amount": 10 }));
        assert_eq!(snapshot["rewardId"], json!(7));
        assert_eq!(snapshot["claimLimit"], json!(2));
        assert_eq!(snapshot["config"]["amount"], json!(10));
    }
}
