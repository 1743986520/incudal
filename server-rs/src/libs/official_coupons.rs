//! 官方优惠券规则与校验 — port of lib/official-coupon-rules.ts and
//! db/official-coupons.ts validateOfficialCoupon/getPackageCouponScope.
//! Shared by the user-facing validate endpoint and (later) the purchase
//! transaction in Wave F.

use chrono::{DateTime, Utc};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde_json::Value;


use crate::error::{code, ApiError};
use crate::state::SharedAppState;

pub fn normalize_official_coupon_code(code: &str) -> String {
    code.trim().to_uppercase()
}

/// package owner role admin → 'official', else 'hosted'.
pub async fn get_package_coupon_scope(
    pool: &sqlx::PgPool,
    package_id: i32,
) -> Result<Option<&'static str>, ApiError> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT u.role::text FROM packages p JOIN users u ON u.id = p.user_id WHERE p.id = $1",
    )
    .bind(package_id)
    .fetch_optional(pool)
    .await?;
    Ok(role.map(|r| if r == "admin" { "official" } else { "hosted" }))
}

pub fn is_coupon_scope_matched(scope: &str, package_scope: &str) -> bool {
    match scope {
        "all" => true,
        "official_only" => package_scope == "official",
        _ => package_scope == "hosted",
    }
}

/// resolveUserUsageLimit: non-reusable → 1; reusable → maxUsesPerUser (None = unlimited).
fn resolve_user_usage_limit(reusable: bool, max_uses_per_user: Option<i32>) -> Option<i32> {
    if !reusable {
        Some(1)
    } else {
        max_uses_per_user
    }
}

pub fn get_remaining_discounted_months(
    renewal_mode: &str,
    discounted_charge_limit: Option<i32>,
    discounted_months_used: i64,
) -> Option<i64> {
    match renewal_mode {
        "recurring" => None,
        "limited" => {
            let limit = discounted_charge_limit?;
            if limit < 1 {
                Some(0)
            } else {
                Some((limit as i64 - discounted_months_used.max(0)).max(0))
            }
        }
        _ => Some(0),
    }
}

pub fn get_discounted_months_for_purchase(
    renewal_mode: &str,
    discounted_charge_limit: Option<i32>,
    purchase_months: i64,
) -> i64 {
    if purchase_months < 1 {
        return 0;
    }
    if renewal_mode == "purchase_only" {
        return purchase_months;
    }
    match get_remaining_discounted_months(renewal_mode, discounted_charge_limit, 0) {
        None => purchase_months,
        Some(remaining) => purchase_months.min(remaining),
    }
}

pub fn calculate_discount_amount_for_months(
    original_amount: f64,
    requested_months: i64,
    discounted_months: i64,
    discount_rate: f64,
) -> f64 {
    if !original_amount.is_finite() || original_amount <= 0.0 {
        return 0.0;
    }
    if requested_months < 1 || !discount_rate.is_finite() || discount_rate <= 0.0 {
        return 0.0;
    }
    let effective_months = requested_months.min(discounted_months).max(0);
    if effective_months == 0 {
        return 0.0;
    }
    let discounted_base =
        round2(original_amount * effective_months as f64 / requested_months as f64);
    round2(discounted_base * discount_rate)
}

fn round2(value: f64) -> f64 {
    (Decimal::try_from(value).unwrap_or_default().round_dp(2))
        .to_f64()
        .unwrap_or(value)
}

pub fn round2_f64(value: f64) -> f64 {
    round2(value)
}

// ==================== validateOfficialCoupon ====================

#[derive(Debug, sqlx::FromRow)]
pub struct OfficialCouponRow {
    pub id: i32,
    pub code: String,
    pub name: String,
    pub remark: Option<String>,
    pub discount_rate: Decimal,
    pub scope: String,
    pub reusable: bool,
    pub max_uses_per_user: Option<i32>,
    pub total_usage_limit: Option<i32>,
    pub used_count: i32,
    pub enabled: bool,
    pub starts_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub renewal_mode: String,
    pub discounted_charge_limit: Option<i32>,
}

pub const COUPON_COLUMNS: &str =
    "id, code, name, remark, discount_rate, scope::text AS scope, reusable, \
     max_uses_per_user, total_usage_limit, used_count, enabled, starts_at, expires_at, \
     renewal_mode::text AS renewal_mode, discounted_charge_limit";

pub struct OfficialCouponValidation {
    pub valid: bool,
    pub error: Option<&'static str>,
    pub error_code: Option<&'static str>,
    pub coupon: Option<OfficialCouponRow>,
    pub code: Option<String>,
    pub name: Option<String>,
    pub remark: Option<String>,
    pub discount_rate: Option<f64>,
    pub remaining_uses: Option<i64>,
}

impl OfficialCouponValidation {
    fn invalid(error: &'static str, error_code: &'static str) -> Self {
        Self {
            valid: false,
            error: Some(error),
            error_code: Some(error_code),
            coupon: None,
            code: None,
            name: None,
            remark: None,
            discount_rate: None,
            remaining_uses: None,
        }
    }
}

pub async fn validate_official_coupon_on_pool(
    state: &SharedAppState,
    code: &str,
    package_id: i32,
    user_id: i32,
) -> Result<OfficialCouponValidation, ApiError> {
    let code = normalize_official_coupon_code(code);
    if code.is_empty() {
        return Ok(OfficialCouponValidation::invalid(
            "Official coupon not found",
            code::COUPON_NOT_FOUND,
        ));
    }

    let coupon: Option<OfficialCouponRow> = sqlx::query_as(&format!(
        "SELECT {COUPON_COLUMNS} FROM official_coupons WHERE code = $1"
    ))
    .bind(&code)
    .fetch_optional(&state.db)
    .await?;
    let Some(coupon) = coupon else {
        return Ok(OfficialCouponValidation::invalid(
            "Official coupon not found",
            code::COUPON_NOT_FOUND,
        ));
    };
    if !coupon.enabled {
        return Ok(OfficialCouponValidation::invalid(
            "This official coupon has been disabled",
            code::COUPON_DISABLED,
        ));
    }

    let now = Utc::now();
    if coupon.starts_at.map(|s| s > now).unwrap_or(false) {
        return Ok(OfficialCouponValidation::invalid(
            "This official coupon is not active yet",
            code::COUPON_NOT_STARTED,
        ));
    }
    if coupon.expires_at.map(|e| e <= now).unwrap_or(false) {
        return Ok(OfficialCouponValidation::invalid(
            "This official coupon has expired",
            code::COUPON_EXPIRED,
        ));
    }

    let Some(package_scope) = get_package_coupon_scope(&state.db, package_id).await? else {
        return Ok(OfficialCouponValidation::invalid("Package not found", code::NOT_FOUND));
    };
    if !is_coupon_scope_matched(&coupon.scope, package_scope) {
        return Ok(OfficialCouponValidation::invalid(
            "This official coupon does not apply to the selected package",
            code::COUPON_SCOPE_MISMATCH,
        ));
    }

    if let Some(limit) = coupon.total_usage_limit {
        if coupon.used_count >= limit {
            return Ok(OfficialCouponValidation::invalid(
                "This official coupon has reached its total usage limit",
                code::COUPON_EXHAUSTED,
            ));
        }
    }

    let user_usage_limit = resolve_user_usage_limit(coupon.reusable, coupon.max_uses_per_user);
    if let Some(limit) = user_usage_limit {
        let (used,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM official_coupon_usages WHERE coupon_id = $1 AND user_id = $2",
        )
        .bind(coupon.id)
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
        if used >= limit as i64 {
            return Ok(OfficialCouponValidation::invalid(
                "You have reached the usage limit for this official coupon",
                code::COUPON_USER_LIMIT_REACHED,
            ));
        }
    }

    let remaining_uses = coupon
        .total_usage_limit
        .map(|limit| (limit as i64 - coupon.used_count as i64).max(0));
    let discount_rate = coupon.discount_rate.to_f64().unwrap_or(0.0);
    Ok(OfficialCouponValidation {
        valid: true,
        error: None,
        error_code: None,
        code: Some(coupon.code.clone()),
        name: Some(coupon.name.clone()),
        remark: coupon.remark.clone(),
        discount_rate: Some(discount_rate),
        remaining_uses,
        coupon: Some(coupon),
    })
}

#[allow(unused)]
fn _unused_json(_: Value) {}
