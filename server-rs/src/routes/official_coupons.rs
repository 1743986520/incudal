//! 官方优惠券路由（用户端）— port of server/src/routes/official-coupons.ts.
//! Mounted at /api/official-coupons. Single endpoint: validate (预览折扣，
//! 实际下单在购买事务内重新校验).

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::{code, ApiError};
use crate::libs::official_coupons::{
    calculate_discount_amount_for_months, get_discounted_months_for_purchase,
    validate_official_coupon_on_pool,
};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new().route("/validate", post(validate))
}

#[derive(Deserialize)]
struct ValidateBody {
    code: Option<String>,
    #[serde(rename = "packageId")]
    package_id: Option<serde_json::Value>,
    #[serde(rename = "planId")]
    plan_id: Option<serde_json::Value>,
}

async fn validate(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<ValidateBody>>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let code = body
        .code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::bad_request(code::COUPON_NOT_FOUND))?;
    let package_id = body
        .package_id
        .as_ref()
        .and_then(Value::as_i64)
        .filter(|id| *id >= 1)
        .ok_or_else(|| {
            ApiError::bad_request(code::INVALID_PARAMS).with_details("packageId is required")
        })? as i32;
    let plan_id = body.plan_id.as_ref().and_then(Value::as_i64).filter(|id| *id >= 1);

    let validation = validate_official_coupon_on_pool(&state, code, package_id, user.id).await?;
    if !validation.valid {
        return Err(ApiError::with_message(
            validation.error_code.unwrap_or(code::COUPON_NOT_FOUND),
            StatusCode::BAD_REQUEST,
            validation.error.unwrap_or("Official coupon not found"),
        ));
    }

    // 折扣金额按方案原价计算（前端价格明细预览）
    let mut plan_price: Option<f64> = None;
    let mut discount_amount: Option<f64> = None;
    let mut final_price: Option<f64> = None;
    let mut discounted_months: Option<i64> = None;

    if let Some(plan_id) = plan_id {
        // getPlanById + package/billing-mode guards
        let plan: Option<(i32, i64, bool, String, i32)> = sqlx::query_as(
            "SELECT package_id, price, is_active, billing_mode::text, billing_cycle \
             FROM package_plans WHERE id = $1",
        )
        .bind(plan_id as i32)
        .fetch_optional(&state.db)
        .await?;
        if let Some((plan_package_id, price_cents, is_active, billing_mode, billing_cycle)) = plan {
            if plan_package_id == package_id && is_active && billing_mode != "hourly" {
                let coupon = validation
                    .coupon
                    .as_ref()
                    .expect("valid validation carries the coupon row");
                plan_price = Some(price_cents.to_f64().unwrap_or(0.0) / 100.0);
                let months = get_discounted_months_for_purchase(
                    &coupon.renewal_mode,
                    coupon.discounted_charge_limit,
                    billing_cycle as i64,
                );
                discount_amount = Some(calculate_discount_amount_for_months(
                    plan_price.unwrap(),
                    billing_cycle as i64,
                    months,
                    validation.discount_rate.unwrap_or(0.0),
                ));
                final_price = Some(
                    crate::libs::official_coupons::round2_f64(
                        plan_price.unwrap() - discount_amount.unwrap(),
                    ),
                );
                discounted_months = Some(months);
            }
        }
    }

    Ok(Json(json!({
        "valid": true,
        "code": validation.code,
        "name": validation.name,
        "remark": validation.remark,
        "discountRate": validation.discount_rate,
        "remainingUses": validation.remaining_uses,
        "planPrice": plan_price,
        "discountAmount": discount_amount,
        "finalPrice": final_price,
        "discountedMonths": discounted_months,
    })))
}
