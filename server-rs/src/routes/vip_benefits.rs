//! VIP 福利路由 — port of server/src/routes/vip-benefits.ts.
//!
//! Like vip-levels.ts the TS module registers FULL paths: /api/vip-benefits/*
//! (user) and /api/admin/vip-benefits/* (admin); this router uses absolute
//! paths merged into the app router in app.rs.
//!
//! Endpoint map (TS decorator -> Rust extractor):
//! - GET    /api/vip-benefits/me                    authenticate -> AuthUser
//! - POST   /api/vip-benefits/{rewardId}/claim      authenticate -> AuthUser
//! - POST   /api/vip-benefits/claim-all             authenticate -> AuthUser
//! - GET    /api/admin/vip-benefits/rewards         authenticate+requireAdmin -> AdminAuth
//! - POST   /api/admin/vip-benefits/rewards         authenticate+requireAdmin -> AdminAuth
//! - PUT    /api/admin/vip-benefits/rewards/{id}    authenticate+requireAdmin -> AdminAuth
//! - DELETE /api/admin/vip-benefits/rewards/{id}    authenticate+requireAdmin -> AdminAuth
//!
//! Inline rate limits from the TS config.rateLimit (NOT in rate_limit.rs):
//! - GET me 60/min; claim 100/3min; claim-all 30/3min;
//! - admin list 30/min; create/update 20/min; delete 10/min.
//!
//! VipBenefitError replies `{ error, code }` with its own status via
//! sendVipBenefitError; invalid :rewardId/:id params reply
//! `400 { error: 'Invalid VIP benefit reward ID', code: 'INVALID_REWARD_ID' }`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::auth::{AdminAuth, AuthUser};
use crate::error::{code, ApiError};
use crate::libs::vip_benefits::{self, BenefitError};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/api/vip-benefits/me", get(me_overview))
        .route("/api/vip-benefits/{reward_id}/claim", post(claim))
        .route("/api/vip-benefits/claim-all", post(claim_all))
        .route(
            "/api/admin/vip-benefits/rewards",
            get(admin_list).post(admin_create),
        )
        .route(
            "/api/admin/vip-benefits/rewards/{id}",
            axum::routing::put(admin_update).delete(admin_delete),
        )
}

/// routes/vip-benefits.ts parseId: Number(param) integer > 0.
/// Non-integer/NaN -> 400 INVALID_REWARD_ID; integral values beyond i32 fail
/// Prisma's Int validation -> 500 (mirrors the other ports).
fn parse_id(raw: &str) -> Result<i32, ApiError> {
    let trimmed = raw.trim();
    let v: f64 = if trimmed.is_empty() {
        0.0
    } else {
        trimmed
            .parse::<f64>()
            .map_err(|_| invalid_reward_id_response())?
    };
    if v.is_nan() || v.fract() != 0.0 || v <= 0.0 {
        return Err(invalid_reward_id_response());
    }
    if !v.is_finite() || !(i32::MIN as f64..=i32::MAX as f64).contains(&v) {
        return Err(ApiError::internal("Prisma Int argument out of range"));
    }
    Ok(v as i32)
}

fn invalid_reward_id_response() -> ApiError {
    ApiError::with_message(
        "INVALID_REWARD_ID",
        StatusCode::BAD_REQUEST,
        "Invalid VIP benefit reward ID",
    )
}

/// sendVipBenefitError: VipBenefitError -> its own status `{ error, code }`;
/// anything else propagates (500 through the app error handler).
fn into_benefit_result(result: Result<Response, BenefitError>) -> Result<Response, ApiError> {
    match result {
        Ok(response) => Ok(response),
        Err(BenefitError::Benefit(err)) => Err(err.into()),
        Err(BenefitError::Db(err)) => Err(err),
    }
}

// ===========================================================================
// GET /api/vip-benefits/me — 当前用户 VIP 福利总览
// ===========================================================================

async fn me_overview(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        vip_benefits::get_vip_benefit_overview(&state.db, user.id).await?,
    ))
}

// ===========================================================================
// POST /api/vip-benefits/{rewardId}/claim — 领取单个福利
// ===========================================================================

async fn claim(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(reward_id): Path<String>,
) -> Result<Response, ApiError> {
    let reward_id = parse_id(&reward_id)?;

    into_benefit_result(async {
        let (claim, overview) =
            vip_benefits::claim_vip_benefit_reward(&state.db, user.id, reward_id as i64).await?;
        Ok(Json(json!({ "claim": claim, "overview": overview })).into_response())
    }
    .await)
}

// ===========================================================================
// POST /api/vip-benefits/claim-all — 领取全部可领福利
// ===========================================================================

async fn claim_all(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Response, ApiError> {
    into_benefit_result(async {
        let (claims, overview) =
            vip_benefits::claim_all_available_vip_benefit_rewards(&state.db, user.id).await?;
        Ok(Json(json!({ "claims": claims, "overview": overview })).into_response())
    }
    .await)
}

// ===========================================================================
// GET /api/admin/vip-benefits/rewards — 管理员奖励列表
// ===========================================================================

async fn admin_list(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    let rewards = vip_benefits::list_admin_vip_benefit_rewards(&state.db).await?;
    Ok(Json(json!({ "rewards": rewards })))
}

// ===========================================================================
// POST /api/admin/vip-benefits/rewards — 创建奖励
// ===========================================================================

async fn admin_create(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    // TS: `request.body || {}` — the schema-less body defaults to {}.
    into_benefit_result(async {
        let reward = vip_benefits::create_vip_benefit_reward(&state.db, &body).await?;
        Ok(Json(json!({ "reward": reward })).into_response())
    }
    .await)
}

// ===========================================================================
// PUT /api/admin/vip-benefits/rewards/{id} — 更新奖励
// ===========================================================================

async fn admin_update(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let id = parse_id(&id)?;

    into_benefit_result(async {
        let reward = vip_benefits::update_vip_benefit_reward(&state.db, id, &body).await?;
        Ok(Json(json!({ "reward": reward })).into_response())
    }
    .await)
}

// ===========================================================================
// DELETE /api/admin/vip-benefits/rewards/{id} — 删除奖励
// ===========================================================================

async fn admin_delete(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id(&id)?;

    into_benefit_result(async {
        vip_benefits::delete_vip_benefit_reward(&state.db, id).await?;
        Ok(Json(json!({ "success": true })).into_response())
    }
    .await)
}

// Silence the unused-import lint for code:: when only used in doc comments.
#[allow(unused)]
fn _unused_code_ref() -> &'static str {
    code::NOT_PORTED
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors app.rs assembly (admin nest + merged absolute routes).
    #[test]
    fn router_builds_without_conflicts_with_admin_nest() {
        let _ = Router::new()
            .nest("/api/admin", crate::routes::not_ported_router())
            .merge(router());
    }

    #[test]
    fn parse_id_matches_ts_number_semantics() {
        assert_eq!(parse_id("42").unwrap(), 42);
        assert!(parse_id("abc").unwrap_err().code == "INVALID_REWARD_ID");
        assert!(parse_id("0").is_err());
        assert!(parse_id("-1").is_err());
        assert!(parse_id("1.5").is_err());
    }
}
