//! VIP 等级规则路由 — port of server/src/routes/vip-levels.ts.
//!
//! The TS module registers FULL paths (no mount prefix): /api/vip-levels/me
//! and /api/admin/vip-levels/:type. This router therefore uses absolute paths
//! and is merged straight into the app router in app.rs (the /api/admin
//! not-ported nest keeps serving 501 for the other admin paths).
//!
//! Endpoint map (TS decorator -> Rust extractor):
//! - GET /api/vip-levels/me              authenticate            -> AuthUser
//! - GET /api/admin/vip-levels/{type}    authenticate+requireAdmin -> AdminAuth
//! - PUT /api/admin/vip-levels/{type}    authenticate+requireAdmin -> AdminAuth
//!
//! Inline rate limits from the TS config.rateLimit (NOT in rate_limit.rs):
//! - GET  me   60/min
//! - GET  admin 30/min
//! - PUT  admin 20/min
//!
//! Validation failures reply bare `400 { error }` (no code), exactly like the
//! TS sendInvalidType / catch handler.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::auth::{AdminAuth, AuthUser};
use crate::error::ApiError;
use crate::libs::vip::{
    self, UserVipMetric, VipRuleType, MAX_VIP_LEVEL,
};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/api/vip-levels/me", get(me_overview))
        .route(
            "/api/admin/vip-levels/{type}",
            get(admin_get_rules).put(admin_replace_rules),
        )
}

fn bare_bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": message })),
    )
        .into_response()
}

/// routes/vip-levels.ts parseRuleType.
fn parse_rule_type(value: &str) -> Option<VipRuleType> {
    VipRuleType::parse(value)
}

/// routes/vip-levels.ts parseUserVipMetric.
fn parse_user_vip_metric(value: Option<&str>) -> Option<UserVipMetric> {
    match value {
        Some("totalRecharge") => Some(UserVipMetric::TotalRecharge),
        Some("totalConsume") => Some(UserVipMetric::TotalConsume),
        _ => None,
    }
}

// ===========================================================================
// GET /api/vip-levels/me — 当前用户 VIP 总览
// ===========================================================================

async fn me_overview(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(vip::get_vip_overview(&state.db, user.id).await?))
}

// ===========================================================================
// GET /api/admin/vip-levels/{type} — 管理员查询规则
// ===========================================================================

async fn admin_get_rules(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(rule_type): Path<String>,
) -> Result<Response, ApiError> {
    let Some(rule_type) = parse_rule_type(&rule_type) else {
        return Ok(bare_bad_request("Invalid VIP rule type"));
    };

    let rules = vip::get_vip_rules(&state.db, rule_type).await?;
    let mut body = json!({
        "type": rule_type.as_str(),
        "maxLevel": MAX_VIP_LEVEL,
        "rules": rules.iter().map(|rule| rule.to_json()).collect::<Vec<_>>(),
    });
    // TS spreads `userMetric: type === 'user' ? await getUserVipMetric() : undefined`
    // — undefined is omitted from the JSON for hosting rules.
    if rule_type == VipRuleType::User {
        let metric = vip::get_user_vip_metric(&state.db).await?;
        body["userMetric"] = json!(metric.as_str());
    }
    Ok(Json(body).into_response())
}

// ===========================================================================
// PUT /api/admin/vip-levels/{type} — 管理员保存规则
// ===========================================================================

async fn admin_replace_rules(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(rule_type): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let Some(rule_type) = parse_rule_type(&rule_type) else {
        return Ok(bare_bad_request("Invalid VIP rule type"));
    };

    let rules: Vec<Value> = body
        .get("rules")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut user_metric = None;
    if rule_type == VipRuleType::User {
        let Some(metric) = parse_user_vip_metric(
            body.get("userMetric").and_then(|v| v.as_str()),
        ) else {
            return Ok(bare_bad_request("Invalid user VIP metric"));
        };
        user_metric = Some(metric);
    }

    let saved = match vip::replace_vip_rules(&state.db, rule_type, &rules, user_metric).await {
        Ok(saved) => saved,
        Err(vip::ReplaceVipRulesError::Validation(message)) => {
            // TS: request.log.warn + 400 { error: message || fallback }.
            tracing::warn!("VIP level rule validation failed: {message}");
            let message = if message.is_empty() {
                "Invalid VIP level rules".to_string()
            } else {
                message
            };
            return Ok(bare_bad_request(&message));
        }
        Err(vip::ReplaceVipRulesError::Db(err)) => {
            // The TS try/catch maps ANY replaceVipRules failure (DB included)
            // to 400 { error: error.message }; the Prisma message text is not
            // portable, so use the same fallback string.
            tracing::warn!("VIP level rule write failed: {err:?}");
            return Ok(bare_bad_request("Invalid VIP level rules"));
        }
    };

    let mut body = json!({
        "type": rule_type.as_str(),
        "maxLevel": MAX_VIP_LEVEL,
        "rules": saved.iter().map(|rule| rule.to_json()).collect::<Vec<_>>(),
    });
    // `userMetric` is undefined (omitted) for hosting rules.
    if let Some(metric) = user_metric {
        body["userMetric"] = json!(metric.as_str());
    }
    Ok(Json(body).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors app.rs assembly: the merged absolute routes must coexist with
    /// the /api/admin not-ported nest (exact routes win over the nest
    /// fallback; the rest still falls through to 501).
    #[test]
    fn router_builds_without_conflicts_with_admin_nest() {
        let _ = Router::new()
            .nest("/api/admin", crate::routes::not_ported_router())
            .merge(router());
    }
}
