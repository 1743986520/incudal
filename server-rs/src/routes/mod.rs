//! Route module registry. Each TS route file maps 1:1 to a Rust module under
//! src/routes/. Ported modules export `pub fn router() -> Router<SharedAppState>`
//! with paths RELATIVE to their mount prefix (see app.rs for the prefix table).

pub mod agent;
pub mod aff;
pub mod announcements;
pub mod auth;
pub mod balance;
pub mod checkin;
pub mod custom_init_commands;
pub mod batch_config;
pub mod friends;
pub mod health;
pub mod hosts;
pub mod help;
pub mod images;
pub mod ip_addresses;
pub mod inbox;
pub mod logs;
pub mod notifications;
pub mod official_coupons;
pub mod oauth;
pub mod instances;
pub mod packages;
pub mod proxy_sites;
pub mod resource_pool;
pub mod site_meta;
pub mod snapshots;
pub mod ssh_keys;
pub mod system_config;
pub mod terminal_saved_commands;
pub mod traffic;
pub mod system_update;
pub mod user_invites;
pub mod users;
pub mod verification;
pub mod vip_benefits;
pub mod vip_levels;

use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::state::SharedAppState;

/// Router returned for modules that are declared but not yet ported.
pub fn not_ported_router() -> Router<SharedAppState> {
    Router::new().fallback(not_ported)
}

async fn not_ported() -> Response {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "This module is not yet ported to the Rust server",
            "code": "NOT_PORTED",
        })),
    )
        .into_response()
}

/// 404 for unknown /api/* paths (mirrors the TS static-server notFoundHandler).
pub async fn api_not_found() -> Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(json!({ "error": "API 路由不存在" })),
    )
        .into_response()
}

pub fn health_router() -> Router<SharedAppState> {
    Router::new().route("/health", get(health::health))
}
