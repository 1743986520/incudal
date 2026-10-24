//! Router assembly mirroring app.ts: plugin order, CORS, security headers,
//! rate limiting, the route prefix table, and the /api 404 fallback.
//! Production static/SPA serving is a port TODO (see PORTING.md).

use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;

use crate::rate_limit;
use crate::routes;
use crate::state::SharedAppState;

pub fn build_router(state: SharedAppState) -> Router {
    let cors = build_cors(&state.config);

    Router::new()
        .route("/api/health", get(routes::health::health))
        // ---- Ported modules nest here (keep in sync with routes/mod.rs) ----
        .nest("/api/auth", routes::auth::router())
        .nest("/api/users", routes::users::router())
        .nest("/api/ssh-keys", routes::ssh_keys::router())
        .nest("/api/friends", routes::friends::router())
        .nest("/api/balance", routes::balance::router())
        .nest("/api/announcements", routes::announcements::router())
        .nest("/api/inbox", routes::inbox::router())
        .nest("/api/help", routes::help::router())
        .nest("/api/packages", routes::packages::router())
        .nest("/api/hosts", routes::hosts::router().merge(routes::batch_config::router()))
        .nest("/api/system-config", routes::system_config::router())
        .nest("/api/images", routes::images::router())
        .nest("/api/logs", routes::logs::router())
        .nest("/api/agent", routes::agent::router())
        .nest("/api/system-update", routes::system_update::router())
        // ---- Not-yet-ported modules return 501 NOT_PORTED on their prefix ----
        .nest("/api/instances", routes::instances::router())
        .nest("/api/transfers", routes::not_ported_router())
        .nest("/api/verification", routes::not_ported_router())
        .nest("/api/ws/instances", routes::not_ported_router())
        .nest("/api/terminal-saved-commands", routes::not_ported_router())
        .nest("/api/tickets", routes::not_ported_router())
        .nest("/api/checkin", routes::not_ported_router())
        .nest("/api/resource-pool", routes::not_ported_router())
        .nest("/api/init-commands", routes::not_ported_router())
        .nest("/api/hosting", routes::not_ported_router())
        .nest("/api/aff", routes::not_ported_router())
        .nest("/api/official-coupons", routes::not_ported_router())
        .nest("/api/entertainment", routes::not_ported_router())
        .nest("/api/telegram", routes::not_ported_router())
        .nest("/api/user-invites", routes::not_ported_router())
        .nest("/api/admin", routes::not_ported_router())
        .nest("/api/recharge", routes::not_ported_router())
        .nest("/api/vip-levels", routes::not_ported_router())
        .nest("/api/vip-benefits", routes::not_ported_router())
        // No-prefix modules (traffic, ip-addresses, proxy-sites, redeem-codes,
        // hourly-billing, site-meta) register scattered /api/* paths; they fall
        // through to the /api fallback until ported.
        .fallback(api_fallback)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit::rate_limit_middleware,
        ))
        .layer(middleware::from_fn(security_headers_mw))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(state.config.body_limit))
        .with_state(state)
}

async fn api_fallback(uri: axum::http::Uri) -> Response {
    if uri.path().starts_with("/api/") {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "API 路由不存在" })),
        )
            .into_response()
    } else {
        // Non-API paths are served by the frontend static build (TODO in the
        // Rust port); report plainly until static serving lands.
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "文件不存在" })),
        )
            .into_response()
    }
}

fn build_cors(config: &crate::config::Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = if !config.frontend_urls.is_empty() {
        config
            .frontend_urls
            .iter()
            .filter_map(|u| u.parse().ok())
            .collect()
    } else if !config.is_production {
        ["http://localhost:43173", "http://127.0.0.1:43173"]
            .iter()
            .filter_map(|u| u.parse().ok())
            .collect()
    } else {
        // Production without FRONTEND_URL: CORS disabled (origin: false).
        Vec::new()
    };

    let mut cors = CorsLayer::new()
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
        .allow_credentials(!origins.is_empty());
    if origins.is_empty() {
        // No allowed origins: deny everything via an impossible origin.
        cors = cors.allow_origin("http://localhost:0".parse::<HeaderValue>().unwrap());
    } else {
        cors = cors.allow_origin(origins);
    }
    cors
}

async fn security_headers_mw(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    if let Some(csp) = csp_value() {
        if let Ok(value) = HeaderValue::from_str(csp) {
            headers.insert(HeaderName::from_static("content-security-policy"), value);
        }
    }
    if hsts_enabled() {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    res
}

fn hsts_enabled() -> bool {
    static HSTS: OnceLock<bool> = OnceLock::new();
    *HSTS.get_or_init(|| std::env::var("ENABLE_HSTS").is_ok_and(|v| v == "true"))
}

/// Production CSP mirrors the @fastify/helmet config in app.ts; dev has no CSP.
fn csp_value() -> Option<&'static str> {
    if !crate::config::runtime_is_production() {
        return None;
    }
    Some(
        "default-src 'self'; \
         script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://www.googletagmanager.com; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data: blob: https://api.dicebear.com https://github.com; \
         connect-src 'self' wss: https://challenges.cloudflare.com; \
         frame-src https://challenges.cloudflare.com; \
         frame-ancestors 'none'; \
         object-src 'none'; \
         base-uri 'self'",
    )
}
