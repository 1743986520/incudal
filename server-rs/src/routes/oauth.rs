//! OAuth 认证路由 — port of server/src/routes/oauth.ts (+ lib/redirect-validator.ts,
//! lib/security.ts OAuth state/login-code, lib/action-ticket.ts oauth-bind ticket,
//! db/oauth.ts).
//!
//! GitHub + Google. State and login codes are HMAC-SHA256(base64url) signed
//! payloads (`payload.signature`) with shared-store nonce consumption
//! (oauth-state-nonce: 10 min / oauth-login-nonce: 60 s); the state nonce is
//! mirrored in the `oauthState` cookie (path /api/oauth, lax) to defeat Login
//! CSRF. Login completes via a one-time login code exchanged at
//! /exchange-code for a fresh refresh cookie + 30-minute access JWT.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::auth::{AuthUser, AdminAuth};
use crate::error::{code, ApiError};
use crate::state::SharedAppState;

const OAUTH_STATE_TTL_MS: u64 = 10 * 60 * 1000;
const OAUTH_LOGIN_CODE_TTL_MS: u64 = 60 * 1000;
const OAUTH_STATE_COOKIE: &str = "oauthState";
const REFRESH_COOKIE: &str = "refreshToken";

struct ProviderConfig {
    auth_url: &'static str,
    token_url: &'static str,
    user_url: &'static str,
    scope: &'static str,
}

fn provider_config(provider: &str) -> Option<&'static ProviderConfig> {
    match provider {
        "github" => Some(&ProviderConfig {
            auth_url: "https://github.com/login/oauth/authorize",
            token_url: "https://github.com/login/oauth/access_token",
            user_url: "https://api.github.com/user",
            scope: "read:user user:email",
        }),
        "google" => Some(&ProviderConfig {
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            user_url: "https://www.googleapis.com/oauth2/v2/userinfo",
            scope: "openid email profile",
        }),
        _ => None,
    }
}

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/configs", get(admin_configs))
        .route("/configs/{provider}", axum::routing::put(admin_update_config).delete(admin_delete_config))
        .route("/providers", get(providers))
        .route("/bind-ticket", post(bind_ticket))
        .route("/authorize/{provider}", get(authorize))
        .route("/callback/{provider}", get(callback))
        .route("/bindings", get(my_bindings))
        .route("/bindings/{provider}", axum::routing::delete(unbind))
        .route("/exchange-code", post(exchange_code))
}

// ==================== signed payload helpers ====================

fn state_secret(state: &SharedAppState) -> Vec<u8> {
    state.config.jwt_secret.clone().into_bytes()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input).ok()
}

fn sign_payload(secret: &[u8], payload_b64: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(payload_b64.as_bytes());
    b64url_encode(&mac.finalize().into_bytes())
}

fn random_hex_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn random_token32() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// lib/redirect-validator.ts: same-origin relative URLs only.
fn is_valid_redirect_url(url: Option<&str>) -> bool {
    let Some(url) = url else { return false };
    let trimmed = url.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') || trimmed.starts_with("//") {
        return false;
    }
    let lower = trimmed.to_lowercase();
    !(lower.contains("javascript:") || lower.contains("data:") || lower.contains("vbscript:"))
}

fn safe_redirect_url(url: Option<&str>, default: &str) -> String {
    if is_valid_redirect_url(url) {
        url.unwrap().trim().to_string()
    } else {
        default.to_string()
    }
}

// ==================== db helpers ====================

#[derive(Debug, sqlx::FromRow)]
struct OAuthConfigRow {
    provider: String,
    client_id: String,
    client_secret: String,
    enabled: bool,
    updated_at: DateTime<Utc>,
}

async fn get_oauth_config(
    state: &SharedAppState,
    provider: &str,
) -> Result<Option<OAuthConfigRow>, ApiError> {
    Ok(sqlx::query_as::<_, OAuthConfigRow>(
        "SELECT provider::text AS provider, client_id, client_secret, enabled, updated_at \
         FROM oauth_configs WHERE provider = $1::\"OAuthProvider\"",
    )
    .bind(provider)
    .fetch_optional(&state.db)
    .await?)
}

// ==================== cookie helpers ====================

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.split_once('='))
        .find(|(k, _)| k.trim() == name)
        .map(|(_, v)| v.trim().to_string())
}

fn build_set_cookie(name: &str, value: &str, max_age: i64, path: &str, state: &SharedAppState) -> String {
    let mut cookie = format!(
        "{name}={value}; Path={path}; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    );
    if state.config.cookie_secure() {
        cookie.push_str("; Secure");
    }
    cookie
}

fn redirect_to(url: String) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, url.as_str())],
    )
        .into_response()
}

// ==================== admin config endpoints ====================

async fn admin_configs(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query_as::<_, OAuthConfigRow>(
        "SELECT provider::text AS provider, client_id, client_secret, enabled, updated_at \
         FROM oauth_configs",
    )
    .fetch_all(&state.db)
    .await?;
    let configs: Vec<Value> = rows
        .iter()
        .map(|c| {
            let masked = if c.client_secret.len() >= 4 {
                format!("****{}", &c.client_secret[c.client_secret.len() - 4..])
            } else if !c.client_secret.is_empty() {
                "****".to_string()
            } else {
                String::new()
            };
            json!({
                "provider": c.provider,
                "clientId": c.client_id,
                "clientSecretMasked": if c.client_secret.is_empty() { Value::Null } else { json!(masked) },
                "enabled": c.enabled,
                "updatedAt": crate::libs::instance_common::iso(c.updated_at),
            })
        })
        .collect();
    Ok(Json(json!({ "configs": configs })))
}

#[derive(Deserialize)]
struct UpdateConfigBody {
    #[serde(rename = "clientId")]
    client_id: Option<String>,
    #[serde(rename = "clientSecret")]
    client_secret: Option<String>,
    enabled: Option<bool>,
}

async fn admin_update_config(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(provider): Path<String>,
    body: Option<Json<UpdateConfigBody>>,
) -> Result<Json<Value>, ApiError> {
    if provider_config(&provider).is_none() {
        return Err(ApiError::validation("provider must be equal to one of the allowed values"));
    }
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let client_id = body
        .client_id
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::validation("clientId must NOT have fewer than 1 characters"))?;
    let client_secret = body
        .client_secret
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::validation("clientSecret must NOT have fewer than 1 characters"))?;
    let enabled = body.enabled.unwrap_or(false);

    sqlx::query(
        "INSERT INTO oauth_configs (provider, client_id, client_secret, enabled) \
         VALUES ($1::\"OAuthProvider\", $2, $3, $4) \
         ON CONFLICT (provider) DO UPDATE SET client_id = EXCLUDED.client_id, \
         client_secret = EXCLUDED.client_secret, enabled = EXCLUDED.enabled, updated_at = now()",
    )
    .bind(&provider)
    .bind(&client_id)
    .bind(&client_secret)
    .bind(enabled)
    .execute(&state.db)
    .await?;

    Ok(Json(json!({ "message": format!("{provider} OAuth 配置已更新") })))
}

async fn admin_delete_config(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(provider): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if provider_config(&provider).is_none() {
        return Err(ApiError::validation("provider must be equal to one of the allowed values"));
    }
    sqlx::query("DELETE FROM oauth_configs WHERE provider = $1::\"OAuthProvider\"")
        .bind(&provider)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "message": format!("{provider} OAuth 配置已删除") })))
}

// ==================== public providers ====================

async fn providers(State(state): State<SharedAppState>) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT provider::text FROM oauth_configs WHERE enabled = true",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "providers": rows.iter().map(|p| p.0.clone()).collect::<Vec<_>>(),
    })))
}

// ==================== bind ticket ====================

async fn bind_ticket(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let now = now_ms();
    let token = random_token32();
    let ticket = json!({
        "type": "oauth-bind",
        "userId": user.id,
        "issuedAt": user.iat,
        "sessionId": user.sid,
        "expiresAt": now + 60_000,
        "createdAt": now,
    });
    state
        .shared
        .set(
            &format!("action-ticket:{token}"),
            &ticket.to_string(),
            Some(Duration::from_secs(60)),
        )
        .await;
    if let Some(sid) = &user.sid {
        state
            .shared
            .set(
                &format!("action-ticket-session:{sid}:{token}"),
                "1",
                Some(Duration::from_secs(60)),
            )
            .await;
    }
    Ok(Json(json!({ "ticket": token, "expiresIn": 60 })))
}

async fn consume_bind_ticket(
    state: &SharedAppState,
    token: &str,
) -> Option<(i32, i64, Option<String>)> {
    let raw = state.shared.consume(&format!("action-ticket:{token}")).await?;
    let ticket: Value = serde_json::from_str(&raw).ok()?;
    if ticket.get("type") != Some(&Value::String("oauth-bind".into())) {
        return None;
    }
    if now_ms() > ticket.get("expiresAt").and_then(Value::as_u64).unwrap_or(0) {
        return None;
    }
    Some((
        ticket.get("userId").and_then(Value::as_i64)? as i32,
        ticket.get("issuedAt").and_then(Value::as_i64)?,
        ticket.get("sessionId").and_then(Value::as_str).map(|s| s.to_string()),
    ))
}

// ==================== authorize ====================

#[derive(Deserialize)]
struct AuthorizeQuery {
    mode: Option<String>,
    redirect: Option<String>,
    #[serde(rename = "bindTicket")]
    bind_ticket: Option<String>,
}

fn request_base_url(headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");
    format!("{scheme}://{host}")
}

async fn authorize(
    State(state): State<SharedAppState>,
    Path(provider): Path<String>,
    Query(query): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let Some(provider_cfg) = provider_config(&provider) else {
        return Err(ApiError::with_message(
            "INVALID_PROVIDER",
            StatusCode::BAD_REQUEST,
            "Unsupported OAuth provider",
        ));
    };

    let config = get_oauth_config(&state, &provider)
        .await?
        .filter(|c| c.enabled)
        .ok_or_else(|| ApiError::bad_request(code::OAUTH_NOT_ENABLED).with_details(provider.clone()))?;

    let mode = if query.mode.as_deref() == Some("bind") { "bind" } else { "login" };

    // 绑定模式：短期票据换取身份
    let mut user_id: Option<i32> = None;
    if mode == "bind" {
        let Some(bind_ticket) = query.bind_ticket.as_deref() else {
            return Ok(redirect_to("/profile?error=not_logged_in".into()));
        };
        let Some((ticket_user, issued_at, session_id)) = consume_bind_ticket(&state, bind_ticket).await else {
            return Ok(redirect_to("/profile?error=invalid_session".into()));
        };
        if crate::libs::security::is_access_token_invalidated(
            &state.db,
            ticket_user,
            issued_at,
            session_id.as_deref(),
        )
        .await
        .unwrap_or(true)
        {
            return Ok(redirect_to("/profile?error=invalid_session".into()));
        }
        let status: Option<String> = sqlx::query_scalar("SELECT status::text FROM users WHERE id = $1")
            .bind(ticket_user)
            .fetch_optional(&state.db)
            .await?;
        if status.as_deref() != Some("active") {
            return Ok(redirect_to("/profile?error=invalid_session".into()));
        }
        user_id = Some(ticket_user);
    }

    // 生成 state + nonce cookie
    let nonce = random_hex_nonce();
    let payload = json!({
        "mode": mode,
        "redirect": safe_redirect_url(query.redirect.as_deref(), "/"),
        "timestamp": now_ms(),
        "nonce": nonce,
        "userId": user_id,
    });
    let payload_b64 = b64url_encode(payload.to_string().as_bytes());
    let signature = sign_payload(&state_secret(&state), &payload_b64);
    let state_token = format!("{payload_b64}.{signature}");

    let callback_url = format!("{}/api/oauth/callback/{provider}", request_base_url(&headers));

    let mut params = vec![
        ("client_id", config.client_id.clone()),
        ("redirect_uri", callback_url.clone()),
        ("scope", provider_cfg.scope.to_string()),
        ("state", state_token),
        ("response_type", "code".to_string()),
    ];
    if provider == "google" {
        params.push(("access_type", "offline".into()));
        params.push(("prompt", "consent".into()));
    }
    let query_string: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let auth_url = format!("{}?{query_string}", provider_cfg.auth_url);

    let mut response = redirect_to(auth_url);
    response.headers_mut().insert(
        header::SET_COOKIE,
        build_set_cookie(OAUTH_STATE_COOKIE, &nonce, 600, "/api/oauth", &state)
            .parse()
            .expect("valid cookie header"),
    );
    Ok(response)
}

// ==================== callback ====================

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

struct OAuthUserInfo {
    id: String,
    username: Option<String>,
    email: Option<String>,
    avatar: Option<String>,
}

fn parse_oauth_user(provider: &str, data: &Value) -> OAuthUserInfo {
    let get_str = |key: &str| data.get(key).and_then(Value::as_str).map(|s| s.to_string());
    match provider {
        "github" => OAuthUserInfo {
            id: data
                .get("id")
                .map(|v| match v {
                    Value::Number(n) => n.to_string(),
                    Value::String(s) => s.clone(),
                    _ => String::new(),
                })
                .unwrap_or_default(),
            username: get_str("login"),
            email: get_str("email"),
            avatar: get_str("avatar_url"),
        },
        "google" => OAuthUserInfo {
            id: get_str("id").unwrap_or_default(),
            username: get_str("name").or_else(|| {
                get_str("email").map(|e| e.split('@').next().unwrap_or("").to_string())
            }),
            email: get_str("email"),
            avatar: get_str("picture"),
        },
        _ => OAuthUserInfo {
            id: get_str("id").unwrap_or_default(),
            username: None,
            email: None,
            avatar: None,
        },
    }
}

async fn callback(
    State(state): State<SharedAppState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(error) = &query.error {
        tracing::warn!("oauth_callback: OAuth error {error}");
        return Ok(redirect_to(format!(
            "/login?error={}",
            urlencoding::encode(error)
        )));
    }

    let Some(state_token) = query.state.clone() else {
        tracing::warn!("oauth_callback: missing state parameter");
        return Ok(redirect_to("/login?error=invalid_state".into()));
    };

    let cookie_nonce = cookie_value(&headers, OAUTH_STATE_COOKIE);

    // 校验签名 + 时间戳 + nonce cookie + 共享存储一次性消费
    let Some((payload_b64, signature)) = state_token.split_once('.') else {
        return Ok(redirect_to("/login?error=state_expired".into()));
    };
    let expected_signature = sign_payload(&state_secret(&state), payload_b64);
    let valid = signature == expected_signature
        && cookie_nonce.as_deref().map_or(false, |n| !n.is_empty());
    let state_data: Option<Value> = if !valid {
        None
    } else {
        b64url_decode(payload_b64)
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(|data| {
                now_ms()
                    .saturating_sub(data.get("timestamp").and_then(Value::as_u64).unwrap_or(0))
                    <= OAUTH_STATE_TTL_MS
            })
            .filter(|data| {
                data.get("nonce").and_then(Value::as_str) == cookie_nonce.as_deref()
            })
    };
    let state_data = match state_data {
        Some(data) => {
            let nonce = data.get("nonce").and_then(Value::as_str).unwrap_or_default();
            if !state
                .shared
                .add_once(
                    &format!("oauth-state-nonce:{nonce}"),
                    "1",
                    Duration::from_millis(OAUTH_STATE_TTL_MS),
                )
                .await
            {
                None
            } else {
                Some(data)
            }
        }
        None => None,
    };
    let Some(state_data) = state_data else {
        tracing::warn!("oauth_callback: invalid state token or nonce mismatch (Login CSRF suspected)");
        return Ok(redirect_to("/login?error=state_expired".into()));
    };

    let mode = state_data.get("mode").and_then(Value::as_str).unwrap_or("login").to_string();
    let redirect_url = safe_redirect_url(
        state_data.get("redirect").and_then(Value::as_str),
        "/",
    );
    let error_base = if mode == "bind" { "/profile" } else { "/login" };

    let Some(code) = query.code.clone() else {
        return Ok(redirect_to(format!("{error_base}?error=missing_code")));
    };

    let provider_cfg = match provider_config(&provider) {
        Some(cfg) => cfg,
        None => return Ok(redirect_to(format!("{error_base}?error=oauth_error"))),
    };
    let config = match get_oauth_config(&state, &provider).await {
        Ok(Some(c)) if c.enabled => c,
        _ => return Ok(redirect_to(format!("{error_base}?error=provider_disabled"))),
    };

    let result: Result<(String, Option<String>, OAuthUserInfo), String> = async {
        let callback_url =
            format!("{}/api/oauth/callback/{provider}", request_base_url(&headers));

        // 1. token exchange
        let token_body = [
            ("client_id", config.client_id.clone()),
            ("client_secret", config.client_secret.clone()),
            ("code", code.clone()),
            ("redirect_uri", callback_url),
            ("grant_type", "authorization_code".to_string()),
        ];
        let form: String = token_body
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let token_resp = state
            .http
            .post(provider_cfg.token_url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|e| format!("token_error: {e}"))?;
        let token_data: Value = token_resp.json().await.map_err(|e| format!("token_error: {e}"))?;
        let Some(access_token) = token_data.get("access_token").and_then(Value::as_str) else {
            return Err("token_error".into());
        };
        let refresh_token = token_data
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(|s| s.to_string());

        // 2. user info
        let user_resp = state
            .http
            .get(provider_cfg.user_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("oauth_error: {e}"))?;
        let user_data: Value = user_resp.json().await.map_err(|e| format!("oauth_error: {e}"))?;
        let oauth_user = parse_oauth_user(&provider, &user_data);

        Ok((access_token.to_string(), refresh_token, oauth_user))
    }
    .await;

    let (access_token, oauth_refresh_token, oauth_user) = match result {
        Ok(parts) => parts,
        Err(err) => {
            tracing::error!("OAuth callback error ({provider}): {err}");
            return Ok(redirect_to(format!("{error_base}?error=oauth_error")));
        }
    };

    if mode == "bind" {
        let Some(user_id) = state_data.get("userId").and_then(Value::as_i64) else {
            return Ok(redirect_to("/profile?error=not_logged_in".into()));
        };
        let user_id = user_id as i32;

        let existing: Option<(i32,)> = sqlx::query_as(
            "SELECT user_id FROM user_oauth_bindings \
             WHERE provider = $1::\"OAuthProvider\" AND provider_user_id = $2",
        )
        .bind(&provider)
        .bind(&oauth_user.id)
        .fetch_optional(&state.db)
        .await?;
        if let Some((owner,)) = existing {
            if owner != user_id {
                return Ok(redirect_to("/profile?error=already_bound_other".into()));
            }
        }

        let bound: Option<i32> = sqlx::query_scalar(
            "SELECT id FROM user_oauth_bindings \
             WHERE user_id = $1 AND provider = $2::\"OAuthProvider\"",
        )
        .bind(user_id)
        .bind(&provider)
        .fetch_optional(&state.db)
        .await?;
        if bound.is_some() {
            sqlx::query(
                "UPDATE user_oauth_bindings SET access_token = $3, refresh_token = $4 \
                 WHERE user_id = $1 AND provider = $2::\"OAuthProvider\"",
            )
            .bind(user_id)
            .bind(&provider)
            .bind(&access_token)
            .bind(&oauth_refresh_token)
            .execute(&state.db)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO user_oauth_bindings \
                 (user_id, provider, provider_user_id, provider_username, provider_email, \
                  provider_avatar, access_token, refresh_token) \
                 VALUES ($1, $2::\"OAuthProvider\", $3, $4, $5, $6, $7, $8)",
            )
            .bind(user_id)
            .bind(&provider)
            .bind(&oauth_user.id)
            .bind(&oauth_user.username)
            .bind(&oauth_user.email)
            .bind(&oauth_user.avatar)
            .bind(&access_token)
            .bind(&oauth_refresh_token)
            .execute(&state.db)
            .await?;
        }
        return Ok(redirect_to(format!("/profile?success=bound_{provider}")));
    }

    // 登录模式
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("OAuth Login");
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string());
    let binding: Option<(i32,)> = sqlx::query_as(
        "SELECT user_id FROM user_oauth_bindings \
         WHERE provider = $1::\"OAuthProvider\" AND provider_user_id = $2",
    )
    .bind(&provider)
    .bind(&oauth_user.id)
    .fetch_optional(&state.db)
    .await?;
    let Some((bound_user_id,)) = binding else {
        return Ok(redirect_to(format!("/login?error=not_bound&provider={provider}")));
    };

    let user: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT username, status::text, email, ban_reason FROM users WHERE id = $1",
    )
    .bind(bound_user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((username, status, email, ban_reason)) = user else {
        return Ok(redirect_to("/login?error=user_not_found".into()));
    };
    if status != "active" {
        return Ok(redirect_to("/login?error=account_banned".into()));
    }
    let _ = ban_reason;

    sqlx::query(
        "UPDATE user_oauth_bindings SET access_token = $3, refresh_token = $4 \
         WHERE user_id = $1 AND provider = $2::\"OAuthProvider\"",
    )
    .bind(bound_user_id)
    .bind(&provider)
    .bind(&access_token)
    .bind(&oauth_refresh_token)
    .execute(&state.db)
    .await?;

    // 异地登录提醒（邮件发送为 stub —— 见 libs/external.rs）
    if let Some(email) = email.clone() {
        let ip = ip.clone().unwrap_or_default();
        let ua = user_agent.to_string();
        let alert_username = username.clone();
        tokio::spawn(async move {
            let _ = crate::libs::external::send_login_alert_email(
                &email, &alert_username, &ip, &ua, false, false,
            ).await;
        });
    }

    // 一次性登录码（60 秒）
    let nonce = random_hex_nonce();
    let payload = json!({
        "userId": bound_user_id,
        "username": username,
        "role": "user",
        "timestamp": now_ms(),
        "nonce": nonce,
    });
    let payload_b64 = b64url_encode(payload.to_string().as_bytes());
    let signature = sign_payload(&state_secret(&state), &payload_b64);
    let login_code = format!("{payload_b64}.{signature}");

    let separator = if redirect_url.contains('?') { '&' } else { '?' };
    Ok(redirect_to(format!(
        "{redirect_url}{separator}oauth_code={}",
        urlencoding::encode(&login_code)
    )))
}

// ==================== user bindings ====================

async fn my_bindings(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(String, Option<String>, Option<String>, Option<String>, DateTime<Utc>)> =
        sqlx::query_as(
            "SELECT provider::text, provider_username, provider_email, provider_avatar, created_at \
             FROM user_oauth_bindings WHERE user_id = $1 ORDER BY created_at ASC",
        )
        .bind(user.id)
        .fetch_all(&state.db)
        .await?;
    let bindings: Vec<Value> = rows
        .iter()
        .map(|(provider, username, email, avatar, bound_at)| {
            json!({
                "provider": provider,
                "username": username,
                "email": email,
                "avatar": avatar,
                "boundAt": crate::libs::instance_common::iso(*bound_at),
            })
        })
        .collect();
    Ok(Json(json!({ "bindings": bindings })))
}

async fn unbind(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(provider): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let bound: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM user_oauth_bindings \
         WHERE user_id = $1 AND provider = $2::\"OAuthProvider\"",
    )
    .bind(user.id)
    .bind(&provider)
    .fetch_optional(&state.db)
    .await?;
    if bound.is_none() {
        return Err(ApiError::with_message(
            code::OAUTH_NOT_BOUND,
            StatusCode::BAD_REQUEST,
            "Account not bound",
        ));
    }
    sqlx::query(
        "DELETE FROM user_oauth_bindings WHERE user_id = $1 AND provider = $2::\"OAuthProvider\"",
    )
    .bind(user.id)
    .bind(&provider)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "message": format!("已解除 {provider} 绑定") })))
}

// ==================== exchange-code ====================

#[derive(Deserialize)]
struct ExchangeBody {
    code: Option<String>,
}

async fn exchange_code(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    body: Option<Json<ExchangeBody>>,
) -> Result<Response, ApiError> {
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let code = body
        .code
        .filter(|c| c.chars().count() >= 10)
        .ok_or_else(|| ApiError::validation("code must NOT have fewer than 10 characters"))?;

    // 验证并消费一次性登录码
    let Some((payload_b64, signature)) = code.split_once('.') else {
        return Err(invalid_login_code());
    };
    let expected_signature = sign_payload(&state_secret(&state), payload_b64);
    let login_data: Option<Value> = if signature != expected_signature {
        None
    } else {
        b64url_decode(payload_b64)
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(|data| {
                now_ms()
                    .saturating_sub(data.get("timestamp").and_then(Value::as_u64).unwrap_or(0))
                    <= OAUTH_LOGIN_CODE_TTL_MS
            })
    };
    let login_data = match login_data {
        Some(data) => {
            let nonce = data.get("nonce").and_then(Value::as_str).unwrap_or_default();
            if !state
                .shared
                .add_once(
                    &format!("oauth-login-nonce:{nonce}"),
                    "1",
                    Duration::from_millis(OAUTH_LOGIN_CODE_TTL_MS),
                )
                .await
            {
                None
            } else {
                Some(data)
            }
        }
        None => None,
    };
    let Some(login_data) = login_data else {
        tracing::warn!("oauth_exchange_code: invalid or expired login code");
        return Err(invalid_login_code());
    };

    let user_id = login_data.get("userId").and_then(Value::as_i64).unwrap_or(0) as i32;
    let username = login_data
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let role = login_data
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("user")
        .to_string();

    // 用户状态复查（回调后、交换前可能被封禁）
    let user: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT status::text, ban_reason FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((status, ban_reason)) = user else {
        return Err(ApiError::with_message(
            "USER_NOT_FOUND",
            StatusCode::UNAUTHORIZED,
            "User not found",
        ));
    };
    if status == "banned" {
        return Err(ApiError::with_message(
            code::ACCOUNT_BANNED,
            StatusCode::FORBIDDEN,
            ban_reason.unwrap_or_else(|| "Account banned".into()),
        ));
    }

    // 生成 refresh token（30 天）+ access token（30 分钟）
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("OAuth Login");
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string());

    let refresh_token = crate::libs::security::generate_refresh_token();
    {
        let mut tx = state.db.begin().await?;
        crate::libs::security::create_refresh_token(
            &mut tx,
            &refresh_token,
            user_id,
            &username,
            &role,
            ip.as_deref(),
            Some(user_agent),
        )
        .await?;
        tx.commit().await?;
    }

    let session_id: String = refresh_token.chars().take(20).collect();
    let access_token = crate::auth::sign_access_token(&state, user_id, &username, &role, &session_id)?;

    let mut response = Json(json!({
        "token": access_token,
        "user": { "id": user_id, "username": username, "role": role },
    }))
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        build_set_cookie(
            REFRESH_COOKIE,
            &refresh_token,
            crate::config::REFRESH_TOKEN_LIFETIME_SECONDS,
            "/",
            &state,
        )
        .parse()
        .expect("valid cookie header"),
    );
    Ok(response)
}

fn invalid_login_code() -> ApiError {
    ApiError::with_message(
        "INVALID_LOGIN_CODE",
        StatusCode::UNAUTHORIZED,
        "Invalid or expired login code",
    )
}
