//! SSH 公钥管理路由 — port of server/src/routes/ssh-keys.ts (mounted at /api/ssh-keys).
//!
//! All endpoints require a regular (non-admin) user: fastify.authenticateUser
//! maps to the `UserOnlyAuth` extractor.
//!
//! Known gap (reported): `POST /generate` needs RSA-4096 keypair generation;
//! the shared Cargo.toml has no `rsa`/`ssh-key` crate, so the endpoint performs
//! the same per-user quota check and then fails exactly like the TS
//! "key generation failed" path (`500 { error: "Failed to generate valid SSH key" }`).

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::FromRow;

use crate::auth::UserOnlyAuth;
use crate::error::{code, ApiError};
use crate::libs::validators::validate_name;
use crate::routes::users::create_log;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list_keys).post(add_key))
        .route("/generate", post(generate_key))
        .route("/{id}", get(get_key).delete(delete_key))
}

// ===========================================================================
// db helpers (port of db/ssh-keys.ts)
// ===========================================================================

#[derive(Debug, FromRow)]
struct SshKeyRow {
    id: i32,
    user_id: i32,
    name: String,
    public_key: String,
    fingerprint: String,
    created_at: DateTime<Utc>,
}

async fn get_ssh_keys_by_user_id(
    state: &SharedAppState,
    user_id: i32,
) -> Result<Vec<SshKeyRow>, ApiError> {
    let rows = sqlx::query_as::<_, SshKeyRow>(
        "SELECT id, user_id, name, public_key, fingerprint, created_at \
         FROM ssh_keys WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

async fn get_ssh_key_by_id(state: &SharedAppState, id: i32) -> Result<Option<SshKeyRow>, ApiError> {
    let row = sqlx::query_as::<_, SshKeyRow>(
        "SELECT id, user_id, name, public_key, fingerprint, created_at \
         FROM ssh_keys WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

async fn create_ssh_key(
    state: &SharedAppState,
    user_id: i32,
    name: &str,
    public_key: &str,
    fingerprint: &str,
) -> Result<i32, ApiError> {
    let row: (i32,) = sqlx::query_as(
        "INSERT INTO ssh_keys (user_id, name, public_key, fingerprint) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(user_id)
    .bind(name)
    .bind(public_key)
    .bind(fingerprint)
    .fetch_one(&state.db)
    .await?;
    Ok(row.0)
}

async fn delete_ssh_key(state: &SharedAppState, id: i32) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM ssh_keys WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(())
}

// ===========================================================================
// local mirrors of the module-level TS functions
// ===========================================================================

/// Mirrors parseSSHPublicKey(): 支持 ssh-rsa, ssh-ed25519, ecdsa-sha2-* 格式.
fn parse_ssh_public_key(key: &str) -> Option<(String /*type*/, String /*keyData*/)> {
    static MATCHER: Lazy<Regex> = Lazy::new(|| {
        // TS: /^(ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+)\s+([A-Za-z0-9+/=]+)(\s+.*)?$/
        Regex::new(r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+)\s+([A-Za-z0-9+/=]+)(\s+.*)?$")
            .expect("valid regex")
    });

    // 移除可能的换行和多余空格
    let clean_key = key.replace("\r\n", " ").replace('\n', " ");
    let captures = MATCHER.captures(clean_key.trim())?;
    Some((
        captures.get(1)?.as_str().to_string(),
        captures.get(2)?.as_str().to_string(),
    ))
}

/// Mirrors calculateFingerprint(): SHA-256 of the decoded key data, base64,
/// padding stripped, "SHA256:" prefixed.
fn calculate_fingerprint(base64_key_data: &str) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    match B64.decode(base64_key_data) {
        Ok(bytes) => {
            let hash = Sha256::digest(&bytes);
            let encoded = B64.encode(hash);
            format!("SHA256:{}", encoded.trim_end_matches('='))
        }
        Err(_) => "SHA256:unknown".to_string(),
    }
}

/// Mirrors truncateKey(): only the head/tail of the public key is returned.
fn truncate_key(public_key: &str) -> String {
    if public_key.is_empty() || public_key.len() < 60 {
        return public_key.to_string();
    }
    let chars: Vec<char> = public_key.chars().collect();
    let head: String = chars[..30].iter().collect();
    let tail: String = chars[chars.len() - 20..].iter().collect();
    format!("{head}...{tail}")
}

/// TS `createdAt` is `createdAt.toISOString()`.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn key_json(key: &SshKeyRow) -> Value {
    json!({
        "id": key.id,
        "name": key.name,
        "fingerprint": key.fingerprint,
        "publicKeyPreview": truncate_key(&key.public_key),
        "createdAt": iso(key.created_at),
    })
}

/// TS `Number(id)` param parse: non-numeric -> 400 INVALID_ID.
fn parse_path_id(raw: &str) -> Result<i32, ApiError> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))
}

/// Bare `{ error }` 400 (TS sends `{ error: message }` without a code for the
/// name-validation and quota failures in this module).
fn bare_bad_request(message: impl Into<String>) -> Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        axum::Json(json!({ "error": message.into() })),
    )
        .into_response()
}

// ===========================================================================
// GET / — 获取用户的 SSH 公钥列表
// ===========================================================================

async fn list_keys(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    let keys = get_ssh_keys_by_user_id(&state, user.0.id).await?;
    let items: Vec<Value> = keys.iter().map(key_json).collect();
    Ok(Json(json!({ "keys": items })))
}

// ===========================================================================
// GET /:id — 获取单个 SSH 公钥详情
// ===========================================================================

async fn get_key(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key_id = parse_path_id(&id)?;
    let key = get_ssh_key_by_id(&state, key_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::NOT_FOUND))?;

    // 管理员只管理系统层面，不参与用户SSH密钥操作
    if key.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    Ok(Json(json!({ "key": key_json(&key) })))
}

// ===========================================================================
// POST / — 添加 SSH 公钥
// ===========================================================================

#[derive(Deserialize)]
struct AddKeyBody {
    name: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

async fn add_key(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Json(body): Json<AddKeyBody>,
) -> Result<Response, ApiError> {
    // Fastify schema pre-checks (name 1..50, publicKey >= 20 chars) that the
    // TS server performs before the handler body.
    if body.name.trim().is_empty() || body.name.chars().count() > 50 {
        return Ok(bare_bad_request(
            "body/name must be at least 1 and at most 50 characters",
        ));
    }

    // 验证密钥名称（防止危险字符注入）。TS: reply.code(400).send({ error: nameValidation.message })
    let name_validation = validate_name(&body.name, "Key name", 1, 50);
    if !name_validation.valid {
        return Ok(bare_bad_request(
            name_validation.message.unwrap_or_else(|| "Invalid name".to_string()),
        ));
    }

    if body.public_key.trim().chars().count() < 20 {
        return Ok(bare_bad_request(
            "body/publicKey must NOT have fewer than 20 characters",
        ));
    }

    // 验证并解析公钥
    let public_key = body.public_key.trim();
    let parsed = parse_ssh_public_key(public_key)
        .ok_or_else(|| ApiError::bad_request(code::INVALID_SSH_KEY))?;

    // 计算指纹
    let fingerprint = calculate_fingerprint(&parsed.1);

    // 检查是否已存在相同指纹的密钥
    let existing_keys = get_ssh_keys_by_user_id(&state, user.0.id).await?;
    if existing_keys.iter().any(|k| k.fingerprint == fingerprint) {
        return Err(ApiError::bad_request(code::SSH_KEY_EXISTS));
    }

    // 保存到数据库
    let key_id = create_ssh_key(&state, user.0.id, &body.name, public_key, &fingerprint).await?;

    create_log(
        &state,
        user.0.id,
        "ssh_key",
        "ssh_key.add",
        &format!("Added SSH key \"{}\" [fingerprint: {fingerprint}]", body.name),
        "success",
    )
    .await;

    Ok((
        axum::http::StatusCode::CREATED,
        axum::Json(json!({
            "message": "SSH key added",
            "key": {
                "id": key_id,
                "name": body.name,
                "fingerprint": fingerprint,
                "publicKeyPreview": truncate_key(public_key),
            },
        })),
    )
        .into_response())
}

// ===========================================================================
// POST /generate — 生成 SSH 密钥对 (RSA 4096)
// ===========================================================================

async fn generate_key(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Response, ApiError> {
    // 检查用户密钥数量限制，防止滥用
    const MAX_SSH_KEYS: usize = 20;
    let existing_keys = get_ssh_keys_by_user_id(&state, user.0.id).await?;
    if existing_keys.len() >= MAX_SSH_KEYS {
        return Ok(bare_bad_request(format!(
            "Maximum {MAX_SSH_KEYS} SSH keys allowed per user"
        )));
    }

    // RSA-4096 keypair generation is unavailable in the Rust server: the shared
    // Cargo.toml has no `rsa`/`ssh-key` dependency (Cargo.toml must not be
    // edited per the porting constraints). Mirrors the TS internal-failure
    // response for "could not produce a valid key". The /generate rate-limit
    // rule (5/minute) lives in rate_limit.rs, which is outside this module.
    tracing::warn!(
        "ssh-keys: POST /generate unavailable in the Rust server (missing rsa crate dependency)"
    );
    Ok((
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({ "error": "Failed to generate valid SSH key" })),
    )
        .into_response())
}

// ===========================================================================
// DELETE /:id — 删除 SSH 公钥
// ===========================================================================

async fn delete_key(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key_id = parse_path_id(&id)?;
    let key = get_ssh_key_by_id(&state, key_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::NOT_FOUND))?;

    // 管理员只管理系统层面，不参与用户SSH密钥操作
    if key.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    delete_ssh_key(&state, key_id).await?;

    create_log(
        &state,
        user.0.id,
        "ssh_key",
        "ssh_key.delete",
        &format!(
            "Deleted SSH key \"{}\" [fingerprint: {}]",
            key.name, key.fingerprint
        ),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "SSH key deleted" })))
}
