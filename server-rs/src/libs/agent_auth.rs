//! HMAC-SHA256 request authentication for Go host agents.
//! Bit-compatible port of lib/agent-auth.ts + the verification flow in
//! routes/agent.ts authenticateAgentRequest.
//!
//! Canonical body JSON: object keys sorted by UTF-8 byte order, numbers printed
//! JS-style (integer floats without a decimal point), U+2028/U+2029 escaped.
//! Signing payload: "METHOD\npath\ntimestamp\nnonce\nbodyHash" (path has no
//! query string), HMAC-SHA256 hex lowercase.

use axum::http::StatusCode;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{code, ApiError};

pub const AGENT_TIMESTAMP_WINDOW_MS: i64 = 5 * 60 * 1000;
pub const AGENT_NONCE_TTL_MS: i64 = 10 * 60 * 1000;

pub struct AgentAuthHeaders {
    pub agent_id: String,
    pub timestamp: String,
    pub nonce: String,
    pub body_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HostAgentRecord {
    pub id: i32,
    pub host_id: i32,
    pub agent_id: String,
    pub secret_encrypted: Option<String>,
    pub enabled: bool,
}

fn agent_auth_error(code_str: &str, message: &str) -> ApiError {
    ApiError::with_message(code_str, StatusCode::UNAUTHORIZED, message)
}

pub fn read_agent_auth_headers(
    headers: &axum::http::HeaderMap,
) -> Option<AgentAuthHeaders> {
    let header = |name: &str| -> Option<String> {
        headers.get(name)?.to_str().ok().map(|s| s.to_string())
    };
    let agent_id = header("x-incudal-agent-id")?;
    let timestamp = header("x-incudal-timestamp")?;
    let nonce = header("x-incudal-nonce")?;
    let body_hash = header("x-incudal-body-sha256")?;
    let signature = header("x-incudal-signature")?;
    Some(AgentAuthHeaders {
        agent_id,
        timestamp,
        nonce,
        body_hash,
        signature,
    })
}

pub fn validate_agent_headers(h: &AgentAuthHeaders) -> Option<&'static str> {
    let agent_id_ok = h.agent_id.starts_with("agt_")
        && h.agent_id.len() >= 4 + 24
        && h.agent_id[4..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !agent_id_ok {
        return Some("invalid agent id");
    }
    if h.timestamp.len() != 13 || !h.timestamp.bytes().all(|b| b.is_ascii_digit()) {
        return Some("invalid timestamp");
    }
    let nonce_ok = (8..=128).contains(&h.nonce.len())
        && h.nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if !nonce_ok {
        return Some("invalid nonce");
    }
    if h.body_hash.len() != 64 || !h.body_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some("invalid body hash");
    }
    if h.signature.len() != 64 || !h.signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some("invalid signature");
    }
    None
}

pub fn is_agent_timestamp_fresh(timestamp_ms: i64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    (now - timestamp_ms).abs() <= AGENT_TIMESTAMP_WINDOW_MS
}

/// JS-flavoured number formatting used by the canonical serializer.
fn js_number_to_string(n: f64) -> String {
    if n.is_nan() || n.is_infinite() {
        return "null".to_string();
    }
    if n == n.trunc() {
        if n.abs() < 9.0e15 {
            return format!("{}", n as i64);
        }
        if n.abs() < 1.0e21 {
            // Full decimal digits, matching Number::toString below 1e21.
            return format!("{}", n);
        }
    }
    if n.abs() >= 1.0e21 || (n != 0.0 && n.abs() < 1.0e-6) {
        // JS switches to exponential notation here: 1e21 -> "1e+21".
        let s = format!("{:e}", n);
        if let Some((mantissa, exponent)) = s.split_once('e') {
            let exp: i64 = exponent.parse().unwrap_or(0);
            return format!("{}e{}{}", mantissa, if exp >= 0 { "+" } else { "-" }, exp.abs());
        }
        return s;
    }
    format!("{}", n)
}

/// Canonical JSON serialization matching stableStringifyAgentBody.
/// NOTE: requires serde_json WITHOUT the "preserve_order" feature so object
/// keys iterate in byte-sorted order (BTreeMap), matching Go's encoding/json.
pub fn stable_stringify(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                out.push_str(&js_number_to_string(f));
            } else {
                out.push_str("null");
            }
        }
        Value::String(s) => {
            // serde_json string escaping matches JSON.stringify; add the
            // U+2028/U+2029 escapes JSON.stringify emits literally.
            let quoted = serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());
            if quoted.contains('\u{2028}') || quoted.contains('\u{2029}') {
                out.push_str(
                    &quoted
                        .replace('\u{2028}', "\\u2028")
                        .replace('\u{2029}', "\\u2029"),
                );
            } else {
                out.push_str(&quoted);
            }
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (key, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_canonical(val, out);
            }
            out.push('}');
        }
    }
}

pub fn create_body_hash(body: &Value) -> String {
    let canonical = stable_stringify(body);
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

pub fn build_signing_payload(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body_hash: &str,
) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        timestamp,
        nonce,
        body_hash.to_lowercase()
    )
    .into_bytes()
}

pub fn create_signature(secret: &str, payload: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_signature(secret: &str, payload: &[u8], signature: &str) -> bool {
    if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let expected = create_signature(secret, payload);
    expected.as_bytes().ct_eq(signature.to_lowercase().as_bytes()).into()
}

/// Full verification flow, mirrors authenticateAgentRequest.
/// `path` must be the request path WITHOUT the query string.
pub async fn verify_agent_request(
    state: &crate::state::AppState,
    method: &str,
    path: &str,
    headers: &axum::http::HeaderMap,
    body_bytes: &[u8],
) -> Result<HostAgentRecord, ApiError> {
    let headers = read_agent_auth_headers(headers).ok_or_else(|| {
        agent_auth_error(
            code::AGENT_AUTH_REQUIRED,
            "Agent authentication headers are required",
        )
    })?;

    if let Some(detail) = validate_agent_headers(&headers) {
        return Err(agent_auth_error(code::AGENT_AUTH_INVALID, "Invalid Agent authentication headers")
            .with_details(detail));
    }

    let timestamp_ms: i64 = headers.timestamp.parse().unwrap_or(0);
    if !is_agent_timestamp_fresh(timestamp_ms) {
        return Err(agent_auth_error(
            code::AGENT_AUTH_EXPIRED,
            "Agent request timestamp is expired",
        ));
    }

    let body: Value = serde_json::from_slice(body_bytes).unwrap_or(Value::Object(Default::default()));
    let body_hash = create_body_hash(&body);
    if body_hash != headers.body_hash.to_lowercase() {
        return Err(agent_auth_error(
            code::AGENT_BODY_HASH_MISMATCH,
            "Agent body hash mismatch",
        ));
    }

    let agent: HostAgentRecord = sqlx::query_as(
        "SELECT id, host_id, agent_id, secret_encrypted, enabled \
         FROM host_agents WHERE agent_id = $1",
    )
    .bind(&headers.agent_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::from_sql)?
    .ok_or_else(|| agent_auth_error(code::AGENT_DISABLED, "Agent is not enabled"))?;

    if !agent.enabled {
        return Err(agent_auth_error(code::AGENT_DISABLED, "Agent is not enabled"));
    }

    let secret_encrypted = agent
        .secret_encrypted
        .clone()
        .ok_or_else(|| agent_auth_error(code::AGENT_SECRET_INVALID, "Agent secret is not available"))?;
    let secret = crate::libs::crypto::decrypt_sensitive_data(&state.config.encryption_key, &secret_encrypted)
        .map_err(|_| agent_auth_error(code::AGENT_SECRET_INVALID, "Agent secret is not available"))?;
    if !secret.starts_with("ias_") || secret.len() < 4 + 32 {
        return Err(agent_auth_error(code::AGENT_SECRET_INVALID, "Agent secret is not available"));
    }

    let payload = build_signing_payload(method, path, &headers.timestamp, &headers.nonce, &body_hash);
    if !verify_signature(&secret, &payload, &headers.signature) {
        return Err(agent_auth_error(
            code::AGENT_SIGNATURE_INVALID,
            "Agent signature verification failed",
        ));
    }

    // Nonce replay protection: purge expired rows, insert fresh; unique
    // violation on (agent_id, nonce) means replay.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(ApiError::from_sql)?;
    sqlx::query("DELETE FROM host_agent_nonces WHERE expires_at < now()")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
    let expires_at = chrono::DateTime::from_timestamp(
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
            + AGENT_NONCE_TTL_MS)
            / 1000,
        0,
    );
    let insert = sqlx::query(
        "INSERT INTO host_agent_nonces (agent_id, nonce, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&agent.agent_id)
    .bind(&headers.nonce)
    .bind(expires_at)
    .execute(&mut *tx)
    .await;
    match insert {
        Ok(_) => {
            tx.commit().await.map_err(ApiError::from_sql)?;
        }
        Err(err) => {
            let is_replay = err
                .as_database_error()
                .and_then(|e| e.code().map(|c| c.into_owned()))
                .map(|c| c == "23505")
                .unwrap_or(false);
            let _ = tx.rollback().await;
            if is_replay {
                return Err(agent_auth_error(
                    code::AGENT_NONCE_REPLAY,
                    "Agent nonce was already used",
                ));
            }
            return Err(ApiError::from_sql(err));
        }
    }

    Ok(agent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_keys_bytewise() {
        let v = json!({"b": 1, "a": [1, {"d": true, "c": null}]});
        assert_eq!(stable_stringify(&v), r#"{"a":[1,{"c":null,"d":true}],"b":1}"#);
    }

    #[test]
    fn canonical_prints_integer_floats_like_js() {
        let v: Value = serde_json::from_str(r#"{"x":1.0,"y":2.5,"z":-3.0}"#).unwrap();
        assert_eq!(stable_stringify(&v), r#"{"x":1,"y":2.5,"z":-3}"#);
    }

    #[test]
    fn signature_roundtrip() {
        let payload = build_signing_payload("POST", "/api/agent/heartbeat", "1700000000000", "nonce1", "ab");
        let sig = create_signature("ias_test", &payload);
        assert!(verify_signature("ias_test", &payload, &sig));
        assert!(!verify_signature("ias_other", &payload, &sig));
    }

    #[test]
    fn header_validation() {
        let h = AgentAuthHeaders {
            agent_id: "agt_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456".to_string(),
            timestamp: "1700000000000".to_string(),
            nonce: "abc.def-ghi_jkl:123".to_string(),
            body_hash: "a".repeat(64),
            signature: "b".repeat(64),
        };
        assert!(validate_agent_headers(&h).is_none());
        assert!(validate_agent_headers(&AgentAuthHeaders {
            nonce: "short".to_string(),
            ..h
        })
        .is_some());
    }
}
