//! Host agent credential rotation and one-time install tokens.
//! Port of lib/host-agent-credentials.ts (plus the generateAgentId /
//! generateAgentSecret / hashAgentSecret helpers from lib/agent-auth.ts, which
//! do not exist in libs/agent_auth.rs yet).
//!
//! DB access is performed by the route layer with sqlx; this module owns the
//! token formats, hashing, and the orchestration helpers that take a handle to
//! the pool.

use sha2::{Digest, Sha256};

use crate::libs::crypto::encrypt_sensitive_data;

pub const AGENT_INSTALL_TOKEN_PREFIX: &str = "ait_";
pub const AGENT_INSTALL_TOKEN_TTL_MS: i64 = 30 * 60 * 1000;

/// Mirrors generateAgentId: `agt_` + 24 random bytes base64url.
pub fn generate_agent_id() -> String {
    format!("agt_{}", random_base64url(24))
}

/// Mirrors generateAgentSecret: `ias_` + 32 random bytes base64url.
pub fn generate_agent_secret() -> String {
    format!("ias_{}", random_base64url(32))
}

/// Mirrors hashAgentSecret: sha256 hex.
pub fn hash_agent_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Mirrors hashAgentInstallToken: sha256 hex.
pub fn hash_agent_install_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Mirrors isAgentInstallToken.
pub fn is_agent_install_token(value: &str) -> bool {
    value.starts_with(AGENT_INSTALL_TOKEN_PREFIX)
        && value.len() >= AGENT_INSTALL_TOKEN_PREFIX.len() + 32
}

/// Mirrors generateAgentInstallToken: `ait_` + 32 random bytes base64url.
pub fn generate_agent_install_token() -> String {
    format!("{}{}", AGENT_INSTALL_TOKEN_PREFIX, random_base64url(32))
}

pub fn base64url_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn random_base64url(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64url_encode(&buf)
}

/// Host + agent identity fields rotated into the DB (routes persist them).
pub struct RotatedAgentCredentials {
    pub agent_id: String,
    pub agent_secret: String,
    pub secret_hash: String,
    pub secret_encrypted: String,
}

/// Mirrors rotateHostAgentCredentials' credential generation (the DB reads and
/// writes stay in routes/hosts.rs because they interleave with other queries).
pub fn new_agent_credentials(key: &[u8; 32]) -> RotatedAgentCredentials {
    let agent_id = generate_agent_id();
    let agent_secret = generate_agent_secret();
    RotatedAgentCredentials {
        secret_hash: hash_agent_secret(&agent_secret),
        secret_encrypted: encrypt_sensitive_data(key, &agent_secret),
        agent_id,
        agent_secret,
    }
}
