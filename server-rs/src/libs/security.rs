//! Refresh-token lifecycle and access-token invalidation.
//! Port of the relevant parts of lib/security.ts (lib/cookie-config.ts constants).

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sqlx::PgPool;

use crate::config::{ACCESS_TOKEN_LIFETIME_SECONDS, REFRESH_TOKEN_LIFETIME_SECONDS};

pub const USER_LEVEL_SESSION_ID: &str = "__USER_LEVEL__";

pub fn generate_refresh_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    format!("rt_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub token: String,
    pub user_id: i32,
    pub username: String,
    pub role: String,
    pub expires_at: DateTime<Utc>,
}

/// Mirrors verifyRefreshToken(): returns the row when valid, deletes it and
/// returns None when expired. DB errors propagate (fail-safe upstream).
pub async fn verify_refresh_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, RefreshTokenRow>(
        "SELECT token, user_id, username, role::text AS role, expires_at \
         FROM refresh_tokens WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(row) if row.expires_at <= Utc::now() => {
            sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
                .bind(token)
                .execute(pool)
                .await?;
            Ok(None)
        }
        other => Ok(other),
    }
}

/// Mirrors updateSessionActivity(): slide expiry forward by the full lifetime.
pub async fn update_session_activity(pool: &PgPool, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE refresh_tokens \
         SET expires_at = $2, last_active_at = now() WHERE token = $1",
    )
    .bind(token)
    .bind(Utc::now() + Duration::seconds(REFRESH_TOKEN_LIFETIME_SECONDS))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn revoke_refresh_token(pool: &PgPool, token: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn revoke_all_user_refresh_tokens(
    pool: &PgPool,
    user_id: i32,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn create_refresh_token(
    tx: &mut sqlx::PgConnection,
    token: &str,
    user_id: i32,
    username: &str,
    role: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO refresh_tokens (token, user_id, username, role, ip, user_agent, expires_at) \
         VALUES ($1, $2, $3, $4::\"UserRole\", $5, $6, $7)",
    )
    .bind(token)
    .bind(user_id)
    .bind(username)
    .bind(role)
    .bind(ip)
    .bind(user_agent)
    .bind(Utc::now() + Duration::seconds(REFRESH_TOKEN_LIFETIME_SECONDS))
    .execute(&mut *tx)
    .await?;
    Ok(())
}

// ---- Access-token invalidation (token_invalidations) ----

/// Mirrors invalidateUserAccessTokens(): upserts the user-level sentinel row.
pub async fn invalidate_user_access_tokens(
    pool: &PgPool,
    user_id: i32,
) -> Result<(), sqlx::Error> {
    let now = Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO token_invalidations (user_id, session_id, invalidated_at, created_at) \
         VALUES ($1, $2, $3, now()) \
         ON CONFLICT (user_id, session_id) \
         DO UPDATE SET invalidated_at = EXCLUDED.invalidated_at",
    )
    .bind(user_id)
    .bind(USER_LEVEL_SESSION_ID)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mirrors invalidateSessionAccessToken().
pub async fn invalidate_session_access_token(
    pool: &PgPool,
    user_id: i32,
    session_id: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO token_invalidations (user_id, session_id, invalidated_at, created_at) \
         VALUES ($1, $2, $3, now()) \
         ON CONFLICT (user_id, session_id) \
         DO UPDATE SET invalidated_at = EXCLUDED.invalidated_at",
    )
    .bind(user_id)
    .bind(session_id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mirrors isAccessTokenInvalidated(): token invalid iff iat <= invalidatedAt.
/// Session-level row wins first, then user-level. DB errors propagate so the
/// caller fails closed.
pub async fn is_access_token_invalidated(
    pool: &PgPool,
    user_id: i32,
    issued_at: i64,
    session_id: Option<&str>,
) -> Result<bool, sqlx::Error> {
    if let Some(sid) = session_id {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT invalidated_at FROM token_invalidations \
             WHERE user_id = $1 AND session_id = $2",
        )
        .bind(user_id)
        .bind(sid)
        .fetch_optional(pool)
        .await?;
        if let Some((invalidated_at,)) = row {
            if issued_at <= invalidated_at {
                return Ok(true);
            }
        }
    }
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT invalidated_at FROM token_invalidations \
         WHERE user_id = $1 AND session_id = $2",
    )
    .bind(user_id)
    .bind(USER_LEVEL_SESSION_ID)
    .fetch_optional(pool)
    .await?;
    Ok(matches!(row, Some((invalidated_at,)) if issued_at <= invalidated_at))
}

/// Mirrors cleanupExpiredTokenInvalidations / cleanupExpiredRefreshTokens —
/// called periodically by the schedulers.
pub async fn cleanup_expired_tokens(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM token_invalidations WHERE invalidated_at < $1")
        .bind(Utc::now().timestamp() - ACCESS_TOKEN_LIFETIME_SECONDS * 10)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now()")
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct JwtClaims {
    pub id: i32,
    pub username: String,
    pub role: String,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub exp: Option<i64>,
}
