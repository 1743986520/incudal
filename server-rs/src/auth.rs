//! Authentication extractors, mirroring plugins/auth-decorators.ts:
//! - AuthUser      == fastify.authenticate      (any active user)
//! - AdminUser     == fastify.authenticateAdmin (role == admin)
//! - RegularUser   == fastify.authenticateUser  (role != admin)
//!
//! Flow: verify HS256 JWT -> check token_invalidations (fail closed) -> re-read
//! the user from the DB (DB is the source of truth for username/role/status).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use crate::error::{code, ApiError};
use crate::libs::security::JwtClaims;
use crate::state::SharedAppState;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub status: String,
    pub sid: Option<String>,
    pub iat: i64,
}

pub type AdminUser = AdminAuth;
pub type RegularUser = UserOnlyAuth;

pub struct AdminAuth(pub AuthUser);
pub struct UserOnlyAuth(pub AuthUser);

fn bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))
}

impl FromRequestParts<SharedAppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedAppState) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or_else(ApiError::unauthorized)?;

        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 0;
        let claims = jsonwebtoken::decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| ApiError::unauthorized())?;
        let claims = claims.claims;
        let issued_at = claims.iat.ok_or_else(ApiError::unauthorized)?;

        if crate::libs::security::is_access_token_invalidated(
            &state.db,
            claims.id,
            issued_at,
            claims.sid.as_deref(),
        )
        .await
        .map_err(|_| ApiError::unauthorized())?
        {
            return Err(ApiError::session_invalidated());
        }

        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT username, role::text AS role, status::text AS status \
             FROM users WHERE id = $1",
        )
        .bind(claims.id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| ApiError::unauthorized())?;

        let Some((username, role, status)) = row else {
            return Err(ApiError::unauthorized());
        };
        if status != "active" {
            return Err(ApiError::account_banned());
        }

        Ok(AuthUser {
            id: claims.id,
            username,
            role,
            status,
            sid: claims.sid,
            iat: issued_at,
        })
    }
}

impl FromRequestParts<SharedAppState> for AdminAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedAppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if user.role != "admin" {
            return Err(ApiError::admin_required());
        }
        Ok(AdminAuth(user))
    }
}

impl FromRequestParts<SharedAppState> for UserOnlyAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedAppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if user.role == "admin" {
            return Err(ApiError::user_only());
        }
        Ok(UserOnlyAuth(user))
    }
}

/// Sign an access token (routes/auth.ts parity): payload {id, username, role, sid},
/// HS256, 30-minute expiry.
pub fn sign_access_token(
    state: &SharedAppState,
    id: i32,
    username: &str,
    role: &str,
    sid: &str,
) -> Result<String, ApiError> {
    use jsonwebtoken::EncodingKey;
    use serde::Serialize;

    #[derive(Serialize)]
    struct AccessTokenClaims<'a> {
        id: i32,
        username: &'a str,
        role: &'a str,
        sid: &'a str,
        iat: i64,
        exp: i64,
    }

    let now = chrono::Utc::now().timestamp();
    let claims = AccessTokenClaims {
        id,
        username,
        role,
        sid,
        iat: now,
        exp: now + crate::config::ACCESS_TOKEN_LIFETIME_SECONDS,
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::internal(format!("jwt sign failed: {e}")))
}
