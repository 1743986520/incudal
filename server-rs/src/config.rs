//! Environment configuration. Variable names and defaults mirror the TS server.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

pub const REFRESH_TOKEN_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60; // 30 days
pub const ACCESS_TOKEN_LIFETIME_SECONDS: i64 = 30 * 60; // 30 minutes

#[derive(Debug, Clone)]
pub struct Config {
    pub is_production: bool,
    pub port: u16,
    pub host: String,
    pub log_level: String,
    pub body_limit: usize,
    pub jwt_secret: String,
    pub cookie_secret: String,
    /// sha256(ENCRYPTION_KEY), falling back to sha256(JWT_SECRET) in development.
    pub encryption_key: [u8; 32],
    pub database_url: String,
    pub redis_url: Option<String>,
    pub frontend_urls: Vec<String>,
    pub cookie_domain: Option<String>,
    pub require_telegram_binding: bool,
    pub enable_hsts: bool,
    pub db_pool_max: u32,
    pub db_acquire_timeout: Duration,
    pub db_idle_timeout: Duration,
    pub db_max_connections_lifetime: Option<Duration>,
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn env_or(key: &str, default: &str) -> String {
    env(key).unwrap_or_else(|| default.to_string())
}

static RUNTIME_IS_PRODUCTION: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Cheap global used by error serialization to hide 5xx messages in production
/// (mirrors the TS setErrorHandler check on NODE_ENV).
pub fn runtime_is_production() -> bool {
    *RUNTIME_IS_PRODUCTION.get().unwrap_or(&false)
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let is_production = env_or("NODE_ENV", "development") == "production";
        let database_url = env("DATABASE_URL")
            .context("DATABASE_URL is required (e.g. postgres://user:pass@host:5432/incudal)")?;
        let jwt_secret = if is_production {
            env("JWT_SECRET")
                .context("JWT_SECRET is required in production")?
        } else {
            env_or("JWT_SECRET", "dev-secret-change-in-production")
        };
        let cookie_secret = if is_production {
            env("COOKIE_SECRET")
                .context("COOKIE_SECRET is required in production")?
        } else {
            env_or("COOKIE_SECRET", "cookie-secret-change-in-production")
        };
        let encryption_secret = if is_production {
            env("ENCRYPTION_KEY")
                .context("ENCRYPTION_KEY is required in production")?
        } else {
            env("ENCRYPTION_KEY").unwrap_or_else(|| jwt_secret.clone())
        };
        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&Sha256::digest(encryption_secret.as_bytes()));

        let frontend_urls = env("FRONTEND_URL")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().trim_end_matches('/').to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let _ = RUNTIME_IS_PRODUCTION.set(is_production);

        Ok(Self {
            is_production,
            port: env_or("PORT", "3000").parse().context("invalid PORT")?,
            host: env_or("HOST", "127.0.0.1"),
            log_level: env_or("LOG_LEVEL", "info"),
            body_limit: env_or("BODY_LIMIT", "10485760").parse().context("invalid BODY_LIMIT")?,
            jwt_secret,
            cookie_secret,
            encryption_key,
            database_url,
            redis_url: env("REDIS_URL"),
            frontend_urls,
            cookie_domain: env("COOKIE_DOMAIN"),
            require_telegram_binding: matches!(
                env("REQUIRE_TELEGRAM_BINDING").as_deref(),
                Some("true") | Some("1")
            ),
            enable_hsts: env_or("ENABLE_HSTS", "false") == "true",
            db_pool_max: env_or("DB_POOL_MAX", "20").parse().context("invalid DB_POOL_MAX")?,
            db_acquire_timeout: Duration::from_millis(
                env_or("DB_CONNECTION_TIMEOUT", "5000").parse().unwrap_or(5000),
            ),
            db_idle_timeout: Duration::from_millis(
                env_or("DB_IDLE_TIMEOUT", "30000").parse().unwrap_or(30000),
            ),
            db_max_connections_lifetime: None,
        })
    }

    /// Mirrors lib/security-config.ts checkJwtConfig(): production secrets must be
    /// strong; development falls back to known dev secrets.
    pub fn check_jwt_config(config: &Config) -> Result<()> {
        if !config.is_production {
            return Ok(());
        }
        let secret = &config.jwt_secret;
        if secret.len() < 32 {
            bail!("JWT_SECRET must be at least 32 characters in production");
        }
        let insecure = [
            "dev-secret",
            "change-in-production",
            "changeme",
            "secret",
            "password",
            "123456",
        ];
        let lower = secret.to_lowercase();
        if insecure.iter().any(|p| lower.contains(p)) {
            bail!("JWT_SECRET looks insecure in production");
        }
        let classes = [
            secret.chars().any(|c| c.is_ascii_lowercase()),
            secret.chars().any(|c| c.is_ascii_uppercase()),
            secret.chars().any(|c| c.is_ascii_digit()),
            secret.chars().any(|c| !c.is_ascii_alphanumeric()),
        ];
        if classes.iter().filter(|c| **c).count() < 3 {
            bail!("JWT_SECRET must contain at least 3 character classes in production");
        }
        Ok(())
    }

    /// Mirrors getCookieSecure().
    pub fn cookie_secure(&self) -> bool {
        self.is_production || env_or("COOKIE_SECURE", "false") == "true"
    }

    /// Mirrors getCookieSameSite(): COOKIE_SAME_SITE override with none->lax
    /// downgrade when not secure, else production=lax / development=strict.
    pub fn cookie_same_site(&self) -> cookie::SameSite {
        let requested = env("COOKIE_SAME_SITE")
            .map(|v| v.to_lowercase())
            .and_then(|v| match v.as_str() {
                "strict" => Some(cookie::SameSite::Strict),
                "lax" => Some(cookie::SameSite::Lax),
                "none" => Some(cookie::SameSite::None),
                _ => None,
            });
        if let Some(site) = requested {
            if matches!(site, cookie::SameSite::None) && !self.cookie_secure() {
                return cookie::SameSite::Lax;
            }
            return site;
        }
        if self.is_production {
            cookie::SameSite::Lax
        } else {
            cookie::SameSite::Strict
        }
    }

    /// Set-Cookie header value for the refresh token cookie.
    pub fn refresh_token_cookie(&self, token: &str) -> String {
        self.build_cookie(token, REFRESH_TOKEN_LIFETIME_SECONDS, "/")
    }

    /// Set-Cookie header value that clears the refresh token cookie.
    pub fn clear_refresh_token_cookie(&self) -> String {
        self.build_cookie("", -1, "/")
    }

    fn build_cookie(&self, value: &str, max_age: i64, path: &str) -> String {
        let mut builder = cookie::CookieBuilder::new("refreshToken", value)
            .http_only(true)
            .secure(self.cookie_secure())
            .same_site(self.cookie_same_site())
            .path(path.to_string())
            .max_age(cookie::time::Duration::seconds(max_age));
        if let Some(domain) = &self.cookie_domain {
            builder = builder.domain(domain.clone());
        }
        let c = builder.build();
        c.to_string()
    }
}
