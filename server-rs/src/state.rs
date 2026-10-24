use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;
use crate::shared_state::SharedState;

pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub shared: SharedState,
    /// In-memory login lockout state (mirrors lib/security.ts module-level maps;
    /// single-replica by design in the TS server too).
    pub login_locks: std::sync::Mutex<LoginLockMap>,
    /// Per-host Incus TLS client cache (mirrors the module-global pool in
    /// lib/incus/incus-pool.ts).
    pub incus_pool: Arc<crate::libs::incus::IncusClientPool>,
    /// reqwest client for outbound panel HTTP (geoip, turnstile, payment
    /// gateways, release downloads) — mirrors Node's global fetch/undici.
    pub http: reqwest::Client,
}

pub type LoginLockMap = std::collections::HashMap<String, LoginLockState>;

#[derive(Debug, Clone)]
pub struct LoginLockState {
    pub failures: Vec<std::time::Instant>,
    pub locked_until: Option<std::time::Instant>,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        db: PgPool,
        shared: SharedState,
        incus_pool: Arc<crate::libs::incus::IncusClientPool>,
    ) -> Self {
        Self {
            config,
            db,
            shared,
            login_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
            incus_pool,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client must build"),
        }
    }
}

pub type SharedAppState = Arc<AppState>;
