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
}

pub type LoginLockMap = std::collections::HashMap<String, LoginLockState>;

#[derive(Debug, Clone)]
pub struct LoginLockState {
    pub failures: Vec<std::time::Instant>,
    pub locked_until: Option<std::time::Instant>,
}

impl AppState {
    pub fn new(config: Arc<Config>, db: PgPool, shared: SharedState) -> Self {
        Self {
            config,
            db,
            shared,
            login_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

pub type SharedAppState = Arc<AppState>;
