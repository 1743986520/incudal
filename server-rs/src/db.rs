//! PostgreSQL access. The Rust server talks to the exact same schema the Prisma
//! migration set produces (snake_case columns, PG enum types named verbatim after
//! the Prisma enums, e.g. "InstanceStatus").

use std::sync::Arc;

use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::warn;

use crate::config::Config;

pub async fn create_pool(config: &Config) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.db_pool_max)
        .min_connections(0)
        .acquire_timeout(config.db_acquire_timeout)
        .idle_timeout(Some(config.db_idle_timeout))
        .max_lifetime(config.db_max_connections_lifetime)
        .connect(&config.database_url)
        .await
}

/// Advisory-lock namespace constants mirrored from db/advisory-locks.ts.
pub mod advisory_lock_namespace {
    pub const HOST_TASK_CLAIM: i32 = 4101;
    pub const HOST_NOTIFICATION_EMAIL: i32 = 4102;
    pub const TRANSFER_CREATE: i32 = 4103;
    pub const REDEEM_CODE: i32 = 4104;
    pub const HOSTING_BALANCE_LOG: i32 = 4105;
    pub const INSTANCE_OPERATION: i32 = 4106;
    pub const USER_DESTROY_BILLING: i32 = 4107;
    pub const USER_ADMIN_ROLE: i32 = 4108;
    pub const USER_CREATE_EMAIL: i32 = 4109;
    pub const USER_BALANCE: i32 = 4110;
    pub const OFFICIAL_COUPON: i32 = 4111;
    pub const INSTANCE_TASK_CLAIM_LOCK_NAMESPACE: i32 = 4112;
    pub const INSTANCE_TASK_LEASE_NAMESPACE: i32 = 4113;
}

/// Blocking transaction-scoped advisory lock: SELECT pg_advisory_xact_lock(ns, key).
pub async fn advisory_transaction_lock(
    tx: &mut sqlx::PgConnection,
    namespace: i32,
    key: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1::int, $2::bigint)")
        .bind(namespace)
        .bind(key)
        .execute(tx)
        .await
        .map(|_| ())
}

/// Non-blocking variant: SELECT pg_try_advisory_xact_lock(ns, key).
/// Returns false when the lock is held elsewhere (maps to ADVISORY_LOCK_BUSY /
/// RESOURCE_BUSY upstream).
pub async fn try_advisory_transaction_lock(
    tx: &mut sqlx::PgConnection,
    namespace: i32,
    key: i64,
) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1::int, $2::bigint)")
        .bind(namespace)
        .bind(key)
        .fetch_one(tx)
        .await?;
    Ok(row.0)
}

pub const BALANCE_TX_RETRIES: usize = 3;

/// Serializable transaction with up to 3 retries on serialization failures /
/// deadlocks, jittered backoff (mirrors db/balance.ts runBalanceTransaction).
///
/// Usage inside an async handler:
/// ```ignore
/// let result = balance_tx!(&state.db, tx, {
///     let row = sqlx::query_as::<_, (Decimal,)>("SELECT balance FROM users WHERE id = $1 FOR UPDATE")
///         .bind(user_id)
///         .fetch_one(&mut *tx)
///         .await
///         .map_err(ApiError::from_sql)?;
///     Ok(row.0)
/// });
/// ```
/// The body must evaluate to `Result<T, ApiError>`; `?` and early `return`
/// inside the body roll the transaction back via drop. The whole block yields
/// `Result<T, ApiError>`.
#[macro_export]
macro_rules! balance_tx {
    ($pool:expr, $tx:ident, $body:expr) => {{
        let mut __attempt: usize = 0;
        loop {
            __attempt += 1;
            let mut $tx = match $pool.begin().await {
                Ok(t) => t,
                Err(err) => break Err($crate::error::ApiError::from_sql(err)),
            };
            if let Err(err) = sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                .execute(&mut *$tx)
                .await
            {
                break Err($crate::error::ApiError::from_sql(err));
            }
            let __result: Result<_, $crate::error::ApiError> = $body;
            match __result {
                Ok(v) => match $tx.commit().await {
                    Ok(()) => break Ok(v),
                    Err(err) => {
                        if __attempt < $crate::db::BALANCE_TX_RETRIES
                            && $crate::db::is_transient_commit_error(&err)
                        {
                            $crate::db::jittered_backoff(__attempt).await;
                            continue;
                        }
                        break Err($crate::error::ApiError::from_sql(err));
                    }
                },
                Err(e) => {
                    let _ = $tx.rollback().await;
                    if __attempt < $crate::db::BALANCE_TX_RETRIES && e.is_serialization_conflict() {
                        $crate::db::jittered_backoff(__attempt).await;
                        continue;
                    }
                    break Err(e);
                }
            }
        }
    }};
}

pub fn is_transient_commit_error(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db) => {
            let code = db.code().map(|c| c.into_owned()).unwrap_or_default();
            matches!(code.as_str(), "40001" | "40P01" | "08000" | "08003" | "08006")
        }
        _ => false,
    }
}

pub async fn jittered_backoff(attempt: usize) {
    let base = 40u64 * attempt as u64;
    let jitter = rand::random::<u64>() % (base.max(1));
    tokio::time::sleep(std::time::Duration::from_millis((base + jitter).min(160 * attempt as u64)))
        .await;
}

/// Detects transient Postgres errors worth retrying (mirrors
/// workers/db-failure-backoff.ts isTransientDatabaseError).
pub fn is_transient_db_error(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db) => {
            let code = db.code().map(|c| c.into_owned()).unwrap_or_default();
            matches!(
                code.as_str(),
                "40001" | "40P01" | "08000" | "08003" | "08006" | "57014" | "57P01" | "57P03"
            )
        }
        sqlx::Error::PoolTimedOut | sqlx::Error::Io(_) => true,
        _ => false,
    }
}

/// Warn-once helper used at startup in place of the TS normalizeLegacyNetworkModes
/// boot query (that migration is owned by the Prisma migration set).
pub fn warn_schema_note(note: &str) {
    warn!("{note}");
}
