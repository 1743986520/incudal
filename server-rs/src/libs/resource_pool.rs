//! 签到/资源池共用层 — ports of lib/distributed-lock.ts (DB distributed_locks
//! table), db/points.ts addPoints, db/resource-pool.ts pool helpers,
//! db/checkin.ts reward randomization + Beijing-midnight check, plus the
//! host/instance resource adjust helpers shared by checkin + resource-pool.

use chrono::{DateTime, Datelike, FixedOffset, TimeZone, Utc};
use rand::Rng;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::state::SharedAppState;

// ==================== distributed lock (lib/distributed-lock.ts) ====================

fn generate_owner_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// acquireLock: insert-or-steal-expired loop until waitTimeout.
pub async fn acquire_lock(
    pool: &PgPool,
    lock_key: &str,
    expire_ms: i64,
    wait_timeout_ms: u64,
) -> Result<Option<String>, sqlx::Error> {
    let owner_id = generate_owner_id();
    let start = std::time::Instant::now();
    loop {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::milliseconds(expire_ms);
        let row: Option<(i32,)> = sqlx::query_as(
            "INSERT INTO distributed_locks (lock_key, owner_id, acquired_at, expires_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (lock_key) DO UPDATE SET \
               owner_id = EXCLUDED.owner_id, acquired_at = EXCLUDED.acquired_at, \
               expires_at = EXCLUDED.expires_at \
             WHERE distributed_locks.expires_at <= $3 OR distributed_locks.owner_id = EXCLUDED.owner_id \
             RETURNING id",
        )
        .bind(lock_key)
        .bind(&owner_id)
        .bind(now)
        .bind(expires_at)
        .fetch_optional(pool)
        .await?;
        if row.is_some() {
            return Ok(Some(owner_id));
        }
        if start.elapsed().as_millis() as u64 >= wait_timeout_ms {
            return Ok(None);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

pub async fn release_lock(pool: &PgPool, lock_key: &str, owner_id: &str) -> bool {
    let result = sqlx::query("DELETE FROM distributed_locks WHERE lock_key = $1 AND owner_id = $2")
        .bind(lock_key)
        .bind(owner_id)
        .execute(pool)
        .await;
    matches!(&result, Ok(r) if r.rows_affected() > 0)
}

pub async fn extend_lock(pool: &PgPool, lock_key: &str, owner_id: &str, extend_ms: i64) -> bool {
    let result = sqlx::query(
        "UPDATE distributed_locks SET expires_at = $3 \
         WHERE lock_key = $1 AND owner_id = $2 AND expires_at > now()",
    )
    .bind(lock_key)
    .bind(owner_id)
    .bind(Utc::now() + chrono::Duration::milliseconds(extend_ms))
    .execute(pool)
    .await;
    matches!(&result, Ok(r) if r.rows_affected() > 0)
}

// ==================== points (db/points.ts addPoints) ====================

/// addPoints: tx upsert + increment + ledger row. Returns new balance.
pub async fn add_points(
    pool: &PgPool,
    user_id: i32,
    amount: i64,
    log_type: &str,
    related_id: Option<i32>,
    remark: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let before: i64 = sqlx::query_scalar(
        "INSERT INTO user_points (user_id) VALUES ($1) \
         ON CONFLICT (user_id) DO NOTHING; \
         SELECT points FROM user_points WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let after: i64 = sqlx::query_scalar(
        "UPDATE user_points SET points = points + $2, total_earned = total_earned + $2 \
         WHERE user_id = $1 RETURNING points",
    )
    .bind(user_id)
    .bind(amount)
    .fetch_one(&mut *tx)
    .await?;
    // total_earned also increments for negative amounts in addPoints (TS does
    // so unconditionally for the checkin/redeem paths).
    sqlx::query(
        "INSERT INTO points_logs (user_id, type, amount, points_before, points_after, related_id, remark) \
         VALUES ($1, $2::\"PointsLogType\", $3, $4, $5, $6, $7)",
    )
    .bind(user_id)
    .bind(log_type)
    .bind(amount)
    .bind(before)
    .bind(after)
    .bind(related_id)
    .bind(remark)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(after)
}

// ==================== reward randomization (db/checkin.ts) ====================

/// CODE_VALUES for c/r/d/t (points fixed via bonus, never random).
pub fn randomize_reward() -> (&'static str, i32) {
    const TYPES: [(&str, &[i32]); 4] = [
        ("c", &[1, 2, 3, 5]),
        ("r", &[2, 4, 6, 12]),
        ("d", &[16, 32, 64, 128]),
        ("t", &[1, 2, 3, 5]),
    ];
    let mut rng = rand::thread_rng();
    let (t, values) = TYPES[rng.gen_range(0..TYPES.len())];
    let v = values[rng.gen_range(0..values.len())];
    (t, v)
}

fn beijing_midnight_of(date: DateTime<Utc>) -> DateTime<Utc> {
    let offset = FixedOffset::east_opt(8 * 3600).expect("valid offset");
    let local = date.with_timezone(&offset);
    let naive = local.date_naive();
    offset
        .with_ymd_and_hms(naive.year(), naive.month(), naive.day(), 0, 0, 0)
        .single()
        .unwrap_or(local)
        .with_timezone(&Utc)
}

pub fn beijing_midnight_now() -> DateTime<Utc> {
    beijing_midnight_of(Utc::now())
}

pub async fn has_checked_in_today(pool: &PgPool, user_id: i32) -> Result<bool, sqlx::Error> {
    let last: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_checkin_date FROM checkin_stats WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    match last {
        Some(last) if last <= Utc::now() => {
            Ok(beijing_midnight_of(last) == beijing_midnight_now())
        }
        _ => Ok(false),
    }
}

// ==================== resource pool (db/resource-pool.ts) ====================

fn pool_column(resource_type: &str) -> Option<&'static str> {
    match resource_type {
        "c" => Some("cpu"),
        "r" => Some("memory"),
        "d" => Some("disk"),
        "t" => Some("traffic"),
        _ => None,
    }
}

pub async fn get_user_resource_pool(pool: &PgPool, user_id: i32) -> Result<Value, sqlx::Error> {
    let row: (i32, i32, i32, i64) = sqlx::query_as(
        "INSERT INTO user_resource_pools (user_id) VALUES ($1) \
         ON CONFLICT (user_id) DO NOTHING; \
         SELECT cpu, memory, disk, traffic FROM user_resource_pools WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "cpu": row.0,
        "memory": row.1,
        "disk": row.2,
        "traffic": row.3,
    }))
}

/// addToResourcePool: upsert-increment + log row (action from caller).
pub async fn add_to_resource_pool(
    state: &SharedAppState,
    user_id: i32,
    resource_type: &str,
    amount: i64,
    action: &str,
    remark: Option<&str>,
) -> Result<(), sqlx::Error> {
    let Some(field) = pool_column(resource_type) else {
        return Err(sqlx::Error::Protocol(format!(
            "Invalid resource type: {resource_type}"
        )));
    };
    let mut tx = state.db.begin().await?;
    let traffic = field == "traffic";
    sqlx::query(&format!(
        "INSERT INTO user_resource_pools (user_id, {field}) VALUES ($1, $2) \
         ON CONFLICT (user_id) DO UPDATE SET {field} = user_resource_pools.{field} + $2"
    ))
    .bind(user_id)
    .bind(if traffic { amount } else { amount })
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO resource_pool_logs (user_id, action, resource_type, amount, remark) \
         VALUES ($1, $2::\"ResourcePoolAction\", $3::\"RedeemCodeType\", $4, $5)",
    )
    .bind(user_id)
    .bind(action)
    .bind(resource_type)
    .bind(amount)
    .bind(remark)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// deductFromResourcePool: conditional decrement + apply log; false when short.
pub async fn deduct_from_resource_pool(
    state: &SharedAppState,
    user_id: i32,
    resource_type: &str,
    amount: i64,
    instance_id: i32,
    remark: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let Some(field) = pool_column(resource_type) else {
        return Err(sqlx::Error::Protocol(format!(
            "Invalid resource type: {resource_type}"
        )));
    };
    let mut tx = state.db.begin().await?;
    let updated = sqlx::query(&format!(
        "UPDATE user_resource_pools SET {field} = {field} - $2 \
         WHERE user_id = $1 AND {field} >= $2"
    ))
    .bind(user_id)
    .bind(amount)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        let _ = tx.rollback().await;
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO resource_pool_logs (user_id, action, resource_type, amount, instance_id, remark) \
         VALUES ($1, 'apply', $2::\"RedeemCodeType\", $3, $4, $5)",
    )
    .bind(user_id)
    .bind(resource_type)
    .bind(-amount)
    .bind(instance_id)
    .bind(remark)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// db adjustHostResources: additive counter update.
pub async fn adjust_host_resources(
    state: &SharedAppState,
    host_id: i32,
    cpu: Option<i64>,
    memory: Option<i64>,
    disk: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE hosts SET \
         cpu_used = cpu_used + COALESCE($1, 0), \
         memory_used = memory_used + COALESCE($2, 0), \
         disk_used = disk_used + COALESCE($3, 0) \
         WHERE id = $4",
    )
    .bind(cpu.unwrap_or(0))
    .bind(memory.unwrap_or(0))
    .bind(disk.unwrap_or(0))
    .bind(host_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// db updateInstanceResources for cpu/memory/disk/traffic limit.
pub async fn update_instance_resources(
    state: &SharedAppState,
    instance_id: i32,
    cpu: Option<i32>,
    memory: Option<i32>,
    disk: Option<i32>,
    monthly_traffic_limit: Option<Option<i64>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE instances SET \
         cpu = COALESCE($1, cpu), \
         memory = COALESCE($2, memory), \
         disk = COALESCE($3, disk), \
         monthly_traffic_limit = CASE WHEN $5::boolean THEN $4 ELSE monthly_traffic_limit END, \
         version = version + 1 \
         WHERE id = $6",
    )
    .bind(cpu)
    .bind(memory)
    .bind(disk)
    .bind(monthly_traffic_limit.flatten())
    .bind(monthly_traffic_limit.is_some())
    .bind(instance_id)
    .execute(&state.db)
    .await?;
    Ok(())
}
