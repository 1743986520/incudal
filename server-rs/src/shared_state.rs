//! Shared cross-replica state: Redis when REDIS_URL is set, bounded in-memory
//! fallback otherwise (mirrors lib/shared-state.ts semantics).

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub enum SharedState {
    Redis(redis::aio::ConnectionManager),
    Memory(MemoryStore),
}

#[derive(Clone)]
pub struct MemoryStore {
    entries: std::sync::Arc<tokio::sync::Mutex<HashMap<String, (String, Option<Instant>)>>>,
}

impl MemoryStore {
    fn new() -> Self {
        Self {
            entries: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    fn expired(expires_at: Option<Instant>) -> bool {
        matches!(expires_at, Some(t) if t <= Instant::now())
    }
}

impl SharedState {
    pub async fn connect(redis_url: Option<&str>) -> Result<Self, anyhow::Error> {
        if let Some(url) = redis_url {
            if let Ok(client) = redis::Client::open(url) {
                if let Ok(conn) = redis::aio::ConnectionManager::new(client).await {
                    return Ok(SharedState::Redis(conn));
                }
            }
        }
        Ok(SharedState::Memory(MemoryStore::new()))
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        match self {
            SharedState::Redis(conn) => {
                let mut conn = conn.clone();
                redis::cmd("GET")
                    .arg(key)
                    .query_async::<Option<String>>(&mut conn)
                    .await
                    .ok()
                    .flatten()
            }
            SharedState::Memory(store) => {
                let mut entries = store.entries.lock().await;
                match entries.get(key) {
                    Some((v, exp)) if !MemoryStore::expired(*exp) => Some(v.clone()),
                    Some(_) => {
                        entries.remove(key);
                        None
                    }
                    None => None,
                }
            }
        }
    }

    pub async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) {
        match self {
            SharedState::Redis(conn) => {
                let mut conn = conn.clone();
                let mut cmd = redis::cmd("SET");
                cmd.arg(key).arg(value);
                if let Some(ttl) = ttl {
                    cmd.arg("EX").arg(ttl.as_secs().max(1));
                }
                let _: Result<(), _> = cmd.query_async(&mut conn).await;
            }
            SharedState::Memory(store) => {
                let mut entries = store.entries.lock().await;
                let expires_at = ttl.map(|t| Instant::now() + t);
                entries.insert(key.to_string(), (value.to_string(), expires_at));
            }
        }
    }

    pub async fn del(&self, key: &str) {
        match self {
            SharedState::Redis(conn) => {
                let mut conn = conn.clone();
                let _: Result<(), _> = redis::cmd("DEL").arg(key).query_async(&mut conn).await;
            }
            SharedState::Memory(store) => {
                store.entries.lock().await.remove(key);
            }
        }
    }

    /// Delete every key with the given prefix (SCAN-free in-memory; SCAN+DEL on Redis).
    pub async fn del_prefix(&self, prefix: &str) {
        match self {
            SharedState::Redis(conn) => {
                let mut conn = conn.clone();
                let mut cursor = String::from("0");
                loop {
                    let (next, keys): (String, Vec<String>) = match redis::cmd("SCAN")
                        .arg(&cursor)
                        .arg("MATCH")
                        .arg(format!("{prefix}*"))
                        .arg("COUNT")
                        .arg(200)
                        .query_async(&mut conn)
                        .await
                    {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                    if !keys.is_empty() {
                        let _: Result<(), _> = redis::cmd("DEL").arg(keys).query_async(&mut conn).await;
                    }
                    cursor = next;
                    if cursor == "0" {
                        break;
                    }
                }
            }
            SharedState::Memory(store) => {
                let mut entries = store.entries.lock().await;
                let stale: Vec<String> = entries
                    .keys()
                    .filter(|k| k.starts_with(prefix))
                    .cloned()
                    .collect();
                for k in stale {
                    entries.remove(&k);
                }
            }
        }
    }

    /// Atomic GETDEL (one-time token consumption; fail-closed on Redis errors).
    pub async fn consume(&self, key: &str) -> Option<String> {
        match self {
            SharedState::Redis(conn) => {
                let mut conn = conn.clone();
                redis::cmd("GETDEL")
                    .arg(key)
                    .query_async::<Option<String>>(&mut conn)
                    .await
                    .ok()
                    .flatten()
            }
            SharedState::Memory(store) => {
                let mut entries = store.entries.lock().await;
                match entries.get(key) {
                    Some((v, exp)) if !MemoryStore::expired(*exp) => {
                        Some(v.clone()).inspect(|_| {
                            entries.remove(key);
                        })
                    }
                    Some(_) => {
                        entries.remove(key);
                        None
                    }
                    None => None,
                }
            }
        }
    }

    /// SET NX (add-once anti-replay). Returns true when the key was newly set.
    pub async fn add_once(&self, key: &str, value: &str, ttl: Duration) -> bool {
        match self {
            SharedState::Redis(conn) => {
                let mut conn = conn.clone();
                redis::cmd("SET")
                    .arg(key)
                    .arg(value)
                    .arg("EX")
                    .arg(ttl.as_secs().max(1))
                    .arg("NX")
                    .query_async::<Option<String>>(&mut conn)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
            }
            SharedState::Memory(store) => {
                let mut entries = store.entries.lock().await;
                match entries.get(key) {
                    Some((_, exp)) if !MemoryStore::expired(*exp) => false,
                    _ => {
                        entries.insert(
                            key.to_string(),
                            (value.to_string(), Some(Instant::now() + ttl)),
                        );
                        true
                    }
                }
            }
        }
    }

    /// Fixed-window counter for the rate limiter: INCR key, EXPIRE window on first hit.
    /// Returns (count, window_seconds).
    pub async fn increment_window(&self, key: &str, window: Duration) -> (i64, u64) {
        let window_secs = window.as_secs().max(1);
        match self {
            SharedState::Redis(conn) => {
                let mut conn = conn.clone();
                match redis::pipe()
                    .atomic()
                    .cmd("INCR").arg(key)
                    .cmd("EXPIRE").arg(key).arg(window_secs).arg("NX")
                    .query_async::<(i64, i64)>(&mut conn)
                    .await
                {
                    Ok((count, _)) => (count, window_secs),
                    Err(_) => (1, window_secs), // fail open on redis errors, like TS allowList fallbacks
                }
            }
            SharedState::Memory(store) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let bucket = now / window_secs;
                let bucket_key = format!("{key}:{bucket}");
                let mut entries = store.entries.lock().await;
                let entry = entries
                    .entry(bucket_key)
                    .or_insert_with(|| ("0".to_string(), Some(Instant::now() + window)));
                let count: i64 = entry.0.parse().unwrap_or(0) + 1;
                entry.0 = count.to_string();
                entry.1 = Some(Instant::now() + window);
                (count, window_secs)
            }
        }
    }
}
