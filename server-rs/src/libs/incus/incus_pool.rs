//! Incus client connection pool (high-availability version).
//! Port of lib/incus/incus-pool.ts.
//!
//! Features kept from the TS server:
//! 1. connection cache reuse (one client per host id);
//! 2. automatic reconnect when a pooled client lost its connection;
//! 3. connect de-duplication via per-host connecting locks;
//! 4. health bookkeeping (response time / error counts) synced into
//!    `host_health`;
//! 5. expiry cleanup of clients unused for 30 minutes. The TS runs a
//!    background interval every 5 minutes; the Rust pool sweeps lazily on
//!    `get_incus_client` (at most once per 5 minutes) because a dropped
//!    reqwest client releases its sockets immediately anyway.
//!
//! The TS pool is a module-global Map; the Rust port is a struct meant to be
//! shared via `Arc` (it will live in AppState later), with the same Default
//! construction.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{watch, Mutex as AsyncMutex};

use crate::libs::incus::host_health::{record_host_error, record_host_success};
use crate::libs::incus::incus_client::{IncusClient, IncusClientOptions, IncusError};

/// Connection expiry time (30 minutes unused).
const CONNECTION_EXPIRE_MS: i64 = 30 * 60 * 1000;
/// Cleanup sweep cadence (every 5 minutes).
const CLEANUP_INTERVAL_MS: i64 = 5 * 60 * 1000;

/// The host fields the pool reads. Mirrors the `Host` interface in
/// incus-pool.ts. `cert_path`/`key_path` are accepted for API compatibility
/// but never used: the client always authenticates with the server-managed
/// panel certificate pair.
#[derive(Debug, Clone, Default)]
pub struct PoolHost {
    pub id: i64,
    pub url: String,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub server_certificate: Option<String>,
    pub server_fingerprint: Option<String>,
    pub allow_private_network: bool,
}

#[derive(Debug)]
struct PooledClient {
    client: Arc<IncusClient>,
    last_used: i64,
    last_response_time: i64,
    error_count: i64,
}

/// Mirrors the per-key value of `getPoolStatus()`.
#[derive(Debug, Clone)]
pub struct PoolStatusEntry {
    pub connected: bool,
    pub last_used: i64,
    pub last_response_time: i64,
    pub error_count: i64,
}

struct ConnectSlot {
    result: Arc<Mutex<Option<Result<Arc<IncusClient>, IncusError>>>>,
    done: watch::Receiver<bool>,
}

async fn await_slot(slot: &ConnectSlot) -> Result<Arc<IncusClient>, IncusError> {
    let mut done = slot.done.clone();
    while !*done.borrow_and_update() {
        if done.changed().await.is_err() {
            break;
        }
    }
    let guard = slot
        .result
        .lock()
        .expect("connect slot result poisoned")
        .clone();
    guard.unwrap_or_else(|| Err(IncusError::Other("connection attempt dropped".to_string())))
}

async fn finish_slot(
    connecting: &AsyncMutex<HashMap<String, ConnectSlot>>,
    key: &str,
    result_cell: &Arc<Mutex<Option<Result<Arc<IncusClient>, IncusError>>>>,
    outcome: &Result<Arc<IncusClient>, IncusError>,
    tx: watch::Sender<bool>,
) {
    *result_cell.lock().expect("connect slot result poisoned") = Some(match outcome {
        Ok(client) => Ok(client.clone()),
        Err(err) => Err(err.clone()),
    });
    let _ = tx.send(true);
    connecting.lock().await.remove(key);
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Mirrors the module-global pool state in incus-pool.ts.
pub struct IncusClientPool {
    clients: AsyncMutex<HashMap<String, PooledClient>>,
    connecting: AsyncMutex<HashMap<String, ConnectSlot>>,
    last_sweep_ms: AtomicI64,
}

impl Default for IncusClientPool {
    fn default() -> Self {
        Self::new()
    }
}

impl IncusClientPool {
    pub fn new() -> Self {
        Self {
            clients: AsyncMutex::new(HashMap::new()),
            connecting: AsyncMutex::new(HashMap::new()),
            last_sweep_ms: AtomicI64::new(0),
        }
    }

    /// Mirrors `ensureCleanupStarted`: expire connections unused for 30
    /// minutes. Runs at most once per 5-minute window (see module docs).
    async fn sweep_expired_if_due(&self) {
        let now = now_ms();
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        if now - last < CLEANUP_INTERVAL_MS {
            return;
        }
        self.last_sweep_ms.store(now, Ordering::Relaxed);

        let expired: Vec<String> = {
            let clients = self.clients.lock().await;
            clients
                .iter()
                .filter(|(_, pooled)| now - pooled.last_used > CONNECTION_EXPIRE_MS)
                .map(|(key, _)| key.clone())
                .collect()
        };

        for key in expired {
            // Remove from the pool first to avoid races with concurrent users
            // of the connection while it is being closed.
            let mut clients = self.clients.lock().await;
            if let Some(pooled) = clients.remove(&key) {
                pooled.client.close();
                tracing::info!("[IncusPool] Closed expired connection: {key}");
            }
        }
    }

    /// Mirrors `getIncusClient`: get or create the client for a host, with
    /// concurrent-connect protection.
    pub async fn get_incus_client(&self, host: &PoolHost) -> Result<Arc<IncusClient>, IncusError> {
        self.sweep_expired_if_due().await;
        let key = host.id.to_string();
        let now = now_ms();

        // An in-flight connection attempt for this host? Await it.
        {
            let connecting = self.connecting.lock().await;
            if let Some(slot) = connecting.get(&key) {
                return await_slot(slot).await;
            }
        }

        let mut clients = self.clients.lock().await;
        if let Some(pooled) = clients.get_mut(&key) {
            pooled.last_used = now;
            if pooled.client.is_connected() {
                return Ok(pooled.client.clone());
            }

            // Reconnect with lock protection (TS reconnects the same client
            // instance; error count resets on success, bumps on failure).
            drop(clients);
            let (tx, rx) = watch::channel(false);
            let result_cell: Arc<Mutex<Option<Result<Arc<IncusClient>, IncusError>>>> =
                Arc::new(Mutex::new(None));
            {
                let mut connecting = self.connecting.lock().await;
                if let Some(existing) = connecting.get(&key) {
                    return await_slot(existing).await;
                }
                connecting.insert(
                    key.clone(),
                    ConnectSlot {
                        result: result_cell.clone(),
                        done: rx,
                    },
                );
            }

            let outcome = async {
                let client = {
                    let clients = self.clients.lock().await;
                    clients.get(&key).map(|pooled| pooled.client.clone())
                };
                let Some(client) = client else {
                    return Err(IncusError::Other(
                        "pooled client vanished during reconnect".to_string(),
                    ));
                };
                match client.connect().await {
                    Ok(_) => {
                        let mut clients = self.clients.lock().await;
                        if let Some(pooled) = clients.get_mut(&key) {
                            pooled.error_count = 0;
                        }
                        Ok(client)
                    }
                    Err(err) => {
                        let mut clients = self.clients.lock().await;
                        if let Some(pooled) = clients.get_mut(&key) {
                            pooled.error_count += 1;
                        }
                        Err(err)
                    }
                }
            }
            .await;

            finish_slot(&self.connecting, &key, &result_cell, &outcome, tx).await;
            return outcome;
        }

        // Create a new connection with lock protection.
        drop(clients);
        let (tx, rx) = watch::channel(false);
        let result_cell: Arc<Mutex<Option<Result<Arc<IncusClient>, IncusError>>>> =
            Arc::new(Mutex::new(None));
        {
            let mut connecting = self.connecting.lock().await;
            if let Some(existing) = connecting.get(&key) {
                return await_slot(existing).await;
            }
            connecting.insert(
                key.clone(),
                ConnectSlot {
                    result: result_cell.clone(),
                    done: rx,
                },
            );
        }

        let connect_key = key.clone();
        let host_url = host.url.clone();
        let server_certificate = host.server_certificate.clone();
        let server_fingerprint = host.server_fingerprint.clone();
        let allow_private_network = host.allow_private_network;
        let outcome = async move {
            let client = Arc::new(IncusClient::new(&IncusClientOptions {
                url: host_url,
                cert_path: None,
                key_path: None,
                ca_path: None,
                server_certificate,
                server_fingerprint,
                allow_private_network,
            })?);
            client.connect().await?;
            let mut clients = self.clients.lock().await;
            clients.insert(
                connect_key,
                PooledClient {
                    client: client.clone(),
                    last_used: now_ms(),
                    last_response_time: 0,
                    error_count: 0,
                },
            );
            Ok(client)
        }
        .await;

        finish_slot(&self.connecting, &key, &result_cell, &outcome, tx).await;
        outcome
    }

    /// Alias mirroring `getIncusClientFromPool` (used by the traffic scheduler
    /// and other services).
    pub async fn get_incus_client_from_pool(
        &self,
        host: &PoolHost,
    ) -> Result<Arc<IncusClient>, IncusError> {
        self.get_incus_client(host).await
    }

    /// Mirrors `updateClientResponseTime`: performance bookkeeping that also
    /// resets the error count and syncs into the shared health module.
    pub async fn update_client_response_time(&self, host_id: i64, response_time: i64) {
        let key = host_id.to_string();
        let mut clients = self.clients.lock().await;
        if let Some(pooled) = clients.get_mut(&key) {
            pooled.last_response_time = response_time;
            pooled.last_used = now_ms();
            pooled.error_count = 0;
        }
        drop(clients);
        record_host_success(host_id, response_time);
    }

    /// Mirrors `recordClientError`.
    pub async fn record_client_error(&self, host_id: i64) {
        let key = host_id.to_string();
        let mut clients = self.clients.lock().await;
        if let Some(pooled) = clients.get_mut(&key) {
            pooled.error_count += 1;
        }
        drop(clients);
        record_host_error(host_id);
    }

    /// Mirrors `getPoolStatus` (for monitoring).
    pub async fn get_pool_status(&self) -> HashMap<String, PoolStatusEntry> {
        let clients = self.clients.lock().await;
        clients
            .iter()
            .map(|(key, pooled)| {
                (
                    key.clone(),
                    PoolStatusEntry {
                        connected: pooled.client.is_connected(),
                        last_used: pooled.last_used,
                        last_response_time: pooled.last_response_time,
                        error_count: pooled.error_count,
                    },
                )
            })
            .collect()
    }

    /// Mirrors `removeIncusClient`.
    pub async fn remove_incus_client(&self, host_id: i64) {
        let key = host_id.to_string();
        let mut clients = self.clients.lock().await;
        if let Some(pooled) = clients.remove(&key) {
            pooled.client.close();
        }
    }

    /// Mirrors `closeAllClients` (stops the cleanup sweeps).
    pub async fn close_all_clients(&self) {
        self.last_sweep_ms.store(i64::MAX, Ordering::Relaxed);
        let mut clients = self.clients.lock().await;
        for pooled in clients.values() {
            pooled.client.close();
        }
        clients.clear();
    }
}
