//! Unified host health tracking.
//! Port of lib/incus/host-health.ts. The TS module keeps a module-global
//! health cache shared by every caller; the Rust port mirrors that with a
//! global Lazy mutex-guarded map.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

const ERROR_THRESHOLD: i64 = 3; // consecutive error threshold
const RECOVERY_COOLDOWN_MS: u128 = 5 * 60 * 1000; // 5 minute recovery cooldown

#[derive(Debug, Clone, Default)]
pub struct HostHealth {
    /// Most recent response time (ms).
    pub last_response_time: i64,
    /// Consecutive error count.
    pub error_count: i64,
    /// Last check timestamp (ms since epoch).
    pub last_check: u128,
    /// Last success timestamp (ms since epoch).
    pub last_success: u128,
}

static HOST_HEALTH_CACHE: Lazy<std::sync::Mutex<HashMap<i64, HostHealth>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn with_cache<T>(f: impl FnOnce(&mut HashMap<i64, HostHealth>) -> T) -> T {
    let mut cache = HOST_HEALTH_CACHE.lock().expect("host health cache poisoned");
    f(&mut cache)
}

/// Mirrors `isHostHealthy`.
pub fn is_host_healthy(host_id: i64) -> bool {
    with_cache(|cache| {
        let Some(health) = cache.get(&host_id) else {
            return true;
        };
        if health.error_count >= ERROR_THRESHOLD {
            // Retry after the cooldown window.
            if now_ms() - health.last_check > RECOVERY_COOLDOWN_MS {
                if let Some(health) = cache.get_mut(&host_id) {
                    health.error_count = 0;
                }
                return true;
            }
            return false;
        }
        true
    })
}

/// Mirrors `recordHostSuccess`.
pub fn record_host_success(host_id: i64, response_time_ms: i64) {
    let now = now_ms();
    with_cache(|cache| {
        let health = cache.entry(host_id).or_insert(HostHealth {
            last_response_time: 0,
            error_count: 0,
            last_check: now,
            last_success: now,
        });
        health.last_response_time = response_time_ms;
        health.error_count = 0;
        health.last_check = now;
        health.last_success = now;
    });
}

/// Mirrors `recordHostError`.
pub fn record_host_error(host_id: i64) {
    let now = now_ms();
    with_cache(|cache| {
        let health = cache.entry(host_id).or_insert(HostHealth {
            last_response_time: 0,
            error_count: 0,
            last_check: now,
            last_success: 0,
        });
        health.error_count += 1;
        health.last_check = now;
    });
}

/// Mirrors `getHostHealth`.
pub fn get_host_health(host_id: i64) -> Option<HostHealth> {
    with_cache(|cache| cache.get(&host_id).cloned())
}

/// Mirrors `getAllHostHealth`.
pub fn get_all_host_health() -> HashMap<i64, HostHealth> {
    with_cache(|cache| cache.clone())
}

/// Mirrors `getUnhealthyHosts`.
pub fn get_unhealthy_hosts() -> Vec<i64> {
    with_cache(|cache| {
        cache
            .iter()
            .filter(|(_, health)| health.error_count >= ERROR_THRESHOLD)
            .map(|(host_id, _)| *host_id)
            .collect()
    })
}

/// Mirrors `clearHostHealth` (called when a host is deleted).
pub fn clear_host_health(host_id: i64) {
    with_cache(|cache| {
        cache.remove(&host_id);
    });
}

/// Mirrors `getHealthSummary`.
#[derive(Debug, Clone, Default)]
pub struct HealthSummary {
    pub total_hosts: usize,
    pub healthy_hosts: usize,
    pub unhealthy_hosts: usize,
    pub avg_response_time: i64,
}

pub fn get_health_summary() -> HealthSummary {
    let now_total = with_cache(|cache| {
        let mut healthy = 0usize;
        let mut unhealthy = 0usize;
        let mut total_response_time: i64 = 0;
        let mut response_count = 0usize;

        for health in cache.values() {
            if health.error_count >= ERROR_THRESHOLD {
                unhealthy += 1;
            } else {
                healthy += 1;
            }
            if health.last_response_time > 0 {
                total_response_time += health.last_response_time;
                response_count += 1;
            }
        }

        (
            cache.len(),
            healthy,
            unhealthy,
            if response_count > 0 {
                (total_response_time / response_count as i64).max(0)
            } else {
                0
            },
        )
    });

    HealthSummary {
        total_hosts: now_total.0,
        healthy_hosts: now_total.1,
        unhealthy_hosts: now_total.2,
        avg_response_time: now_total.3,
    }
}
