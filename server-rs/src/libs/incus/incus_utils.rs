//! Incus client utility functions.
//! Port of lib/incus/incus-utils.ts, plus the CPU allowance helper from
//! lib/cpu-allowance.ts that the instance config builders depend on.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::libs::incus::incus_client::{IncusClient, IncusError};
use crate::libs::incus::incus_execution_guard::{
    get_incus_execution_guard, throw_if_incus_execution_aborted,
};

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn sleep(ms: u64) -> impl std::future::Future<Output = ()> {
    tokio::time::sleep(Duration::from_millis(ms))
}

/// Mirrors `waitForOperation`: polls `/wait?timeout=10` until the operation
/// succeeds or fails. Default timeout 300s (5 minutes) like the TS.
pub async fn wait_for_operation(
    client: &IncusClient,
    operation_url: &str,
    timeout_ms: u64,
) -> Result<Value, IncusError> {
    let timeout_ms = if timeout_ms == 0 {
        300_000
    } else {
        timeout_ms
    };
    let start = now_ms();

    while now_ms() - start < u128::from(timeout_ms) {
        throw_if_incus_execution_aborted()?;
        // Boxed to break the request() -> wait_for_operation() -> request()
        // async recursion cycle (the TS call graph is recursive too).
        let op = Box::pin(client.request(
            "GET",
            &format!("{operation_url}/wait?timeout=10"),
            None,
            0,
        ))
        .await?;

        let status = op.get("status").and_then(Value::as_str).unwrap_or("");
        if status == "Success" {
            return Ok(op
                .get("metadata")
                .cloned()
                .filter(|m| !m.is_null())
                .unwrap_or(Value::Null));
        }

        if status == "Failure" {
            let message = op
                .get("err")
                .and_then(Value::as_str)
                .or_else(|| op.get("error").and_then(Value::as_str))
                .unwrap_or("操作失败");
            return Err(IncusError::Other(message.to_string()));
        }
    }

    Err(IncusError::Other(
        "Operation timeout (5 minutes)".to_string(),
    ))
}

/// Mirrors `waitForOperationLong`: long-polls `/wait?timeout=N` (up to 30s per
/// poll) with retry-on-transient-error semantics. Default timeout 600s.
pub async fn wait_for_operation_long(
    client: &IncusClient,
    operation_url: &str,
    timeout_ms: u64,
) -> Result<Value, IncusError> {
    let timeout_ms = if timeout_ms == 0 { 600_000 } else { timeout_ms };
    let start = now_ms();

    while now_ms() - start < u128::from(timeout_ms) {
        throw_if_incus_execution_aborted()?;
        // Wait up to 30 seconds per poll.
        let remaining_ms = timeout_ms as i128 - (now_ms() as i128 - start as i128);
        let wait_timeout = ((remaining_ms / 1000).min(30)).max(0) as i64;
        if wait_timeout <= 0 {
            break;
        }

        let wait_url = format!("{operation_url}/wait?timeout={wait_timeout}");
        let guard = get_incus_execution_guard();

        let send = client.request_raw_get(&wait_url, guard.as_ref());
        match send.await {
            Ok((_status, text, _peer)) => {
                let data: Value = match serde_json::from_str(&text) {
                    Ok(value) => value,
                    Err(_) => {
                        tracing::error!("[Incus] 解析响应失败: {}", truncate(&text, 200));
                        return Err(IncusError::Other(format!(
                            "无效的响应: {}",
                            truncate(&text, 100)
                        )));
                    }
                };

                let metadata = data.get("metadata");
                let op_status = metadata
                    .and_then(|m| m.get("status"))
                    .and_then(Value::as_str)
                    .or_else(|| data.get("status").and_then(Value::as_str));
                let op_status_code = metadata
                    .and_then(|m| m.get("status_code"))
                    .and_then(Value::as_i64)
                    .or_else(|| data.get("status_code").and_then(Value::as_i64));

                if op_status == Some("Success") || op_status_code == Some(200) {
                    return Ok(match metadata {
                        Some(m) if !m.is_null() => m.clone(),
                        _ => data,
                    });
                }

                if op_status == Some("Failure") || op_status_code.map(|c| c >= 400).unwrap_or(false)
                {
                    let message = metadata
                        .and_then(|m| m.get("err"))
                        .and_then(Value::as_str)
                        .or_else(|| data.get("error").and_then(Value::as_str))
                        .or_else(|| metadata.and_then(|m| m.get("error")).and_then(Value::as_str))
                        .unwrap_or("操作失败");
                    tracing::error!("[Incus] 操作失败: {message}");
                    return Err(IncusError::Other(message.to_string()));
                }
                // Still running, continue polling.
            }
            Err(err) => {
                let message = err.message().to_string();
                if message.contains("操作失败") || message.contains("Failure") {
                    return Err(err);
                }
                tracing::error!("[Incus] 轮询出错: {message}");
                // Brief pause before retry.
                sleep(2000).await;
            }
        }
    }

    Err(IncusError::Other(
        "Image download timeout (10 minutes)".to_string(),
    ))
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        let mut end = max;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}... (truncated, total: {} chars)", &text[..end], text.len())
    }
}

/// Mirrors `mapInstanceStatus`: Incus status -> system status compatible with
/// the Instance.status column ('creating'|'running'|'stopped'|'error'|'deleted').
pub fn map_instance_status(incus_status: &str) -> &'static str {
    match incus_status {
        "Running" => "running",
        "Stopped" => "stopped",
        // Frozen maps to stopped (unusable for the user either way).
        "Frozen" => "stopped",
        "Error" => "error",
        // Starting maps to creating (startup in progress).
        "Starting" => "creating",
        // Stopping maps to running (not fully stopped until the next sync).
        "Stopping" => "running",
        _ => "unknown",
    }
}

// ==================== CPU allowance (lib/cpu-allowance.ts) ====================

/// Mirrors `allowanceToCores`: <=100% means 1 core, otherwise ceil(n / 100).
pub fn allowance_to_cores(allowance: i64) -> i64 {
    if allowance <= 100 {
        1
    } else {
        (allowance + 99) / 100
    }
}

/// Mirrors `isValidAllowance` (min default 15, step 5).
pub fn is_valid_allowance(allowance: i64, min_allowance: i64, max_allowance: Option<i64>) -> bool {
    if allowance < min_allowance {
        return false;
    }
    if let Some(max) = max_allowance {
        if allowance > max {
            return false;
        }
    }
    allowance % 5 == 0
}

/// Mirrors `normalizeAllowance`.
pub fn normalize_allowance(allowance: i64, min_allowance: i64, max_allowance: Option<i64>) -> i64 {
    let mut value = allowance.max(min_allowance);
    if let Some(max) = max_allowance {
        value = value.min(max);
    }
    let value = (value / 5) * 5;
    value.max(min_allowance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowance_to_cores_matches_ts() {
        assert_eq!(allowance_to_cores(0), 1);
        assert_eq!(allowance_to_cores(-20), 1);
        assert_eq!(allowance_to_cores(100), 1);
        assert_eq!(allowance_to_cores(150), 2);
        assert_eq!(allowance_to_cores(200), 2);
        assert_eq!(allowance_to_cores(250), 3);
    }

    #[test]
    fn map_instance_status_matches_ts() {
        assert_eq!(map_instance_status("Running"), "running");
        assert_eq!(map_instance_status("Stopped"), "stopped");
        assert_eq!(map_instance_status("Frozen"), "stopped");
        assert_eq!(map_instance_status("Error"), "error");
        assert_eq!(map_instance_status("Starting"), "creating");
        assert_eq!(map_instance_status("Stopping"), "running");
        assert_eq!(map_instance_status("Whatever"), "unknown");
    }
}
