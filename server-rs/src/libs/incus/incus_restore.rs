//! Incus backup restore service.
//! Port of lib/incus/incus-restore.ts: restore an instance from a backup
//! stream, rename instances, and probe existence.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::libs::incus::incus_client::{IncusClient, IncusError};

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Mirrors `generateTempInstanceName`: `{originalName}-restore-{timestamp}`.
pub fn generate_temp_instance_name(original_name: &str) -> String {
    format!("{}-restore-{}", original_name, now_ms())
}

/// Mirrors `waitForRestoreOperation` (5 minute default timeout).
async fn wait_for_restore_operation(
    client: &IncusClient,
    operation_url: &str,
    timeout_ms: u64,
) -> Result<(), IncusError> {
    let timeout_ms = if timeout_ms == 0 { 300_000 } else { timeout_ms };
    let start = now_ms();

    while now_ms() - start < u128::from(timeout_ms) {
        let remaining_ms = timeout_ms as i128 - (now_ms() as i128 - start as i128);
        let wait_timeout = ((remaining_ms / 1000).min(30)).max(0) as i64;
        if wait_timeout <= 0 {
            break;
        }

        let wait_url = format!(
            "{}{}/wait?timeout={wait_timeout}",
            client.base_url(),
            operation_url
        );
        let send = client.request_raw_get(&wait_url, None);
        match send.await {
            Ok((_status, text, _peer)) => {
                let data: Value = match serde_json::from_str(&text) {
                    Ok(value) => value,
                    Err(_) => {
                        tracing::error!(
                            "[Incus Restore] 解析响应失败: {}",
                            &text[..text.len().min(200)]
                        );
                        return Err(IncusError::Other(format!(
                            "无效的响应: {}",
                            &text[..text.len().min(100)]
                        )));
                    }
                };

                let metadata = data.get("metadata");
                let status = metadata
                    .and_then(|m| m.get("status"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let status_code = metadata
                    .and_then(|m| m.get("status_code"))
                    .and_then(Value::as_i64);

                if status == "Success" || status_code == Some(200) {
                    return Ok(());
                }

                if status == "Failure" || status_code.map(|code| code >= 400).unwrap_or(false) {
                    let message = metadata
                        .and_then(|m| m.get("err"))
                        .and_then(Value::as_str)
                        .or_else(|| {
                            metadata
                                .and_then(|m| m.get("error"))
                                .and_then(Value::as_str)
                        })
                        .unwrap_or("操作失败");
                    tracing::error!("[Incus Restore] 操作失败: {message}");
                    return Err(IncusError::Other(message.to_string()));
                }
            }
            Err(err) => {
                let message = err.message();
                if message.contains("操作失败") || message.contains("Failure") {
                    return Err(err);
                }
                tracing::error!("[Incus Restore] 轮询出错: {message}");
                tokio::time::sleep(Duration::from_millis(2000)).await;
            }
        }
    }

    Err(IncusError::Other("恢复操作超时 (5 分钟)".to_string()))
}

/// Mirrors `restoreFromStream`: POST the backup bytes straight to the Incus
/// instance-creation endpoint with the `X-Incus-*` headers, then wait for the
/// async operation.
///
/// Note: the TS streams a Node Readable; reqwest's `stream` feature is disabled
/// in this crate, so the backup is provided as an in-memory byte buffer.
pub async fn restore_from_stream(
    client: &IncusClient,
    backup_bytes: Vec<u8>,
    target_name: &str,
    pool_name: Option<&str>,
) -> Result<(), IncusError> {
    let url = format!("{}/1.0/instances", client.base_url());

    // Incus uses X-Incus-* headers but also accepts X-LXD-* (legacy).
    let mut headers: Vec<(&str, String)> = vec![
        ("Content-Type", "application/octet-stream".to_string()),
        ("X-Incus-name", target_name.to_string()),
    ];
    if let Some(pool) = pool_name {
        headers.push(("X-Incus-pool", pool.to_string()));
    }

    let response = client
        .raw_request("POST", &url, &headers, Some(backup_bytes))
        .await?;
    let status = response.status().as_u16();
    let text = response
        .text()
        .await
        .map_err(|e| IncusError::Transport(format!("{e}")))?;

    let data: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => {
            tracing::error!(
                "[Incus Restore] 解析响应失败: {}",
                &text[..text.len().min(200)]
            );
            return Err(IncusError::Other(format!(
                "无效的响应: {}",
                &text[..text.len().min(200)]
            )));
        }
    };

    if data.get("type").and_then(Value::as_str) == Some("error") {
        let message = data
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("恢复失败");
        tracing::error!("[Incus Restore] 恢复失败: {message}");
        return Err(IncusError::Api {
            message: message.to_string(),
            status_code: status as i64,
            method: "POST".to_string(),
            path: "/1.0/instances".to_string(),
        });
    }

    // Async operation: wait for completion.
    if data.get("type").and_then(Value::as_str) == Some("async") {
        if let Some(operation) = data.get("operation").and_then(Value::as_str) {
            wait_for_restore_operation(client, operation, 0).await?;
        }
    }
    Ok(())
}

/// Mirrors `renameInstance`.
pub async fn rename_instance(
    client: &IncusClient,
    old_name: &str,
    new_name: &str,
) -> Result<(), IncusError> {
    client
        .request_default(
            "POST",
            &format!("/1.0/instances/{old_name}"),
            Some(&serde_json::json!({ "name": new_name })),
        )
        .await?;
    Ok(())
}

/// Mirrors `instanceExists`.
pub async fn instance_exists(client: &IncusClient, instance_name: &str) -> bool {
    client
        .request_default(
            "GET",
            &format!("/1.0/instances/{instance_name}"),
            None,
        )
        .await
        .is_ok()
}
