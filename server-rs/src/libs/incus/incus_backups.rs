//! Incus backup management.
//! Port of lib/incus/incus-backups.ts.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::libs::incus::incus_client::{IncusClient, IncusError};

/// Mirrors the `IncusBackup` type from types/incus.ts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncusBackup {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub instance_only: bool,
    #[serde(default)]
    pub optimized_storage: bool,
    #[serde(default)]
    pub compression_algorithm: String,
}

/// Mirrors `CreateBackupOptions`.
#[derive(Debug, Clone, Default)]
pub struct CreateBackupOptions {
    /// Default true (no snapshots included).
    pub instance_only: Option<bool>,
    /// Default true (optimized storage).
    pub optimized_storage: Option<bool>,
    /// Default "gzip".
    pub compression: Option<String>,
}

/// Mirrors `listBackups`.
pub async fn list_backups(
    client: &IncusClient,
    instance_name: &str,
) -> Result<Vec<IncusBackup>, IncusError> {
    let value = client
        .request_default("GET", &format!("/1.0/instances/{instance_name}/backups"), None)
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid backup list payload: {e}")))
}

/// Mirrors `getBackup`.
pub async fn get_backup(
    client: &IncusClient,
    instance_name: &str,
    backup_name: &str,
) -> Result<IncusBackup, IncusError> {
    let value = client
        .request_default(
            "GET",
            &format!("/1.0/instances/{instance_name}/backups/{backup_name}"),
            None,
        )
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid backup payload: {e}")))
}

/// Mirrors `createBackup`.
pub async fn create_backup(
    client: &IncusClient,
    instance_name: &str,
    backup_name: &str,
    options: CreateBackupOptions,
) -> Result<Value, IncusError> {
    client
        .request_default(
            "POST",
            &format!("/1.0/instances/{instance_name}/backups"),
            Some(&json!({
                "name": backup_name,
                // Default: no snapshots included.
                "instance_only": options.instance_only != Some(false),
                // Default: optimized storage.
                "optimized_storage": options.optimized_storage != Some(false),
                "compression_algorithm": options.compression.unwrap_or_else(|| "gzip".to_string())
            })),
        )
        .await
}

/// Mirrors `deleteBackup`.
pub async fn delete_backup(
    client: &IncusClient,
    instance_name: &str,
    backup_name: &str,
) -> Result<Value, IncusError> {
    client
        .request_default(
            "DELETE",
            &format!("/1.0/instances/{instance_name}/backups/{backup_name}"),
            None,
        )
        .await
}

/// Mirrors `getBackupExportUrl`.
pub fn get_backup_export_url(
    client: &IncusClient,
    instance_name: &str,
    backup_name: &str,
) -> String {
    format!(
        "{}/1.0/instances/{instance_name}/backups/{backup_name}/export",
        client.base_url()
    )
}

/// Export stream chunk: raw backup bytes.
pub type BackupExportChunk = Result<Vec<u8>, IncusError>;

/// Mirrors `getBackupExportStream`: streams the backup export from a dedicated
/// long-timeout request (backups can be huge). Returns the byte stream plus the
/// Content-Length when the host provides one.
///
/// Note: reqwest's `stream` feature is disabled in this crate, so the stream is
/// produced from repeated `Response::chunk` calls via `stream::unfold` instead
/// of `bytes_stream()`; observable chunking semantics are the same.
pub async fn get_backup_export_stream(
    client: &IncusClient,
    instance_name: &str,
    backup_name: &str,
) -> Result<
    (
        impl futures_util::Stream<Item = BackupExportChunk> + 'static,
        Option<u64>,
    ),
    IncusError,
> {
    let url = get_backup_export_url(client, instance_name, backup_name);
    let response = client.raw_request("GET", &url, &[], None).await?;
    let status = response.status().as_u16();

    if status != 200 {
        let text = response.text().await.unwrap_or_default();
        return Err(IncusError::Other(format!(
            "导出备份失败: {}",
            if text.is_empty() {
                format!("HTTP {status}")
            } else {
                text
            }
        )));
    }

    let content_length = response.content_length();
    let stream = futures_util::stream::unfold(response, |mut response| async move {
        match response.chunk().await {
            Ok(Some(chunk)) => Some((Ok(chunk.to_vec()), response)),
            Ok(None) => None,
            Err(err) => Some((Err(IncusError::Transport(format!("{err}"))), response)),
        }
    });
    Ok((stream, content_length))
}

/// Mirrors `restoreFromBackup`.
pub async fn restore_from_backup(
    client: &IncusClient,
    new_instance_name: &str,
    backup_data: &Value,
) -> Result<Value, IncusError> {
    let mut source = json!({ "type": "backup" });
    if let (Some(obj), Some(source_obj)) = (backup_data.as_object(), source.as_object_mut()) {
        for (key, value) in obj {
            source_obj.insert(key.clone(), value.clone());
        }
    }
    client
        .request_default(
            "POST",
            "/1.0/instances",
            Some(&json!({
                "name": new_instance_name,
                "source": source
            })),
        )
        .await
}
