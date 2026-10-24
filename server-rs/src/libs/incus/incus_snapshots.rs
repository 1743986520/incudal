//! Incus snapshot management.
//! Port of lib/incus/incus-snapshots.ts.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::libs::incus::incus_client::{IncusClient, IncusError};

/// Mirrors the `IncusSnapshot` type from types/incus.ts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncusSnapshot {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub stateful: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Mirrors `listSnapshots`.
pub async fn list_snapshots(
    client: &IncusClient,
    instance_name: &str,
) -> Result<Vec<IncusSnapshot>, IncusError> {
    let value = client
        .request_default("GET", &format!("/1.0/instances/{instance_name}/snapshots"), None)
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid snapshot list payload: {e}")))
}

/// Mirrors `getSnapshot`.
pub async fn get_snapshot(
    client: &IncusClient,
    instance_name: &str,
    snapshot_name: &str,
) -> Result<IncusSnapshot, IncusError> {
    let value = client
        .request_default(
            "GET",
            &format!("/1.0/instances/{instance_name}/snapshots/{snapshot_name}"),
            None,
        )
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid snapshot payload: {e}")))
}

/// Mirrors `createSnapshot`.
pub async fn create_snapshot(
    client: &IncusClient,
    instance_name: &str,
    snapshot_name: &str,
) -> Result<Value, IncusError> {
    client
        .request_default(
            "POST",
            &format!("/1.0/instances/{instance_name}/snapshots"),
            Some(&serde_json::json!({ "name": snapshot_name })),
        )
        .await
}

/// Mirrors `deleteSnapshot`.
pub async fn delete_snapshot(
    client: &IncusClient,
    instance_name: &str,
    snapshot_name: &str,
) -> Result<Value, IncusError> {
    client
        .request_default(
            "DELETE",
            &format!("/1.0/instances/{instance_name}/snapshots/{snapshot_name}"),
            None,
        )
        .await
}

/// Mirrors `restoreSnapshot`.
pub async fn restore_snapshot(
    client: &IncusClient,
    instance_name: &str,
    snapshot_name: &str,
) -> Result<Value, IncusError> {
    client
        .request_default(
            "PUT",
            &format!("/1.0/instances/{instance_name}"),
            Some(&serde_json::json!({ "restore": snapshot_name })),
        )
        .await
}

/// Mirrors `renameSnapshot`.
pub async fn rename_snapshot(
    client: &IncusClient,
    instance_name: &str,
    snapshot_name: &str,
    new_name: &str,
) -> Result<Value, IncusError> {
    client
        .request_default(
            "POST",
            &format!("/1.0/instances/{instance_name}/snapshots/{snapshot_name}"),
            Some(&serde_json::json!({ "name": new_name })),
        )
        .await
}
