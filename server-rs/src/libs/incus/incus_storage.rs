//! Incus storage pool management.
//! Port of lib/incus/incus-storage.ts.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::libs::incus::incus_client::{IncusClient, IncusError};

/// Mirrors the `IncusStoragePool` type from types/incus.ts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncusStoragePool {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub driver: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub used_by: Option<Vec<String>>,
    #[serde(default)]
    pub config: Option<Map<String, Value>>,
    /// Present on `listStoragePools` fallback entries.
    #[serde(default)]
    pub resources: Option<StorageSpace>,
}

/// Mirrors `CreateStoragePoolOptions`.
#[derive(Debug, Clone)]
pub struct CreateStoragePoolOptions {
    pub name: String,
    /// 'zfs' | 'lvm' | 'btrfs' | 'dir'
    pub driver: String,
    pub config: Map<String, Value>,
    pub description: Option<String>,
}

/// Mirrors `StoragePoolWithResources.resources`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageSpace {
    #[serde(default)]
    pub used: i64,
    #[serde(default)]
    pub total: i64,
}

/// Mirrors `getStoragePoolResources` return shape.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoragePoolResources {
    #[serde(default)]
    pub space: Option<StorageSpace>,
}

/// Mirrors `listStoragePools`: the Incus API returns URL entries; each pool is
/// fetched separately. A pool that fails to load falls back to its basic shape
/// exactly like the TS server.
pub async fn list_storage_pools(client: &IncusClient) -> Result<Vec<IncusStoragePool>, IncusError> {
    let value = client
        .request_default("GET", "/1.0/storage-pools", None)
        .await?;
    let pool_urls: Vec<String> = serde_json::from_value(value).unwrap_or_default();
    if pool_urls.is_empty() {
        return Ok(Vec::new());
    }

    let mut pools = Vec::new();
    for url in pool_urls {
        let name = url.rsplit('/').next().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        match get_storage_pool(client, &name).await {
            Ok(pool) => pools.push(pool),
            Err(_) => pools.push(IncusStoragePool {
                name,
                driver: "unknown".to_string(),
                config: Some(Map::new()),
                ..Default::default()
            }),
        }
    }
    Ok(pools)
}

/// Mirrors `getStoragePool`.
pub async fn get_storage_pool(
    client: &IncusClient,
    name: &str,
) -> Result<IncusStoragePool, IncusError> {
    let value = client
        .request_default("GET", &format!("/1.0/storage-pools/{name}"), None)
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid storage pool payload: {e}")))
}

/// Mirrors `getStoragePoolResources`.
pub async fn get_storage_pool_resources(
    client: &IncusClient,
    name: &str,
) -> Result<StoragePoolResources, IncusError> {
    let value = client
        .request_default("GET", &format!("/1.0/storage-pools/{name}/resources"), None)
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid storage pool resources payload: {e}")))
}

/// Mirrors `createStoragePool`.
pub async fn create_storage_pool(
    client: &IncusClient,
    options: &CreateStoragePoolOptions,
) -> Result<(), IncusError> {
    client
        .request_default(
            "POST",
            "/1.0/storage-pools",
            Some(&json!({
                "name": options.name,
                "driver": options.driver,
                "config": Value::Object(options.config.clone()),
                "description": options.description.clone().unwrap_or_default()
            })),
        )
        .await?;
    Ok(())
}

/// Mirrors `deleteStoragePool`.
pub async fn delete_storage_pool(client: &IncusClient, name: &str) -> Result<(), IncusError> {
    client
        .request_default("DELETE", &format!("/1.0/storage-pools/{name}"), None)
        .await?;
    Ok(())
}

/// Mirrors `UpdateStoragePoolOptions`.
#[derive(Debug, Clone, Default)]
pub struct UpdateStoragePoolOptions {
    pub config: Option<Map<String, Value>>,
    pub description: Option<String>,
}

/// Mirrors `updateStoragePool` (PATCH partial update).
pub async fn update_storage_pool(
    client: &IncusClient,
    name: &str,
    options: &UpdateStoragePoolOptions,
) -> Result<(), IncusError> {
    let mut payload = Map::new();
    if let Some(config) = &options.config {
        payload.insert("config".to_string(), Value::Object(config.clone()));
    }
    if let Some(description) = &options.description {
        payload.insert("description".to_string(), json!(description));
    }
    client
        .request_default(
            "PATCH",
            &format!("/1.0/storage-pools/{name}"),
            Some(&Value::Object(payload)),
        )
        .await?;
    Ok(())
}
