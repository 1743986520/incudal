//! Incus network management.
//! Port of lib/incus/incus-network.ts.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::libs::incus::incus_client::{IncusClient, IncusError};

/// Mirrors the `IncusNetwork` type from types/incus.ts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncusNetwork {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub network_type: String,
    #[serde(default)]
    pub used_by: Option<Vec<String>>,
    #[serde(default)]
    pub config: Option<Value>,
}

/// Mirrors `listNetworks`.
pub async fn list_networks(client: &IncusClient) -> Result<Vec<IncusNetwork>, IncusError> {
    let value = client.request_default("GET", "/1.0/networks", None).await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid network list payload: {e}")))
}

/// Mirrors `getNetwork`.
pub async fn get_network(client: &IncusClient, name: &str) -> Result<IncusNetwork, IncusError> {
    let value = client
        .request_default("GET", &format!("/1.0/networks/{name}"), None)
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid network payload: {e}")))
}
