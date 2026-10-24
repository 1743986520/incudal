//! Incus image management.
//! Port of lib/incus/incus-images.ts.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::libs::incus::incus_client::{IncusClient, IncusError};
use crate::libs::incus::incus_utils::wait_for_operation_long;

/// Mirrors the `IncusImage` type from types/incus.ts (fields the panel reads).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncusImage {
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub uploaded_at: String,
    #[serde(default)]
    pub auto_update: bool,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
    #[serde(default)]
    pub aliases: Option<Vec<ImageAliasEntry>>,
    #[serde(default, rename = "update_source")]
    pub update_source: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImageAliasEntry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub target: String,
}

/// Mirrors the `IncusImageAlias` type from types/incus.ts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncusImageAlias {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub target: String,
}

/// Mirrors `PullImageOptions`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PullImageOptions {
    pub server: Option<&'static str>,
    pub protocol: Option<&'static str>,
    pub auto_update: Option<bool>,
    pub is_public: Option<bool>,
}

impl PullImageOptions {
    fn server_str(&self) -> &str {
        self.server.unwrap_or("https://images.linuxcontainers.org")
    }
    fn protocol_str(&self) -> &str {
        self.protocol.unwrap_or("simplestreams")
    }
    fn auto_update_bool(&self) -> bool {
        self.auto_update.unwrap_or(true)
    }
    fn is_public_bool(&self) -> bool {
        self.is_public.unwrap_or(false)
    }
}

fn pull_payload(remote_alias: &str, options: &PullImageOptions) -> Value {
    json!({
        "source": {
            "type": "image",
            "mode": "pull",
            "server": options.server_str(),
            "protocol": options.protocol_str(),
            "alias": remote_alias
        },
        "public": options.is_public_bool(),
        "auto_update": options.auto_update_bool()
    })
}

/// Mirrors `listImages`.
pub async fn list_images(client: &IncusClient) -> Result<Vec<IncusImage>, IncusError> {
    let urls = client.request_default("GET", "/1.0/images", None).await?;
    let url_list: Vec<String> = serde_json::from_value(urls).unwrap_or_default();
    let mut images = Vec::new();
    for url in url_list {
        let fingerprint = url.rsplit('/').next().unwrap_or("").to_string();
        if fingerprint.is_empty() {
            continue;
        }
        images.push(get_image(client, &fingerprint).await?);
    }
    Ok(images)
}

/// Mirrors `getImage`.
pub async fn get_image(
    client: &IncusClient,
    fingerprint: &str,
) -> Result<IncusImage, IncusError> {
    let value = client
        .request_default("GET", &format!("/1.0/images/{fingerprint}"), None)
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid image payload: {e}")))
}

/// Mirrors `listImageAliases`.
pub async fn list_image_aliases(client: &IncusClient) -> Result<Vec<IncusImageAlias>, IncusError> {
    let value = client
        .request_default("GET", "/1.0/images/aliases", None)
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid image alias list payload: {e}")))
}

/// Mirrors `pullImage` (async operation waited to completion by the client).
pub async fn pull_image(
    client: &IncusClient,
    remote_alias: &str,
    options: PullImageOptions,
) -> Result<Value, IncusError> {
    client
        .request_default("POST", "/1.0/images", Some(&pull_payload(remote_alias, &options)))
        .await
}

/// Mirrors `pullImageWithLongTimeout`: sends the pull request and waits for the
/// async operation with a long (default 10 minute) timeout.
pub async fn pull_image_with_long_timeout(
    client: &IncusClient,
    remote_alias: &str,
    options: PullImageOptions,
    timeout_ms: u64,
) -> Result<Value, IncusError> {
    let timeout_ms = if timeout_ms == 0 { 600_000 } else { timeout_ms };
    let payload = pull_payload(remote_alias, &options);
    let url = format!("{}/1.0/images", client.base_url());

    tracing::info!(
        "[Incus API Request] POST {url} operation=pullImageWithLongTimeout body={}",
        serde_json::to_string(&payload).unwrap_or_default()
    );

    // Mirrors the TS direct undici POST (no envelope handling here).
    let (status, text, _peer) = client
        .dispatch_raw("POST", "/1.0/images", Some(&payload))
        .await?;

    tracing::info!(
        "[Incus API Response] POST {url} body={}",
        if text.len() > 1000 {
            format!("{}... (truncated, total: {} chars)", &text[..1000.min(text.len())], text.len())
        } else {
            text.clone()
        }
    );

    let data: Value = serde_json::from_str(&text)
        .map_err(|_| IncusError::Other(if text.is_empty() { format!("HTTP {status}") } else { text }))?;

    let response_type = data.get("type").and_then(Value::as_str).unwrap_or("");
    if response_type == "error" {
        return Err(IncusError::Other(
            data.get("error")
                .and_then(Value::as_str)
                .unwrap_or("Incus API 错误")
                .to_string(),
        ));
    }

    // Wait for the async operation with the long timeout.
    if response_type == "async" {
        if let Some(operation) = data.get("operation").and_then(Value::as_str) {
            return wait_for_operation_long(client, operation, timeout_ms).await;
        }
    }

    Ok(data.get("metadata").cloned().unwrap_or(Value::Null))
}

/// Mirrors `createImageAlias`.
pub async fn create_image_alias(
    client: &IncusClient,
    alias_name: &str,
    fingerprint: &str,
) -> Result<Value, IncusError> {
    client
        .request_default(
            "POST",
            "/1.0/images/aliases",
            Some(&json!({ "name": alias_name, "target": fingerprint })),
        )
        .await
}

/// Mirrors `deleteImageAlias`.
pub async fn delete_image_alias(
    client: &IncusClient,
    alias_name: &str,
) -> Result<Value, IncusError> {
    client
        .request_default("DELETE", &format!("/1.0/images/aliases/{alias_name}"), None)
        .await
}

/// Mirrors `getImageAlias`.
pub async fn get_image_alias(
    client: &IncusClient,
    alias_name: &str,
) -> Result<IncusImageAlias, IncusError> {
    let value = client
        .request_default("GET", &format!("/1.0/images/aliases/{alias_name}"), None)
        .await?;
    serde_json::from_value(value)
        .map_err(|e| IncusError::Other(format!("invalid image alias payload: {e}")))
}

/// Mirrors `updateImageAlias`.
pub async fn update_image_alias(
    client: &IncusClient,
    alias_name: &str,
    new_target: &str,
) -> Result<Value, IncusError> {
    client
        .request_default(
            "PUT",
            &format!("/1.0/images/aliases/{alias_name}"),
            Some(&json!({ "target": new_target })),
        )
        .await
}

/// Mirrors `deleteImage`.
pub async fn delete_image(client: &IncusClient, fingerprint: &str) -> Result<Value, IncusError> {
    client
        .request_default("DELETE", &format!("/1.0/images/{fingerprint}"), None)
        .await
}

/// Mirrors `imageExistsByAlias`.
pub async fn image_exists_by_alias(client: &IncusClient, alias_name: &str) -> bool {
    get_image_alias(client, alias_name).await.is_ok()
}
