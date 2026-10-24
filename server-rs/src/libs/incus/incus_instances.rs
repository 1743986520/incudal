//! Incus instance management.
//! Port of lib/incus/incus-instances.ts.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::libs::incus::incus_client::{
    is_incus_not_found, IncusClient, IncusError, DEFAULT_REQUEST_TIMEOUT_MS,
};
use crate::libs::incus::incus_utils::allowance_to_cores;
use crate::libs::incus::instance_swap::resolve_incus_swap_value;
use crate::libs::incus::network_payload_builder::{
    build_network_devices, generate_cloud_init_network_config, has_ipv6_support,
    BuildNetworkDevicesOptions, CloudInitNetworkOptions, Ipv6Config, NetworkMode,
    PartialVmNicMacs,
};
use crate::libs::incus::vm_network_identifiers::{generate_vm_nic_macs, VmNicMacs};

pub const INSTANCE_BUSY_WAIT_TIMEOUT_MS: u64 = 300_000;
pub const INSTANCE_BUSY_POLL_INTERVAL_MS: u64 = 2_000;
const INSTANCE_BUSY_CANCEL_CHECK_INTERVAL_MS: u64 = 30_000;
pub const INSTANCE_BUSY_CANCEL_STALE_UPDATE_MS: u64 = 45_000;
const INSTANCE_DELETE_CONFIRM_TIMEOUT_MS: u64 = 30_000;
const INSTANCE_DELETE_CONFIRM_POLL_INTERVAL_MS: u64 = 1_000;
const INSTANCE_PROVISIONING_SETTLE_TIMEOUT_MS: u64 = 30_000;
pub const INSTANCE_PROVISIONING_POLL_INTERVAL_MS: u64 = 1_000;
pub const INSTANCE_CREATE_TIMEOUT_MS: u64 = 15 * 60 * 1000;
const INSTANCE_APPEAR_TIMEOUT_MS: u64 = 30 * 1000;
const INSTANCE_NVRAM_REPAIR_TIMEOUT_MS: u64 = 2 * 60 * 1000;

static MISSING_VM_NVRAM_ERROR: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r"(?i)failed (?:copying|opening) nvram file:\s*open .+/qemu\.nvram:\s*no such file or directory",
    )
    .expect("static regex")
});

static BUSY_OPERATION: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"(?i)busy running a "([^"]+)" operation"#).expect("static regex")
});

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

async fn sleep(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Mirrors the `IncusInstance` type from types/incus.ts. Unknown fields are
/// kept so the object can be round-tripped in PUT bodies like the TS server
/// does with `{ ...instance, updates }`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncusInstance {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub instance_type: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub status_code: i64,
    #[serde(default)]
    pub config: Map<String, Value>,
    #[serde(default)]
    pub devices: Map<String, Value>,
    #[serde(default)]
    pub expanded_config: Map<String, Value>,
    #[serde(default)]
    pub expanded_devices: Map<String, Value>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub profiles: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Mirrors the `IncusOperation` type from types/incus.ts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncusOperation {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub status_code: Option<i64>,
    #[serde(default)]
    pub may_cancel: Option<bool>,
    #[serde(default)]
    pub resources: Option<Value>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub err: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

fn extract_busy_operation_name(error: &IncusError) -> Option<String> {
    BUSY_OPERATION
        .captures(error.message())
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

fn normalize_operations_payload(payload: &Value) -> Vec<IncusOperation> {
    let entries: Vec<Value> = match payload {
        Value::Array(items) => items.clone(),
        Value::Object(map) => map.values().cloned().collect(),
        _ => Vec::new(),
    };
    entries
        .into_iter()
        .filter(|entry| entry.is_object())
        .filter_map(|entry| serde_json::from_value(entry).ok())
        .collect()
}

fn is_operation_running(operation: &IncusOperation) -> bool {
    if let Some(status) = &operation.status {
        let status = status.to_lowercase();
        if ["success", "failure", "cancelled", "canceled"].contains(&status.as_str()) {
            return false;
        }
    }
    match operation.status_code {
        Some(code) => code < 200,
        None => true,
    }
}

fn operation_touches_instance(resources: &Value, instance_name: &str) -> bool {
    let instance_path = format!("/1.0/instances/{instance_name}");
    match resources {
        Value::String(s) => s == &instance_path || s.starts_with(&instance_path),
        Value::Array(items) => items
            .iter()
            .any(|entry| operation_touches_instance(entry, instance_name)),
        Value::Object(map) => map
            .values()
            .any(|entry| operation_touches_instance(entry, instance_name)),
        _ => false,
    }
}

fn describe_operation(operation: &IncusOperation) -> String {
    operation
        .description
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| {
            if !operation.class.is_empty() {
                operation.class.clone()
            } else if !operation.id.is_empty() {
                operation.id.clone()
            } else {
                "operation".to_string()
            }
        })
}

async fn list_active_instance_operations(
    client: &IncusClient,
    instance_name: &str,
) -> Result<Vec<IncusOperation>, IncusError> {
    let payload = client
        .request_default("GET", "/1.0/operations?recursion=1", None)
        .await?;
    let operations = normalize_operations_payload(&payload);
    Ok(operations
        .into_iter()
        .filter(|operation| {
            is_operation_running(operation)
                && operation
                    .resources
                    .as_ref()
                    .map(|resources| operation_touches_instance(resources, instance_name))
                    .unwrap_or(false)
        })
        .collect())
}

fn describe_operations(operations: &[IncusOperation]) -> String {
    operations
        .iter()
        .map(describe_operation)
        .collect::<Vec<_>>()
        .join(", ")
}

fn get_operation_path(operation: &IncusOperation) -> Option<String> {
    if operation.id.is_empty() {
        return None;
    }
    Some(if operation.id.starts_with("/1.0/operations/") {
        operation.id.clone()
    } else {
        format!("/1.0/operations/{}", operation.id)
    })
}

fn parse_incus_time_ms(value: &str) -> Option<i128> {
    // Node Date.parse accepts ISO-8601; chrono parses the same shapes.
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp_millis() as i128)
}

fn operation_age_ms(operation: &IncusOperation) -> u128 {
    let now = now_ms() as i128;
    if let Some(created_at) = parse_incus_time_ms(&operation.created_at) {
        return (now - created_at).max(0) as u128;
    }
    if let Some(updated_at) = parse_incus_time_ms(&operation.updated_at) {
        return (now - updated_at).max(0) as u128;
    }
    0
}

fn is_update_operation(operation: &IncusOperation) -> bool {
    let description = operation
        .description
        .as_deref()
        .unwrap_or("")
        .to_lowercase();
    let metadata_action = operation
        .metadata
        .as_ref()
        .and_then(|m| m.get("action"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    description.contains("update") || metadata_action == "update"
}

async fn cancel_stale_update_operations(
    client: &IncusClient,
    instance_name: &str,
) -> Result<u32, IncusError> {
    let active_operations = list_active_instance_operations(client, instance_name).await?;
    let cancellable: Vec<&IncusOperation> = active_operations
        .iter()
        .filter(|operation| {
            is_update_operation(operation)
                && operation.may_cancel != Some(false)
                && operation_age_ms(operation) >= u128::from(INSTANCE_BUSY_CANCEL_STALE_UPDATE_MS)
        })
        .collect();

    let mut cancelled = 0u32;
    for operation in cancellable {
        let Some(operation_path) = get_operation_path(operation) else {
            continue;
        };
        match client.request_default("DELETE", &operation_path, None).await {
            Ok(_) => cancelled += 1,
            Err(error) => {
                tracing::warn!(
                    "[Incus] Failed to cancel stale update operation {} for {instance_name}: {}",
                    operation.id,
                    error
                );
            }
        }
    }
    Ok(cancelled)
}

/// Mirrors `BusyRetryOptions`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BusyRetryOptions {
    pub allow_cancel_busy_update: bool,
    pub busy_update_cancel_after_ms: Option<u64>,
}

fn extract_instance_status(state: &Value) -> String {
    state
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase()
}

async fn run_instance_action_with_busy_retry<T, F, Fut>(
    client: &IncusClient,
    instance_name: &str,
    action_label: &str,
    action: F,
    options: BusyRetryOptions,
) -> Result<T, IncusError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, IncusError>>,
{
    let busy_since = now_ms();
    let mut last_log_at: u128 = 0;
    let mut last_cancel_check_at: u128 = 0;
    let mut last_busy_operation: Option<String> = None;
    let busy_update_cancel_after_ms = options
        .busy_update_cancel_after_ms
        .unwrap_or(INSTANCE_BUSY_CANCEL_STALE_UPDATE_MS);

    loop {
        if now_ms() - busy_since > u128::from(INSTANCE_BUSY_WAIT_TIMEOUT_MS) {
            break;
        }
        match action().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                let Some(busy_operation) = extract_busy_operation_name(&error) else {
                    return Err(error);
                };

                last_busy_operation = Some(busy_operation.clone());
                let now = now_ms();
                let elapsed_ms = now - busy_since;
                let remaining_ms =
                    INSTANCE_BUSY_WAIT_TIMEOUT_MS.saturating_sub((elapsed_ms as u64).min(u64::MAX));
                let mut active_operation_description = String::new();

                // Operation list is best-effort diagnostics only.
                if let Ok(active_operations) =
                    list_active_instance_operations(client, instance_name).await
                {
                    if !active_operations.is_empty() {
                        active_operation_description = describe_operations(&active_operations);
                    }
                }

                if now - last_log_at >= 10_000 {
                    let details = if active_operation_description.is_empty() {
                        String::new()
                    } else {
                        format!(" activeOps=[{active_operation_description}]")
                    };
                    tracing::warn!(
                        "[Incus] Instance {instance_name} is busy running a \"{busy_operation}\" operation while trying to {action_label}; elapsed={}s remaining={}s{details}",
                        elapsed_ms / 1000,
                        u128::from(remaining_ms) / 1000
                    );
                    last_log_at = now;
                }

                if options.allow_cancel_busy_update
                    && busy_operation.to_lowercase() == "update"
                    && elapsed_ms >= u128::from(busy_update_cancel_after_ms)
                    && now - last_cancel_check_at >= u128::from(INSTANCE_BUSY_CANCEL_CHECK_INTERVAL_MS)
                {
                    last_cancel_check_at = now;
                    match cancel_stale_update_operations(client, instance_name).await {
                        Ok(count) if count > 0 => {
                            tracing::warn!(
                                "[Incus] Cancelled {count} stale update operation(s) for {instance_name}"
                            );
                        }
                        Ok(_) => {}
                        Err(cancel_error) => {
                            tracing::warn!(
                                "[Incus] Failed stale update cancellation check for {instance_name}: {cancel_error}"
                            );
                        }
                    }
                }

                if remaining_ms == 0 {
                    if !active_operation_description.is_empty() {
                        return Err(IncusError::Other(format!(
                            "Instance \"{instance_name}\" remained busy after waiting to {action_label}: {active_operation_description}"
                        )));
                    }
                    return Err(IncusError::Other(format!(
                        "Instance \"{instance_name}\" remained busy running a \"{busy_operation}\" operation while trying to {action_label}"
                    )));
                }

                sleep(INSTANCE_BUSY_POLL_INTERVAL_MS.min(remaining_ms)).await;
            }
        }
    }

    if let Some(busy_operation) = last_busy_operation {
        return Err(IncusError::Other(format!(
            "Instance \"{instance_name}\" remained busy running a \"{busy_operation}\" operation while trying to {action_label}"
        )));
    }
    Err(IncusError::Other(format!("Failed to {action_label}")))
}

// ==================== instance CRUD ====================

/// Mirrors `listInstances`.
pub async fn list_instances(client: &IncusClient) -> Result<Vec<IncusInstance>, IncusError> {
    let urls = client
        .request_default("GET", "/1.0/instances", None)
        .await?;
    let url_list: Vec<String> = serde_json::from_value(urls).unwrap_or_default();
    let mut instances = Vec::new();
    for url in url_list {
        let name = url.rsplit('/').next().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        instances.push(get_instance(client, &name).await?);
    }
    Ok(instances)
}

/// Mirrors `getInstance`.
pub async fn get_instance(
    client: &IncusClient,
    name: &str,
) -> Result<IncusInstance, IncusError> {
    let value = get_instance_value(client, name).await?;
    serde_json::from_value(value).map_err(|e| IncusError::Other(format!("invalid instance payload: {e}")))
}

/// Raw variant used when the full envelope object must be re-serialized.
pub async fn get_instance_value(client: &IncusClient, name: &str) -> Result<Value, IncusError> {
    client
        .request_default("GET", &format!("/1.0/instances/{name}"), None)
        .await
}

/// Mirrors `getInstanceState`.
pub async fn get_instance_state(client: &IncusClient, name: &str) -> Result<Value, IncusError> {
    client
        .request_default("GET", &format!("/1.0/instances/{name}/state"), None)
        .await
}

/// Mirrors `ProvisioningInstanceResolution`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningInstanceResolution {
    Absent,
    Present { status: ProvisionStatus },
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionStatus {
    Running,
    Stopped,
}

/// Mirrors `waitForProvisioningInstanceResolution`: a timed-out Incus
/// operation can finish after the caller's wait expires, so a single 404 is
/// not enough evidence that creation failed.
pub async fn wait_for_provisioning_instance_resolution(
    client: &IncusClient,
    name: &str,
    timeout_ms: u64,
) -> Result<ProvisioningInstanceResolution, IncusError> {
    let timeout_ms = if timeout_ms == 0 {
        INSTANCE_PROVISIONING_SETTLE_TIMEOUT_MS
    } else {
        timeout_ms
    };
    let deadline = now_ms() + u128::from(timeout_ms);

    loop {
        let mut instance: Option<IncusInstance> = None;

        match get_instance(client, name).await {
            Ok(found) => instance = Some(found),
            Err(error) => {
                if !is_incus_not_found(&error) {
                    return Err(error);
                }
            }
        }

        if let Some(instance) = &instance {
            if instance.status == "Running" {
                return Ok(ProvisioningInstanceResolution::Present {
                    status: ProvisionStatus::Running,
                });
            }
            if instance.status == "Stopped" || instance.status == "Frozen" {
                return Ok(ProvisioningInstanceResolution::Present {
                    status: ProvisionStatus::Stopped,
                });
            }
            // A terminal Incus error is a real failed provision and can be
            // cleaned up. Transitional states must settle.
            if instance.status == "Error" || instance.status.is_empty() {
                return Ok(ProvisioningInstanceResolution::Failed);
            }
        } else {
            let active_operations = list_active_instance_operations(client, name).await?;
            if active_operations.is_empty() {
                return Ok(ProvisioningInstanceResolution::Absent);
            }
        }

        if now_ms() >= deadline {
            let state = instance
                .map(|i| i.status)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "absent with an active operation".to_string());
            return Err(IncusError::Other(format!(
                "Incus provisioning for \"{name}\" did not settle (state: {state})"
            )));
        }

        let remaining = deadline.saturating_sub(now_ms());
        sleep(INSTANCE_PROVISIONING_POLL_INTERVAL_MS.min(remaining.max(1) as u64)).await;
    }
}

/// Mirrors `createInstance`: image pulls and VM creation can exceed the two
/// minute default, so the create operation gets the 15 minute timeout.
pub async fn create_instance(client: &IncusClient, config: &Value) -> Result<Value, IncusError> {
    client
        .request("POST", "/1.0/instances", Some(config), INSTANCE_CREATE_TIMEOUT_MS)
        .await
}

/// Mirrors `waitForCreatedInstance`: wait until a completed create is visible
/// before issuing the start action. Returns "Running" or "Stopped". Both
/// timeout and poll interval are taken verbatim (TS default parameters are
/// passed explicitly by callers: 30s / 1s).
pub async fn wait_for_created_instance(
    client: &IncusClient,
    name: &str,
    timeout_ms: u64,
    poll_interval_ms: u64,
) -> Result<&'static str, IncusError> {
    let deadline = now_ms() + u128::from(timeout_ms);
    loop {
        match get_instance(client, name).await {
            Ok(instance) => {
                if instance.status == "Error" {
                    return Err(IncusError::Other(format!(
                        "Incus instance \"{name}\" entered Error state after creation"
                    )));
                }
                if instance.status == "Running" {
                    return Ok("Running");
                }
                if instance.status == "Stopped" {
                    return Ok("Stopped");
                }
            }
            Err(error) => {
                if !is_incus_not_found(&error) {
                    return Err(error);
                }
                if now_ms() >= deadline {
                    return Err(IncusError::Other(format!(
                        "Incus instance \"{name}\" was not found after creation"
                    )));
                }
            }
        }
        if now_ms() >= deadline {
            return Err(IncusError::Other(format!(
                "Incus instance \"{name}\" did not become ready after creation"
            )));
        }
        let remaining = deadline.saturating_sub(now_ms());
        sleep(poll_interval_ms.min(remaining.max(1) as u64)).await;
    }
}

/// Mirrors `deleteInstance`.
pub async fn delete_instance(client: &IncusClient, name: &str) -> Result<Value, IncusError> {
    client
        .request_default("DELETE", &format!("/1.0/instances/{name}"), None)
        .await
}

/// Mirrors `ensureInstanceDeleted`: stop, delete, and positively confirm the
/// instance is gone. Any result other than a confirmed 404 is unknown and must
/// keep the provisioning charge/reservation intact.
pub async fn ensure_instance_deleted(client: &IncusClient, name: &str) -> Result<(), IncusError> {
    let resolution = wait_for_provisioning_instance_resolution(client, name, 0).await?;
    if resolution == ProvisioningInstanceResolution::Absent {
        return Ok(());
    }

    if let Err(error) = stop_instance(client, name, true, BusyRetryOptions {
        allow_cancel_busy_update: true,
        busy_update_cancel_after_ms: None,
    })
    .await
    {
        if !is_incus_not_found(&error) {
            return Err(error);
        }
    }

    if let Err(error) = delete_instance(client, name).await {
        if !is_incus_not_found(&error) {
            return Err(error);
        }
    }

    let deadline = now_ms() + u128::from(INSTANCE_DELETE_CONFIRM_TIMEOUT_MS);
    while now_ms() <= deadline {
        match get_instance(client, name).await {
            Err(error) => {
                if is_incus_not_found(&error) {
                    return Ok(());
                }
                return Err(error);
            }
            Ok(_) => {}
        }
        sleep(INSTANCE_DELETE_CONFIRM_POLL_INTERVAL_MS).await;
    }

    Err(IncusError::Other(format!(
        "Incus instance \"{name}\" still exists after deletion was requested"
    )))
}

/// Mirrors `startInstance`.
pub async fn start_instance(client: &IncusClient, name: &str) -> Result<Value, IncusError> {
    client
        .request_default(
            "PUT",
            &format!("/1.0/instances/{name}/state"),
            Some(&json!({
                "action": "start",
                "timeout": 60
            })),
        )
        .await
}

/// Mirrors `isMissingVmNvramError`.
pub fn is_missing_vm_nvram_error(error: &IncusError) -> bool {
    MISSING_VM_NVRAM_ERROR.is_match(error.message())
}

/// Mirrors `startInstanceWithNvramRepair`: repairs only the exact missing
/// qemu.nvram failure and retries once; all other start errors pass through.
pub async fn start_instance_with_nvram_repair(
    client: &IncusClient,
    name: &str,
) -> Result<(Value, bool), IncusError> {
    match start_instance(client, name).await {
        Ok(result) => Ok((result, false)),
        Err(error) => {
            if !is_missing_vm_nvram_error(&error) {
                return Err(error);
            }
            client
                .request(
                    "POST",
                    &format!("/1.0/instances/{}/debug/repair", urlencoding::encode(name)),
                    Some(&json!({ "action": "rebuild-nvram" })),
                    INSTANCE_NVRAM_REPAIR_TIMEOUT_MS,
                )
                .await?;
            let result = start_instance(client, name).await?;
            Ok((result, true))
        }
    }
}

/// Mirrors `stopInstance`. On images like Alpine a stale update operation lock
/// can survive even though the instance already stopped; no second stop is
/// sent in that case.
pub async fn stop_instance(
    client: &IncusClient,
    name: &str,
    force: bool,
    options: BusyRetryOptions,
) -> Result<Value, IncusError> {
    run_instance_action_with_busy_retry(
        client,
        name,
        "stop the instance",
        || async {
            let current_state = get_instance_state(client, name).await?;
            let current_status = extract_instance_status(&current_state);
            if current_status == "stopped" {
                return Ok(current_state);
            }
            client
                .request_default(
                    "PUT",
                    &format!("/1.0/instances/{name}/state"),
                    Some(&json!({
                        "action": "stop",
                        "timeout": 60,
                        "force": force
                    })),
                )
                .await
        },
        options,
    )
    .await
}

/// Mirrors `restartInstance`.
pub async fn restart_instance(
    client: &IncusClient,
    name: &str,
    force: bool,
) -> Result<Value, IncusError> {
    client
        .request_default(
            "PUT",
            &format!("/1.0/instances/{name}/state"),
            Some(&json!({
                "action": "restart",
                "timeout": 60,
                "force": force
            })),
        )
        .await
}

/// Mirrors `freezeInstance`.
pub async fn freeze_instance(client: &IncusClient, name: &str) -> Result<Value, IncusError> {
    client
        .request_default(
            "PUT",
            &format!("/1.0/instances/{name}/state"),
            Some(&json!({
                "action": "freeze",
                "timeout": 60
            })),
        )
        .await
}

/// Mirrors `unfreezeInstance`.
pub async fn unfreeze_instance(client: &IncusClient, name: &str) -> Result<Value, IncusError> {
    client
        .request_default(
            "PUT",
            &format!("/1.0/instances/{name}/state"),
            Some(&json!({
                "action": "unfreeze",
                "timeout": 30
            })),
        )
        .await
}

/// Mirrors the `rebuildInstance` imageSource parameter.
#[derive(Debug, Clone, Default)]
pub struct RebuildImageSource {
    pub alias: Option<String>,
    pub fingerprint: Option<String>,
    pub server: Option<String>,
    pub mode: Option<String>,
    pub protocol: Option<String>,
}

/// Mirrors `rebuildInstance` (system reinstall, optional cloud-init config).
pub async fn rebuild_instance(
    client: &IncusClient,
    name: &str,
    image_source: &RebuildImageSource,
    config: Option<&Map<String, Value>>,
    options: BusyRetryOptions,
) -> Result<Value, IncusError> {
    // A remote "images:" alias pulls from images.linuxcontainers.org.
    let source = match &image_source.alias {
        Some(alias) if alias.starts_with("images:") => {
            let remote_alias = alias.strip_prefix("images:").unwrap_or(alias);
            json!({
                "type": "image",
                "mode": "pull",
                "server": "https://images.linuxcontainers.org",
                "protocol": "simplestreams",
                "alias": remote_alias
            })
        }
        _ => {
            let mut source = Map::new();
            source.insert("type".to_string(), json!("image"));
            if let Some(alias) = &image_source.alias {
                source.insert("alias".to_string(), json!(alias));
            }
            if let Some(fingerprint) = &image_source.fingerprint {
                source.insert("fingerprint".to_string(), json!(fingerprint));
            }
            if let Some(server) = &image_source.server {
                source.insert("server".to_string(), json!(server));
            }
            if let Some(mode) = &image_source.mode {
                source.insert("mode".to_string(), json!(mode));
            }
            if let Some(protocol) = &image_source.protocol {
                source.insert("protocol".to_string(), json!(protocol));
            }
            Value::Object(source)
        }
    };

    let mut payload = Map::new();
    payload.insert("source".to_string(), source);
    if let Some(config) = config {
        if !config.is_empty() {
            payload.insert("config".to_string(), Value::Object(config.clone()));
        }
    }

    // rebuild is a long operation: 5 minute timeout.
    run_instance_action_with_busy_retry(
        client,
        name,
        "rebuild the instance",
        || {
            let payload = Value::Object(payload.clone());
            async move {
                client
                    .request(
                        "POST",
                        &format!("/1.0/instances/{name}/rebuild"),
                        Some(&payload),
                        300_000,
                    )
                    .await
            }
        },
        options,
    )
    .await
}

/// Mirrors `updateInstance`: the config object merges with the existing
/// configuration instead of replacing it.
pub async fn update_instance(
    client: &IncusClient,
    name: &str,
    updates: &Map<String, Value>,
) -> Result<Value, IncusError> {
    run_instance_action_with_busy_retry(
        client,
        name,
        "update the instance configuration",
        || async {
            let current = get_instance_value(client, name).await?;
            let mut body = current;

            // Config updates merge with the existing config.
            if let Some(updated_config) = updates.get("config") {
                let mut merged = body
                    .get("config")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                if let Some(updated) = updated_config.as_object() {
                    for (key, value) in updated {
                        merged.insert(key.clone(), value.clone());
                    }
                }
                body["config"] = Value::Object(merged);
            }

            for (key, value) in updates {
                if key == "config" {
                    continue;
                }
                body[key.clone()] = value.clone();
            }

            client
                .request_default("PUT", &format!("/1.0/instances/{name}"), Some(&body))
                .await
        },
        BusyRetryOptions::default(),
    )
    .await
}

/// Mirrors `patchInstanceResources` resources parameter.
#[derive(Debug, Clone, Copy, Default)]
pub struct InstanceResourcePatch {
    /// CPU allowance percentage.
    pub cpu: Option<i64>,
    /// Memory in MB.
    pub memory: Option<i64>,
    /// Disk in MB (grow only, Incus enforces it).
    pub disk: Option<i64>,
}

/// Mirrors `patchInstanceResources`: incremental PATCH, live without restart.
pub async fn patch_instance_resources(
    client: &IncusClient,
    name: &str,
    resources: InstanceResourcePatch,
) -> Result<Value, IncusError> {
    let mut config = Map::new();

    if let Some(cpu) = resources.cpu {
        config.insert("limits.cpu".to_string(), json!(allowance_to_cores(cpu).to_string()));
        config.insert("limits.cpu.allowance".to_string(), json!(format!("{cpu}%")));
    }

    if let Some(memory) = resources.memory {
        config.insert("limits.memory".to_string(), json!(format!("{memory}MB")));
    }

    let mut devices: Option<Map<String, Value>> = None;
    if let Some(disk) = resources.disk {
        // Preserve the other root device properties.
        let current = get_instance(client, name).await?;
        let current_root = current
            .devices
            .get("root")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let mut root = current_root.clone();
        root.insert("path".to_string(), json!("/"));
        let pool = current_root
            .get("pool")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .unwrap_or("default")
            .to_string();
        root.insert("pool".to_string(), json!(pool));
        root.insert("type".to_string(), json!("disk"));
        root.insert("size".to_string(), json!(format!("{disk}MB")));

        let mut devices_map = Map::new();
        devices_map.insert("root".to_string(), Value::Object(root));
        devices = Some(devices_map);
    }

    let mut patch = Map::new();
    if !config.is_empty() {
        patch.insert("config".to_string(), Value::Object(config));
    }
    if let Some(devices) = devices {
        patch.insert("devices".to_string(), Value::Object(devices));
    }

    client
        .request_default("PATCH", &format!("/1.0/instances/{name}"), Some(&Value::Object(patch)))
        .await
}

/// Mirrors `updateInstanceIpv6Addresses`: atomic PATCH that clears volatile
/// state and updates the IPv6 device list.
#[allow(clippy::too_many_arguments)]
pub async fn update_instance_ipv6_addresses(
    client: &IncusClient,
    instance_name: &str,
    ipv6_list: &[String],
    device_name: Option<&str>,
    network_name: Option<&str>,
    restart: bool,
) -> Result<Value, IncusError> {
    let device_name = device_name.unwrap_or("eth0");
    let network_name = network_name.unwrap_or("incusbr0");

    let instance = get_instance(client, instance_name).await?;
    let eth0_config = instance
        .devices
        .get(device_name)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    // Incus wants "IP1,IP2" with no spaces; empty entries are dropped.
    let ip_string = ipv6_list
        .iter()
        .filter(|ip| !ip.trim().is_empty())
        .map(|ip| ip.trim())
        .collect::<Vec<_>>()
        .join(",");

    // volatile state only exists while the instance runs.
    let state = get_instance_state(client, instance_name).await?;
    let is_running = state.get("status").and_then(Value::as_str) == Some("Running");

    let mut device = eth0_config.clone();
    device.insert("name".to_string(), json!(device_name));
    device.insert("type".to_string(), json!("nic"));
    device.insert("network".to_string(), json!(network_name));
    device.insert("ipv6.address".to_string(), json!(ip_string));
    device.insert("security.ipv6_filtering".to_string(), json!("true"));
    // Explicitly clear stale IPv4 data ("Item \"\": Not an IP address").
    device.insert("ipv4.address".to_string(), Value::Null);

    let mut patch = Map::new();
    let mut devices_patch = Map::new();
    devices_patch.insert(device_name.to_string(), Value::Object(device));
    patch.insert("devices".to_string(), Value::Object(devices_patch));

    if is_running {
        patch.insert(
            "config".to_string(),
            json!({
                format!("volatile.{device_name}.host_name"): Value::Null,
                format!("volatile.{device_name}.hwaddr"): Value::Null,
                format!("volatile.{device_name}.last_state.ip_addresses"): Value::Null,
            }),
        );
    }

    let result = client
        .request_default(
            "PATCH",
            &format!("/1.0/instances/{instance_name}"),
            Some(&Value::Object(patch)),
        )
        .await?;

    // Restart running instances so the change applies; stopped instances pick
    // it up on the next boot. Restart failures are logged, not fatal.
    if restart && is_running {
        if let Err(err) = restart_instance(client, instance_name, false).await {
            tracing::warn!("[updateInstanceIpv6Addresses] 重启容器 {instance_name} 失败: {err}");
        }
    }

    Ok(result)
}

/// Mirrors `addDevice`.
pub async fn add_device(
    client: &IncusClient,
    instance_name: &str,
    device_name: &str,
    device: &Value,
) -> Result<Value, IncusError> {
    let instance = get_instance_value(client, instance_name).await?;
    let mut body = instance;
    let mut devices = body
        .get("devices")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    devices.insert(device_name.to_string(), device.clone());
    body["devices"] = Value::Object(devices);
    client
        .request_default("PUT", &format!("/1.0/instances/{instance_name}"), Some(&body))
        .await
}

/// Mirrors `removeDevice` (no-op returns null when the device does not exist).
pub async fn remove_device(
    client: &IncusClient,
    instance_name: &str,
    device_name: &str,
) -> Result<Value, IncusError> {
    let instance = get_instance_value(client, instance_name).await?;
    let mut body = instance;
    let mut devices = body
        .get("devices")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if devices.remove(device_name).is_some() {
        body["devices"] = Value::Object(devices);
        return client
            .request_default("PUT", &format!("/1.0/instances/{instance_name}"), Some(&body))
            .await;
    }
    Ok(Value::Null)
}

/// Mirrors `normalizeBandwidth`: legacy Gbit values become Mbit so Incus
/// accepts them across versions.
fn normalize_bandwidth(value: Option<&str>) -> Option<String> {
    static GBIT: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"(?i)^(\d+(?:\.\d+)?)\s*Gbit$").expect("static regex")
    });
    let value = value?;
    if let Some(captures) = GBIT.captures(value) {
        let number: f64 = captures.get(1).and_then(|m| m.as_str().parse().ok())?;
        let mbit = (number * 1000.0).round();
        return Some(format!(
            "{}Mbit",
            mbit as i64
        ));
    }
    Some(value.to_string())
}

/// Mirrors `BuildInstanceConfigOptions` from types/incus.ts.
#[derive(Debug, Clone, Default)]
pub struct BuildInstanceConfigOptions {
    pub name: String,
    pub image: String,
    pub cpu: i64,
    pub memory: i64,
    pub disk: i64,
    pub swap_enabled: Option<bool>,
    pub swap_size: Option<i64>,
    pub network_mode: Option<NetworkMode>,
    pub ssh_key: Option<String>,
    pub password: Option<String>,
    pub nested: bool,
    pub privileged: bool,
    /// Optional prebuilt cloud-init payload from the config generators.
    pub cloud_init_config: Option<Map<String, Value>>,
    /// "container" (default) or "vm".
    pub instance_type: Option<String>,
    pub storage_pool: Option<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub ipv6_gateway: Option<String>, // deprecated, unused like in TS
    pub network_bridge: Option<String>,
    pub ipv6_config: Option<Ipv6Config>,
    pub host_interface: Option<String>,
    pub limits_read: Option<String>,
    pub limits_write: Option<String>,
    pub limits_read_iops: Option<i64>,
    pub limits_write_iops: Option<i64>,
    pub limits_ingress: Option<String>,
    pub limits_egress: Option<String>,
    pub limits_processes: Option<i64>,
    pub limits_cpu_priority: Option<i64>,
    pub boot_autostart: Option<bool>,
    pub boot_autostart_priority: Option<i64>,
    pub boot_autostart_delay: Option<i64>,
    pub boot_host_shutdown_timeout: Option<i64>,
}

/// Mirrors `buildInstanceConfig`.
pub fn build_instance_config(options: &BuildInstanceConfigOptions) -> Value {
    let instance_type = options.instance_type.as_deref().unwrap_or("container");
    let network_mode = options.network_mode.unwrap_or(NetworkMode::Nat);
    let storage_pool = options
        .storage_pool
        .clone()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "default".to_string());
    let host_interface = options
        .host_interface
        .clone()
        .filter(|h| !h.is_empty());
    let network_bridge = options
        .network_bridge
        .clone()
        .filter(|b| !b.is_empty());

    let normalized_ingress = normalize_bandwidth(options.limits_ingress.as_deref());
    let normalized_egress = normalize_bandwidth(options.limits_egress.as_deref());

    let mut config_obj = Map::new();
    config_obj.insert(
        "limits.cpu".to_string(),
        json!(allowance_to_cores(options.cpu).to_string()),
    );
    config_obj.insert(
        "limits.cpu.allowance".to_string(),
        json!(format!("{}%", options.cpu)),
    );
    config_obj.insert(
        "limits.memory".to_string(),
        json!(format!("{}MB", options.memory)),
    );

    if instance_type == "container" && (options.swap_enabled.is_some() || options.swap_size.is_some())
    {
        config_obj.insert(
            "limits.memory.swap".to_string(),
            json!(resolve_incus_swap_value(options.swap_enabled == Some(true), options.swap_size)),
        );
    }

    // Root device with storage I/O limits. Incus limits.read/write accept
    // either bandwidth ("100MB") or IOPS ("500iops"); bandwidth wins.
    let mut root_device = Map::new();
    root_device.insert("path".to_string(), json!("/"));
    root_device.insert("pool".to_string(), json!(storage_pool));
    root_device.insert("type".to_string(), json!("disk"));
    root_device.insert("size".to_string(), json!(format!("{}MB", options.disk)));

    if let Some(limits_read) = options.limits_read.as_deref().filter(|v| !v.is_empty()) {
        root_device.insert("limits.read".to_string(), json!(limits_read));
    } else if let Some(iops) = options.limits_read_iops {
        root_device.insert("limits.read".to_string(), json!(format!("{iops}iops")));
    }
    if let Some(limits_write) = options.limits_write.as_deref().filter(|v| !v.is_empty()) {
        root_device.insert("limits.write".to_string(), json!(limits_write));
    } else if let Some(iops) = options.limits_write_iops {
        root_device.insert("limits.write".to_string(), json!(format!("{iops}iops")));
    }

    if let Some(processes) = options.limits_processes {
        config_obj.insert("limits.processes".to_string(), json!(processes.to_string()));
    }

    // Incus maps limits.cpu.priority 0-10 internally; no conversion here.
    if let Some(priority) = options.limits_cpu_priority {
        config_obj.insert("limits.cpu.priority".to_string(), json!(priority.to_string()));
    }

    if let Some(autostart) = options.boot_autostart {
        config_obj.insert(
            "boot.autostart".to_string(),
            json!(if autostart { "true" } else { "false" }),
        );
    }
    if let Some(priority) = options.boot_autostart_priority {
        config_obj.insert(
            "boot.autostart.priority".to_string(),
            json!(priority.to_string()),
        );
    }
    if let Some(delay) = options.boot_autostart_delay {
        config_obj.insert("boot.autostart.delay".to_string(), json!(delay.to_string()));
    }
    if let Some(timeout) = options.boot_host_shutdown_timeout {
        config_obj.insert(
            "boot.host_shutdown_timeout".to_string(),
            json!(timeout.to_string()),
        );
    }

    let mut devices: Map<String, Value> = Map::new();
    devices.insert("root".to_string(), Value::Object(root_device));

    if instance_type == "vm" {
        // RHEL-family cloud images need the agent config ISO at boot.
        let mut agent = Map::new();
        agent.insert("type".to_string(), json!("disk"));
        agent.insert("source".to_string(), json!("agent:config"));
        devices.insert("agent".to_string(), Value::Object(agent));
    }

    // New dual-NIC architecture applies when a static IPv4 exists or a routed
    // IPv6 config is present; the legacy single-NIC NAT path is the fallback.
    let effective_ipv6_config: Option<Ipv6Config> = options.ipv6_config.clone().or_else(|| {
        options
            .ipv6_address
            .clone()
            .filter(|ip| !ip.is_empty())
            .map(|ip| Ipv6Config {
                primary_ip: ip,
                extra_ips: None,
                subnet: None,
            })
    });
    let vm_nic_macs: Option<VmNicMacs> = if instance_type == "vm" {
        Some(generate_vm_nic_macs(&options.name))
    } else {
        None
    };

    let use_new_network_architecture = options
        .ipv4_address
        .as_deref()
        .filter(|ip| !ip.is_empty())
        .is_some()
        || (has_ipv6_support(network_mode)
            && effective_ipv6_config.is_some()
            && host_interface
                .as_deref()
                .filter(|h| !h.is_empty())
                .is_some());

    if use_new_network_architecture {
        let network_devices = build_network_devices(&BuildNetworkDevicesOptions {
            network_mode,
            host_interface: host_interface
                .clone()
                .unwrap_or_else(|| "eth0".to_string()),
            ipv6_config: effective_ipv6_config.clone(),
            limits_ingress: normalized_ingress.clone(),
            limits_egress: normalized_egress.clone(),
            nat_bridge: Some(network_bridge.clone().unwrap_or_else(|| "incusbr0".to_string())),
            ipv4_address: options.ipv4_address.clone().filter(|ip| !ip.is_empty()),
            eth0_hwaddr: vm_nic_macs.as_ref().map(|m| m.eth0.clone()),
            eth1_hwaddr: vm_nic_macs.as_ref().map(|m| m.eth1.clone()),
        });
        for (key, value) in network_devices {
            devices.insert(key, value);
        }
    } else {
        // Legacy: single-NIC NAT mode.
        let needs_explicit_network = instance_type == "vm"
            || options
                .ipv4_address
                .as_deref()
                .filter(|ip| !ip.is_empty())
                .is_some()
            || options
                .ipv6_address
                .as_deref()
                .filter(|ip| !ip.is_empty())
                .is_some()
            || normalized_ingress.is_some()
            || normalized_egress.is_some()
            || network_mode != NetworkMode::Nat;

        if needs_explicit_network {
            let mut eth0_device = Map::new();
            eth0_device.insert("type".to_string(), json!("nic"));
            eth0_device.insert("name".to_string(), json!("eth0"));
            eth0_device.insert(
                "network".to_string(),
                json!(network_bridge.unwrap_or_else(|| "incusbr0".to_string())),
            );
            if let Some(macs) = &vm_nic_macs {
                eth0_device.insert("hwaddr".to_string(), json!(macs.eth0));
            }
            // VMs must declare the static IPv4 or Incus rejects NAT proxy rules.
            if let Some(ipv4) = options.ipv4_address.as_deref().filter(|ip| !ip.is_empty()) {
                eth0_device.insert("ipv4.address".to_string(), json!(ipv4));
            }
            if let Some(ingress) = &normalized_ingress {
                eth0_device.insert("limits.ingress".to_string(), json!(ingress));
            }
            if let Some(egress) = &normalized_egress {
                eth0_device.insert("limits.egress".to_string(), json!(egress));
            }
            devices.insert("eth0".to_string(), Value::Object(eth0_device));
        }
    }

    // Image source: "images:" prefixed aliases pull from the remote.
    let source = if let Some(remote_alias) = options.image.strip_prefix("images:") {
        json!({
            "type": "image",
            "mode": "pull",
            "server": "https://images.linuxcontainers.org",
            "protocol": "simplestreams",
            "alias": remote_alias
        })
    } else {
        json!({
            "type": "image",
            "alias": options.image
        })
    };

    let mut config = Map::new();
    config.insert("name".to_string(), json!(options.name));
    config.insert(
        "type".to_string(),
        json!(if instance_type == "vm" {
            "virtual-machine"
        } else {
            "container"
        }),
    );
    config.insert("source".to_string(), source);
    config.insert("config".to_string(), Value::Object(config_obj));
    config.insert("devices".to_string(), Value::Object(devices));

    {
        let config_inner = config
            .get_mut("config")
            .and_then(Value::as_object_mut)
            .expect("config object just inserted");
        // VMs disable UEFI secure boot (allows user DD installs).
        if instance_type == "vm" {
            config_inner.insert("security.secureboot".to_string(), json!("false"));
        }
        if options.nested {
            config_inner.insert("security.nesting".to_string(), json!("true"));
        }
        if options.privileged {
            config_inner.insert("security.privileged".to_string(), json!("true"));
        }

        // Prebuilt cloud-init payload from the config generators.
        let has_user_data = options
            .cloud_init_config
            .as_ref()
            .and_then(|c| c.get("user.user-data"))
            .and_then(Value::as_str)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if has_user_data {
            let payload = options.cloud_init_config.as_ref().expect("checked");
            config_inner.insert(
                "user.user-data".to_string(),
                payload.get("user.user-data").cloned().expect("checked"),
            );
            if let Some(network_config) = payload.get("user.network-config") {
                config_inner.insert("user.network-config".to_string(), network_config.clone());
            }
        } else {
            // Legacy fallback: SSH key injection + password + hostname.
            let mut lines: Vec<String> = vec![
                "#cloud-config".to_string(),
                format!("hostname: {}", options.name),
                "manage_etc_hosts: true".to_string(),
            ];
            if let Some(password) = options.password.as_deref().filter(|p| !p.is_empty()) {
                lines.push("chpasswd:".to_string());
                lines.push("  expire: false".to_string());
                lines.push("  list:".to_string());
                lines.push(format!("    - root:{password}"));
                lines.push("ssh_pwauth: true".to_string());
            }
            if let Some(ssh_key) = options.ssh_key.as_deref().filter(|k| !k.trim().is_empty()) {
                lines.push("ssh_authorized_keys:".to_string());
                lines.push(format!("  - {}", ssh_key.trim()));
            }
            lines.push("disable_root: false".to_string());
            lines.push("runcmd:".to_string());
            lines.push(
                "  - sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config"
                    .to_string(),
            );
            lines.push(
                "  - sed -i 's/PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config"
                    .to_string(),
            );
            lines.push("  - systemctl restart sshd || service ssh restart || true".to_string());
            config_inner.insert("user.user-data".to_string(), json!(lines.join("\n")));
        }
    }

    // Dual-NIC architecture needs a v2 network-config covering eth0 + eth1.
    // VM network-config comes from generateVmConfig (MAC matched) and must
    // never be overwritten.
    if has_ipv6_support(network_mode)
        && effective_ipv6_config.is_some()
        && options
            .ipv4_address
            .as_deref()
            .filter(|ip| !ip.is_empty())
            .is_some()
        && instance_type != "vm"
    {
        let ipv6_config = effective_ipv6_config.as_ref().expect("checked");
        let mut ipv6_list = vec![ipv6_config.primary_ip.clone()];
        if let Some(extra) = &ipv6_config.extra_ips {
            ipv6_list.extend(extra.iter().cloned());
        }
        if let Some(config_inner) = config.get_mut("config").and_then(Value::as_object_mut) {
            config_inner.insert(
                "user.network-config".to_string(),
                json!(generate_cloud_init_network_config(&CloudInitNetworkOptions {
                    ipv4_address: options.ipv4_address.clone().expect("checked"),
                    ipv6_list: Some(ipv6_list),
                    nic_macs: vm_nic_macs.as_ref().map(PartialVmNicMacs::from),
                })),
            );
        }
    }

    Value::Object(config)
}

// ==================== exec ====================

/// Mirrors the `command: string | string[]` parameter of `exec`.
#[derive(Debug, Clone)]
pub enum IncusExecCommand {
    /// Raw shell string, wrapped into ['/bin/sh', '-c', <command>].
    Shell(String),
    /// Explicit argv.
    Argv(Vec<String>),
}

/// Mirrors `exec`.
pub async fn exec(
    client: &IncusClient,
    instance_name: &str,
    command: IncusExecCommand,
    options: Option<&Map<String, Value>>,
    timeout_ms: u64,
) -> Result<Value, IncusError> {
    let timeout_ms = if timeout_ms == 0 {
        DEFAULT_REQUEST_TIMEOUT_MS
    } else {
        timeout_ms
    };
    let command_value = match command {
        IncusExecCommand::Shell(shell) => json!(["/bin/sh", "-c", shell]),
        IncusExecCommand::Argv(argv) => json!(argv),
    };
    let mut body = Map::new();
    body.insert("command".to_string(), command_value);
    body.insert("wait-for-websocket".to_string(), json!(false));
    body.insert("interactive".to_string(), json!(false));
    if let Some(options) = options {
        for (key, value) in options {
            body.insert(key.clone(), value.clone());
        }
    }
    client
        .request(
            "POST",
            &format!("/1.0/instances/{instance_name}/exec"),
            Some(&Value::Object(body)),
            timeout_ms,
        )
        .await
}

/// Mirrors `IncusExecOutput`.
#[derive(Debug, Clone)]
pub struct IncusExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub metadata: Value,
}

fn extract_output_file_path(metadata: &Value, fd: &str) -> Option<String> {
    metadata
        .get("output")
        .and_then(|output| output.get(fd))
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .map(|path| path.to_string())
}

/// Mirrors `execWithOutput`.
pub async fn exec_with_output(
    client: &IncusClient,
    instance_name: &str,
    command: IncusExecCommand,
    options: Option<&Map<String, Value>>,
    timeout_ms: u64,
) -> Result<IncusExecOutput, IncusError> {
    let mut merged = Map::new();
    merged.insert("record-output".to_string(), json!(true));
    if let Some(options) = options {
        for (key, value) in options {
            merged.insert(key.clone(), value.clone());
        }
    }

    let metadata = exec(
        client,
        instance_name,
        command,
        Some(&merged),
        timeout_ms,
    )
    .await?;

    let stdout_path = extract_output_file_path(&metadata, "1");
    let stderr_path = extract_output_file_path(&metadata, "2");

    let read_side = async {
        match &stdout_path {
            Some(path) => client
                .read_file(path)
                .await
                .map(|(content, _)| content)
                .unwrap_or_default(),
            None => String::new(),
        }
    };
    let read_err = async {
        match &stderr_path {
            Some(path) => client
                .read_file(path)
                .await
                .map(|(content, _)| content)
                .unwrap_or_default(),
            None => String::new(),
        }
    };
    let (stdout, stderr) = tokio::join!(read_side, read_err);

    Ok(IncusExecOutput {
        stdout,
        stderr,
        metadata,
    })
}

/// Mirrors `getConsoleWebSocketUrl` (used by the terminal proxy).
pub fn get_console_websocket_url(client: &IncusClient, instance_name: &str) -> String {
    let ws_url = client
        .base_url()
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    format!("{ws_url}/1.0/instances/{instance_name}/console?wait-for-websocket=true")
}

// ==================== bridge defense ====================

/// Mirrors `ensureBridgeIpv6`: defensive fix for bridge-level IPv6 NAT on
/// ipv6_nat / nat_ipv6_nat modes. Failures never block instance creation.
pub async fn ensure_bridge_ipv6(
    client: &IncusClient,
    network_mode: &str,
    bridge_name: Option<&str>,
) -> Result<(), IncusError> {
    let bridge_name = bridge_name.unwrap_or("incusbr0");
    if network_mode != "ipv6_nat" && network_mode != "nat_ipv6_nat" {
        return Ok(());
    }

    match async {
        let bridge = client
            .request_default("GET", &format!("/1.0/networks/{bridge_name}"), None)
            .await?;
        let config = bridge
            .get("config")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let ipv6_address = config
            .get("ipv6.address")
            .and_then(Value::as_str)
            .unwrap_or("");
        let ipv6_nat = config.get("ipv6.nat").and_then(Value::as_str);
        let needs_fix = ipv6_address == "none"
            || ipv6_nat
                .map(|v| v != "true")
                .unwrap_or(true);

        if needs_fix {
            client
                .request_default(
                    "PATCH",
                    &format!("/1.0/networks/{bridge_name}"),
                    Some(&json!({
                        "config": {
                            "ipv6.address": "auto",
                            "ipv6.nat": "true",
                            "ipv6.dhcp": "true"
                        }
                    })),
                )
                .await?;
            tracing::info!(
                "[ensureBridgeIpv6] 已自动为网桥 {bridge_name} 启用 IPv6 NAT（网络模式: {network_mode}）"
            );
        }
        Ok::<(), IncusError>(())
    }
    .await
    {
        Ok(()) => Ok(()),
        Err(err) => {
            tracing::warn!("[ensureBridgeIpv6] 网桥 IPv6 校验失败（{bridge_name}）: {err}");
            Ok(())
        }
    }
}

// ==================== tests (ports of the TS *.test.ts files) ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libs::incus::incus_client::DispatchResult;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    type Calls = std::sync::Mutex<Vec<String>>;

    fn mock_client<F>(handler: F) -> IncusClient
    where
        F: Fn(String, String, Option<Value>, u64) -> DispatchResult + Send + Sync + 'static,
    {
        IncusClient::for_tests(Arc::new(move |method, path, body, timeout| {
            let result = handler(method, path, body, timeout);
            Box::pin(async move { result })
        }))
    }

    fn api_not_found(method: &str, path: &str) -> IncusError {
        IncusError::Api {
            message: "Instance not found".to_string(),
            status_code: 404,
            method: method.to_string(),
            path: path.to_string(),
        }
    }

    // ---- incus-instances.cleanup.test.ts ----

    #[tokio::test]
    async fn ensure_instance_deleted_confirms_a_successful_deletion_with_404() {
        let calls: Arc<Calls> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let deleted = Arc::new(AtomicBool::new(false));

        let calls_for_handler = calls.clone();
        let deleted_for_handler = deleted.clone();
        let client = mock_client(move |method, path, _body, _timeout| {
            calls_for_handler
                .lock()
                .unwrap()
                .push(format!("{method} {path}"));

            if method == "DELETE" && path == "/1.0/instances/demo" {
                deleted_for_handler.store(true, Ordering::SeqCst);
                return Ok((200, "{}".to_string(), None));
            }
            if method == "GET" && path == "/1.0/instances/demo" {
                if deleted_for_handler.load(Ordering::SeqCst) {
                    return Err(api_not_found(&method, &path));
                }
                return Ok((200, r#"{"name":"demo"}"#.to_string(), None));
            }
            if path == "/1.0/instances/demo/state" {
                return Ok((200, r#"{"status":"Stopped"}"#.to_string(), None));
            }
            Err(IncusError::Other(format!("Unexpected request: {method} {path}")))
        });

        ensure_instance_deleted(&client, "demo").await.expect("deleted");

        let calls = calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                "GET /1.0/instances/demo".to_string(),
                "GET /1.0/instances/demo/state".to_string(),
                "DELETE /1.0/instances/demo".to_string(),
                "GET /1.0/instances/demo".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn ensure_instance_deleted_keeps_unknown_incus_errors_as_failures() {
        let client = mock_client(|_method, _path, _body, _timeout| {
            Err(IncusError::Transport("connect ETIMEDOUT".to_string()))
        });
        let result = ensure_instance_deleted(&client, "demo").await;
        let message = format!("{}", result.expect_err("must fail"));
        assert!(message.contains("connect ETIMEDOUT"), "{message}");
    }

    #[tokio::test]
    async fn provisioning_resolution_treats_a_running_instance_as_a_successful_provision() {
        let client = mock_client(|method, path, _body, _timeout| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/1.0/instances/demo");
            Ok((200, r#"{"name":"demo","status":"Running"}"#.to_string(), None))
        });

        let resolution = wait_for_provisioning_instance_resolution(&client, "demo", 0)
            .await
            .expect("resolves");
        assert_eq!(
            resolution,
            ProvisioningInstanceResolution::Present {
                status: ProvisionStatus::Running
            }
        );
    }

    #[tokio::test]
    async fn provisioning_resolution_only_accepts_absence_after_operations_are_gone() {
        let operation_active = Arc::new(AtomicBool::new(true));
        let flag = operation_active.clone();
        let client = mock_client(move |method, path, _body, _timeout| {
            if path == "/1.0/instances/demo" {
                return Err(api_not_found(&method, &path));
            }
            if path == "/1.0/operations?recursion=1" {
                let payload = if flag.swap(false, Ordering::SeqCst) {
                    r#"[{"id":"/1.0/operations/1","status":"Running","status_code":103,"resources":{"instances":["/1.0/instances/demo"]}}]"#
                } else {
                    "[]"
                };
                return Ok((200, payload.to_string(), None));
            }
            Err(IncusError::Other(format!("Unexpected request: {method} {path}")))
        });

        let resolution = wait_for_provisioning_instance_resolution(&client, "demo", 0)
            .await
            .expect("resolves");
        assert_eq!(resolution, ProvisioningInstanceResolution::Absent);
    }

    #[tokio::test]
    async fn create_waits_long_enough_for_remote_image_pulls_and_vm_creation() {
        let client = mock_client(|method, path, body, timeout| {
            assert_eq!(method, "POST");
            assert_eq!(path, "/1.0/instances");
            assert_eq!(body, Some(json!({ "name": "demo" })));
            assert_eq!(timeout, 15 * 60 * 1000);
            Ok((200, "{}".to_string(), None))
        });
        create_instance(&client, &json!({ "name": "demo" }))
            .await
            .expect("create resolves");
    }

    #[tokio::test]
    async fn create_retry_waits_for_the_new_instance_to_appear_before_start() {
        let checks = Arc::new(AtomicUsize::new(0));
        let flag = checks.clone();
        let client = mock_client(move |method, path, _body, _timeout| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/1.0/instances/demo");
            if flag.fetch_add(1, Ordering::SeqCst) + 1 < 3 {
                return Err(api_not_found(&method, &path));
            }
            Ok((200, r#"{"name":"demo","status":"Stopped"}"#.to_string(), None))
        });
        let status = wait_for_created_instance(&client, "demo", 100, 1)
            .await
            .expect("becomes visible");
        assert_eq!(status, "Stopped");
        assert_eq!(checks.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn create_retry_waits_through_a_transitional_instance_state() {
        let checks = Arc::new(AtomicUsize::new(0));
        let flag = checks.clone();
        let client = mock_client(move |_method, _path, _body, _timeout| {
            let attempt = flag.fetch_add(1, Ordering::SeqCst) + 1;
            let status = if attempt == 1 { "Creating" } else { "Running" };
            Ok((
                200,
                format!(r#"{{"name":"demo","status":"{status}"}}"#),
                None,
            ))
        });
        let status = wait_for_created_instance(&client, "demo", 100, 1)
            .await
            .expect("becomes ready");
        assert_eq!(status, "Running");
        assert_eq!(checks.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn create_retry_reports_a_still_missing_instance_and_does_not_start_it() {
        let client = mock_client(|method, path, _body, _timeout| {
            Err(api_not_found(&method, &path))
        });
        let result = wait_for_created_instance(&client, "demo", 0, 0).await;
        let message = format!("{}", result.expect_err("must fail"));
        assert!(message.contains("was not found after creation"), "{message}");
    }

    #[tokio::test]
    async fn create_retry_does_not_treat_an_incus_error_as_a_missing_instance() {
        let client = mock_client(|_method, _path, _body, _timeout| {
            Err(IncusError::Api {
                message: "Storage pool is unavailable".to_string(),
                status_code: 503,
                method: "GET".to_string(),
                path: "/1.0/instances/demo".to_string(),
            })
        });
        let result = wait_for_created_instance(&client, "demo", 100, 1).await;
        let message = format!("{}", result.expect_err("must fail"));
        assert!(message.contains("Storage pool is unavailable"), "{message}");
    }

    // ---- incus-instances.nvram.test.ts ----

    #[test]
    fn missing_vm_nvram_detection_only_matches_the_incus_missing_file_failure() {
        assert!(is_missing_vm_nvram_error(&IncusError::Other(
            "Failed copying NVRAM file: open /var/lib/incus/virtual-machines/demo/qemu.nvram: no such file or directory"
                .to_string()
        )));
        assert!(is_missing_vm_nvram_error(&IncusError::Other(
            "Failed opening NVRAM file: open /var/lib/incus/virtual-machines/demo/qemu.nvram: no such file or directory"
                .to_string()
        )));
        assert!(!is_missing_vm_nvram_error(&IncusError::Other(
            "Failed to start VM: permission denied".to_string()
        )));
    }

    #[tokio::test]
    async fn start_repairs_missing_vm_nvram_and_retries_exactly_once() {
        let calls: Arc<std::sync::Mutex<Vec<(String, String, Option<Value>, Option<u64>)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let start_attempts = Arc::new(AtomicUsize::new(0));

        let calls_ref = calls.clone();
        let attempts_ref = start_attempts.clone();
        let client = mock_client(move |method, path, body, timeout| {
            calls_ref
                .lock()
                .unwrap()
                .push((method.clone(), path.clone(), body.clone(), Some(timeout)));

            if method == "PUT" && path == "/1.0/instances/demo/state" {
                if attempts_ref.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(IncusError::Other(
                        "Failed copying NVRAM file: open /var/lib/incus/virtual-machines/demo/qemu.nvram: no such file or directory"
                            .to_string(),
                    ));
                }
                return Ok((200, r#"{"status":"Running"}"#.to_string(), None));
            }
            if method == "POST" && path == "/1.0/instances/demo/debug/repair" {
                return Ok((200, "{}".to_string(), None));
            }
            Err(IncusError::Other(format!("Unexpected request: {method} {path}")))
        });

        let (result, repaired) = start_instance_with_nvram_repair(&client, "demo")
            .await
            .expect("start succeeds after repair");

        assert!(repaired);
        assert_eq!(result, json!({ "status": "Running" }));
        assert_eq!(start_attempts.load(Ordering::SeqCst), 2);
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls[1],
            (
                "POST".to_string(),
                "/1.0/instances/demo/debug/repair".to_string(),
                Some(json!({ "action": "rebuild-nvram" })),
                Some(2 * 60 * 1000)
            )
        );
    }

    #[tokio::test]
    async fn start_does_not_repair_or_retry_unrelated_incus_errors() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let flag = attempts.clone();
        let client = mock_client(move |_method, _path, _body, _timeout| {
            flag.fetch_add(1, Ordering::SeqCst);
            Err(IncusError::Transport("connect ETIMEDOUT".to_string()))
        });

        let result = start_instance_with_nvram_repair(&client, "demo").await;
        let message = format!("{}", result.expect_err("must fail"));
        assert!(message.contains("connect ETIMEDOUT"), "{message}");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}
