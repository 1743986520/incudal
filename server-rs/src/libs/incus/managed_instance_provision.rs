//! Managed instance provisioning orchestration.
//! Port of lib/managed-instance-provision.ts, together with the pure address
//! resolution helpers it consumes from lib/instance-network-sync.ts.
//!
//! The three `db/billing-operations.ts` settlement functions used by the
//! failure path are ported where they are self-contained
//! (`claimCreatingInstanceForCleanup`, `markCreatingInstanceProvisioned` —
//! instance-table transactions with the INSTANCE_OPERATION advisory lock).
//! `failCreatingInstanceAndRefund` is NOT portable here: it drags in coupon
//! release, AFF commission reversal, hourly-billing accounts, and host
//! resource counters from the 2.6k-line billing-operations module. It is
//! represented by an explicit settlement error so the provisioner follows the
//! TS "cleanup confirmed but database settlement is pending" branch and no
//! silent money movement can happen before the billing-operations port lands.

use serde_json::Value;
use sqlx::{PgConnection, PgPool};

use crate::db::advisory_lock_namespace;
use crate::libs::incus::incus_client::{IncusClient, IncusError};
use crate::libs::incus::incus_instances::{
    build_instance_config, create_instance, ensure_instance_deleted, get_instance,
    get_instance_state, start_instance, BuildInstanceConfigOptions,
};
use crate::libs::incus::incus_pool::PoolHost;
use crate::libs::incus::network_payload_builder::{Ipv6Config, NetworkMode};

/// Mirrors `ManagedInstanceProvisionConfig`.
#[derive(Debug, Clone, Default)]
pub struct ManagedInstanceProvisionConfig {
    pub name: String,
    pub image: String,
    pub cpu: i64,
    pub memory: i64,
    pub disk: i64,
    pub cloud_init_config: Option<serde_json::Map<String, Value>>,
    pub network_mode: NetworkMode,
    pub nested: Option<bool>,
    pub privileged: Option<bool>,
    pub port_limit: Option<i64>,
    pub instance_type: Option<String>,
    pub ssh_port: Option<i64>,
    pub storage_pool: Option<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub ipv6_gateway: Option<String>,
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

/// Mirrors `ResolvedInstanceNetworkAddresses`.
#[derive(Debug, Clone, Default)]
pub struct ResolvedInstanceNetworkAddresses {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub ipv4_device: String,
    pub ipv6_device: String,
    pub configured_ipv6: Option<String>,
    pub observed_ipv6: Option<String>,
}

/// Mirrors `InstanceNetworkSyncTarget`.
#[derive(Debug, Clone, Default)]
pub struct InstanceNetworkSyncTarget {
    pub id: i64,
    pub name: Option<String>,
    pub host_id: Option<i64>,
    pub network_mode: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

const ROUTED_IPV6_MODES: [&str; 2] = ["nat_ipv6", "ipv6_only"];
const SHARED_IPV6_MODES: [&str; 2] = ["nat_ipv6_nat", "ipv6_nat"];
const SKIPPED_INTERFACES: [&str; 5] = ["lo", "docker", "br-", "veth", "warp"];

fn normalize_ipv6_address_value(value: Option<&str>) -> Option<String> {
    let value = value?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let first = trimmed.split(',').next().unwrap_or("").trim();
    let raw = first.split('/').next().unwrap_or("").trim();
    if raw.is_empty() {
        None
    } else {
        Some(raw.to_string())
    }
}

fn is_global_routable_ipv6(value: Option<&str>) -> bool {
    let Some(normalized) = normalize_ipv6_address_value(value) else {
        return false;
    };
    let ip = normalized.to_lowercase();
    !ip.starts_with("fd")
        && !ip.starts_with("fc")
        && !ip.starts_with("fe80:")
        && ip != "::1"
        && ip != "::"
}

fn should_skip_interface(iface: &str) -> bool {
    SKIPPED_INTERFACES
        .iter()
        .any(|prefix| iface == *prefix || iface.starts_with(prefix))
}

fn get_instance_mode(mode: Option<&str>) -> &'static str {
    match mode {
        Some("nat_ipv6") => "nat_ipv6",
        Some("nat_ipv6_nat") => "nat_ipv6_nat",
        Some("ipv6_only") => "ipv6_only",
        Some("ipv6_nat") => "ipv6_nat",
        _ => "nat",
    }
}

fn pick_global_ipv6(addresses: Option<&Value>) -> Option<String> {
    let addresses = addresses?;
    let addresses = addresses.as_array()?;
    for addr in addresses {
        let family = addr.get("family").and_then(Value::as_str).unwrap_or("");
        let scope = addr.get("scope").and_then(Value::as_str).unwrap_or("");
        if family != "inet6" || scope != "global" {
            continue;
        }
        let normalized = normalize_ipv6_address_value(addr.get("address").and_then(Value::as_str));
        if is_global_routable_ipv6(normalized.as_deref()) {
            return normalized;
        }
    }
    None
}

/// Mirrors `extractIpv4FromState`.
pub fn extract_ipv4_from_state(state: Option<&Value>) -> Option<String> {
    let network = state?.get("network")?.as_object()?;
    let eth0 = network.get("eth0");
    if let Some(eth0) = eth0 {
        if let Some(addresses) = eth0.get("addresses").and_then(Value::as_array) {
            for addr in addresses {
                if addr.get("family").and_then(Value::as_str) == Some("inet")
                    && addr.get("scope").and_then(Value::as_str) == Some("global")
                {
                    return addr.get("address").and_then(Value::as_str).map(String::from);
                }
            }
        }
    }

    for (iface, info) in network {
        if should_skip_interface(iface) {
            continue;
        }
        if let Some(addresses) = info.get("addresses").and_then(Value::as_array) {
            for addr in addresses {
                if addr.get("family").and_then(Value::as_str) == Some("inet")
                    && addr.get("scope").and_then(Value::as_str) == Some("global")
                {
                    return addr.get("address").and_then(Value::as_str).map(String::from);
                }
            }
        }
    }

    None
}

/// Mirrors `extractIpv6FromState`.
pub fn extract_ipv6_from_state(state: Option<&Value>) -> Option<String> {
    let network = state?.get("network")?.as_object()?;
    let preferred_interfaces = ["eth1", "enp5s0", "ens5", "eno1"];
    for iface in preferred_interfaces {
        let addresses = network.get(iface).and_then(|info| info.get("addresses"));
        if let Some(ipv6) = pick_global_ipv6(addresses) {
            return Some(ipv6);
        }
    }

    for (iface, info) in network {
        if should_skip_interface(iface) {
            continue;
        }
        if let Some(ipv6) = pick_global_ipv6(info.get("addresses")) {
            return Some(ipv6);
        }
    }

    None
}

fn get_device_entries<'a>(
    devices: Option<&'a Value>,
    expanded_devices: Option<&'a Value>,
) -> Vec<(String, &'a Value)> {
    let expanded = expanded_devices.and_then(Value::as_object);
    if let Some(map) = expanded {
        if !map.is_empty() {
            return map.iter().map(|(k, v)| (k.clone(), v)).collect();
        }
    }
    devices
        .and_then(Value::as_object)
        .map(|map| map.iter().map(|(k, v)| (k.clone(), v)).collect())
        .unwrap_or_default()
}

/// Mirrors `extractConfiguredPrimaryIpv6`.
pub fn extract_configured_primary_ipv6(
    devices: Option<&Value>,
    expanded_devices: Option<&Value>,
) -> (Option<String>, String) {
    let entries = get_device_entries(devices, expanded_devices);
    if entries.is_empty() {
        return (None, "eth1".to_string());
    }

    let mut ordered: Vec<&(String, &Value)> =
        entries.iter().filter(|(name, _)| name == "eth1").collect();
    ordered.extend(entries.iter().filter(|(name, _)| name != "eth1"));

    for (fallback_device, device) in ordered {
        let raw_ipv6 = device
            .get("ipv6.address")
            .and_then(Value::as_str)
            .unwrap_or("");
        let candidates: Vec<String> = raw_ipv6
            .split(',')
            .filter_map(|item| normalize_ipv6_address_value(Some(item)))
            .collect();
        let configured_ipv6 = candidates
            .iter()
            .find(|item| is_global_routable_ipv6(Some(item)))
            .cloned();
        if let Some(configured_ipv6) = configured_ipv6 {
            let device_name = device
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .unwrap_or(fallback_device);
            return (
                Some(configured_ipv6),
                if device_name.is_empty() {
                    "eth1".to_string()
                } else {
                    device_name.to_string()
                },
            );
        }
    }

    (None, "eth1".to_string())
}

/// Mirrors `resolveInstanceNetworkAddresses`.
pub fn resolve_instance_network_addresses(
    instance: &InstanceNetworkSyncTarget,
    incus_devices: Option<&Value>,
    incus_expanded_devices: Option<&Value>,
    state: Option<&Value>,
) -> ResolvedInstanceNetworkAddresses {
    let mode = get_instance_mode(instance.network_mode.as_deref());
    let observed_ipv4 = extract_ipv4_from_state(state);
    let observed_ipv6 = extract_ipv6_from_state(state);
    let (configured_ipv6, configured_device) =
        extract_configured_primary_ipv6(incus_devices, incus_expanded_devices);

    let resolved_ipv4 = observed_ipv4.or_else(|| instance.ipv4.clone());

    let resolved_ipv6 = if ROUTED_IPV6_MODES.contains(&mode) {
        configured_ipv6
            .clone()
            .or_else(|| observed_ipv6.clone())
            .or_else(|| instance.ipv6.clone())
    } else if SHARED_IPV6_MODES.contains(&mode) {
        observed_ipv6.clone().or_else(|| instance.ipv6.clone())
    } else {
        instance.ipv6.clone()
    };

    ResolvedInstanceNetworkAddresses {
        ipv4: resolved_ipv4,
        ipv6: resolved_ipv6,
        ipv4_device: "eth0".to_string(),
        ipv6_device: configured_device,
        configured_ipv6,
        observed_ipv6,
    }
}

/// Mirrors `syncPrimaryIpAddress` against the shared `ip_addresses` table.
async fn sync_primary_ip_address(
    tx: &mut PgConnection,
    instance: &InstanceNetworkSyncTarget,
    ip_type: &str,
    address: Option<&str>,
    device: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(address) = address else {
        sqlx::query(
            "DELETE FROM ip_addresses WHERE instance_id = $1 AND type = $2::\"IpType\" \
             AND is_primary = true AND is_custom = false",
        )
        .bind(instance.id)
        .bind(ip_type)
        .execute(&mut *tx)
        .await?;
        return Ok(());
    };

    let mut host_id = instance.host_id;
    if host_id.is_none() {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT host_id FROM instances WHERE id = $1")
                .bind(instance.id)
                .fetch_optional(&mut *tx)
                .await?;
        host_id = row.map(|r| r.0);
    }
    let Some(host_id) = host_id else {
        return Err(format!(
            "Unable to resolve host scope for instance {}",
            instance.id
        )
        .into());
    };

    //inet4 uniqueness is scoped to the host; inet6 addresses are globally unique.
    let existing_by_address: Option<(i64,)> = if ip_type == "inet4" {
        sqlx::query_as(
            "SELECT i.id FROM instances i WHERE i.id <> $1 AND i.status <> 'deleted' \
             AND i.host_id = $2 AND (i.ipv4 = $3 OR EXISTS ( \
               SELECT 1 FROM ip_addresses p WHERE p.instance_id = i.id \
               AND p.address = $3 AND p.type = 'inet4')) LIMIT 1",
        )
        .bind(instance.id)
        .bind(host_id)
        .bind(address)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_as(
            "SELECT i.id FROM instances i WHERE i.id <> $1 AND i.status <> 'deleted' \
             AND (i.ipv6 = $2 OR EXISTS ( \
               SELECT 1 FROM ip_addresses p WHERE p.instance_id = i.id \
               AND p.address = $2 AND p.type = 'inet6')) LIMIT 1",
        )
        .bind(instance.id)
        .bind(address)
        .fetch_optional(&mut *tx)
        .await?
    };

    if let Some((existing_id,)) = existing_by_address {
        return Err(format!(
            "IP address {address} is already assigned to instance {existing_id}"
        )
        .into());
    }

    let existing_primary: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM ip_addresses WHERE instance_id = $1 AND type = $2::\"IpType\" \
         AND is_primary = true AND is_custom = false ORDER BY id ASC LIMIT 1",
    )
    .bind(instance.id)
    .bind(ip_type)
    .fetch_optional(&mut *tx)
    .await?;

    let primary_record_id: i64 = match existing_primary {
        Some((id,)) => {
            sqlx::query(
                "UPDATE ip_addresses SET address = $1, type = $2::\"IpType\", is_primary = true, \
                 is_custom = false, device = $3, host_id = $4 WHERE id = $5",
            )
            .bind(address)
            .bind(ip_type)
            .bind(device)
            .bind(host_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            id
        }
        None => {
            let row: (i64,) = sqlx::query_as(
                "INSERT INTO ip_addresses (address, type, is_primary, is_custom, device, host_id, instance_id, created_at) \
                 VALUES ($1, $2::\"IpType\", true, false, $3, $4, $5, NOW()) RETURNING id",
            )
            .bind(address)
            .bind(ip_type)
            .bind(device)
            .bind(host_id)
            .bind(instance.id)
            .fetch_one(&mut *tx)
            .await?;
            row.0
        }
    };

    sqlx::query(
        "DELETE FROM ip_addresses WHERE instance_id = $1 AND type = $2::\"IpType\" \
         AND is_primary = true AND is_custom = false AND id <> $3",
    )
    .bind(instance.id)
    .bind(ip_type)
    .bind(primary_record_id)
    .execute(&mut *tx)
    .await?;

    Ok(())
}

/// Mirrors `persistResolvedInstanceNetworkAddresses`.
pub async fn persist_resolved_instance_network_addresses(
    db: &PgPool,
    instance: &InstanceNetworkSyncTarget,
    resolved: &ResolvedInstanceNetworkAddresses,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tx = db.begin().await?;

    let current: Option<(String,)> =
        sqlx::query_as("SELECT status::text FROM instances WHERE id = $1")
            .bind(instance.id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((status,)) = current {
        if status != "deleted" {
            // TS compares against the stored values and only writes changes.
            sqlx::query(
                "UPDATE instances SET ipv4 = $1, ipv6 = $2 WHERE id = $3 AND status <> 'deleted'",
            )
            .bind(&resolved.ipv4)
            .bind(&resolved.ipv6)
            .bind(instance.id)
            .execute(&mut *tx)
            .await?;
        }
    }

    sync_primary_ip_address(&mut tx, instance, "inet4", resolved.ipv4.as_deref(), &resolved.ipv4_device).await?;
    sync_primary_ip_address(&mut tx, instance, "inet6", resolved.ipv6.as_deref(), &resolved.ipv6_device).await?;

    tx.commit().await?;
    Ok(())
}

// ==================== billing-operations claim helpers (self-contained) ====================

/// Mirrors `claimCreatingInstanceForCleanup`: claims the cleanup lease while
/// keeping the row `creating` (non-retryable, no refund before confirmation).
pub async fn claim_creating_instance_for_cleanup(
    db: &PgPool,
    instance_id: i64,
    reclaim_pending_before: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    crate::db::advisory_transaction_lock(
        &mut tx,
        advisory_lock_namespace::INSTANCE_OPERATION,
        instance_id,
    )
    .await?;

    let claimed = match reclaim_pending_before {
        Some(before) => {
            sqlx::query(
                "UPDATE instances SET provisioning_cleanup_pending = true, version = version + 1, \
                 updated_at = NOW() WHERE id = $1 AND status = 'creating' AND \
                 (provisioning_cleanup_pending = false OR \
                  (provisioning_cleanup_pending = true AND updated_at < $2))",
            )
            .bind(instance_id)
            .bind(before)
            .execute(&mut *tx)
            .await?
        }
        None => {
            sqlx::query(
                "UPDATE instances SET provisioning_cleanup_pending = true, version = version + 1, \
                 updated_at = NOW() WHERE id = $1 AND status = 'creating' AND \
                 provisioning_cleanup_pending = false",
            )
            .bind(instance_id)
            .execute(&mut *tx)
            .await?
        }
    };

    tx.commit().await?;
    Ok(claimed.rows_affected() == 1)
}

/// Mirrors `markCreatingInstanceProvisioned`: reconcile a timed-out provision
/// that did finish on Incus.
pub async fn mark_creating_instance_provisioned(
    db: &PgPool,
    instance_id: i64,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    crate::db::advisory_transaction_lock(
        &mut tx,
        advisory_lock_namespace::INSTANCE_OPERATION,
        instance_id,
    )
    .await?;

    let current: Option<(String,)> =
        sqlx::query_as("SELECT status::text FROM instances WHERE id = $1")
            .bind(instance_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((current_status,)) = current else {
        tx.commit().await?;
        return Ok(false);
    };
    if current_status == "running" || current_status == "stopped" {
        tx.commit().await?;
        return Ok(true);
    }
    if current_status != "creating" {
        tx.commit().await?;
        return Ok(false);
    }

    sqlx::query(
        "UPDATE instances SET status = $2::\"InstanceStatus\", provisioning_cleanup_pending = false, \
         version = version + 1 WHERE id = $1",
    )
    .bind(instance_id)
    .bind(status)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
}

// ==================== failed-provision cleanup service ====================

/// Mirrors `FailedProvisionCleanupResult`.
#[derive(Debug, Clone, Default)]
pub struct FailedProvisionCleanupResult {
    pub claimed: bool,
    pub cleaned: bool,
    pub recovered: Option<bool>,
    pub settlement_claimed: Option<bool>,
    pub refund_amount: f64,
    pub error: Option<String>,
}

/// Mirrors `FailedProvisionResourceRollback`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailedProvisionResourceRollback {
    pub host_id: i64,
    pub cpu: i64,
    pub memory: i64,
    pub disk: i64,
    pub port_count: Option<i64>,
}

/// Mirrors `cleanupAndSettleFailedProvision` (services/provisioning-cleanup.ts).
///
/// NOTE: `failCreatingInstanceAndRefund` (billing settlement) is not yet
/// ported, so the final settlement step fails with an explicit error and the
/// cleanup-pending claim stays held — exactly the TS branch
/// `{ claimed: true, cleaned: true, error }` used when settlement throws.
pub async fn cleanup_and_settle_failed_provision(
    db: &PgPool,
    pool: &crate::libs::incus::incus_pool::IncusClientPool,
    host: &PoolHost,
    instance_id: i64,
    instance_name: &str,
    reason: &str,
    resource_rollback: Option<FailedProvisionResourceRollback>,
    reclaim_pending_before: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<FailedProvisionCleanupResult, IncusError> {
    let _ = reason;
    let _ = resource_rollback;

    // Resolve the external operation before claiming failure. A normal
    // Running/Stopped instance means the timeout was a false negative.
    let client = match pool.get_incus_client(host).await {
        Ok(client) => client,
        Err(error) => {
            return Ok(FailedProvisionCleanupResult {
                claimed: false,
                cleaned: false,
                error: Some(error.message().to_string()),
                ..Default::default()
            });
        }
    };

    let resolution = match wait_for_provisioning_settlement(&client, instance_name).await {
        Ok(resolution) => resolution,
        Err(error) => {
            return Ok(FailedProvisionCleanupResult {
                claimed: false,
                cleaned: false,
                error: Some(error.message().to_string()),
                ..Default::default()
            });
        }
    };

    if let Some(status) = resolution {
        match mark_creating_instance_provisioned(db, instance_id, status).await {
            Ok(true) => {
                return Ok(FailedProvisionCleanupResult {
                    claimed: false,
                    cleaned: false,
                    recovered: Some(true),
                    ..Default::default()
                });
            }
            Ok(false) => {}
            Err(error) => {
                return Ok(FailedProvisionCleanupResult {
                    claimed: false,
                    cleaned: false,
                    error: Some(error.to_string()),
                    ..Default::default()
                });
            }
        }
    }

    let claimed = match claim_creating_instance_for_cleanup(db, instance_id, reclaim_pending_before)
        .await
    {
        Ok(claimed) => claimed,
        Err(error) => {
            return Ok(FailedProvisionCleanupResult {
                claimed: false,
                cleaned: false,
                error: Some(error.to_string()),
                ..Default::default()
            });
        }
    };
    if !claimed {
        return Ok(FailedProvisionCleanupResult {
            claimed: false,
            cleaned: false,
            ..Default::default()
        });
    }

    // Re-check after the database claim.
    let resolution = match wait_for_provisioning_settlement(&client, instance_name).await {
        Ok(resolution) => resolution,
        Err(error) => {
            return Ok(FailedProvisionCleanupResult {
                claimed: true,
                cleaned: false,
                error: Some(error.message().to_string()),
                ..Default::default()
            });
        }
    };
    if let Some(status) = resolution {
        match mark_creating_instance_provisioned(db, instance_id, status).await {
            Ok(true) => {
                return Ok(FailedProvisionCleanupResult {
                    claimed: true,
                    cleaned: false,
                    recovered: Some(true),
                    ..Default::default()
                });
            }
            Ok(false) => {
                return Ok(FailedProvisionCleanupResult {
                    claimed: true,
                    cleaned: false,
                    error: Some(format!(
                        "Instance {instance_id} changed state while reconciling provisioning"
                    )),
                    ..Default::default()
                });
            }
            Err(error) => {
                return Ok(FailedProvisionCleanupResult {
                    claimed: true,
                    cleaned: false,
                    error: Some(error.to_string()),
                    ..Default::default()
                });
            }
        }
    }

    if let Err(error) = ensure_instance_deleted(&client, instance_name).await {
        // Keep the cleanup-pending claim and all reservations; the timeout
        // worker retries after the next stale window.
        return Ok(FailedProvisionCleanupResult {
            claimed: true,
            cleaned: false,
            error: Some(error.message().to_string()),
            ..Default::default()
        });
    }

    // TODO(port): failCreatingInstanceAndRefund lives in db/billing-operations.ts
    // (coupon release, AFF reversal, hourly billing, host counters, refund
    // ledger). Until that module is ported the settlement explicitly fails and
    // the persistent claim keeps the instance non-retryable, mirroring the TS
    // settlement-failure branch (no refund can be issued twice or skipped
    // silently).
    Ok(FailedProvisionCleanupResult {
        claimed: true,
        cleaned: true,
        settlement_claimed: Some(false),
        error: Some(
            "billing settlement (failCreatingInstanceAndRefund) is not ported yet; \
             cleanup-pending claim kept"
                .to_string(),
        ),
        ..Default::default()
    })
}

/// Resolution helper mirroring the cleanup service's use of
/// `waitForProvisioningInstanceResolution`: returns `Some(status)` for a
/// present instance and `None` for absent/failed.
async fn wait_for_provisioning_settlement(
    client: &IncusClient,
    instance_name: &str,
) -> Result<Option<&'static str>, IncusError> {
    use crate::libs::incus::incus_instances::{ProvisionStatus, ProvisioningInstanceResolution};
    match crate::libs::incus::incus_instances::wait_for_provisioning_instance_resolution(
        client,
        instance_name,
        0,
    )
    .await
    {
        Ok(ProvisioningInstanceResolution::Present { status }) => Ok(Some(match status {
            ProvisionStatus::Running => "running",
            ProvisionStatus::Stopped => "stopped",
        })),
        Ok(_) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Mirrors `provisionManagedInstanceAsync`: create → wait visible → start →
/// wait running → resolve/persist network addresses → promote to running.
pub async fn provision_managed_instance_async(
    db: &PgPool,
    pool: &crate::libs::incus::incus_pool::IncusClientPool,
    instance_id: i64,
    host: &PoolHost,
    config: &ManagedInstanceProvisionConfig,
) -> Result<(), IncusError> {
    tracing::info!("\n[Managed Provisioning] ===== start =====");
    tracing::info!(
        "[Managed Provisioning] instanceId={instance_id}, name={}, host={}",
        config.name,
        host.name_or_id()
    );

    let result: Result<(), IncusError> = async {
        let client = pool.get_incus_client(host).await?;
        let ipv6_config: Option<Ipv6Config> = config
            .ipv6_address
            .clone()
            .filter(|ip| !ip.is_empty())
            .map(|primary_ip| Ipv6Config {
                primary_ip,
                extra_ips: None,
                subnet: None,
            });

        let incus_config = build_instance_config(&BuildInstanceConfigOptions {
            name: config.name.clone(),
            image: config.image.clone(),
            cpu: config.cpu,
            memory: config.memory,
            disk: config.disk,
            ssh_key: Some(String::new()),
            password: Some(String::new()),
            cloud_init_config: config.cloud_init_config.clone(),
            network_mode: Some(config.network_mode),
            nested: config.nested.unwrap_or(false),
            privileged: config.privileged.unwrap_or(false),
            instance_type: Some(config.instance_type.clone().unwrap_or_else(|| "container".to_string())),
            storage_pool: Some(config.storage_pool.clone().unwrap_or_else(|| "default".to_string())),
            swap_enabled: None,
            swap_size: None,
            network_bridge: None,
            ipv6_config: ipv6_config.clone(),
            ipv4_address: config.ipv4_address.clone(),
            ipv6_address: config.ipv6_address.clone(),
            ipv6_gateway: config.ipv6_gateway.clone(),
            host_interface: Some(config.host_interface.clone().unwrap_or_else(|| "eth0".to_string())),
            limits_read: config.limits_read.clone(),
            limits_write: config.limits_write.clone(),
            limits_read_iops: config.limits_read_iops,
            limits_write_iops: config.limits_write_iops,
            limits_ingress: config.limits_ingress.clone(),
            limits_egress: config.limits_egress.clone(),
            limits_processes: config.limits_processes,
            limits_cpu_priority: config.limits_cpu_priority,
            boot_autostart: config.boot_autostart,
            boot_autostart_priority: config.boot_autostart_priority,
            boot_autostart_delay: config.boot_autostart_delay,
            boot_host_shutdown_timeout: config.boot_host_shutdown_timeout,
        });

        create_instance(&client, &incus_config).await?;

        let mut ready = false;
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            match get_instance_state(&client, &config.name).await {
                Ok(state) => {
                    if state.get("status").map(|s| !s.is_null()).unwrap_or(false) {
                        ready = true;
                        break;
                    }
                }
                Err(_) => {
                    // keep waiting
                }
            }
        }

        if !ready {
            return Err(IncusError::Other("Instance creation timed out".to_string()));
        }

        start_instance(&client, &config.name).await?;

        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            match get_instance_state(&client, &config.name).await {
                Ok(state) => {
                    if state.get("status").and_then(Value::as_str) == Some("Running") {
                        break;
                    }
                }
                Err(_) => {
                    // keep waiting
                }
            }
        }

        let stored: Option<StoredInstance> = sqlx::query_as(
            "SELECT id, name, host_id, network_mode::text, ipv4, ipv6 FROM instances WHERE id = $1",
        )
        .bind(instance_id)
        .fetch_optional(db)
        .await
        .map_err(|e| IncusError::Other(format!("database error: {e}")))?;
        let Some(stored) = stored else {
            // TS findUniqueOrThrow throws when the row vanished.
            return Err(IncusError::Other(format!(
                "instance {instance_id} disappeared during provisioning"
            )));
        };

        let mut resolved_network = ResolvedInstanceNetworkAddresses {
            ipv4: config
                .ipv4_address
                .clone()
                .or(stored.ipv4.clone()),
            ipv6: config
                .ipv6_address
                .clone()
                .or(stored.ipv6.clone()),
            ipv4_device: "eth0".to_string(),
            ipv6_device: "eth1".to_string(),
            configured_ipv6: config.ipv6_address.clone(),
            observed_ipv6: None,
        };

        // Resolve from live Incus state; keep pre-allocated addresses on error.
        if let (Ok(incus_instance), Ok(state_resp)) = (
            get_instance(&client, &config.name).await,
            get_instance_state(&client, &config.name).await,
        ) {
            let target = InstanceNetworkSyncTarget {
                id: stored.id,
                name: Some(stored.name.clone()),
                host_id: Some(stored.host_id),
                network_mode: stored.network_mode.clone(),
                ipv4: config
                    .ipv4_address
                    .clone()
                    .or(stored.ipv4.clone()),
                ipv6: config
                    .ipv6_address
                    .clone()
                    .or(stored.ipv6.clone()),
            };
            resolved_network = resolve_instance_network_addresses(
                &target,
                Some(&serde_json::to_value(&incus_instance).unwrap_or(Value::Null)),
                None,
                Some(&state_resp),
            );
        }

        persist_resolved_instance_network_addresses(
            db,
            &InstanceNetworkSyncTarget {
                id: stored.id,
                name: Some(stored.name.clone()),
                host_id: Some(stored.host_id),
                network_mode: stored.network_mode.clone(),
                ipv4: stored.ipv4.clone(),
                ipv6: stored.ipv6.clone(),
            },
            &resolved_network,
        )
        .await
        .map_err(|e| IncusError::Other(format!("network address sync failed: {e}")))?;

        let update_result = sqlx::query(
            "UPDATE instances SET status = 'running', storage_pool_name = $2 WHERE id = $1 \
             AND status = 'creating' AND provisioning_cleanup_pending = false",
        )
        .bind(instance_id)
        .bind(config.storage_pool.clone().unwrap_or_else(|| "default".to_string()))
        .execute(db)
        .await
        .map_err(|e| IncusError::Other(format!("database error: {e}")))?;

        if update_result.rows_affected() == 0 {
            let current: Option<(String,)> =
                sqlx::query_as("SELECT status::text FROM instances WHERE id = $1")
                    .bind(instance_id)
                    .fetch_optional(db)
                    .await
                    .map_err(|e| IncusError::Other(format!("database error: {e}")))?;
            tracing::info!(
                "[Managed Provisioning] instance {instance_id} is already owned by another flow; skip state promotion"
            );
            if current.map(|(status,)| status != "running").unwrap_or(true) {
                if let Err(cleanup_error) =
                    ensure_instance_deleted(&client, &config.name).await
                {
                    tracing::error!(
                        "[Managed Provisioning] race cleanup could not confirm {} is absent: {cleanup_error}",
                        config.name
                    );
                } else {
                    tracing::info!(
                        "[Managed Provisioning] race cleanup confirmed {} is absent",
                        config.name
                    );
                }
            }
            return Ok(());
        }

        Ok(())
    }
    .await;

    if let Err(error) = result {
        tracing::error!("[Managed Provisioning] instance {instance_id} failed: {error}");

        let routed = matches!(
            config.network_mode,
            NetworkMode::Nat
                | NetworkMode::NatIpv6
                | NetworkMode::NatIpv6Nat
                | NetworkMode::Ipv6Nat
                | NetworkMode::Ipv6Only
        );
        let cleanup = cleanup_and_settle_failed_provision(
            db,
            pool,
            host,
            instance_id,
            &config.name,
            error.message(),
            Some(FailedProvisionResourceRollback {
                host_id: host.id,
                cpu: config.cpu,
                memory: config.memory,
                disk: config.disk,
                port_count: if routed { Some(config.port_limit.unwrap_or(0)) } else { Some(0) },
            }),
            None,
        )
        .await;

        match cleanup {
            Ok(cleanup) if !cleanup.claimed => {
                tracing::info!(
                    "[Managed Provisioning] instance {instance_id} was already claimed or could not be claimed; no settlement performed"
                );
                let current: Option<(String, bool)> = sqlx::query_as(
                    "SELECT status::text, provisioning_cleanup_pending FROM instances WHERE id = $1",
                )
                .bind(instance_id)
                .fetch_optional(db)
                .await
                .ok()
                .flatten();
                let needs_cleanup = match current {
                    Some((status, pending)) => {
                        status == "error" || (status == "creating" && pending)
                    }
                    None => false,
                };
                if needs_cleanup {
                    match pool.get_incus_client(host).await {
                        Ok(client) => match ensure_instance_deleted(&client, &config.name).await {
                            Ok(()) => tracing::info!(
                                "[Managed Provisioning] late failure cleanup confirmed {} is absent",
                                config.name
                            ),
                            Err(cleanup_error) => tracing::error!(
                                "[Managed Provisioning] late failure cleanup could not confirm {} is absent: {cleanup_error}",
                                config.name
                            ),
                        },
                        Err(cleanup_error) => tracing::error!(
                            "[Managed Provisioning] late failure cleanup could not confirm {} is absent: {cleanup_error}",
                            config.name
                        ),
                    }
                }
            }
            Ok(cleanup) if !cleanup.cleaned => {
                tracing::error!(
                    "[Managed Provisioning] instance {instance_id} cleanup is unconfirmed; reservations remain held: {}",
                    cleanup.error.unwrap_or_default()
                );
            }
            Ok(cleanup) if cleanup.settlement_claimed == Some(true) => {
                tracing::info!(
                    "[Managed Provisioning] instance {instance_id} resources released after confirmed cleanup"
                );
            }
            Ok(cleanup) => {
                tracing::error!(
                    "[Managed Provisioning] instance {instance_id} cleanup confirmed but database settlement is pending: {}",
                    cleanup.error.unwrap_or_default()
                );
            }
            Err(cleanup_error) => {
                tracing::error!(
                    "[Managed Provisioning] instance {instance_id} cleanup invocation failed: {cleanup_error}"
                );
            }
        }

        return Err(error);
    }

    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct StoredInstance {
    id: i64,
    name: String,
    host_id: i64,
    network_mode: Option<String>,
    ipv4: Option<String>,
    ipv6: Option<String>,
}

/// Small helper used in logs (TS prints host.name).
trait HostNameOrId {
    fn name_or_id(&self) -> String;
}

impl HostNameOrId for PoolHost {
    fn name_or_id(&self) -> String {
        format!("#{}", self.id)
    }
}
