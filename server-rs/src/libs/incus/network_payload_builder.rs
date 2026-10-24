//! IPv6 Routed payload builder.
//! Port of lib/network-payload-builder.ts.
//!
//! Responsibilities:
//! 1. build Incus device configs (dual NIC: eth0 bridged + eth1 routed);
//! 2. generate cloud-init network-config YAML (guest OS networking);
//! 3. sync instance network configuration (add/remove IPs).

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::libs::incus::incus_client::IncusError;
use crate::libs::incus::incus_instances::{get_instance_value, restart_instance};
use crate::libs::incus::ip_calculator::Ipv4Config;
use crate::libs::incus::vm_network_identifiers::{generate_vm_nic_macs, VmNicMacs};

pub type DeviceMap = Map<String, Value>;

// ==================== types ====================

/// Mirrors the `NetworkMode` union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    #[default]
    Nat,
    NatIpv6,
    NatIpv6Nat,
    Ipv6Only,
    Ipv6Nat,
}

impl NetworkMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkMode::Nat => "nat",
            NetworkMode::NatIpv6 => "nat_ipv6",
            NetworkMode::NatIpv6Nat => "nat_ipv6_nat",
            NetworkMode::Ipv6Only => "ipv6_only",
            NetworkMode::Ipv6Nat => "ipv6_nat",
        }
    }

    pub fn parse(value: &str) -> Option<NetworkMode> {
        match value {
            "nat" => Some(NetworkMode::Nat),
            "nat_ipv6" => Some(NetworkMode::NatIpv6),
            "nat_ipv6_nat" => Some(NetworkMode::NatIpv6Nat),
            "ipv6_only" => Some(NetworkMode::Ipv6Only),
            "ipv6_nat" => Some(NetworkMode::Ipv6Nat),
            _ => None,
        }
    }
}

/// Mirrors `IPv6Config` (types/incus.ts and network-payload-builder.ts).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Ipv6Config {
    #[serde(rename = "primaryIp")]
    pub primary_ip: String,
    #[serde(rename = "extraIps", default, skip_serializing_if = "Option::is_none")]
    pub extra_ips: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
}

/// Mirrors `BuildNetworkDevicesOptions`.
#[derive(Debug, Clone, Default)]
pub struct BuildNetworkDevicesOptions {
    pub network_mode: NetworkMode,
    /// Host physical NIC name (used by routed mode).
    pub host_interface: String,
    pub ipv6_config: Option<Ipv6Config>,
    pub limits_ingress: Option<String>,
    pub limits_egress: Option<String>,
    pub nat_bridge: Option<String>,
    pub ipv4_address: Option<String>,
    pub eth0_hwaddr: Option<String>,
    pub eth1_hwaddr: Option<String>,
}

// ==================== device config ====================

/// Mirrors `buildNetworkDevices`:
/// - eth0: bridged NAT IPv4 (all modes);
/// - eth1: routed IPv6 (nat_ipv6 / ipv6_only only).
pub fn build_network_devices(options: &BuildNetworkDevicesOptions) -> DeviceMap {
    let mut devices = DeviceMap::new();

    // eth0: IPv4 NAT (every mode).
    let mut eth0 = Map::new();
    eth0.insert("type".to_string(), json!("nic"));
    eth0.insert("nictype".to_string(), json!("bridged"));
    eth0.insert(
        "parent".to_string(),
        json!(options.nat_bridge.clone().unwrap_or_else(|| "incusbr0".to_string())),
    );
    eth0.insert("name".to_string(), json!("eth0"));

    // Pinned internal IPv4 (static DHCP lease).
    if let Some(ipv4) = &options.ipv4_address {
        eth0.insert("ipv4.address".to_string(), json!(ipv4));
    }
    if let Some(hwaddr) = &options.eth0_hwaddr {
        eth0.insert("hwaddr".to_string(), json!(hwaddr));
    }

    // Bandwidth limits apply to eth0 (the NAT egress).
    if let Some(ingress) = &options.limits_ingress {
        eth0.insert("limits.ingress".to_string(), json!(ingress));
    }
    if let Some(egress) = &options.limits_egress {
        eth0.insert("limits.egress".to_string(), json!(egress));
    }

    devices.insert("eth0".to_string(), Value::Object(eth0));

    // eth1: IPv6 routed (only nat_ipv6 / ipv6_only need standalone IPv6).
    let has_routed_ipv6 = matches!(
        options.network_mode,
        NetworkMode::NatIpv6 | NetworkMode::Ipv6Only
    );

    if has_routed_ipv6 {
        if let Some(ipv6_config) = &options.ipv6_config {
            let mut all_ips = vec![ipv6_config.primary_ip.clone()];
            if let Some(extra) = &ipv6_config.extra_ips {
                all_ips.extend(extra.iter().cloned());
            }

            let mut eth1 = Map::new();
            eth1.insert("type".to_string(), json!("nic"));
            eth1.insert("nictype".to_string(), json!("routed"));
            eth1.insert("parent".to_string(), json!(options.host_interface));
            eth1.insert("name".to_string(), json!("eth1"));
            // All IPv6 addresses, comma separated. security.ipv6_filtering and
            // security.mac_filtering are bridged-only and intentionally absent.
            eth1.insert("ipv6.address".to_string(), json!(all_ips.join(",")));
            if let Some(hwaddr) = &options.eth1_hwaddr {
                eth1.insert("hwaddr".to_string(), json!(hwaddr));
            }
            // Subnet route when one was allocated.
            if let Some(subnet) = &ipv6_config.subnet {
                eth1.insert("ipv6.routes".to_string(), json!(subnet));
            }

            devices.insert("eth1".to_string(), Value::Object(eth1));
        }
    }

    devices
}

// ==================== cloud-init network config ====================

/// Mirrors `CloudInitNetworkOptions`.
#[derive(Debug, Clone, Default)]
pub struct CloudInitNetworkOptions {
    pub ipv4_address: String,
    pub ipv6_list: Option<Vec<String>>,
    /// NIC MACs (preferred over guest interface naming). Unused by the YAML
    /// body, kept for signature compatibility with the TS options.
    pub nic_macs: Option<PartialVmNicMacs>,
}

/// Mirrors the `Partial<VmNicMacs>` parameter.
#[derive(Debug, Clone, Default)]
pub struct PartialVmNicMacs {
    pub eth0: Option<String>,
    pub eth1: Option<String>,
}

impl From<&VmNicMacs> for PartialVmNicMacs {
    fn from(macs: &VmNicMacs) -> Self {
        Self {
            eth0: Some(macs.eth0.clone()),
            eth1: Some(macs.eth1.clone()),
        }
    }
}

/// Mirrors `generateCloudInitNetworkConfig` (network-config v2).
/// eth0 has DHCPv6/RA explicitly disabled so routed-IPv6 guests do not pick up
/// a second NAT IPv6 from the bridge.
pub fn generate_cloud_init_network_config(options: &CloudInitNetworkOptions) -> String {
    let gateway = Ipv4Config::GATEWAY;

    let mut config = format!(
        "version: 2\nethernets:\n  eth0:\n    dhcp4: false\n    dhcp6: false\n    accept-ra: false\n    addresses:\n      - {}/22\n    routes:\n      - to: 0.0.0.0/0\n        via: {}\n    nameservers:\n      addresses:\n        - 10.10.0.1\n",
        options.ipv4_address, gateway
    );

    if let Some(ipv6_list) = &options.ipv6_list {
        if !ipv6_list.is_empty() {
            let formatted: Vec<String> = ipv6_list
                .iter()
                .filter(|ip| !ip.trim().is_empty())
                .map(|ip| {
                    let trimmed = ip.trim();
                    if trimmed.contains('/') {
                        trimmed.to_string()
                    } else {
                        format!("{trimmed}/128")
                    }
                })
                .collect();
            let addresses_yaml = formatted
                .iter()
                .map(|addr| format!("      - {addr}"))
                .collect::<Vec<_>>()
                .join("\n");
            config.push_str(&format!(
                "  eth1:\n    dhcp4: false\n    dhcp6: false\n    accept-ra: false\n    addresses:\n{addresses_yaml}\n    gateway6: fe80::1\n    nameservers:\n      addresses:\n        - 10.10.0.1\n"
            ));
        }
    }

    config
}

/// Mirrors `generateCloudInitNetworkConfigLegacy` (deprecated in TS).
pub fn generate_cloud_init_network_config_legacy(ipv6_list: &[String]) -> String {
    if ipv6_list.is_empty() {
        return "version: 2\nethernets:\n  eth0:\n    dhcp4: true\n".to_string();
    }

    let formatted: Vec<String> = ipv6_list
        .iter()
        .filter(|ip| !ip.trim().is_empty())
        .map(|ip| {
            let trimmed = ip.trim();
            if trimmed.contains('/') {
                trimmed.to_string()
            } else {
                format!("{trimmed}/128")
            }
        })
        .collect();
    let addresses_yaml = formatted
        .iter()
        .map(|addr| format!("      - {addr}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "version: 2\nethernets:\n  eth0:\n    dhcp4: true\n  eth1:\n    dhcp4: false\n    dhcp6: false\n    addresses:\n{addresses_yaml}\n    gateway6: fe80::1\n"
    )
}

// ==================== network sync ====================

fn device_object<'a>(devices: &'a DeviceMap, name: &str) -> Option<&'a Map<String, Value>> {
    devices.get(name).and_then(Value::as_object)
}

fn device_string(devices: &DeviceMap, name: &str, key: &str) -> Option<String> {
    device_object(devices, name)
        .and_then(|d| d.get(key))
        .and_then(Value::as_str)
        .map(|s| s.to_string())
}

/// Mirrors `syncInstanceNetwork`: update eth1 ipv6.address/ipv6.routes and the
/// cloud-init network-config, then restart.
pub async fn sync_instance_network(
    client: &crate::libs::incus::incus_client::IncusClient,
    instance_name: &str,
    ipv6_config: &Ipv6Config,
    host_interface: &str,
    restart: bool,
) -> Result<(), IncusError> {
    let current = get_instance_value(client, instance_name).await?;
    let current_devices = current
        .get("devices")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let current_config = current
        .get("config")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    // Current instance IPv4.
    let current_ipv4 = device_string(&current_devices, "eth0", "ipv4.address")
        .unwrap_or_else(|| "10.10.1.1".to_string());

    let mut all_ips = vec![ipv6_config.primary_ip.clone()];
    if let Some(extra) = &ipv6_config.extra_ips {
        all_ips.extend(extra.iter().cloned());
    }

    let generated_macs = generate_vm_nic_macs(instance_name);
    let mut devices = current_devices.clone();

    if devices.contains_key("eth1") {
        let mut eth1 = devices
            .get("eth1")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        eth1.insert("ipv6.address".to_string(), json!(all_ips.join(",")));
        if let Some(subnet) = &ipv6_config.subnet {
            eth1.insert("ipv6.routes".to_string(), json!(subnet));
        } else {
            eth1.remove("ipv6.routes");
        }
        devices.insert("eth1".to_string(), Value::Object(eth1));
    } else {
        // Create a new routed eth1.
        let mut eth1 = Map::new();
        eth1.insert("type".to_string(), json!("nic"));
        eth1.insert("nictype".to_string(), json!("routed"));
        eth1.insert("parent".to_string(), json!(host_interface));
        eth1.insert("name".to_string(), json!("eth1"));
        eth1.insert("hwaddr".to_string(), json!(generated_macs.eth1));
        eth1.insert("ipv6.address".to_string(), json!(all_ips.join(",")));
        if let Some(subnet) = &ipv6_config.subnet {
            eth1.insert("ipv6.routes".to_string(), json!(subnet));
        }
        devices.insert("eth1".to_string(), Value::Object(eth1));
    }

    // Refresh the cloud-init network-config.
    let mut config = current_config;
    let eth0_hwaddr = device_string(&current_devices, "eth0", "hwaddr")
        .unwrap_or_else(|| generated_macs.eth0.clone());
    let eth1_hwaddr = device_string(&devices, "eth1", "hwaddr")
        .or_else(|| device_string(&current_devices, "eth1", "hwaddr"))
        .unwrap_or_else(|| generated_macs.eth1.clone());
    config.insert(
        "user.network-config".to_string(),
        json!(generate_cloud_init_network_config(&CloudInitNetworkOptions {
            ipv4_address: current_ipv4,
            ipv6_list: Some(all_ips),
            nic_macs: Some(PartialVmNicMacs {
                eth0: Some(eth0_hwaddr),
                eth1: Some(eth1_hwaddr),
            }),
        })),
    );

    // Full PUT replacement.
    let body = json!({
        "config": Value::Object(config),
        "devices": Value::Object(devices),
        "profiles": current.get("profiles").cloned().unwrap_or(Value::Null),
        "description": current.get("description").cloned().unwrap_or(json!("")),
    });
    client
        .request_default("PUT", &format!("/1.0/instances/{instance_name}"), Some(&body))
        .await?;

    // Restart so the configuration takes effect.
    if restart {
        if let Err(err) = restart_instance(client, instance_name, false).await {
            tracing::warn!("[syncInstanceNetwork] 重启实例 {instance_name} 失败: {err}");
        }
    }
    Ok(())
}

/// Mirrors `removeInstanceIpv6` (switch back to pure NAT).
pub async fn remove_instance_ipv6(
    client: &crate::libs::incus::incus_client::IncusClient,
    instance_name: &str,
    restart: bool,
) -> Result<(), IncusError> {
    let current = get_instance_value(client, instance_name).await?;
    let current_devices = current
        .get("devices")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let current_ipv4 = device_string(&current_devices, "eth0", "ipv4.address")
        .unwrap_or_else(|| "10.10.1.1".to_string());

    let mut devices = current_devices.clone();
    devices.remove("eth1");

    let generated_macs = generate_vm_nic_macs(instance_name);
    let mut config = current
        .get("config")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let eth0_hwaddr = device_string(&current_devices, "eth0", "hwaddr")
        .unwrap_or_else(|| generated_macs.eth0.clone());
    config.insert(
        "user.network-config".to_string(),
        json!(generate_cloud_init_network_config(&CloudInitNetworkOptions {
            ipv4_address: current_ipv4,
            // No ipv6 list: eth0-only config.
            ipv6_list: None,
            nic_macs: Some(PartialVmNicMacs {
                eth0: Some(eth0_hwaddr),
                eth1: None,
            }),
        })),
    );

    let body = json!({
        "config": Value::Object(config),
        "devices": Value::Object(devices),
        "profiles": current.get("profiles").cloned().unwrap_or(Value::Null),
        "description": current.get("description").cloned().unwrap_or(json!("")),
    });
    client
        .request_default("PUT", &format!("/1.0/instances/{instance_name}"), Some(&body))
        .await?;

    if restart {
        if let Err(err) = restart_instance(client, instance_name, false).await {
            tracing::warn!("[removeInstanceIpv6] 重启实例 {instance_name} 失败: {err}");
        }
    }
    Ok(())
}

// ==================== helpers ====================

/// Mirrors `hasIpv6Support`: routed-mode with standalone IPv6 addresses.
pub fn has_ipv6_support(network_mode: NetworkMode) -> bool {
    matches!(network_mode, NetworkMode::NatIpv6 | NetworkMode::Ipv6Only)
}

static LOOSE_IPV6: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$").expect("static regex")
});

/// Mirrors `isValidIpv6` (loose format check kept for parity with TS).
pub fn is_valid_ipv6(address: &str) -> bool {
    let trimmed = address.trim().split('/').next().unwrap_or("");
    LOOSE_IPV6.is_match(trimmed) || trimmed == "::1" || trimmed == "::"
}

/// Mirrors `isValidIpv6Subnet` (loose: prefix 48-128).
pub fn is_valid_ipv6_subnet_loose(cidr: &str) -> bool {
    let Some((addr, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix_num) = prefix.parse::<i32>() else {
        return false;
    };
    if !(48..=128).contains(&prefix_num) {
        return false;
    }
    is_valid_ipv6(addr)
}

/// Convenience used by tests/callers: normalized device map from raw JSON.
pub fn devices_from_value(value: Option<&Value>) -> DeviceMap {
    value
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// Helper mirroring `Object.entries(devices)` ordering tolerance.
pub fn devices_to_lookup(devices: &DeviceMap) -> HashMap<String, DeviceMap> {
    devices
        .iter()
        .filter_map(|(k, v)| v.as_object().map(|obj| (k.clone(), obj.clone())))
        .collect()
}
