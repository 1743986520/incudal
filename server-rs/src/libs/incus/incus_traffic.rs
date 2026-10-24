//! Incus traffic management.
//! Port of lib/incus/incus-traffic.ts: network traffic counters and bandwidth
//! throttling.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::libs::incus::incus_client::{IncusClient, IncusError};
use crate::libs::incus::incus_instances::{get_instance, update_instance};
use crate::libs::incus::vm_network_identifiers::generate_vm_nic_macs;

/// Mirrors `NetworkCounters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkCounters {
    pub rx_bytes: u128,
    pub tx_bytes: u128,
}

/// Mirrors `InstanceStateNetwork`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct InstanceStateNetwork {
    #[serde(default)]
    pub addresses: Option<Vec<Value>>,
    #[serde(default)]
    pub hwaddr: Option<String>,
    #[serde(default)]
    pub counters: Option<NetworkCountersRaw>,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkCountersRaw {
    #[serde(default)]
    pub bytes_received: Option<Value>,
    #[serde(default)]
    pub bytes_sent: Option<Value>,
    #[serde(default)]
    pub packets_received: Option<i64>,
    #[serde(default)]
    pub packets_sent: Option<i64>,
}

/// Mirrors `InstanceTrafficState`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct InstanceTrafficState {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub network: Option<Map<String, Value>>,
}

fn normalize_mac(value: Option<&str>) -> Option<String> {
    let value = value?
        .trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_lowercase())
    }
}

fn get_billable_vm_macs(instance_name: &str) -> HashSet<String> {
    // VM guest interface names are distro-dependent (e.g. enp5s0), so match the
    // deterministic MACs assigned when creating VM NICs.
    let macs = generate_vm_nic_macs(instance_name);
    HashSet::from([macs.eth0.to_lowercase(), macs.eth1.to_lowercase()])
}

fn parse_state_network(value: &Value) -> Option<Map<String, Value>> {
    value.as_object().and_then(|obj| {
        obj.get("network").and_then(Value::as_object).cloned()
    })
}

fn is_billable_network_interface(
    if_name: &str,
    if_data: &InstanceStateNetwork,
    billable_vm_macs: &HashSet<String>,
) -> bool {
    if if_name == "lo" {
        return false;
    }

    // Incudal-created LXC NICs are eth0 (IPv4/NAT) and optionally eth1 (routed
    // IPv6). Guest-created bridges/veth/docker/tunnel interfaces are excluded
    // so the same packet is not counted twice and quota usage stays honest.
    if if_name == "eth0" || if_name == "eth1" {
        return true;
    }

    let hwaddr = normalize_mac(if_data.hwaddr.as_deref());
    hwaddr.map(|mac| billable_vm_macs.contains(&mac)).unwrap_or(false)
}

fn is_likely_external_guest_interface(if_name: &str) -> bool {
    static ETH: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^eth[0-9]+$").expect("static regex")
    });
    static EN: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^en(?:o|p|s|x)[a-z0-9]+$").expect("static regex")
    });
    let normalized = if_name.to_lowercase();
    ETH.is_match(&normalized) || EN.is_match(&normalized)
}

/// Mirrors `counterToBigInt`: digit strings pass through exactly, invalid
/// strings and non-positive numbers become 0.
fn counter_to_big_int(value: Option<&Value>) -> u128 {
    match value {
        Some(Value::String(s)) => {
            if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
                s.parse::<u128>().unwrap_or(0)
            } else {
                0
            }
        }
        Some(Value::Number(n)) => {
            let value = n.as_f64().unwrap_or(0.0);
            if !value.is_finite() || value <= 0.0 {
                0
            } else {
                value.floor() as u128
            }
        }
        _ => 0,
    }
}

fn add_counters(totals: &mut NetworkCounters, counters: Option<&NetworkCountersRaw>) {
    let Some(counters) = counters else {
        return;
    };
    totals.rx_bytes += counter_to_big_int(counters.bytes_received.as_ref());
    totals.tx_bytes += counter_to_big_int(counters.bytes_sent.as_ref());
}

/// Mirrors `getTrafficCounters`: only Incudal-created external NICs count, so
/// Docker/veth/tunnel guest interfaces do not double the metering.
pub async fn get_traffic_counters(
    client: &IncusClient,
    instance_name: &str,
) -> Result<NetworkCounters, IncusError> {
    let state = client
        .request_default("GET", &format!("/1.0/instances/{instance_name}/state"), None)
        .await?;
    Ok(get_traffic_counters_from_state(instance_name, &state))
}

/// Mirrors `getTrafficCountersFromState`.
pub fn get_traffic_counters_from_state(instance_name: &str, state: &Value) -> NetworkCounters {
    let billable_vm_macs = get_billable_vm_macs(instance_name);
    let mut totals = NetworkCounters::default();
    let Some(network) = parse_state_network(state) else {
        return totals;
    };

    let mut fallback_interfaces: Vec<InstanceStateNetwork> = Vec::new();
    let mut has_strict_billable_interface = false;

    for (if_name, if_value) in &network {
        let Ok(if_data) = serde_json::from_value::<InstanceStateNetwork>(if_value.clone()) else {
            continue;
        };
        if is_billable_network_interface(if_name, &if_data, &billable_vm_macs) {
            has_strict_billable_interface = true;
            add_counters(&mut totals, if_data.counters.as_ref());
            continue;
        }

        if is_likely_external_guest_interface(if_name) {
            fallback_interfaces.push(if_data.clone());
        }

        if std::env::var("DEBUG_TRAFFIC").ok().as_deref() == Some("true")
            && if_data.counters.is_some()
        {
            tracing::info!(
                "[Traffic Debug] {instance_name} - {if_name}: skipped non-billable interface"
            );
        }
    }

    if !has_strict_billable_interface {
        for if_data in &fallback_interfaces {
            add_counters(&mut totals, if_data.counters.as_ref());
        }
    }

    totals
}

/// Mirrors `THROTTLE_BANDWIDTH`.
pub const THROTTLE_BANDWIDTH: &str = "1Mbit";

/// Mirrors `applyThrottle`: set limits.ingress/egress to 1Mbit on every NIC.
pub async fn apply_throttle(client: &IncusClient, instance_name: &str) -> Result<(), IncusError> {
    let instance = get_instance(client, instance_name).await?;
    let mut devices = instance.devices.clone();

    for (_, device) in devices.iter_mut() {
        let Some(device_obj) = device.as_object_mut() else {
            continue;
        };
        if device_obj.get("type").and_then(Value::as_str) == Some("nic") {
            device_obj.insert("limits.ingress".to_string(), Value::String(THROTTLE_BANDWIDTH.to_string()));
            device_obj.insert("limits.egress".to_string(), Value::String(THROTTLE_BANDWIDTH.to_string()));
        }
    }

    update_instance(client, instance_name, &json_devices(devices)).await?;
    Ok(())
}

/// Mirrors `restoreBandwidth`: restore the original per-instance/package
/// bandwidth, or remove the limits entirely.
pub async fn restore_bandwidth(
    client: &IncusClient,
    instance_name: &str,
    limits_ingress: Option<&str>,
    limits_egress: Option<&str>,
) -> Result<(), IncusError> {
    let instance = get_instance(client, instance_name).await?;
    let mut devices = instance.devices.clone();

    for (_, device) in devices.iter_mut() {
        let Some(device_obj) = device.as_object_mut() else {
            continue;
        };
        if device_obj.get("type").and_then(Value::as_str) != Some("nic") {
            continue;
        }
        match limits_ingress.filter(|v| !v.is_empty()) {
            Some(ingress) => {
                device_obj.insert("limits.ingress".to_string(), Value::String(ingress.to_string()));
            }
            None => {
                device_obj.remove("limits.ingress");
            }
        }
        match limits_egress.filter(|v| !v.is_empty()) {
            Some(egress) => {
                device_obj.insert("limits.egress".to_string(), Value::String(egress.to_string()));
            }
            None => {
                device_obj.remove("limits.egress");
            }
        }
    }

    update_instance(client, instance_name, &json_devices(devices)).await?;
    Ok(())
}

/// Mirrors `isThrottled`.
pub async fn is_throttled(client: &IncusClient, instance_name: &str) -> Result<bool, IncusError> {
    let instance = get_instance(client, instance_name).await?;
    for (_, device) in &instance.devices {
        let Some(device_obj) = device.as_object() else {
            continue;
        };
        if device_obj.get("type").and_then(Value::as_str) == Some("nic") {
            let ingress = device_obj.get("limits.ingress").and_then(Value::as_str);
            if ingress == Some(THROTTLE_BANDWIDTH) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn json_devices(devices: Map<String, Value>) -> Map<String, Value> {
    devices
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Port of incus-traffic.test.ts: canonical Incus NICs win; guest-external
    // fallback interfaces (enp6s0) are never mixed into the total.
    #[test]
    fn does_not_mix_fallback_interfaces_with_canonical_incus_nics() {
        let state = json!({
            "network": {
                "eth0": { "counters": { "bytes_received": "100", "bytes_sent": "200" } },
                "enp6s0": { "counters": { "bytes_received": "300", "bytes_sent": "400" } },
                "docker0": { "counters": { "bytes_received": "500", "bytes_sent": "600" } }
            }
        });

        let counters = get_traffic_counters_from_state("vm-test", &state);
        assert_eq!(
            counters,
            NetworkCounters {
                rx_bytes: 100,
                tx_bytes: 200
            }
        );
    }

    #[test]
    fn falls_back_to_external_guest_interfaces_without_canonical_nics() {
        // A VM whose guest interfaces use distro naming: MACs created by
        // generateVmNicMacs are billable, other external-looking interfaces
        // become the fallback.
        let macs = generate_vm_nic_macs("vm-9");
        let state = json!({
            "network": {
                "lo": { "counters": { "bytes_received": "1", "bytes_sent": "2" } },
                "enp5s0": { "hwaddr": macs.eth0, "counters": { "bytes_received": "10", "bytes_sent": "20" } },
                "ens6": { "hwaddr": macs.eth1, "counters": { "bytes_received": "30", "bytes_sent": "40" } },
                "eth2": { "counters": { "bytes_received": "1000", "bytes_sent": "2000" } }
            }
        });

        let counters = get_traffic_counters_from_state("vm-9", &state);
        assert_eq!(
            counters,
            NetworkCounters {
                rx_bytes: 40,
                tx_bytes: 60
            }
        );
    }
}
