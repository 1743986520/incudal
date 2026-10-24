//! Host network policy input normalization.
//! Port of services/host-network-policy.ts normalizeNetworkPolicyInput.
//! Errors mirror the TS `throw new Error(<message>)`; the route turns the
//! message into `400 { error: <message> }`.

use serde_json::{json, Map, Value};

pub const HOST_NETWORK_POLICY_TYPES: &[&str] = &[
    "ip_block",
    "dns_lock",
    "dns_override",
    "udp_block",
    "ping_block",
];

#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedNetworkPolicyInput {
    pub policy_type: String,
    pub target_mode: String,
    pub target_instance_ids: Vec<i64>,
    pub config: Value,
}

fn is_ip(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn is_ipv4(value: &str) -> bool {
    matches!(
        value.parse::<std::net::IpAddr>(),
        Ok(std::net::IpAddr::V4(_))
    )
}

fn string_list(value: Option<&Value>, max_items: usize) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if let Some(s) = item.as_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() && !out.contains(&trimmed.to_string()) {
                out.push(trimmed.to_string());
            }
        }
    }
    out.truncate(max_items);
    out
}

fn valid_cidr(value: &str) -> bool {
    let mut parts = value.splitn(3, '/');
    let (Some(address), raw_prefix, extra) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if extra.is_some() || !is_ip(address) {
        return false;
    }
    let Some(raw_prefix) = raw_prefix else {
        return true;
    };
    if raw_prefix.is_empty() || !raw_prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(prefix) = raw_prefix.parse::<u32>() else {
        return false;
    };
    let max = if is_ipv4(address) { 32 } else { 128 };
    prefix <= max
}

fn valid_domain(value: &str) -> bool {
    if value.len() > 253 {
        return false;
    }
    // TS: /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i
    let body = value.strip_prefix("*.").unwrap_or(value);
    let mut labels: Vec<&str> = body.split('.').collect();
    // The regex requires at least one trailing "." label group, i.e. >= 2 labels.
    if labels.len() < 2 {
        return false;
    }
    let tld = labels.pop().unwrap_or("");
    if tld.len() < 2 || tld.len() > 63 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
    })
}

/// Mirrors normalizeNetworkPolicyInput; Err carries the TS error message.
pub fn normalize_network_policy_input(
    policy_type: Option<&Value>,
    target_mode: Option<&Value>,
    target_instance_ids: Option<&Value>,
    config: Option<&Value>,
) -> Result<NormalizedNetworkPolicyInput, String> {
    let policy_type_str = policy_type.and_then(Value::as_str).unwrap_or("");
    if !HOST_NETWORK_POLICY_TYPES.contains(&policy_type_str) {
        return Err("不支持的网络策略类型".to_string());
    }
    let policy_type = policy_type_str.to_string();

    let mode_str = target_mode.and_then(Value::as_str).unwrap_or("");
    let target_mode = if ["selected", "all_current", "all_dynamic"].contains(&mode_str) {
        mode_str.to_string()
    } else {
        "selected".to_string()
    };

    let mut target_instance_ids: Vec<i64> = match target_instance_ids {
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Some(i)
                    } else {
                        n.as_f64().and_then(|f| {
                            if f.is_finite() && f.fract() == 0.0 {
                                Some(f as i64)
                            } else {
                                None
                            }
                        })
                    }
                }
                _ => None,
            })
            .collect::<Option<Vec<i64>>>()
            .unwrap_or_default()
            .into_iter()
            .filter(|id| *id > 0)
            .collect(),
        _ => Vec::new(),
    };
    target_instance_ids.sort();
    target_instance_ids.dedup();
    target_instance_ids.truncate(1000);

    if target_mode == "selected" && target_instance_ids.is_empty() {
        return Err("请至少选择一个实例".to_string());
    }

    let raw: Map<String, Value> = match config {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };

    let config_value: Value = match policy_type.as_str() {
        "ip_block" => {
            let cidrs: Vec<String> = string_list(raw.get("cidrs"), 256)
                .into_iter()
                .filter(|c| valid_cidr(c))
                .collect();
            if cidrs.is_empty() {
                return Err("请填写有效的 IPv4、IPv6 或 CIDR".to_string());
            }
            json!({ "cidrs": cidrs })
        }
        "dns_lock" => {
            let upstreams: Vec<String> = string_list(raw.get("upstreams"), 8)
                .into_iter()
                .filter(|u| is_ip(u))
                .collect();
            if upstreams.is_empty() {
                return Err("请填写平台 DNS 上游 IP".to_string());
            }
            json!({
                "upstreams": upstreams,
                "blockDot": raw.get("blockDot") == Some(&Value::Bool(true)),
            })
        }
        "dns_override" => {
            let domains: Vec<String> = string_list(raw.get("domains"), 256)
                .into_iter()
                .map(|d| d.to_lowercase())
                .filter(|d| valid_domain(d))
                .collect();
            let action_str = raw.get("action").and_then(Value::as_str).unwrap_or("");
            let action = if ["address", "nxdomain", "zero"].contains(&action_str) {
                action_str.to_string()
            } else {
                "address".to_string()
            };
            let addresses: Vec<String> = string_list(raw.get("addresses"), 16)
                .into_iter()
                .filter(|a| is_ip(a))
                .collect();
            let upstreams: Vec<String> = string_list(raw.get("upstreams"), 8)
                .into_iter()
                .filter(|u| is_ip(u))
                .collect();
            if domains.is_empty() {
                return Err("请填写有效域名".to_string());
            }
            if action == "address" && addresses.is_empty() {
                return Err("DNS 劫持必须填写目标 IP".to_string());
            }
            if upstreams.is_empty() {
                return Err("请填写平台 DNS 上游 IP".to_string());
            }
            json!({
                "domains": domains,
                "action": action,
                "addresses": if action == "address" { addresses } else { Vec::new() },
                "upstreams": upstreams,
            })
        }
        _ => json!({}),
    };

    Ok(NormalizedNetworkPolicyInput {
        policy_type,
        target_mode,
        target_instance_ids,
        config: config_value,
    })
}
