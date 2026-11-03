//! 端口映射代理设备工厂 — port of lib/proxy/{LxcProxyStrategy,KvmProxyStrategy,
//! IProxyStrategy, index} plus resolveInstanceTargetIpv4FromIncusDevice
//! (routes/instances.ts).

use serde_json::{Map, Value};

use crate::libs::incus::network_address::{normalize_ipv4_address, select_bindable_ipv4_listen_address};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyKind {
    Container,
    VirtualMachine,
}

pub struct ProxyDeviceConfig {
    pub name_suffix: Option<&'static str>,
    pub config: Map<String, Value>,
}

pub struct ProxyDeviceResult {
    pub success: bool,
    pub error_message: Option<String>,
    pub device_configs: Vec<ProxyDeviceConfig>,
}

fn device_config(config: Value) -> Map<String, Value> {
    config.as_object().cloned().unwrap_or_default()
}

fn proxy_config(listen: String, connect: String, nat: bool) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("type".into(), Value::String("proxy".into()));
    map.insert("listen".into(), Value::String(listen));
    map.insert("connect".into(), Value::String(connect));
    if nat {
        map.insert("nat".into(), Value::String("true".into()));
    }
    map
}

fn normalize_host_ipv6(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.trim_start_matches('[').trim_end_matches(']').to_string())
}

/// LxcProxyStrategy.createProxyDevice.
pub fn lxc_create_proxy_device(
    host_nat_ip: Option<&str>,
    host_ipv6: Option<&str>,
    network_mode: &str,
    protocol: &str,
    public_port: i64,
    private_port: i64,
    target_ipv4: Option<&str>,
) -> ProxyDeviceResult {
    let target_ipv4 = target_ipv4.map(str::trim).filter(|s| !s.is_empty());
    let normalized_host_ipv6 = normalize_host_ipv6(host_ipv6);

    if network_mode == "nat_ipv6_nat" {
        let mut device_configs: Vec<ProxyDeviceConfig> = Vec::new();
        let ipv4_listen_addr = host_nat_ip.unwrap_or("0.0.0.0");

        if ipv4_listen_addr.is_empty() || ipv4_listen_addr == "0.0.0.0" {
            return ProxyDeviceResult {
                success: false,
                error_message: Some("Current host has no bindable IPv4 listen address for NAT port mapping. Please configure Listen IPv4 in host NAT settings.".into()),
                device_configs: Vec::new(),
            };
        }
        if target_ipv4.is_none() {
            return ProxyDeviceResult {
                success: false,
                error_message: Some("Current instance has no static IPv4 address for NAT port mapping.".into()),
                device_configs: Vec::new(),
            };
        }

        device_configs.push(ProxyDeviceConfig {
            name_suffix: None,
            config: proxy_config(
                format!("{protocol}:{ipv4_listen_addr}:{public_port}"),
                format!("{protocol}:{}:{private_port}", target_ipv4.unwrap()),
                true,
            ),
        });

        if let Some(v6) = &normalized_host_ipv6 {
            device_configs.push(ProxyDeviceConfig {
                name_suffix: Some("-v6"),
                config: proxy_config(
                    format!("{protocol}:[{v6}]:{public_port}"),
                    format!("{protocol}:0.0.0.0:{private_port}"),
                    false,
                ),
            });
        }

        return ProxyDeviceResult { success: true, error_message: None, device_configs };
    }

    let is_v6_mode = network_mode == "ipv6_only" || network_mode == "ipv6_nat";
    let listen_addr = if is_v6_mode {
        match &normalized_host_ipv6 {
            Some(v6) => format!("[{v6}]"),
            None => {
                return ProxyDeviceResult {
                    success: false,
                    error_message: Some("当前所在节点暂无任何公网 IPv6 记录！请通知管理员在节点设置中补充【公网 IPv6 或 NAT IPv6 地址】，否则无法穿透映射。".into()),
                    device_configs: Vec::new(),
                }
            }
        }
    } else {
        host_nat_ip.unwrap_or("0.0.0.0").to_string()
    };

    if !is_v6_mode {
        if listen_addr.is_empty() || listen_addr == "0.0.0.0" || listen_addr == "[::]" {
            return ProxyDeviceResult {
                success: false,
                error_message: Some("Current host has no bindable IPv4 listen address for NAT port mapping. Please configure Listen IPv4 in host NAT settings.".into()),
                device_configs: Vec::new(),
            };
        }
        if target_ipv4.is_none() {
            return ProxyDeviceResult {
                success: false,
                error_message: Some("Current instance has no static IPv4 address for NAT port mapping.".into()),
                device_configs: Vec::new(),
            };
        }
        return ProxyDeviceResult {
            success: true,
            error_message: None,
            device_configs: vec![ProxyDeviceConfig {
                name_suffix: None,
                config: proxy_config(
                    format!("{protocol}:{listen_addr}:{public_port}"),
                    format!("{protocol}:{}:{private_port}", target_ipv4.unwrap()),
                    true,
                ),
            }],
        };
    }

    // 普通情况下连接使用 0.0.0.0 自适应；仅 IPv6-only/ipv6_nat 环境启用 [::]
    let connect_addr = if is_v6_mode { "[::]" } else { "0.0.0.0" };
    ProxyDeviceResult {
        success: true,
        error_message: None,
        device_configs: vec![ProxyDeviceConfig {
            name_suffix: None,
            config: proxy_config(
                format!("{protocol}:{listen_addr}:{public_port}"),
                format!("{protocol}:{connect_addr}:{private_port}"),
                false,
            ),
        }],
    }
}

/// KvmProxyStrategy.createProxyDevice.
pub fn kvm_create_proxy_device(
    host_nat_ip: Option<&str>,
    host_ipv6: Option<&str>,
    network_mode: &str,
    protocol: &str,
    public_port: i64,
    private_port: i64,
    target_ipv4: Option<&str>,
) -> ProxyDeviceResult {
    let target_ipv4 = target_ipv4.map(str::trim).filter(|s| !s.is_empty());
    let normalized_host_ipv6 = normalize_host_ipv6(host_ipv6);

    if network_mode == "nat_ipv6_nat" {
        let mut device_configs: Vec<ProxyDeviceConfig> = Vec::new();

        if let Some(nat_ip) = host_nat_ip.filter(|s| !s.is_empty() && *s != "0.0.0.0") {
            if target_ipv4.is_none() {
                return ProxyDeviceResult {
                    success: false,
                    error_message: Some("Current instance has no static IPv4 address for KVM NAT port mapping.".into()),
                    device_configs: Vec::new(),
                };
            }
            device_configs.push(ProxyDeviceConfig {
                name_suffix: None,
                config: proxy_config(
                    format!("{protocol}:{nat_ip}:{public_port}"),
                    format!("{protocol}:{}:{private_port}", target_ipv4.unwrap()),
                    true,
                ),
            });
        }

        if let Some(v6) = &normalized_host_ipv6 {
            device_configs.push(ProxyDeviceConfig {
                name_suffix: Some("-v6"),
                config: proxy_config(
                    format!("{protocol}:[{v6}]:{public_port}"),
                    format!("{protocol}:0.0.0.0:{private_port}"),
                    false,
                ),
            });
        }

        if device_configs.is_empty() {
            return ProxyDeviceResult {
                success: false,
                error_message: Some("Current host has no usable NAT public IPv4 or IPv6 address for KVM port mapping.".into()),
                device_configs: Vec::new(),
            };
        }

        return ProxyDeviceResult { success: true, error_message: None, device_configs };
    }

    let is_v6_mode = network_mode == "ipv6_only" || network_mode == "ipv6_nat";
    let listen_addr = if is_v6_mode {
        match &normalized_host_ipv6 {
            Some(v6) => format!("[{v6}]"),
            None => {
                return ProxyDeviceResult {
                    success: false,
                    error_message: Some("Current host has no public IPv6/NAT IPv6 configured for KVM port mapping.".into()),
                    device_configs: Vec::new(),
                }
            }
        }
    } else {
        match host_nat_ip.filter(|s| !s.is_empty() && *s != "0.0.0.0") {
            Some(ip) => ip.to_string(),
            None => {
                return ProxyDeviceResult {
                    success: false,
                    error_message: Some("Current host has no bindable IPv4 listen address for KVM port mapping. Please configure a local Listen IPv4 address in host NAT settings.".into()),
                    device_configs: Vec::new(),
                }
            }
        }
    };

    let connect_addr = if network_mode == "ipv6_only" { "[::]" } else { "0.0.0.0" };
    if !is_v6_mode && target_ipv4.is_none() {
        return ProxyDeviceResult {
            success: false,
            error_message: Some("Current instance has no static IPv4 address for KVM NAT port mapping.".into()),
            device_configs: Vec::new(),
        };
    }

    let connect = if is_v6_mode {
        connect_addr.to_string()
    } else {
        target_ipv4.unwrap().to_string()
    };
    let mut config = proxy_config(
        format!("{protocol}:{listen_addr}:{public_port}"),
        format!("{protocol}:{connect}:{private_port}"),
        false,
    );
    if network_mode != "ipv6_nat" {
        config.insert("nat".into(), Value::String("true".into()));
    }

    ProxyDeviceResult {
        success: true,
        error_message: None,
        device_configs: vec![ProxyDeviceConfig { name_suffix: None, config }],
    }
}

/// ProxyStrategyFactory.getStrategy + createProxyDevice dispatch.
pub fn create_proxy_device(
    strategy: StrategyKind,
    host_nat_ip: Option<&str>,
    host_ipv6: Option<&str>,
    network_mode: &str,
    protocol: &str,
    public_port: i64,
    private_port: i64,
    target_ipv4: Option<&str>,
) -> ProxyDeviceResult {
    match strategy {
        StrategyKind::Container => lxc_create_proxy_device(
            host_nat_ip, host_ipv6, network_mode, protocol, public_port, private_port, target_ipv4,
        ),
        StrategyKind::VirtualMachine => kvm_create_proxy_device(
            host_nat_ip, host_ipv6, network_mode, protocol, public_port, private_port, target_ipv4,
        ),
    }
}

/// resolveInstanceTargetIpv4FromIncusDevice: devices.eth0['ipv4.address'].
pub fn resolve_instance_target_ipv4_from_incus_device(
    devices: &Map<String, Value>,
) -> Option<String> {
    let eth0 = devices.get("eth0")?;
    let ipv4 = eth0.get("ipv4.address")?.as_str()?;
    normalize_ipv4_address(Some(ipv4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lxc_nat_ipv4_creates_nat_proxy() {
        let result = lxc_create_proxy_device(Some("1.2.3.4"), None, "nat", "tcp", 10001, 22, Some("10.10.1.5"));
        assert!(result.success);
        assert_eq!(result.device_configs.len(), 1);
        assert_eq!(result.device_configs[0].config.get("listen").unwrap(), &json!("tcp:1.2.3.4:10001"));
        assert_eq!(result.device_configs[0].config.get("connect").unwrap(), &json!("tcp:10.10.1.5:22"));
        assert_eq!(result.device_configs[0].config.get("nat").unwrap(), &json!("true"));
    }

    #[test]
    fn lxc_nat_ipv6_nat_adds_v6_device() {
        let result = lxc_create_proxy_device(Some("1.2.3.4"), Some("[2001:db8::1]"), "nat_ipv6_nat", "tcp", 10001, 22, Some("10.10.1.5"));
        assert!(result.success);
        assert_eq!(result.device_configs.len(), 2);
        assert_eq!(result.device_configs[1].name_suffix, Some("-v6"));
        assert_eq!(
            result.device_configs[1].config.get("listen").unwrap(),
            &json!("tcp:[2001:db8::1]:10001")
        );
    }

    #[test]
    fn lxc_requires_target_ipv4_for_nat() {
        let result = lxc_create_proxy_device(Some("1.2.3.4"), None, "nat", "tcp", 10001, 22, None);
        assert!(!result.success);
    }

    #[test]
    fn kvm_ipv6_only_uses_bracketed_listen() {
        let result = kvm_create_proxy_device(Some("1.2.3.4"), Some("2001:db8::1"), "ipv6_only", "tcp", 10001, 22, Some("10.10.1.5"));
        assert!(result.success);
        assert_eq!(result.device_configs[0].config.get("listen").unwrap(), &json!("tcp:[2001:db8::1]:10001"));
        assert_eq!(result.device_configs[0].config.get("connect").unwrap(), &json!("tcp:[::]:22"));
    }
}
