//! Network host/address helpers.
//! Port of lib/network-address.ts.

use std::net::IpAddr;

/// Mirrors `DnsRecordType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
}

impl DnsRecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::Aaaa => "AAAA",
            DnsRecordType::Cname => "CNAME",
        }
    }
}

/// 0 = not an IP, 4 = IPv4, 6 = IPv6 (mirrors getAddressFamily()).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    None,
    V4,
    V6,
}

/// Mirrors `normalizeNetworkHost`: trims and strips a single bracket pair
/// around IPv6 literals.
pub fn normalize_network_host(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = trimmed[1..trimmed.len() - 1].trim();
        if inner.contains(':') {
            return inner.to_string();
        }
    }
    trimmed.to_string()
}

/// Mirrors `getAddressFamily`.
pub fn get_address_family(value: &str) -> AddressFamily {
    match normalize_network_host(value).parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => AddressFamily::V4,
        Ok(IpAddr::V6(_)) => AddressFamily::V6,
        Err(_) => AddressFamily::None,
    }
}

/// Mirrors `isIpLiteral`.
pub fn is_ip_literal(value: &str) -> bool {
    get_address_family(value) != AddressFamily::None
}

/// Mirrors `formatHostForUrl` (brackets IPv6 literals).
pub fn format_host_for_url(value: &str) -> String {
    let normalized = normalize_network_host(value);
    if get_address_family(&normalized) == AddressFamily::V6 {
        format!("[{normalized}]")
    } else {
        normalized
    }
}

/// Mirrors `formatHostForListen`.
pub fn format_host_for_listen(value: &str) -> String {
    format_host_for_url(value)
}

/// Mirrors `extractHostAddressFromUrl`.
pub fn extract_host_address_from_url(value: Option<&str>) -> Option<String> {
    let value = value?;
    let url = reqwest::Url::parse(value).ok()?;
    let hostname = url.host_str()?;
    Some(normalize_network_host(hostname))
}

/// Mirrors `selectBindableIpv4ListenAddress`.
pub fn select_bindable_ipv4_listen_address(
    explicit_bind_ipv4: Option<&str>,
    fallback_public_ipv4: Option<&str>,
    host_url: Option<&str>,
    host_ip_address: Option<&str>,
) -> String {
    let _ = host_url; // unused in the TS implementation too
    let explicit = explicit_bind_ipv4
        .filter(|v| !v.is_empty())
        .map(normalize_network_host)
        .unwrap_or_default();
    if get_address_family(&explicit) == AddressFamily::V4 {
        return explicit;
    }

    let mut local_candidates: std::collections::HashSet<String> = std::collections::HashSet::new();
    let normalized_host_ip = host_ip_address.filter(|v| !v.is_empty()).map(normalize_network_host);
    let fallback = fallback_public_ipv4
        .filter(|v| !v.is_empty())
        .map(normalize_network_host)
        .unwrap_or_default();

    if get_address_family(&fallback) != AddressFamily::V4 {
        return "0.0.0.0".to_string();
    }

    if let Some(host_ip) = &normalized_host_ip {
        if get_address_family(host_ip) == AddressFamily::V4 {
            local_candidates.insert(host_ip.clone());
        }
    }

    if local_candidates.contains(&fallback) {
        fallback
    } else {
        "0.0.0.0".to_string()
    }
}

/// Mirrors `normalizeIpv4Address`.
pub fn normalize_ipv4_address(value: Option<&str>) -> Option<String> {
    let value = value?;
    let normalized = normalize_network_host(value);
    let address = normalized.split('/').next().unwrap_or("").trim();
    if address.is_empty() {
        return None;
    }
    if get_address_family(address) == AddressFamily::V4 {
        Some(address.to_string())
    } else {
        None
    }
}

/// Mirrors `isIpv6Address`.
pub fn is_ipv6_address(value: &str) -> bool {
    get_address_family(value) == AddressFamily::V6
}

/// Mirrors `getDnsRecordType`.
pub fn get_dns_record_type(value: &str) -> DnsRecordType {
    match get_address_family(value) {
        AddressFamily::V4 => DnsRecordType::A,
        AddressFamily::V6 => DnsRecordType::Aaaa,
        AddressFamily::None => DnsRecordType::Cname,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_normalization_and_family_detection() {
        assert_eq!(normalize_network_host(" [::1] "), "::1");
        assert_eq!(normalize_network_host("1.2.3.4"), "1.2.3.4");
        assert_eq!(get_address_family("1.2.3.4"), AddressFamily::V4);
        assert_eq!(get_address_family("[::1]"), AddressFamily::V6);
        assert_eq!(get_address_family("example.com"), AddressFamily::None);
        assert!(is_ip_literal("::1"));
        assert!(!is_ip_literal("example.com"));
        assert_eq!(format_host_for_url("::1"), "[::1]");
        assert_eq!(format_host_for_url("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn bindable_listen_address_fallbacks() {
        assert_eq!(
            select_bindable_ipv4_listen_address(Some("10.0.0.5"), None, None, None),
            "10.0.0.5"
        );
        assert_eq!(
            select_bindable_ipv4_listen_address(None, Some("8.8.8.8"), None, Some("8.8.8.8")),
            "8.8.8.8"
        );
        assert_eq!(
            select_bindable_ipv4_listen_address(None, Some("8.8.8.8"), None, Some("1.1.1.1")),
            "0.0.0.0"
        );
        assert_eq!(
            select_bindable_ipv4_listen_address(None, Some("::1"), None, None),
            "0.0.0.0"
        );
    }

    #[test]
    fn ipv4_normalization_and_dns_types() {
        assert_eq!(normalize_ipv4_address(Some("10.1.2.3/24")), Some("10.1.2.3".to_string()));
        assert_eq!(normalize_ipv4_address(Some("::1")), None);
        assert_eq!(normalize_ipv4_address(Some("")), None);
        assert!(is_ipv6_address("2606:4700::1111"));
        assert_eq!(get_dns_record_type("1.2.3.4").as_str(), "A");
        assert_eq!(get_dns_record_type("::1").as_str(), "AAAA");
        assert_eq!(get_dns_record_type("example.com").as_str(), "CNAME");
    }
}
