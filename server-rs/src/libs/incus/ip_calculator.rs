//! IPv6 address calculator (IPAM) and the shared NAT IPv4 plan.
//! Port of lib/ip-calculator.ts.
//!
//! The TS implementation uses the `ip-address` library's BigInt arithmetic;
//! the Rust port uses u128 (the full IPv6 space fits exactly). Address output
//! uses Rust's canonical compressed IPv6 formatting, which matches the
//! library's `correctForm()`.

use std::net::Ipv6Addr;

use rand::Rng;

/// Shared NAT IPv4 plan (mirrors `IPV4_CONFIG`).
pub struct Ipv4Config;

impl Ipv4Config {
    pub const SUBNET: &'static str = "10.10.0.0/22";
    pub const GATEWAY: &'static str = "10.10.0.1";
    /// Allocatable range: 10.10.1.1 - 10.10.3.254 (10.10.0.x is reserved for
    /// the gateway and infrastructure).
    pub const RANGE_START: [u8; 4] = [10, 10, 1, 1];
    pub const RANGE_END: [u8; 4] = [10, 10, 3, 254];
    pub const DNS: [&'static str; 2] = ["8.8.8.8", "1.1.1.1"];
}

fn ipv4_to_int(ip: &str) -> Option<u32> {
    let parts: Vec<u8> = ip
        .split('.')
        .map(|p| p.parse::<u8>())
        .collect::<Result<_, _>>()
        .ok()?;
    if parts.len() != 4 {
        return None;
    }
    Some(
        ((parts[0] as u32) << 24)
            | ((parts[1] as u32) << 16)
            | ((parts[2] as u32) << 8)
            | parts[3] as u32,
    )
}

fn int_to_ipv4(num: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (num >> 24) & 255,
        (num >> 16) & 255,
        (num >> 8) & 255,
        num & 255
    )
}

const IPV4_RANGE_START: u32 = (10 << 24) | (10 << 16) | (1 << 8) | 1;
const IPV4_RANGE_END: u32 = (10 << 24) | (10 << 16) | (3 << 8) | 254;

/// Mirrors `generateRandomIPv4`: a random address in 10.10.1.1 - 10.10.3.254.
pub fn generate_random_ipv4() -> String {
    let range = IPV4_RANGE_END - IPV4_RANGE_START + 1;
    let offset = rand::thread_rng().gen_range(0..range);
    int_to_ipv4(IPV4_RANGE_START + offset)
}

/// Mirrors `isIpv4InRange`.
pub fn is_ipv4_in_range(address: &str) -> bool {
    let Some(num) = ipv4_to_int(address) else {
        return false;
    };
    num >= IPV4_RANGE_START && num <= IPV4_RANGE_END
}

// ==================== IPv6 ====================

fn parse_ipv6_subnet(subnet: &str) -> Result<(u128, u32), String> {
    let trimmed = subnet.trim();
    let (addr_part, prefix) = match trimmed.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (trimmed, None),
    };
    let addr: Ipv6Addr = addr_part
        .parse()
        .map_err(|_| format!("Invalid IPv6 subnet: {subnet}"))?;
    let prefix = match prefix {
        Some(p) => p
            .parse::<u32>()
            .ok()
            .filter(|v| *v <= 128)
            .ok_or_else(|| format!("Invalid IPv6 subnet: {subnet}"))?,
        None => 128,
    };
    Ok((u128::from_be_bytes(addr.octets()), prefix))
}

fn subnet_start(bits: u128, prefix: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - prefix))
    }
}

fn subnet_end(bits: u128, prefix: u32) -> u128 {
    subnet_start(bits, prefix) | if prefix == 0 { u128::MAX } else { u128::MAX >> prefix }
}

fn format_ipv6(bits: u128) -> String {
    Ipv6Addr::from(bits).to_string()
}

/// Mirrors `calculateIPv6`: subnet start + offset + 2 (skipping ::0 the subnet
/// router anycast and ::1 the reserved gateway).
pub fn calculate_ipv6(subnet: &str, offset: i64) -> Result<String, String> {
    let (bits, prefix) = parse_ipv6_subnet(subnet)?;
    if offset < 0 {
        return Err(format!("Invalid IPv6 offset: {offset}"));
    }
    let start = subnet_start(bits, prefix);
    let target = start
        .checked_add(offset as u128)
        .and_then(|v| v.checked_add(2))
        .ok_or_else(|| format!("Invalid IPv6 offset: {offset}"))?;
    Ok(format_ipv6(target))
}

/// Mirrors `isValidIPv6Subnet`.
pub fn is_valid_ipv6_subnet(subnet: &str) -> bool {
    parse_ipv6_subnet(subnet).is_ok()
}

/// Mirrors `getIPv6Offset`: address - subnet start - the 2 reserved addresses.
pub fn get_ipv6_offset(subnet: &str, address: &str) -> Result<i64, String> {
    let (bits, prefix) = parse_ipv6_subnet(subnet)?;
    let addr: Ipv6Addr = address
        .parse()
        .map_err(|_| "Invalid subnet or address".to_string())?;
    let addr_bits = u128::from_be_bytes(addr.octets());
    let start = subnet_start(bits, prefix);
    let delta = (addr_bits as i128) - (start as i128) - 2;
    if delta < i64::MIN as i128 || delta > i64::MAX as i128 {
        return Err("Invalid subnet or address".to_string());
    }
    Ok(delta as i64)
}

fn random_u128() -> u128 {
    let bytes: [u8; 16] = rand::random();
    u128::from_be_bytes(bytes)
}

/// Mirrors `generateRandomIPv6`: a random address in the subnet, skipping ::0
/// and ::1.
pub fn generate_random_ipv6(subnet: &str) -> Result<String, String> {
    let (bits, prefix) = parse_ipv6_subnet(subnet)?;
    let min = subnet_start(bits, prefix)
        .checked_add(2)
        .ok_or_else(|| format!("Invalid IPv6 subnet: {subnet}"))?;
    let max = subnet_end(bits, prefix);
    if max < min {
        return Err(format!("Invalid IPv6 subnet: {subnet}"));
    }
    // Range is u128-inclusive; modulo of a uniform u128 is the practical
    // equivalent of the TS BigInt random mapping (bias is negligible and the
    // TS Number path had the same property below 2^53).
    let range = max - min + 1;
    let offset = random_u128() % range;
    Ok(format_ipv6(min + offset))
}

/// Mirrors `generateRandomSubnet`: a random child subnet of the given prefix
/// length carved out of the host subnet.
pub fn generate_random_subnet(host_subnet: &str, prefix: u32) -> Result<String, String> {
    let (bits, host_prefix) = parse_ipv6_subnet(host_subnet)?;
    if prefix <= host_prefix {
        return Err(format!(
            "Target prefix /{prefix} must be greater than host prefix /{host_prefix}"
        ));
    }
    let subnet_bits = prefix - host_prefix;
    // Random index in [0, 2^subnet_bits); the full-space case (128 bits)
    // overflows u128 so it uses the whole range directly.
    let index = if subnet_bits >= 128 {
        random_u128()
    } else {
        random_u128() % (1u128 << subnet_bits)
    };
    let host_start = subnet_start(bits, host_prefix);
    let subnet_size = 1u128 << (128 - prefix);
    let subnet_start_bits = host_start + index * subnet_size;
    Ok(format!("{}/{prefix}", format_ipv6(subnet_start_bits)))
}

/// Mirrors `isIpv6InSubnet`.
pub fn is_ipv6_in_subnet(address: &str, subnet: &str) -> bool {
    let (Ok((bits, prefix)), Ok(())) = (
        parse_ipv6_subnet(subnet),
        address
            .trim()
            .parse::<Ipv6Addr>()
            .map(|_| ()),
    ) else {
        return false;
    };
    let addr: u128 = u128::from_be_bytes(address.trim().parse::<Ipv6Addr>().expect("checked").octets());
    addr >= subnet_start(bits, prefix) && addr <= subnet_end(bits, prefix)
}

/// Mirrors `isStrictValidIpv6`.
pub fn is_strict_valid_ipv6(address: &str) -> bool {
    let trimmed = address.trim().split('/').next().unwrap_or("");
    trimmed.parse::<Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_range_math() {
        assert!(is_ipv4_in_range("10.10.1.1"));
        assert!(is_ipv4_in_range("10.10.3.254"));
        assert!(is_ipv4_in_range("10.10.2.100"));
        assert!(!is_ipv4_in_range("10.10.0.5"));
        assert!(!is_ipv4_in_range("10.10.4.0"));
        assert!(!is_ipv4_in_range("10.10.1.256"));
        assert!(!is_ipv4_in_range("not-an-ip"));
        assert!(is_ipv4_in_range(&generate_random_ipv4()));
    }

    #[test]
    fn ipv6_offset_calculation_skips_reserved_addresses() {
        let subnet = "2a0a:51c1:9:13b:1::/80";
        assert_eq!(calculate_ipv6(subnet, 0).unwrap(), "2a0a:51c1:9:13b:1::2");
        assert_eq!(calculate_ipv6(subnet, 5).unwrap(), "2a0a:51c1:9:13b:1::7");
        assert_eq!(get_ipv6_offset(subnet, "2a0a:51c1:9:13b:1::7").unwrap(), 5);
        assert!(calculate_ipv6("not-an-ip", 1).is_err());
        assert!(calculate_ipv6("10.0.0.1", 1).is_err());
    }

    #[test]
    fn random_ipv6_and_subnet_generation_stay_in_bounds() {
        let subnet = "2a0a:51c1:9:13b::/64";
        for _ in 0..32 {
            let address = generate_random_ipv6(subnet).unwrap();
            assert!(is_strict_valid_ipv6(&address));
            assert!(is_ipv6_in_subnet(&address, subnet));
            assert_ne!(address, "::");
            assert_ne!(address, "::1");
        }

        for _ in 0..32 {
            let child = generate_random_subnet(subnet, 112).unwrap();
            assert!(child.ends_with("/112"));
            let child_addr = child.split('/').next().unwrap();
            assert!(is_ipv6_in_subnet(child_addr, subnet));
        }

        assert!(generate_random_subnet(subnet, 64).is_err());
        assert!(generate_random_subnet(subnet, 48).is_err());
    }

    #[test]
    fn subnet_membership_checks() {
        assert!(is_ipv6_in_subnet("2001:db8::5", "2001:db8::/64"));
        assert!(is_ipv6_in_subnet("2001:db8::ffff:ffff:ffff:ffff", "2001:db8::/64"));
        assert!(!is_ipv6_in_subnet("2001:db9::1", "2001:db8::/64"));
        assert!(!is_ipv6_in_subnet("garbage", "2001:db8::/64"));
        assert!(!is_ipv6_in_subnet("2001:db8::1", "garbage"));
        assert!(is_valid_ipv6_subnet("2a01:4f9:c012:e7:aaaa::/112"));
        // Address6.isValid accepts any parseable prefix (including /47); only
        // unparseable prefixes are rejected.
        assert!(is_valid_ipv6_subnet("2a01:4f9:c012:e7:aaaa::/47"));
        assert!(!is_valid_ipv6_subnet("2a01:4f9:c012:e7:aaaa::/129"));
        assert!(!is_valid_ipv6_subnet("2a01:4f9:c012:e7:aaaa::/abc"));
        assert!(is_strict_valid_ipv6("2001:DB8::1/64"));
        assert!(!is_strict_valid_ipv6("2001:db8::zzzz"));
    }
}
