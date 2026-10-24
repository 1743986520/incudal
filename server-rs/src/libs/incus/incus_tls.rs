//! Incus TLS trust handling.
//! Port of lib/incus/incus-tls.ts.
//!
//! Trust model (must stay identical to the TS server):
//! - The panel always authenticates itself with the server-managed certificate
//!   pair (PANEL_CRT_PATH / PANEL_KEY_PATH, defaults certs/client.crt /
//!   certs/client.key). Per-host certPath/keyPath columns are legacy and are
//!   never used for filesystem access.
//! - Trust anchors: host.serverCertificate (pinned, with optional fingerprint)
//!   > host.caPath > INCUS_CA_PATH (must be absolute). No CA configured means
//!   the default webpki root store is used.
//! - When a fingerprint is pinned, the TS server replaces Node's hostname
//!   check with an exact sha256 comparison of the peer certificate. reqwest
//!   cannot swap hostname verification per connection, so the Rust port
//!   disables certificate verification for pinned clients and re-checks the
//!   exact sha256 pin of the live peer certificate on every response instead
//!   (see incus_client::IncusClient::request).

use std::net::IpAddr;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::libs::incus::incus_client::IncusError;

pub const PIN_MISMATCH_MESSAGE: &str =
    "Incus server certificate does not match the stored host fingerprint";

/// Mirrors `IncusTlsTrust`: CA PEM contents plus an optional sha256 pin.
#[derive(Debug, Clone, Default)]
pub struct IncusTlsTrust {
    pub ca_pem: Option<String>,
    pub fingerprint: Option<String>,
}

/// Mirrors `IncusTlsConnectOptions` for the reqwest backend. `pinned_fingerprint`
/// is enforced per-response by the client (see module docs).
#[derive(Debug, Clone, Default)]
pub struct TlsConnectOptions {
    pub ca_pem: Option<String>,
    pub pinned_fingerprint: Option<String>,
}

/// Mirrors `ResolvedIncusTarget`.
#[derive(Debug, Clone)]
pub struct ResolvedIncusTarget {
    pub url: String,
    pub servername: Option<String>,
    pub address: String,
}

fn configured_path(value: Option<String>, fallback: &str) -> String {
    match value {
        Some(v) if !v.is_empty() => v,
        // TS resolves the fallback against <repo>/certs; the Rust server runs
        // from its deployment root, so the relative default is kept.
        _ => format!("certs/{fallback}"),
    }
}

/// Mirrors `panelCertificatePaths()`: PANEL_CRT_PATH / PANEL_KEY_PATH with
/// `certs/client.crt` / `certs/client.key` defaults.
pub fn panel_certificate_paths() -> (String, String) {
    let cert = configured_path(std::env::var("PANEL_CRT_PATH").ok(), "client.crt");
    let key = configured_path(std::env::var("PANEL_KEY_PATH").ok(), "client.key");
    (cert, key)
}

/// Mirrors `assertServerManagedCertificatePaths`.
pub fn assert_server_managed_certificate_paths(
    cert_path: &str,
    key_path: &str,
) -> Result<(), IncusError> {
    let (managed_cert, managed_key) = panel_certificate_paths();
    let path = |p: &str| std::path::Path::new(p).to_path_buf();
    let normalized = |p: &str| normalize_path(&path(p));
    let managed_cert_norm = normalize_path(&path(&managed_cert));
    let managed_key_norm = normalize_path(&path(&managed_key));
    let cert_abs = path(cert_path).is_absolute();
    let key_abs = path(key_path).is_absolute();
    if !cert_abs
        || !key_abs
        || normalized(cert_path) != managed_cert_norm
        || normalized(key_path) != managed_key_norm
    {
        return Err(IncusError::Other(
            "Incus certificate paths must use the server-managed panel certificate pair"
                .to_string(),
        ));
    }
    Ok(())
}

fn normalize_path(path: &std::path::Path) -> std::path::PathBuf {
    // Best-effort lexical normalization (Node path.normalize + resolve).
    let mut out = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Extract the DER body of the first PEM CERTIFICATE block.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, IncusError> {
    let normalized = pem.trim();
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = normalized
        .find(begin)
        .ok_or_else(|| IncusError::Other("unable to verify the first certificate".to_string()))?
        + begin.len();
    let stop = normalized[start..]
        .find(end)
        .ok_or_else(|| IncusError::Other("unable to verify the first certificate".to_string()))?
        + start;
    let body: String = normalized[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body.as_bytes())
        .map_err(|_| IncusError::Other("invalid PEM certificate body".to_string()))
}

fn der_to_pem(der: &[u8]) -> String {
    use base64::Engine as _;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    let encoded = B64.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Mirrors `normalizeCertificatePem`: re-emits the certificate as canonical PEM
/// (base64 wrapped at 64 columns) with a trailing newline.
pub fn normalize_certificate_pem(certificate: &str) -> Result<String, IncusError> {
    let der = pem_to_der(certificate)?;
    let pem = der_to_pem(&der);
    Ok(format!("{}\n", pem.trim()))
}

/// Mirrors `certificateFingerprint`: sha256 of the DER, hex, lowercase, no colons.
pub fn certificate_fingerprint(certificate: &str) -> Result<String, IncusError> {
    let der = pem_to_der(certificate)?;
    Ok(hex::encode(Sha256::digest(&der)))
}

/// SHA-256 pin of a DER leaf (used for live peer checks).
pub fn der_fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Mirrors `assertCertificateMatchesFingerprint`.
pub fn assert_certificate_matches_fingerprint(
    certificate: &str,
    fingerprint: Option<&str>,
) -> Result<(), IncusError> {
    let Some(fingerprint) = fingerprint else {
        return Ok(());
    };
    let expected = normalize_fingerprint(fingerprint);
    let valid = expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit());
    if !valid || certificate_fingerprint(certificate)? != expected {
        return Err(IncusError::Other(PIN_MISMATCH_MESSAGE.to_string()));
    }
    Ok(())
}

fn normalize_fingerprint(fingerprint: &str) -> String {
    fingerprint.replace(':', "").trim().to_lowercase()
}

/// Mirrors `buildIncusTlsConnectOptions`. Validates that a configured CA
/// matches the configured fingerprint before any connection is made.
pub fn build_incus_tls_connect_options(
    trust: &IncusTlsTrust,
) -> Result<TlsConnectOptions, IncusError> {
    if let Some(ca) = &trust.ca_pem {
        assert_certificate_matches_fingerprint(ca, trust.fingerprint.as_deref())?;
    }
    Ok(TlsConnectOptions {
        ca_pem: trust.ca_pem.clone(),
        pinned_fingerprint: trust
            .fingerprint
            .as_deref()
            .map(normalize_fingerprint)
            .filter(|f| !f.is_empty()),
    })
}

// ==================== SSRF guard: public address checks ====================

fn ipv4_in_cidr(ip: u32, cidr: &str) -> bool {
    let (base, prefix) = cidr.split_once('/').expect("blocked cidr has a prefix");
    let prefix: u32 = prefix.parse().expect("blocked cidr prefix is valid");
    let base: u32 = base
        .split('.')
        .filter_map(|o| o.parse::<u8>().ok())
        .fold(0u32, |acc, o| (acc << 8) | o as u32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (ip & mask) == (base & mask)
}

fn ipv6_in_cidr(ip: u128, cidr: &str) -> bool {
    let (base, prefix) = cidr.split_once('/').expect("blocked cidr has a prefix");
    let prefix: u32 = prefix.parse().expect("blocked cidr prefix is valid");
    let base: u128 = base
        .parse::<IpAddr>()
        .ok()
        .and_then(|a| match a {
            IpAddr::V6(v6) => Some(u128::from_be_bytes(v6.octets())),
            _ => None,
        })
        .expect("blocked ipv6 cidr base is valid");
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (ip & mask) == (base & mask)
}

const BLOCKED_IPV4_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

// Unspecified/IPv4-compatible space, NAT64 translation prefixes, discard,
// documentation/special-use ranges, ULA, link-local and multicast. NAT64
// literals must not bypass the IPv4 private-range checks through a public-
// looking IPv6 address.
const BLOCKED_IPV6_CIDRS: &[&str] = &[
    "::/96",
    "::1/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

fn normalized_mapped_ipv4(address: &str) -> Option<String> {
    let value = address.to_lowercase();
    let value = value.split('%').next().unwrap_or(&value);
    if let Some(rest) = value.strip_prefix("::ffff:") {
        // ::ffff:a.b.c.d dotted form
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
        {
            let octets: Vec<u8> = parts
                .iter()
                .filter_map(|p| p.parse::<u8>().ok())
                .collect();
            if octets.len() == 4 {
                return Some(format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]));
            }
        }
        // ::ffff:hhhh:hhhh hex form
        let tail: Vec<&str> = rest.split(':').collect();
        if tail.len() == 2
            && tail
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 4 && p.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            let high = u16::from_str_radix(tail[0], 16).ok()?;
            let low = u16::from_str_radix(tail[1], 16).ok()?;
            return Some(format!(
                "{}.{}.{}.{}",
                high >> 8,
                high & 255,
                low >> 8,
                low & 255
            ));
        }
    }
    None
}

/// Mirrors `isPublicHostAddress`: rejects private/special-use ranges, IPv4
/// mapped IPv6 literals included.
pub fn is_public_host_address(address: &str) -> bool {
    let value = address.to_lowercase();
    let value = value.split('%').next().unwrap_or(&value);
    if let Some(mapped) = normalized_mapped_ipv4(value) {
        return is_public_host_address(&mapped);
    }
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let bits = u32::from_be_bytes(v4.octets());
            !BLOCKED_IPV4_CIDRS.iter().any(|cidr| ipv4_in_cidr(bits, cidr))
        }
        Ok(IpAddr::V6(v6)) => {
            let bits = u128::from_be_bytes(v6.octets());
            !BLOCKED_IPV6_CIDRS
                .iter()
                .any(|cidr| ipv6_in_cidr(bits, cidr))
        }
        Err(_) => false,
    }
}

// ==================== Target resolution ====================

fn is_ip(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

fn is_ipv6(value: &str) -> bool {
    matches!(value.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
}

/// Default DNS resolver (Node dns.lookup with { all: true, verbatim: true }).
pub async fn default_dns_resolver(hostname: &str, port: u16) -> Result<Vec<String>, String> {
    let target = if is_ip(hostname) {
        return Ok(vec![hostname.to_string()]);
    } else {
        format!("{hostname}:{port}")
    };
    match tokio::net::lookup_host(target).await {
        Ok(addrs) => {
            let mut out = Vec::new();
            for addr in addrs {
                let ip = addr.ip().to_string();
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
            Ok(out)
        }
        Err(err) => Err(format!("getaddrinfo {hostname}: {err}")),
    }
}

/// Mirrors `resolveIncusTarget`: validate the URL, resolve DNS once, enforce
/// the public-address policy, and pin the connection URL to a single address.
pub async fn resolve_incus_target(
    input: &str,
    allow_private_network: bool,
) -> Result<ResolvedIncusTarget, IncusError> {
    resolve_incus_target_with(input, allow_private_network, |hostname: String, port: u16| async move {
        default_dns_resolver(&hostname, port).await
    })
    .await
}

/// Resolver-injecting variant used by tests and `assertAllowedHostUrl`.
pub async fn resolve_incus_target_with<F, Fut>(
    input: &str,
    allow_private_network: bool,
    resolver: F,
) -> Result<ResolvedIncusTarget, IncusError>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<String>, String>>,
{
    let url = reqwest::Url::parse(input)
        .map_err(|_| IncusError::Other("Host URL is invalid".to_string()))?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(IncusError::Other(
            "Incus host URL must use HTTPS without credentials".to_string(),
        ));
    }

    let hostname = url
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    let mut addresses = if is_ip(&hostname) {
        vec![hostname.clone()]
    } else {
        resolver(hostname.clone(), port)
            .await
            .map_err(IncusError::Other)?
    };
    // Array.from(new Set(...)) — de-duplicate while keeping order.
    let mut deduped: Vec<String> = Vec::new();
    for addr in addresses {
        if !deduped.contains(&addr) {
            deduped.push(addr);
        }
    }
    addresses = deduped;

    if addresses.is_empty() {
        return Err(IncusError::Other(
            "Host URL did not resolve to an address".to_string(),
        ));
    }
    if !allow_private_network
        && addresses
            .iter()
            .any(|addr| !is_public_host_address(addr))
    {
        return Err(IncusError::Other(
            "Ordinary host creators must use a publicly routable host URL".to_string(),
        ));
    }

    let address = addresses
        .iter()
        .find(|candidate| !is_ipv6(candidate))
        .cloned()
        .unwrap_or_else(|| addresses[0].clone());
    if !is_ip(&address) {
        return Err(IncusError::Other(
            "Host URL resolved to an invalid address".to_string(),
        ));
    }

    let ip: IpAddr = address
        .split('%')
        .next()
        .unwrap_or(&address)
        .parse()
        .map_err(|_| {
            IncusError::Other("Host URL resolved to an invalid address".to_string())
        })?;
    let mut rewritten = url.clone();
    rewritten.set_ip_host(ip).map_err(|_| {
        IncusError::Other("Host URL resolved to an invalid address".to_string())
    })?;
    let rewritten_url = rewritten.to_string();
    let rewritten_url = rewritten_url
        .strip_suffix('/')
        .map(|s| s.to_string())
        .unwrap_or(rewritten_url);

    Ok(ResolvedIncusTarget {
        url: rewritten_url,
        servername: if is_ip(&hostname) {
            None
        } else {
            Some(hostname)
        },
        address,
    })
}

/// Mirrors `assertAllowedHostUrl`.
pub async fn assert_allowed_host_url(
    input: &str,
    is_admin: bool,
) -> Result<(), IncusError> {
    resolve_incus_target(input, is_admin).await.map(|_| ())
}

/// Mirrors `trustFromEnvironment`: INCUS_CA_PATH (absolute server-managed path)
/// or nothing.
pub fn trust_ca_path_from_environment() -> Result<Option<String>, IncusError> {
    let ca_path = std::env::var("INCUS_CA_PATH")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if let Some(path) = ca_path {
        if !std::path::Path::new(&path).is_absolute() {
            return Err(IncusError::Other(
                "INCUS_CA_PATH must be an absolute server-managed path".to_string(),
            ));
        }
        return Ok(Some(path));
    }
    Ok(None)
}

/// Mirrors `captureIncusServerCertificate`: connect with verification disabled
/// and return the presented certificate PEM plus its sha256 pin. The TS server
/// opens a raw TLS socket; the Rust port completes an HTTPS request instead
/// (the handshake, which is the part that matters, is identical) and reads the
/// peer certificate from reqwest's TlsInfo response extension.
pub async fn capture_incus_server_certificate(
    input: &str,
    allow_private_network: bool,
) -> Result<
    (
        String,
        String,
        ResolvedIncusTarget,
    ),
    IncusError,
> {
    let target = resolve_incus_target(input, allow_private_network).await?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| IncusError::Other(format!("TLS probe failed: {e}")))?;

    let url = format!("{}/1.0", target.url);
    let response = client
        .get(&url)
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                IncusError::Other(
                    "Timed out while capturing the Incus server certificate".to_string(),
                )
            } else {
                IncusError::Other(format!("{}", e))
            }
        })?;

    let der = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate().map(|d| d.to_vec()))
        .ok_or_else(|| {
            IncusError::Other("Incus did not present a server certificate".to_string())
        })?;

    let certificate = der_to_pem(&der);
    let fingerprint = der_fingerprint(&der);
    Ok((certificate, fingerprint, target))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Same self-signed test certificate as lib/incus/incus-tls.test.ts
    // (SAN: localhost only, CN: incus-test).
    const CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUbG4wPtA5lVld1pWgfOCOjR+dK3swDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKaW5jdXMtdGVzdDAeFw0yNjA5MTIxMTQ2MDBaFw0zNjA5
MDkxMTQ2MDBaMBUxEzARBgNVBAMMCmluY3VzLXRlc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCzE55lb0+c4NGQj0aWSoMq9A/m6VznVbdgbECxmAXl
Ue+wmcULUljv6k5ZkHF0GulTMX4+zNHKtvaGfT6jECxXKRiug7wxUyzZh6JpJJK0
Aw85cNL8/IYI/wXQofPfEZJ1bUPSZ2FRo3DvAh+nXAtP8hcaPgFAX0egzjxOrzje
W4QC3k6NRAhdwTJfRCq1VCVrfiUuAFENA/+C23qN5HsTDdVoYt0QrUp1qUYzQPyc
HLU1nz3Pkh0CLYSMeTnrVWoBX3gxrIuj3/tywiI+mRvmJOOUkwVsjUcm6XSAiSR6
O4ptz9tkCYLYIKuciQxIqUx2aXIh7sOaWKx/04+wTqKrAgMBAAGjaTBnMB0GA1Ud
DgQWBBQUf4W4x7iUu/Jrov0H+NOBSzFsCjAfBgNVHSMEGDAWgBQUf4W4x7iUu/Jr
ov0H+NOBSzFsCjAPBgNVHRMBAf8EBTADAQH/MBQGA1UdEQQNMAuCCWxvY2FsaG9z
dDANBgkqhkiG9w0BAQsFAAOCAQEAUu0Dh5Aklk63rKfGTJsmyIaemUZMCeoO/HCc
e8+SiSzadDoMjdqOrrU7drOhgwwy2CHUDkITo6CxlICwmBPph6JKC5mhat/jd7d1
F9tsrSyq8yVuLFFKe5cxWmULfjt2fkqWukRGpvBzlOxJmyUO897RsS+uXJPiVJdC
fmG7Yr2X/pODxP1eofOPlRzJ6++fZYUtcKGqG2IDxu7QjRnZMKxvMs5D7TEuyYd2
25efYhOB6S28lSvyJq0Avzc8syQvyLu4cJ6T//gKbKDSQYeMhYXy8213AxhX7uBl
Sn11mwPdzEspwCNivdob4/JpR5QqpYw/ZAIiVXec9xKy5OroCA==
-----END CERTIFICATE-----";

    #[test]
    fn rejects_ipv4_mapped_private_ipv6_and_special_ranges() {
        for address in [
            "::ffff:127.0.0.1",
            "::ffff:0a00:0001",
            "::ffff:c0a8:0101",
            "64:ff9b::7f00:1",
            "2001:db8::1",
            "100.64.0.1",
            "192.0.2.1",
        ] {
            assert!(!is_public_host_address(address), "{address}");
        }
        assert!(is_public_host_address("8.8.8.8"));
        assert!(is_public_host_address("2606:4700:4700::1111"));
    }

    #[tokio::test]
    async fn rejects_rebinding_answers_when_any_resolved_address_is_private() {
        let resolver = |_host: String, _port: u16| async move {
            Ok(vec!["8.8.8.8".to_string(), "127.0.0.1".to_string()])
        };
        let result = resolve_incus_target_with("https://host.example:8443", false, resolver).await;
        let message = format!("{}", result.expect_err("must reject rebinding answers"));
        assert!(message.contains("publicly routable"), "{message}");
    }

    #[tokio::test]
    async fn resolves_once_and_rewrites_the_connection_url_to_the_pinned_address() {
        let resolver = |_host: String, _port: u16| async move {
            Ok(vec!["8.8.8.8".to_string()])
        };
        let target = resolve_incus_target_with("https://host.example:8443", false, resolver)
            .await
            .expect("target resolves");
        assert_eq!(target.url, "https://8.8.8.8:8443");
        assert_eq!(target.servername.as_deref(), Some("host.example"));
    }

    #[test]
    fn normalizes_certificates_and_produces_stable_sha256_pins() {
        let normalized = normalize_certificate_pem(CERTIFICATE).expect("certificate parses");
        assert!(normalized.starts_with("-----BEGIN CERTIFICATE-----"));
        let fingerprint = certificate_fingerprint(&normalized).expect("fingerprint");
        assert_eq!(fingerprint.len(), 64);
        assert!(
            fingerprint.bytes().all(|b| b.is_ascii_hexdigit()
                && !b.is_ascii_uppercase()),
            "fingerprint must be lowercase hex"
        );
    }

    #[test]
    fn accepts_a_pinned_peer_certificate_even_when_its_hostname_does_not_match_its_san() {
        let fingerprint = certificate_fingerprint(CERTIFICATE).expect("fingerprint");
        let options = build_incus_tls_connect_options(&IncusTlsTrust {
            ca_pem: Some(CERTIFICATE.to_string()),
            fingerprint: Some(fingerprint.clone()),
        })
        .expect("trust builds");
        assert_eq!(options.pinned_fingerprint.as_deref(), Some(fingerprint.as_str()));

        // Building trust with a mismatching pin must fail exactly like the TS
        // assertCertificateMatchesFingerprint.
        let wrong = build_incus_tls_connect_options(&IncusTlsTrust {
            ca_pem: Some(CERTIFICATE.to_string()),
            fingerprint: Some("0".repeat(64)),
        });
        assert!(wrong.is_err());
    }
}
