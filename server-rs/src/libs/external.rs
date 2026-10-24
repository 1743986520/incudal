//! External side effects used by the auth port:
//! - Cloudflare Turnstile verification  — REAL (lib/turnstile.ts verifyTurnstileToken)
//! - GeoIP lookup via ip-api.com        — REAL (lib/geoip.ts getGeoIpInfo)
//! - Email sending                      — STUB (SMTP stack not ported; see TODOs)
//! - Telegram/other channel push        — STUB (lib/notifier.ts external fan-out)
//!
//! The stubs return success exactly where the TS callers treat a send failure
//! as non-fatal or gate the next step on `result.success`; every stub logs a
//! `tracing::warn` with the TS file/line it needs to be ported from.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use serde::Deserialize;

static HTTP: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

// ===========================================================================
// Turnstile (port of lib/turnstile.ts verifyTurnstileToken)
// ===========================================================================

#[derive(Debug, Deserialize)]
struct TurnstileVerifyResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

/// POSTs to https://challenges.cloudflare.com/turnstile/v0/siteverify.
/// Ok(()) on success; Err(message) mirrors the TS `{ success: false, error }`
/// string ("error-codes" joined, "Verification failed", or the transport error
/// prefixed with "Turnstile verification error: ").
pub async fn verify_turnstile_token(
    token: &str,
    secret_key: &str,
    remote_ip: Option<&str>,
) -> Result<(), String> {
    let mut form: Vec<(&str, &str)> = vec![("secret", secret_key), ("response", token)];
    if let Some(ip) = remote_ip {
        form.push(("remoteip", ip));
    }

    let result = HTTP
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&form)
        .send()
        .await;
    let response = match result {
        Ok(r) => r,
        Err(err) => return Err(format!("Turnstile verification error: {err}")),
    };

    match response.json::<TurnstileVerifyResponse>().await {
        Ok(parsed) => {
            if parsed.success {
                return Ok(());
            }
            let codes = parsed.error_codes.unwrap_or_default();
            if codes.is_empty() {
                Err("Verification failed".to_string())
            } else {
                Err(codes.join(", "))
            }
        }
        Err(err) => Err(format!("Turnstile verification error: {err}")),
    }
}

// ===========================================================================
// GeoIP (port of lib/geoip.ts getGeoIpInfo)
// ===========================================================================

#[derive(Debug, Clone)]
pub struct GeoIpInfo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub timezone: Option<String>,
}

fn empty_geo_info() -> GeoIpInfo {
    GeoIpInfo {
        country: None,
        region: None,
        city: None,
        isp: None,
        timezone: None,
    }
}

/// 24h cache (lib/geoip.ts CACHE_TTL).
const GEO_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const GEO_CACHE_MAX_ENTRIES: usize = 1000;
/// ip-api.com free tier allows 45 req/min; the TS queue targets 40/min.
const GEO_RATE_LIMIT: usize = 40;
const GEO_RATE_WINDOW: Duration = Duration::from_secs(60);

static GEO_CACHE: Lazy<tokio::sync::Mutex<HashMap<String, (GeoIpInfo, Instant)>>> =
    Lazy::new(|| tokio::sync::Mutex::new(HashMap::new()));
static GEO_RATE_TIMESTAMPS: Lazy<tokio::sync::Mutex<Vec<Instant>>> =
    Lazy::new(|| tokio::sync::Mutex::new(Vec::new()));

#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: Option<String>,
    #[serde(rename = "country")]
    country: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    timezone: Option<String>,
}

/// Mirrors getGeoIpInfo(): local IPs short-circuit, results cached 24h, calls
/// rate-limited to 40/min. This variant gates with a sleep instead of the TS
/// request queue (same effect for the fire-and-forget login-record callers:
/// they never block the HTTP response). Errors return an empty result exactly
/// like the TS catch path.
pub async fn get_geo_ip_info(ip: &str) -> GeoIpInfo {
    if is_local_ip(ip) {
        return empty_geo_info();
    }

    // Cache hit returns immediately without entering the rate gate.
    {
        let cache = GEO_CACHE.lock().await;
        if let Some((info, at)) = cache.get(ip) {
            if at.elapsed() < GEO_CACHE_TTL {
                return info.clone();
            }
        }
    }

    rate_gate().await;

    let info = fetch_geo_ip_info(ip).await;
    let mut cache = GEO_CACHE.lock().await;
    if cache.len() >= GEO_CACHE_MAX_ENTRIES {
        cache.retain(|_, (_, at)| at.elapsed() < GEO_CACHE_TTL);
    }
    cache.insert(ip.to_string(), (info.clone(), Instant::now()));
    info
}

/// Blocks until the request budget allows one more call, then consumes a slot.
async fn rate_gate() {
    loop {
        let wait: Option<Duration> = {
            let mut ts = GEO_RATE_TIMESTAMPS.lock().await;
            ts.retain(|t| t.elapsed() < GEO_RATE_WINDOW);
            if ts.len() >= GEO_RATE_LIMIT {
                let elapsed = ts[0].elapsed();
                Some((GEO_RATE_WINDOW - elapsed) + Duration::from_millis(100))
            } else {
                ts.push(Instant::now());
                None
            }
        };
        match wait {
            Some(d) => tokio::time::sleep(d).await,
            None => return,
        }
    }
}

async fn fetch_geo_ip_info(ip: &str) -> GeoIpInfo {
    let url = format!(
        "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,timezone,query"
    );
    let response = match HTTP.get(&url).header("Accept", "application/json").send().await {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!("[GeoIP] Error querying IP {ip}: {err}");
            return empty_geo_info();
        }
    };
    if !response.status().is_success() {
        tracing::warn!("[GeoIP] HTTP error: {}", response.status());
        return empty_geo_info();
    }
    let data: IpApiResponse = match response.json().await {
        Ok(d) => d,
        Err(err) => {
            tracing::warn!("[GeoIP] Error parsing response for IP {ip}: {err}");
            return empty_geo_info();
        }
    };
    if data.status.as_deref() != Some("success") {
        tracing::warn!(
            "[GeoIP] Query failed for {ip}: {}",
            data.status.unwrap_or_else(|| "unknown".into())
        );
        return empty_geo_info();
    }
    GeoIpInfo {
        country: data.country,
        region: data.region_name,
        city: data.city,
        isp: data.isp,
        timezone: data.timezone,
    }
}

/// Mirrors geoip.ts isLocalIp (string prefix checks kept verbatim).
fn is_local_ip(ip: &str) -> bool {
    if ip == "127.0.0.1" || ip == "localhost" || ip.starts_with("192.168.") || ip.starts_with("10.")
    {
        return true;
    }
    if ip.starts_with("172.") && is_private_172(ip) {
        return true;
    }
    let lower = ip.to_lowercase();
    if ip == "::1" || lower.starts_with("fe80:") || lower.starts_with("fc") || lower.starts_with("fd")
    {
        return true;
    }
    false
}

fn is_private_172(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    match parts[1].parse::<u32>() {
        Ok(second) => (16..=31).contains(&second),
        Err(_) => false,
    }
}

// ===========================================================================
// Email sending — STUBS
// ===========================================================================

/// TODO: real SMTP delivery. Port of lib/mailer.ts sendVerificationEmail
/// (server/src/lib/mailer.ts:559) — nodemailer transport built from the
/// smtp_* system configs. Returns success so the calling routes keep their
/// TS contract (failure would map to 500 EMAIL_SEND_FAILED).
pub async fn send_verification_email(email: &str, code: &str, expires_in_minutes: i64, purpose: &str) -> bool {
    tracing::warn!(
        "[email stub] sendVerificationEmail not implemented in the Rust server \
         (TODO server/src/lib/mailer.ts:559): to={email} purpose={purpose} code={code} ttl={expires_in_minutes}m"
    );
    let _ = (code, expires_in_minutes);
    true
}

/// TODO: port of lib/mailer.ts sendLoginAlertEmail (server/src/lib/mailer.ts:763).
pub async fn send_login_alert_email(
    email: &str,
    username: &str,
    ip: &str,
    user_agent: &str,
    is_new_ip: bool,
    is_new_device: bool,
) -> bool {
    tracing::warn!(
        "[email stub] sendLoginAlertEmail not implemented in the Rust server \
         (TODO server/src/lib/mailer.ts:763): to={email} user={username} ip={ip} \
         newIp={is_new_ip} newDevice={is_new_device} ua={user_agent}"
    );
    true
}

/// TODO: port of lib/mailer.ts sendPasswordResetEmail (server/src/lib/mailer.ts:919).
/// The caller treats `false` as "abort the password change" (502), so this stub
/// returns success to preserve the TS flow with SMTP configured.
pub async fn send_password_reset_email(email: &str, username: &str, new_password: &str, two_factor_disabled: bool) -> bool {
    tracing::warn!(
        "[email stub] sendPasswordResetEmail not implemented in the Rust server \
         (TODO server/src/lib/mailer.ts:919): to={email} user={username} \
         twoFactorDisabled={two_factor_disabled} newPassword={new_password}"
    );
    true
}

/// TODO: port of lib/mailer.ts sendFreeSiteRegisterGiftEmail
/// (server/src/lib/mailer.ts:1390). Non-fatal in TS.
pub async fn send_free_site_register_gift_email(email: &str, username: &str) -> bool {
    tracing::warn!(
        "[email stub] sendFreeSiteRegisterGiftEmail not implemented in the Rust server \
         (TODO server/src/lib/mailer.ts:1390): to={email} user={username}"
    );
    true
}

/// TODO: Telegram/external-channel push. Port of lib/notifier.ts sendTelegram
/// / sendDiscord / webhook fan-out (server/src/lib/notifier.ts). The inbox
/// message part of sendNotification is ported in routes/auth.rs (real DB
/// insert); only the external channel delivery is stubbed here. Non-fatal.
pub async fn push_external_notification(user_id: i32, event_type: &str, title: &str) {
    tracing::warn!(
        "[notifier stub] external channel push (Telegram/Discord/webhook/email) not \
         implemented in the Rust server (TODO server/src/lib/notifier.ts): \
         user={user_id} event={event_type} title={title}"
    );
}
