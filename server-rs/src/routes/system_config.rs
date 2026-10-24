//! 系统配置路由 — port of server/src/routes/system-config.ts (mounted at
//! /api/system-config).
//!
//! Endpoint map (TS decorator -> Rust extractor):
//! - GET  /public                  public, rateLimit 60/min (rate_limit.rs)
//! - POST /seo/indexnow/submit     authenticateAdmin -> AdminAuth
//! - GET  /                        authenticateAdmin -> AdminAuth
//! - GET  /default-quota           authenticateAdmin -> AdminAuth
//! - PUT  /                        authenticateAdmin -> AdminAuth
//! - POST /smtp/test               authenticateAdmin -> AdminAuth
//! - POST /smtp/send-test          authenticateAdmin -> AdminAuth
//!
//! Reported deviations:
//! - lib/config-cache.ts (PERF001 5-minute in-memory cache) is not ported:
//!   every read goes to PostgreSQL. Values and update visibility are
//!   identical; only repeated-read latency differs.
//! - clearTransporterCache / nodemailer are not ported: SMTP config updates
//!   skip the transporter-cache reset (no-op), and /smtp/test + /smtp/send-test
//!   reproduce the TS "configuration incomplete" failure paths exactly but
//!   report a failure instead of dialing SMTP when a full config exists.
//! - logAdminAction is ported as the logs-table row it produces
//!   (module 'admin', content built from details; both call sites here log an
//!   empty content string, matching the TS contentParts construction).

use std::collections::HashMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};

use crate::auth::AdminAuth;
use crate::error::{code, ApiError};
use crate::libs::crypto;
use crate::routes::users::create_log;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/public", get(public_config))
        .route("/seo/indexnow/submit", post(seo_indexnow_submit))
        .route("/", get(list_configs).put(update_configs))
        .route("/default-quota", get(default_quota))
        .route("/smtp/test", post(smtp_test))
        .route("/smtp/send-test", post(smtp_send_test))
}

// ===========================================================================
// constants (db/system-config.ts + routes/system-config.ts)
// ===========================================================================

const MASKED_SECRET_PLACEHOLDER: &str = "********";

const SENSITIVE_CONFIG_KEYS: &[&str] = &[
    "smtp_password",
    "turnstile_secret_key",
    "ticket_image_lsky_token",
    "telegram_bot_token",
    "telegram_webhook_secret",
];

const DEFAULT_QUOTA_HOST: i64 = 0;
const DEFAULT_QUOTA_FRIEND: i64 = 0;
const DEFAULT_QUOTA_PACKAGE: i64 = 0;

const MAX_REGISTER_GIFT_BALANCE: f64 = 99999999.99;
const MAX_REGISTER_GIFT_POINTS: f64 = 2147483647.0;
const MAX_TRANSFER_FEE: f64 = 100.0;

static TELEGRAM_WEBHOOK_SECRET_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,256}$").expect("valid regex"));
static EMAIL_DOMAIN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        .expect("valid regex")
});
static SEO_TRACKING_ID_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,128}$").expect("valid regex"));
static SEO_INDEXNOW_KEY_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,256}$").expect("valid regex"));
static DECIMAL_MONEY_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d+(?:\.\d{1,2})?$").expect("valid regex"));
static LOC_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<loc>\s*([^<]+?)\s*</loc>").expect("valid regex"));
static EMAIL_FORMAT_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\S+@\S+\.\S+$").expect("valid regex"));

/// lib/email-domain.ts DEFAULT_ALLOWED_DOMAINS.
const DEFAULT_ALLOWED_DOMAINS: &[&str] = &[
    // Gmail
    "gmail.com",
    // Outlook/Microsoft
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    // iCloud/Apple
    "icloud.com",
    "me.com",
    "mac.com",
    // Yahoo
    "yahoo.com",
    // Zoho
    "zoho.com",
    // Proton
    "proton.me",
    "pm.me",
    "protonmail.com",
    "protonmail.ch",
    // Fastmail
    "fastmail.com",
    // Tuta (Tutanota)
    "tuta.com",
    "tutanota.com",
    "tuta.io",
    "keemail.me",
    // Posteo
    "posteo.de",
    "posteo.net",
    // Disroot
    "disroot.org",
    // Riseup
    "riseup.net",
];

// ===========================================================================
// helpers
// ===========================================================================

/// JS `Date` fields serialize as ISO strings through Fastify's JSON encoder.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// JS Math.round: halves round toward +Infinity.
fn js_round(v: f64) -> f64 {
    (v + 0.5).floor()
}

/// JS String(number) (integers print without ".0").
fn js_num_string(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    format!("{v}")
}

/// JSON number the way JS would serialize it (integral f64 -> integer node).
fn js_json_num(v: f64) -> Value {
    if v.is_finite() && v.fract() == 0.0 && v.abs() <= 9.007_199_254_740_992e15 {
        json!(v as i64)
    } else {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

/// JS string length (UTF-16 code units).
fn js_len(s: &str) -> usize {
    s.chars().map(|c| c.len_utf16()).sum()
}

/// JS Number(string) for config values ('' -> 0, invalid -> NaN).
fn js_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        0.0
    } else {
        t.parse::<f64>().unwrap_or(f64::NAN)
    }
}

/// Fastify schema validation failure -> 400 { error, code: VALIDATION_ERROR }.
fn validation_error(messages: Vec<String>) -> ApiError {
    let first = messages[0].clone();
    let mut err = ApiError::with_message(code::VALIDATION_ERROR, StatusCode::BAD_REQUEST, first);
    if messages.len() > 1 {
        err = err.with_details(messages.join(", "));
    }
    err
}

fn is_sensitive_key(key: &str) -> bool {
    SENSITIVE_CONFIG_KEYS.contains(&key)
}

// ---- URL validation (lib/external-url.ts) ----

fn parse_url(value: &str) -> Option<reqwest::Url> {
    // JS new URL() rejects control characters in the WHATWG parser anyway;
    // explicit check keeps parity for the C0 range.
    if value
        .chars()
        .any(|c| c <= '\u{1f}' || c == '\u{7f}')
    {
        return None;
    }
    reqwest::Url::parse(value.trim()).ok()
}

fn is_http_url(value: &str) -> bool {
    match parse_url(value) {
        Some(url) => matches!(url.scheme(), "http" | "https"),
        None => false,
    }
}

fn is_http_image_url(value: &str) -> bool {
    is_http_url(value)
}

/// lib/external-url.ts isValidSeoSiteUrl.
fn is_valid_seo_site_url(value: &str) -> bool {
    if !is_http_url(value) {
        return false;
    }
    match parse_url(value) {
        Some(url) => {
            url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none()
        }
        None => false,
    }
}

const SEO_PATH_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!$&'()*+,;=:@%/-";

/// routes/system-config.ts seoPathPattern:
/// ^\/(?!\/|api(?:\/|$))[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,199}$
/// (hand-rolled because the negative lookahead is outside rust-regex).
fn is_valid_seo_path(value: &str, allow_empty: bool) -> bool {
    if allow_empty && value.is_empty() {
        return true;
    }
    let Some(rest) = value.strip_prefix('/') else {
        return false;
    };
    if rest.starts_with('/') {
        return false;
    }
    if rest == "api" || rest.starts_with("api/") {
        return false;
    }
    let chars: Vec<char> = rest.chars().collect();
    if chars.is_empty() || chars.len() > 199 {
        return false;
    }
    chars.iter().all(|c| SEO_PATH_CHARS.contains(*c))
}

/// lib/external-url.ts validateOptionalTelegramUrl: '' / null clear the value;
/// otherwise an absolute https://t.me/<path> URL is required.
fn validate_optional_telegram_url(value: &str) -> Result<Option<String>, String> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    let url = match parse_url(value) {
        Some(u) => u,
        None => return Err("Telegram group link format is invalid".to_string()),
    };
    if url.scheme() != "https" || url.host_str().map(|h| h.to_lowercase()) != Some("t.me".to_string()) || url.path().len() <= 1 {
        return Err("Telegram group link must use an https://t.me/<path> URL".to_string());
    }
    Ok(Some(url.to_string()))
}

/// lib/external-url.ts getSafeTelegramUrl.
fn get_safe_telegram_url(value: Option<&str>) -> Value {
    match value {
        Some(v) => match validate_optional_telegram_url(v) {
            Ok(Some(url)) => json!(url),
            _ => Value::Null,
        },
        None => Value::Null,
    }
}

/// lib/registration-role.ts parseAdminRegistrationEmailSuffixes.
fn parse_admin_registration_email_suffixes(value: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in value.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let item = item.trim().to_lowercase();
        // filter(item => item.length > 1 && !item.slice(1).includes('@'))
        if item.chars().count() <= 1 || item[1..].contains('@') {
            continue;
        }
        let normalized = if item.starts_with('@') {
            item
        } else {
            format!("@{item}")
        };
        if !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    out
}

// ===========================================================================
// db helpers (port of db/system-config.ts; the PERF001 cache is a no-op)
// ===========================================================================

async fn get_system_config_raw(state: &SharedAppState, key: &str) -> Result<Option<String>, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT value FROM system_configs WHERE key = $1")
            .bind(key)
            .fetch_optional(&state.db)
            .await?;
    // TS: `if (!config?.value) return config?.value ?? null` — an existing row
    // with an empty value returns Some("").
    Ok(row.and_then(|(v,)| v))
}

/// getSystemConfig(key, decrypt=true): sensitive values are decrypted;
/// decryption failure returns None (TS logs and returns null).
async fn get_system_config(state: &SharedAppState, key: &str) -> Result<Option<String>, ApiError> {
    let value = get_system_config_raw(state, key).await?;
    let Some(value) = value else {
        return Ok(None);
    };
    if is_sensitive_key(key) && value.contains(':') {
        return match crypto::decrypt_sensitive_data(&state.config.encryption_key, &value) {
            Ok(plain) => Ok(Some(plain)),
            Err(_) => Ok(None),
        };
    }
    Ok(Some(value))
}

async fn get_system_config_boolean(
    state: &SharedAppState,
    key: &str,
    default_value: bool,
) -> Result<bool, ApiError> {
    match get_system_config(state, key).await? {
        None => Ok(default_value),
        Some(v) => Ok(v == "true" || v == "1"),
    }
}

async fn get_system_config_number(
    state: &SharedAppState,
    key: &str,
    default_value: i64,
) -> Result<i64, ApiError> {
    match get_system_config(state, key).await? {
        None => Ok(default_value),
        Some(v) => Ok(js_parse_int(&v).unwrap_or(default_value)),
    }
}

async fn get_system_config_float(
    state: &SharedAppState,
    key: &str,
    default_value: f64,
) -> Result<f64, ApiError> {
    match get_system_config(state, key).await? {
        None => Ok(default_value),
        Some(v) => Ok(js_parse_float(&v).filter(|n| n.is_finite()).unwrap_or(default_value)),
    }
}

/// getSystemConfigValueWithUpdatedAt — no decryption (popup keys).
struct ConfigWithUpdatedAt {
    value: Option<String>,
    updated_at: Option<String>,
}

async fn get_system_config_with_updated_at(
    state: &SharedAppState,
    key: &str,
) -> Result<ConfigWithUpdatedAt, ApiError> {
    let row: Option<(Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT value, updated_at FROM system_configs WHERE key = $1",
    )
    .bind(key)
    .fetch_optional(&state.db)
    .await?;
    Ok(match row {
        None => ConfigWithUpdatedAt {
            value: None,
            updated_at: None,
        },
        Some((value, updated_at)) => ConfigWithUpdatedAt {
            value,
            updated_at: updated_at.map(iso),
        },
    })
}

/// JS parseInt base-10: optional sign + leading digits, else NaN.
fn js_parse_int(raw: &str) -> Option<i64> {
    let s = raw.trim_start();
    let bytes = s.as_bytes();
    let mut idx = 0usize;
    let mut sign = 1i64;
    if idx < bytes.len() && (bytes[idx] == b'+' || bytes[idx] == b'-') {
        if bytes[idx] == b'-' {
            sign = -1;
        }
        idx += 1;
    }
    let start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == start {
        return None;
    }
    s[start..idx].parse::<i64>().ok().map(|v| sign * v)
}

/// JS parseFloat: leading float prefix, else NaN.
fn js_parse_float(raw: &str) -> Option<f64> {
    let s = raw.trim_start();
    let bytes = s.as_bytes();
    let mut end = 0usize;
    if end < bytes.len() && (bytes[end] == b'+' || bytes[end] == b'-') {
        end += 1;
    }
    let mut seen_digit = false;
    let mut seen_dot = false;
    let mut seen_exp = false;
    let mut exp_digits = 0usize;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_digit() {
            seen_digit = true;
            if seen_exp {
                exp_digits += 1;
            }
            end += 1;
        } else if b == b'.' && !seen_dot && !seen_exp {
            seen_dot = true;
            end += 1;
        } else if (b == b'e' || b == b'E') && seen_digit && !seen_exp {
            seen_exp = true;
            end += 1;
            if end < bytes.len() && (bytes[end] == b'+' || bytes[end] == b'-') {
                end += 1;
            }
        } else {
            break;
        }
    }
    if !seen_digit {
        return None;
    }
    if seen_exp && exp_digits == 0 {
        // "1e+" without exponent digits is not consumed by parseFloat.
        let trimmed = &s[..end];
        let cut = trimmed.trim_end_matches(|c: char| c == '+' || c == '-' || c == 'e' || c == 'E');
        return cut.parse::<f64>().ok();
    }
    s[..end].parse::<f64>().ok()
}

// ===========================================================================
// GET /public — 获取公开的系统配置 (无需登录)
// ===========================================================================

async fn public_config(State(state): State<SharedAppState>) -> Result<Json<Value>, ApiError> {
    let registration_enabled = get_system_config_boolean(&state, "registration_enabled", true).await?;
    let require_invite_code = get_system_config_boolean(&state, "require_invite_code", true).await?;
    let ticket_enabled = get_system_config_boolean(&state, "ticket_enabled", true).await?;
    let free_site_mode = get_system_config_boolean(&state, "free_site_mode", false).await?;
    let aff_rebate_enabled = get_system_config_boolean(&state, "aff_rebate_enabled", false).await?;
    let turnstile_enabled = get_system_config_boolean(&state, "turnstile_enabled", false).await?;
    let turnstile_site_key = get_system_config(&state, "turnstile_site_key").await?;
    let avatar_api_base = get_system_config(&state, "avatar_api_base").await?;
    let smtp_enabled = is_smtp_enabled(&state).await?;
    let email_domain_whitelist_enabled =
        get_system_config_boolean(&state, "email_domain_whitelist_enabled", false).await?;
    let email_allowed_domains = get_system_config(&state, "email_allowed_domains").await?;
    let transfer_fee = get_system_config_float(&state, "transfer_fee", 0.0).await?;
    let balance_transfer_enabled =
        get_system_config_boolean(&state, "balance_transfer_enabled", false).await?;
    let balance_transfer_fee = get_system_config_float(&state, "balance_transfer_fee", 0.0).await?;
    let footer_contact_email = get_system_config(&state, "footer_contact_email").await?;
    let footer_telegram_link = get_system_config(&state, "footer_telegram_link").await?;
    let hosting_market_entry_enabled =
        get_system_config_boolean(&state, "hosting_market_entry_enabled", true).await?;
    let hosting_notice = get_system_config(&state, "hosting_notice").await?;
    let brand_name = get_system_config(&state, "brand_name").await?;
    let brand_subtitle = get_system_config(&state, "brand_subtitle").await?;
    let brand_logo_url = get_system_config(&state, "brand_logo_url").await?;
    let popup_announcement_config =
        get_system_config_with_updated_at(&state, "popup_announcement").await?;
    let popup_promo_image_url_config =
        get_system_config_with_updated_at(&state, "popup_promo_image_url").await?;
    let popup_promo_package_id_config =
        get_system_config_with_updated_at(&state, "popup_promo_package_id").await?;

    let seo_site_url = get_system_config(&state, "seo_site_url").await?;
    let seo_sitemap_path = get_system_config(&state, "seo_sitemap_path").await?;
    let seo_verification_path = get_system_config(&state, "seo_verification_path").await?;
    let seo_indexnow_endpoint = get_system_config(&state, "seo_indexnow_endpoint").await?;
    let seo_indexnow_key = get_system_config(&state, "seo_indexnow_key").await?;
    let seo_tracking_enabled = get_system_config_boolean(&state, "seo_tracking_enabled", false).await?;
    let seo_tracking_script_url = get_system_config(&state, "seo_tracking_script_url").await?;
    let seo_tracking_id = get_system_config(&state, "seo_tracking_id").await?;

    // 解析允许的邮箱域名列表
    let allowed_domains: Option<Vec<String>> = if email_domain_whitelist_enabled {
        match email_allowed_domains.as_deref() {
            Some(domains) if !domains.is_empty() => Some(
                domains
                    .split(',')
                    .map(|d| d.trim().to_lowercase())
                    .filter(|d| !d.is_empty())
                    .collect(),
            ),
            _ => Some(DEFAULT_ALLOWED_DOMAINS.iter().map(|s| s.to_string()).collect()),
        }
    } else {
        None
    };

    // 图片推广弹窗套餐
    let popup_announcement_raw = popup_announcement_config.value.clone();
    let popup_announcement_trim = popup_announcement_raw.as_deref().map(str::trim).unwrap_or("");
    let popup_promo_image_url_raw = popup_promo_image_url_config.value.clone();
    let popup_promo_image_url_trim = popup_promo_image_url_raw
        .as_deref()
        .map(str::trim)
        .unwrap_or("");
    let popup_promo_package_id_trim = popup_promo_package_id_config
        .value
        .as_deref()
        .map(str::trim)
        .unwrap_or("");

    let mut popup_promo_package: Option<Value> = None;
    if !popup_promo_image_url_trim.is_empty()
        && is_http_image_url(popup_promo_image_url_trim)
        && !popup_promo_package_id_trim.is_empty()
    {
        let package_id = js_number(popup_promo_package_id_trim);
        if package_id.is_finite() && package_id.fract() == 0.0 && package_id > 0.0 {
            let pkg = query_promo_package(&state, package_id as i64).await?;
            if let Some(pkg) = pkg {
                popup_promo_package = Some(pkg);
            }
        }
    }

    // popupPromoUpdatedAt: latest (lexicographic) of the two updatedAt values.
    let popup_promo_updated_at: Value = if popup_promo_package.is_some() {
        let mut stamps: Vec<&String> = [&popup_promo_image_url_config, &popup_promo_package_id_config]
            .iter()
            .filter_map(|c| c.updated_at.as_ref())
            .collect();
        stamps.sort();
        match stamps.pop() {
            Some(v) => json!(v),
            None => Value::Null,
        }
    } else {
        Value::Null
    };

    // Owned JSON values for the response (avoids partial moves).
    let has_popup_announcement = !popup_announcement_trim.is_empty();
    let popup_announcement_json: Value = if has_popup_announcement {
        json!(popup_announcement_raw)
    } else {
        Value::Null
    };
    let popup_announcement_updated_json: Value = if has_popup_announcement {
        match popup_announcement_config.updated_at.clone() {
            Some(v) => json!(v),
            None => Value::Null,
        }
    } else {
        Value::Null
    };
    let popup_promo_image_json: Value = if popup_promo_package.is_some() {
        json!(popup_promo_image_url_raw)
    } else {
        Value::Null
    };

    // TS `value || default`: empty strings fall back to the defaults.
    let non_empty = |v: Option<String>| v.filter(|s| !s.is_empty());

    Ok(Json(json!({
        "registrationEnabled": registration_enabled,
        "requireInviteCode": require_invite_code,
        "ticketEnabled": ticket_enabled,
        "freeSiteMode": free_site_mode,
        "affRebateEnabled": aff_rebate_enabled,
        "turnstileEnabled": turnstile_enabled,
        "turnstileSiteKey": if turnstile_enabled { turnstile_site_key } else { None::<String> },
        "avatarApiBase": non_empty(avatar_api_base).unwrap_or_else(|| "https://api.dicebear.com/9.x".to_string()),
        "emailVerificationEnabled": smtp_enabled,
        "emailDomainWhitelistEnabled": email_domain_whitelist_enabled,
        "allowedEmailDomains": allowed_domains,
        "transferFee": js_json_num(transfer_fee),
        "balanceTransferEnabled": balance_transfer_enabled,
        "balanceTransferFee": js_json_num(balance_transfer_fee),
        "footerContactEmail": footer_contact_email,
        "footerTelegramLink": get_safe_telegram_url(footer_telegram_link.as_deref()),
        "hostingMarketEntryEnabled": hosting_market_entry_enabled,
        "hostingNotice": hosting_notice,
        "brandName": non_empty(brand_name).unwrap_or_else(|| "Incudal".to_string()),
        "brandSubtitle": non_empty(brand_subtitle).unwrap_or_else(|| "基于 Incus 的低价 NAT VPS".to_string()),
        "brandLogoUrl": non_empty(brand_logo_url).unwrap_or_else(|| "/incudal_logo.webp".to_string()),
        "seoSiteUrl": non_empty(seo_site_url).unwrap_or_else(|| "https://incudal.di0.uk".to_string()),
        "seoSitemapPath": non_empty(seo_sitemap_path).unwrap_or_else(|| "/sitemap.xml".to_string()),
        "seoVerificationPath": non_empty(seo_verification_path),
        "seoIndexNowEndpoint": non_empty(seo_indexnow_endpoint).unwrap_or_else(|| "https://api.indexnow.org/IndexNow".to_string()),
        "seoIndexNowKey": non_empty(seo_indexnow_key),
        "seoTrackingEnabled": seo_tracking_enabled,
        "seoTrackingScriptUrl": non_empty(seo_tracking_script_url).unwrap_or_else(|| "https://www.googletagmanager.com/gtag/js".to_string()),
        "seoTrackingId": non_empty(seo_tracking_id),
        "popupAnnouncement": popup_announcement_json,
        "popupAnnouncementUpdatedAt": popup_announcement_updated_json,
        "popupPromoImageUrl": popup_promo_image_json,
        "popupPromoPackage": popup_promo_package,
        "popupPromoUpdatedAt": popup_promo_updated_at,
    })))
}

/// The promo package lookup behind popupPromoPackage (prisma.package.findFirst
/// with active + globalShared + up to 3 active plans).
async fn query_promo_package(
    state: &SharedAppState,
    package_id: i64,
) -> Result<Option<Value>, ApiError> {
    #[derive(sqlx::FromRow)]
    struct PkgRow {
        id: i32,
        name: String,
        description: Option<String>,
        owner_role: String,
    }

    let pkg: Option<PkgRow> = sqlx::query_as::<_, PkgRow>(
        "SELECT p.id, p.name, p.description, u.role::text AS owner_role \
         FROM packages p JOIN users u ON u.id = p.user_id \
         WHERE p.id = $1 AND p.active = TRUE AND p.global_shared = TRUE \
         LIMIT 1",
    )
    .bind(package_id as i32)
    .fetch_optional(&state.db)
    .await?;

    let Some(pkg) = pkg else {
        return Ok(None);
    };

    #[derive(sqlx::FromRow)]
    struct PlanRow {
        id: i32,
        name: String,
        description: Option<String>,
        cpu: i32,
        memory: i32,
        disk: i32,
        traffic_limit: i64,
        traffic_billing_mode: String,
        traffic_unit_price: rust_decimal::Decimal,
        billing_mode: String,
        price: rust_decimal::Decimal,
        billing_cycle: i32,
        is_sold_out: bool,
    }

    let plans: Vec<PlanRow> = sqlx::query_as::<_, PlanRow>(
        "SELECT id, name, description, cpu, memory, disk, traffic_limit, \
         traffic_billing_mode::text AS traffic_billing_mode, traffic_unit_price, \
         billing_mode::text AS billing_mode, price, billing_cycle, is_sold_out \
         FROM package_plans WHERE package_id = $1 AND is_active = TRUE \
         ORDER BY is_sold_out ASC, sort_order ASC, id ASC LIMIT 3",
    )
    .bind(pkg.id)
    .fetch_all(&state.db)
    .await?;

    let plan_values: Vec<Value> = plans
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "cpu": p.cpu,
                "memory": p.memory,
                "disk": p.disk,
                "trafficLimit": p.traffic_limit.to_string(),
                "trafficBillingMode": p.traffic_billing_mode,
                "trafficUnitPrice": crate::response::num(p.traffic_unit_price),
                "billingMode": p.billing_mode,
                "price": crate::response::num(p.price),
                "billingCycle": p.billing_cycle,
                "isSoldOut": p.is_sold_out,
            })
        })
        .collect();

    Ok(Some(json!({
        "id": pkg.id,
        "name": pkg.name,
        "description": pkg.description,
        "source": if pkg.owner_role == "admin" { "official" } else { "market" },
        "plans": plan_values,
    })))
}

// ===========================================================================
// POST /seo/indexnow/submit — 管理员提交公开 Sitemap 中的 URL 到 IndexNow
// ===========================================================================

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

async fn seo_indexnow_submit(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
) -> Result<Response, ApiError> {
    let configured_site_url = get_system_config(&state, "seo_site_url")
        .await?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://incudal.di0.uk".to_string());
    let sitemap_path = get_system_config(&state, "seo_sitemap_path")
        .await?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/sitemap.xml".to_string());
    let endpoint = get_system_config(&state, "seo_indexnow_endpoint")
        .await?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://api.indexnow.org/IndexNow".to_string());
    let key = get_system_config(&state, "seo_indexnow_key")
        .await?
        .map(|v| v.trim().to_string())
        .unwrap_or_default();

    if !is_valid_seo_site_url(&configured_site_url)
        || !is_valid_seo_path(&sitemap_path, false)
        || !is_http_url(&endpoint)
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "SEO 站点地址、Sitemap 路径或 IndexNow 地址配置无效",
                "code": code::CONFIG_INVALID_VALUE,
            })),
        )
            .into_response());
    }
    if key.is_empty() || !SEO_INDEXNOW_KEY_PATTERN.is_match(&key) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "请先配置有效的 IndexNow Key",
                "code": code::CONFIG_INVALID_VALUE,
            })),
        )
            .into_response());
    }

    let site_url = configured_site_url
        .trim_end_matches('/')
        .to_string();

    // TS: new URL(sitemapPath, `${siteUrl}/`).
    let (sitemap_url, key_location, host) = {
        let base = reqwest::Url::parse(&format!("{site_url}/"))
            .map_err(|e| ApiError::internal(format!("invalid site url: {e}")))?;
        let sitemap_url = base
            .join(&sitemap_path)
            .map_err(|e| ApiError::internal(format!("invalid sitemap path: {e}")))?;
        let key_location = base
            .join(&format!("/{key}.txt"))
            .map_err(|e| ApiError::internal(format!("invalid key location: {e}")))?;
        let host = reqwest::Url::parse(&site_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default();
        (sitemap_url, key_location, host)
    };

    let sitemap_response = match HTTP_CLIENT.get(sitemap_url.clone()).send().await {
        Ok(r) => r,
        Err(_) => {
            return Ok((
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "IndexNow 提交请求失败",
                    "code": "SEO_INDEXNOW_SUBMIT_FAILED",
                })),
            )
                .into_response());
        }
    };
    if !sitemap_response.status().is_success() {
        return Ok((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": format!("读取 Sitemap 失败（HTTP {}）", sitemap_response.status().as_u16()),
                "code": "SEO_SITEMAP_FETCH_FAILED",
            })),
        )
            .into_response());
    }

    let sitemap_xml = match sitemap_response.text().await {
        Ok(text) => text,
        Err(_) => {
            return Ok((
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "IndexNow 提交请求失败",
                    "code": "SEO_INDEXNOW_SUBMIT_FAILED",
                })),
            )
                .into_response());
        }
    };
    let urls: Vec<String> = LOC_PATTERN
        .captures_iter(&sitemap_xml)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
        .filter(|u| !u.is_empty())
        .take(10_000)
        .collect();

    if urls.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Sitemap 中没有可提交的 URL",
                "code": "SEO_SITEMAP_EMPTY",
            })),
        )
            .into_response());
    }

    let index_now_response = match HTTP_CLIENT
        .post(endpoint)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(
            json!({
                "host": host,
                "key": key,
                "keyLocation": key_location.to_string(),
                "urlList": urls,
            })
            .to_string(),
        )
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return Ok((
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "IndexNow 提交请求失败",
                    "code": "SEO_INDEXNOW_SUBMIT_FAILED",
                })),
            )
                .into_response());
        }
    };

    if !index_now_response.status().is_success() {
        return Ok((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": format!("IndexNow 提交失败（HTTP {}）", index_now_response.status().as_u16()),
                "code": "SEO_INDEXNOW_SUBMIT_FAILED",
            })),
        )
            .into_response());
    }

    // logAdminAction -> logAuditEvent -> createLog(userId, 'admin', action,
    // contentParts.join(', '), 'success'); neither call site provides
    // targetUsername/resourceName/reason, so content is ''.
    create_log(&state, admin.0.id, "admin", "seo.indexnow.submit", "", "success").await;

    Ok(Json(json!({
        "success": true,
        "submitted": urls.len(),
        "sitemapUrl": sitemap_url.to_string(),
    }))
    .into_response())
}

// ===========================================================================
// GET / — 获取所有系统配置 (管理员)
// ===========================================================================

#[derive(sqlx::FromRow)]
struct SystemConfigDbRow {
    id: i32,
    key: String,
    value: String,
    #[sqlx(rename = "type")]
    config_type: String,
    label: Option<String>,
    description: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

async fn list_configs(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    let configs = sqlx::query_as::<_, SystemConfigDbRow>(
        "SELECT id, key, value, type, label, description, created_at, updated_at \
         FROM system_configs ORDER BY id ASC",
    )
    .fetch_all(&state.db)
    .await?;

    // 如果 email_allowed_domains 为空，填充默认白名单域名，让管理员看到
    // 实际生效的默认配置。
    let items: Vec<Value> = configs
        .iter()
        .map(|c| {
            let mut value = if is_sensitive_key(&c.key) && !c.value.is_empty() {
                MASKED_SECRET_PLACEHOLDER.to_string()
            } else {
                c.value.clone()
            };
            if c.key == "email_allowed_domains" && value.is_empty() {
                value = DEFAULT_ALLOWED_DOMAINS.join(",");
            }
            json!({
                "id": c.id,
                "key": c.key,
                "value": value,
                "type": c.config_type,
                "label": c.label,
                "description": c.description,
                "created_at": iso(c.created_at),
                "updated_at": iso(c.updated_at),
            })
        })
        .collect();

    Ok(Json(json!({ "configs": items })))
}

// ===========================================================================
// GET /default-quota — 获取默认配额配置 (管理员)
// ===========================================================================

async fn default_quota(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    let host = get_system_config_number(&state, "default_quota_host", DEFAULT_QUOTA_HOST).await?;
    let friend =
        get_system_config_number(&state, "default_quota_friend", DEFAULT_QUOTA_FRIEND).await?;
    let package =
        get_system_config_number(&state, "default_quota_package", DEFAULT_QUOTA_PACKAGE).await?;

    Ok(Json(json!({
        "quota": {
            "hostLimit": host,
            "friendLimit": friend,
            "packageLimit": package,
        }
    })))
}

// ===========================================================================
// PUT / — 批量更新配置 (管理员)
// ===========================================================================

const VALID_KEYS: &[&str] = &[
    "default_quota_host",
    "default_quota_friend",
    "default_quota_package",
    "registration_enabled",
    "require_invite_code",
    "admin_registration_emails",
    "invite_generation_costs",
    "invite_default_expire_days",
    "hosting_feature_enabled",
    "hosting_market_entry_enabled",
    "aff_rebate_enabled",
    "hosting_notice",
    "ticket_enabled",
    "free_site_mode",
    "free_site_register_gift_enabled",
    "free_site_register_gift_balance",
    "free_site_register_gift_points",
    "brand_name",
    "brand_subtitle",
    "brand_logo_url",
    "seo_site_url",
    "seo_sitemap_path",
    "seo_verification_path",
    "seo_verification_content",
    "seo_indexnow_endpoint",
    "seo_indexnow_key",
    "seo_tracking_enabled",
    "seo_tracking_script_url",
    "seo_tracking_id",
    "popup_announcement",
    "popup_promo_image_url",
    "popup_promo_package_id",
    "turnstile_enabled",
    "turnstile_site_key",
    "turnstile_secret_key",
    "avatar_api_base",
    "footer_contact_email",
    "footer_telegram_link",
    // Telegram bot binding
    "telegram_bot_enabled",
    "telegram_bot_username",
    "telegram_bot_token",
    "telegram_webhook_secret",
    "telegram_group_join_enabled",
    "telegram_group_chat_id",
    "telegram_group_join_mode",
    "telegram_group_min_recharge",
    "telegram_group_min_consume",
    "telegram_group_invite_expire_minutes",
    "telegram_vip_group_join_enabled",
    "telegram_vip_group_chat_id",
    "telegram_vip_group_join_mode",
    "telegram_vip_group_min_recharge",
    "telegram_vip_group_min_consume",
    "telegram_vip_group_invite_expire_minutes",
    // SMTP configuration
    "smtp_enabled",
    "smtp_host",
    "smtp_port",
    "smtp_secure",
    "smtp_username",
    "smtp_password",
    "smtp_from_email",
    "smtp_from_name",
    // Email domain whitelist
    "email_domain_whitelist_enabled",
    "email_allowed_domains",
    // Transfer fee
    "transfer_fee",
    "balance_transfer_enabled",
    "balance_transfer_fee",
    // Ticket image Lsky config
    "ticket_image_lsky_base_url",
    "ticket_image_lsky_token",
    "ticket_image_lsky_api_version",
    "ticket_image_lsky_target_id",
];

const BOOLEAN_KEYS: &[&str] = &[
    "registration_enabled",
    "require_invite_code",
    "hosting_feature_enabled",
    "hosting_market_entry_enabled",
    "aff_rebate_enabled",
    "ticket_enabled",
    "free_site_mode",
    "free_site_register_gift_enabled",
    "turnstile_enabled",
    "telegram_bot_enabled",
    "telegram_group_join_enabled",
    "telegram_vip_group_join_enabled",
    "smtp_enabled",
    "smtp_secure",
    "email_domain_whitelist_enabled",
    "balance_transfer_enabled",
    "seo_tracking_enabled",
];

const STRING_KEYS: &[&str] = &[
    "turnstile_site_key",
    "turnstile_secret_key",
    "avatar_api_base",
    "footer_contact_email",
    "footer_telegram_link",
    "brand_name",
    "brand_subtitle",
    "brand_logo_url",
    "seo_site_url",
    "seo_sitemap_path",
    "seo_verification_path",
    "seo_verification_content",
    "seo_indexnow_endpoint",
    "seo_indexnow_key",
    "seo_tracking_script_url",
    "seo_tracking_id",
    "telegram_bot_username",
    "telegram_bot_token",
    "telegram_webhook_secret",
    "telegram_group_chat_id",
    "telegram_group_join_mode",
    "telegram_vip_group_chat_id",
    "telegram_vip_group_join_mode",
    "hosting_notice",
    "popup_announcement",
    "popup_promo_image_url",
    "popup_promo_package_id",
    "smtp_host",
    "smtp_username",
    "smtp_password",
    "smtp_from_email",
    "smtp_from_name",
    "email_allowed_domains",
    "admin_registration_emails",
    "ticket_image_lsky_base_url",
    "ticket_image_lsky_token",
    "ticket_image_lsky_api_version",
    "ticket_image_lsky_target_id",
];

const JSON_KEYS: &[&str] = &["invite_generation_costs"];

const NUMBER_KEYS: &[&str] = &[
    "smtp_port",
    "default_quota_host",
    "default_quota_friend",
    "default_quota_package",
    "free_site_register_gift_points",
    "invite_default_expire_days",
    "telegram_group_invite_expire_minutes",
    "telegram_vip_group_invite_expire_minutes",
];

const DECIMAL_KEYS: &[&str] = &[
    "free_site_register_gift_balance",
    "telegram_group_min_recharge",
    "telegram_group_min_consume",
    "telegram_vip_group_min_recharge",
    "telegram_vip_group_min_consume",
];

/// lib/invite-pricing.ts supported resources.
fn is_supported_invite_cost_resource(resource: &str) -> bool {
    resource == "balance" || resource == "points"
}

/// lib/invite-pricing.ts serializeInviteCostOptions (normalize + defaults).
fn serialize_invite_cost_options(options: Vec<(String, f64, bool)>) -> String {
    // ensureDefaultCostOptions: keep option order, append missing defaults.
    let mut merged: Vec<(String, f64, bool)> = Vec::new();
    for (resource, amount, enabled) in options {
        let normalized_amount = match resource.as_str() {
            "balance" => js_round(f64::max(0.0, amount) * 100.0) / 100.0,
            "points" => f64::max(0.0, amount.floor()),
            _ => f64::max(0.0, if amount.is_finite() { amount } else { 0.0 }),
        };
        if !merged.iter().any(|(r, _, _)| *r == resource) {
            merged.push((resource, normalized_amount, enabled));
        }
    }
    for (resource, amount) in [("balance", 0.0f64), ("points", 0.0f64)] {
        if !merged.iter().any(|(r, _, _)| *r == resource) {
            merged.push((resource.to_string(), amount, false));
        }
    }

    let items: Vec<Value> = merged
        .into_iter()
        .map(|(resource, amount, enabled)| {
            json!({
                "resource": resource,
                "amount": js_json_num(amount),
                "enabled": enabled,
            })
        })
        .collect();
    json!(items).to_string()
}

/// Body-shape validation for PUT / (Fastify schema: configs array of
/// { key: string, value: string }, both required).
fn validate_update_configs_body(body: &Value) -> Result<Vec<(String, String)>, ApiError> {
    let obj = match body.as_object() {
        Some(o) => o,
        None => return Err(validation_error(vec!["body must be object".to_string()])),
    };
    let Some(configs_value) = obj.get("configs") else {
        return Err(validation_error(vec!["configs is required".to_string()]));
    };
    let Some(configs) = configs_value.as_array() else {
        return Err(validation_error(vec!["configs must be array".to_string()]));
    };

    let mut messages: Vec<String> = Vec::new();
    let mut out: Vec<(String, String)> = Vec::new();
    for (index, item) in configs.iter().enumerate() {
        let Some(item_obj) = item.as_object() else {
            messages.push(format!("configs/{index} must be object"));
            continue;
        };
        let mut key: Option<String> = None;
        let mut value: Option<String> = None;
        for field in ["key", "value"] {
            match item_obj.get(field) {
                None => messages.push(format!("{field} is required")),
                Some(Value::String(s)) => {
                    if field == "key" {
                        key = Some(s.clone());
                    } else {
                        value = Some(s.clone());
                    }
                }
                Some(_) => messages.push(format!("configs/{index}/{field} must be string")),
            }
        }
        if let (Some(k), Some(v)) = (key, value) {
            out.push((k, v));
        }
    }
    if !messages.is_empty() {
        return Err(validation_error(messages));
    }
    Ok(out)
}

async fn update_configs(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let mut configs = validate_update_configs_body(&body)?;

    // 验证配置键是否合法 + per-key value validation/normalization.
    for config in configs.iter_mut() {
        let key = config.0.clone();
        let value = config.1.clone();
        if !VALID_KEYS.contains(&key.as_str()) {
            return Err(ApiError::bad_request(code::CONFIG_INVALID_KEY).with_details(key));
        }

        // 布尔类型配置
        if BOOLEAN_KEYS.contains(&key.as_str()) {
            if value != "true" && value != "false" {
                return Err(
                    ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key)
                );
            }
            continue;
        }

        // 字符串类型配置（允许空值）
        if STRING_KEYS.contains(&key.as_str()) {
            if key == "footer_telegram_link" {
                match validate_optional_telegram_url(&value) {
                    Ok(validated) => {
                        config.1 = validated.unwrap_or_default();
                    }
                    Err(message) => {
                        return Err(ApiError::with_message(
                            code::CONFIG_INVALID_VALUE,
                            StatusCode::BAD_REQUEST,
                            message,
                        )
                        .with_details(key));
                    }
                }
            }
            if key == "admin_registration_emails" {
                let raw_suffixes: Vec<String> = value
                    .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                let suffixes = parse_admin_registration_email_suffixes(&value);
                let raw_unique: usize = {
                    let mut seen: Vec<&String> = Vec::new();
                    for s in &raw_suffixes {
                        if !seen.contains(&s) {
                            seen.push(s);
                        }
                    }
                    seen.len()
                };                let bad_suffix = suffixes.iter().any(|s| {
                    s.chars().count() > 254
                        || !EMAIL_DOMAIN_PATTERN.is_match(&s[1..])
                });
                if raw_suffixes.len() > 50
                    || suffixes.len() != raw_unique
                    || bad_suffix
                {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE)
                        .with_details(key));
                }
                config.1 = suffixes.join(",");
            }
            if key == "popup_announcement" && js_len(&value) > 5000 {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            if key == "brand_name" {
                config.1 = value.trim().to_string();
                if js_len(config.1.as_str()) > 200 {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "brand_subtitle" {
                config.1 = value.trim().to_string();
                if js_len(config.1.as_str()) > 300 {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "brand_logo_url" {
                config.1 = value.trim().to_string();
                if !config.1.is_empty() && js_len(config.1.as_str()) > 1000 {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
                if !config.1.is_empty()
                    && !is_http_image_url(&config.1)
                    && !config.1.starts_with('/')
                {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "seo_site_url" {
                config.1 = value.trim().trim_end_matches('/').to_string();
                if js_len(config.1.as_str()) > 500 || !is_valid_seo_site_url(&config.1) {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "seo_sitemap_path" || key == "seo_verification_path" {
                config.1 = value.trim().to_string();
                let allow_empty = key == "seo_verification_path";
                let has_expected_extension = if key == "seo_sitemap_path" {
                    config.1.to_lowercase().ends_with(".xml")
                } else {
                    (allow_empty && config.1.is_empty())
                        || config.1.to_lowercase().ends_with(".html")
                        || config.1.to_lowercase().ends_with(".htm")
                        || config.1.to_lowercase().ends_with(".txt")
                };
                if !is_valid_seo_path(&config.1, allow_empty) || !has_expected_extension {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "seo_verification_content" && js_len(&value) > 20000 {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            if key == "seo_indexnow_endpoint" || key == "seo_tracking_script_url" {
                config.1 = value.trim().to_string();
                if js_len(config.1.as_str()) > 500 || !is_http_url(&config.1) {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "seo_indexnow_key" {
                config.1 = value.trim().to_string();
                if !config.1.is_empty() && !SEO_INDEXNOW_KEY_PATTERN.is_match(&config.1) {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "seo_tracking_id" {
                config.1 = value.trim().to_string();
                if !config.1.is_empty() && !SEO_TRACKING_ID_PATTERN.is_match(&config.1) {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "popup_promo_image_url" {
                config.1 = value.trim().to_string();
                if !config.1.is_empty() && js_len(config.1.as_str()) > 1000 {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
                if !config.1.is_empty() && !is_http_image_url(&config.1) {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "popup_promo_package_id" {
                config.1 = value.trim().to_string();
            }
            if key == "popup_promo_package_id" && !config.1.is_empty() {
                let package_id = js_number(&config.1);
                let is_integer = package_id.is_finite() && package_id.fract() == 0.0;
                if !is_integer || package_id <= 0.0 {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
                if package_id > i32::MAX as f64 {
                    // TS: an out-of-range Int fails Prisma validation -> 500.
                    return Err(ApiError::internal("Prisma Int argument out of range"));
                }
                let pkg: Option<(i32,)> = sqlx::query_as(
                    "SELECT id FROM packages WHERE id = $1 AND active = TRUE AND global_shared = TRUE LIMIT 1",
                )
                .bind(package_id as i32)
                .fetch_optional(&state.db)
                .await?;
                if pkg.is_none() {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
            }
            if key == "ticket_image_lsky_api_version"
                && config.1 != "v1"
                && config.1 != "v2"
            {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            if (key == "telegram_group_join_mode" || key == "telegram_vip_group_join_mode")
                && config.1 != "any"
                && config.1 != "all"
            {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            if key == "telegram_webhook_secret"
                && !config.1.is_empty()
                && config.1 != MASKED_SECRET_PLACEHOLDER
                && !TELEGRAM_WEBHOOK_SECRET_PATTERN.is_match(&config.1)
            {
                return Err(ApiError::with_message(
                    "TELEGRAM_WEBHOOK_SECRET_INVALID",
                    StatusCode::BAD_REQUEST,
                    "Telegram webhook secret can only contain letters, numbers, underscores, and hyphens",
                ));
            }
            continue;
        }

        if JSON_KEYS.contains(&key.as_str()) && key == "invite_generation_costs" {
            let parsed: Result<Value, _> = serde_json::from_str(&value);
            let Ok(parsed) = parsed else {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            };
            let Some(items) = parsed.as_array() else {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            };

            let mut options: Vec<(String, f64, bool)> = Vec::new();
            for item in items {
                let Some(item_obj) = item.as_object() else {
                    return Err(
                        ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key)
                    );
                };
                let resource = item_obj
                    .get("resource")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !is_supported_invite_cost_resource(&resource) {
                    return Err(
                        ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key)
                    );
                }
                // TS: Number(item.amount) coerces strings/bools too.
                let amount = match item_obj.get("amount") {
                    Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
                    Some(Value::String(s)) => js_number(s),
                    Some(Value::Bool(b)) => {
                        if *b {
                            1.0
                        } else {
                            0.0
                        }
                    }
                    _ => f64::NAN,
                };
                if !amount.is_finite() {
                    return Err(
                        ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key)
                    );
                }
                if amount < 0.0 {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
                if resource == "balance" && amount > MAX_REGISTER_GIFT_BALANCE {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
                if resource == "points"
                    && (amount.fract() != 0.0 || amount > MAX_REGISTER_GIFT_POINTS)
                {
                    return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
                }
                let enabled = item_obj
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                options.push((resource, amount, enabled));
            }

            config.1 = serialize_invite_cost_options(options);
            continue;
        }

        if DECIMAL_KEYS.contains(&key.as_str()) {
            let num = js_number(&value);
            if num.is_nan() || num < 0.0 {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            if key == "free_site_register_gift_balance" && num > MAX_REGISTER_GIFT_BALANCE {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            config.1 = js_num_string(js_round(num * 100.0) / 100.0);
            continue;
        }

        // 转移/转账手续费特殊验证（0-100，支持两位小数）
        if key == "transfer_fee" || key == "balance_transfer_fee" {
            let trimmed = value.trim().to_string();
            let num = js_number(&trimmed);
            if !DECIMAL_MONEY_PATTERN.is_match(&trimmed)
                || !num.is_finite()
                || num < 0.0
                || num > MAX_TRANSFER_FEE
            {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(
                    format!("手续费必须在 0-{MAX_TRANSFER_FEE} 元之间，最多支持两位小数"),
                ));
            }
            config.1 = js_num_string(js_round(num * 100.0) / 100.0);
            continue;
        }

        // 数字类型配置（smtp_port 等）
        if NUMBER_KEYS.contains(&key.as_str()) {
            let num = js_number(&value);
            if !num.is_finite() || num.fract() != 0.0 || num < 0.0 {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            if key == "free_site_register_gift_points" && num > MAX_REGISTER_GIFT_POINTS {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            if (key == "telegram_group_invite_expire_minutes"
                || key == "telegram_vip_group_invite_expire_minutes")
                && !(1.0..=10080.0).contains(&num)
            {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            if key == "invite_default_expire_days" && num > 3650.0 {
                return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key));
            }
            config.1 = js_num_string(num);
            continue;
        }

        // 验证数值类型（默认配额等；unreachable for the valid key set, kept
        // for parity with the TS fallback branch）.
        let num = js_parse_int(&value);
        match num {
            Some(n) if n >= 0 => {}
            _ => return Err(ApiError::bad_request(code::CONFIG_INVALID_VALUE).with_details(key)),
        }
    }

    // free_site_mode 联动（TS ensureConfigValue semantics).
    let request_index: HashMap<String, usize> = configs
        .iter()
        .enumerate()
        .map(|(i, (k, _))| (k.clone(), i))
        .collect();

    let next_free_site_mode = match request_index.get("free_site_mode") {
        Some(&i) => configs[i].1 == "true",
        None => get_system_config_boolean(&state, "free_site_mode", false).await?,
    };

    let ensure = |configs: &mut Vec<(String, String)>,
                      index: &HashMap<String, usize>,
                      key: &str,
                      value: &str| {
        if let Some(&i) = index.get(key) {
            configs[i].1 = value.to_string();
        } else {
            configs.push((key.to_string(), value.to_string()));
        }
    };

    if !next_free_site_mode {
        ensure(&mut configs, &request_index, "free_site_register_gift_enabled", "false");
        ensure(&mut configs, &request_index, "free_site_register_gift_balance", "0");
        ensure(&mut configs, &request_index, "free_site_register_gift_points", "0");
    } else {
        let next_gift_enabled = match request_index.get("free_site_register_gift_enabled") {
            Some(&i) => configs[i].1 == "true",
            None => {
                get_system_config_boolean(&state, "free_site_register_gift_enabled", false)
                    .await?
            }
        };
        if !next_gift_enabled {
            ensure(&mut configs, &request_index, "free_site_register_gift_balance", "0");
            ensure(&mut configs, &request_index, "free_site_register_gift_points", "0");
        }
    }

    update_system_configs(&state, &configs).await?;

    // Clear SMTP transporter cache — nodemailer stack not ported (no-op).

    create_log(
        &state,
        admin.0.id,
        "system",
        "system.config_update",
        &format!("Updated {} system configurations", configs.len()),
        "success",
    )
    .await;

    // AUTH003 管理员操作审计日志（过滤敏感字段）。logAdminAction reduces to a
    // logs-table row with module 'admin' and empty content here.
    create_log(&state, admin.0.id, "admin", "system.config_update", "", "success").await;

    Ok(Json(json!({ "message": "Config updated" })))
}

/// db/system-config.ts updateSystemConfigs: skip masked secrets, encrypt new
/// sensitive values, then update each row (Prisma .update throws P2025 when a
/// key is missing -> 500).
async fn update_system_configs(
    state: &SharedAppState,
    configs: &[(String, String)],
) -> Result<(), ApiError> {
    let mut updates: Vec<(String, String)> = Vec::new();
    for (key, value) in configs {
        let mut final_value = value.clone();
        if is_sensitive_key(key) && value == MASKED_SECRET_PLACEHOLDER {
            continue;
        }
        if is_sensitive_key(key) && !value.is_empty() && !value.contains(':') {
            final_value =
                crypto::encrypt_sensitive_data(&state.config.encryption_key, value);
        }
        updates.push((key.clone(), final_value));
    }

    if updates.is_empty() {
        return Ok(());
    }

    let mut tx = state.db.begin().await?;
    for (key, value) in updates {
        let result = sqlx::query("UPDATE system_configs SET value = $2 WHERE key = $1")
            .bind(&key)
            .bind(&value)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            // Prisma would throw P2025 (record not found) -> 500.
            tx.rollback().await.ok();
            return Err(ApiError::internal(format!(
                "system config not found: {key}"
            )));
        }
    }
    tx.commit().await?;
    // invalidateAllConfigCache — the Rust port has no config cache (no-op).
    Ok(())
}

// ===========================================================================
// SMTP test endpoints (admin)
// ===========================================================================

/// lib/mailer.ts isSmtpEnabled: enabled && host && username && password.
async fn is_smtp_enabled(state: &SharedAppState) -> Result<bool, ApiError> {
    let enabled = get_system_config_boolean(state, "smtp_enabled", false).await?;
    if !enabled {
        return Ok(false);
    }
    let host = get_system_config(state, "smtp_host").await?.unwrap_or_default();
    let username = get_system_config(state, "smtp_username")
        .await?
        .unwrap_or_default();
    let password = get_system_config(state, "smtp_password")
        .await?
        .unwrap_or_default();
    Ok(!host.is_empty() && !username.is_empty() && !password.is_empty())
}

struct SmtpConfig {
    host: String,
    username: String,
    password: String,
    from_email: String,
}

/// lib/mailer.ts getSmtpConfig (only the fields the test endpoints need).
async fn get_smtp_config(state: &SharedAppState) -> Result<SmtpConfig, ApiError> {
    Ok(SmtpConfig {
        host: get_system_config(state, "smtp_host").await?.unwrap_or_default(),
        username: get_system_config(state, "smtp_username")
            .await?
            .unwrap_or_default(),
        password: get_system_config(state, "smtp_password")
            .await?
            .unwrap_or_default(),
        from_email: get_system_config(state, "smtp_from_email")
            .await?
            .unwrap_or_default(),
    })
}

fn smtp_config_incomplete(config: &SmtpConfig) -> bool {
    config.host.is_empty()
        || config.username.is_empty()
        || config.password.is_empty()
        || config.from_email.is_empty()
}

async fn smtp_test(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
) -> Result<Response, ApiError> {
    let config = get_smtp_config(&state).await?;

    // 检查必需字段是否已提供（即使未启用）
    if smtp_config_incomplete(&config) {
        create_log(
            &state,
            admin.0.id,
            "system",
            "smtp.test",
            "SMTP connection test failed: SMTP configuration incomplete. Please fill in host, username, password, and sender email.",
            "failed",
        )
        .await;
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "SMTP configuration incomplete. Please fill in host, username, password, and sender email.",
            })),
        )
            .into_response());
    }

    // nodemailer transporter.verify() is not ported; report the failure the
    // TS would report for an unreachable server, with a clear message.
    tracing::warn!("smtp.test: nodemailer stack not ported to the Rust server");
    create_log(
        &state,
        admin.0.id,
        "system",
        "smtp.test",
        "SMTP connection test failed: SMTP connection test is not supported by the Rust server",
        "failed",
    )
    .await;
    Ok((
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": "SMTP connection test is not supported by the Rust server",
        })),
    )
        .into_response())
}

async fn smtp_send_test(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    // Fastify schema: { to: string, format: email }.
    let obj = match body.as_object() {
        Some(o) => o,
        None => return Err(validation_error(vec!["body must be object".to_string()])),
    };
    let to = match obj.get("to") {
        None => return Err(validation_error(vec!["to is required".to_string()])),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err(validation_error(vec!["to must be string".to_string()])),
    };
    if !EMAIL_FORMAT_PATTERN.is_match(&to) {
        return Err(validation_error(vec![
            "Please enter a valid email address".to_string(),
        ]));
    }

    let config = get_smtp_config(&state).await?;
    if smtp_config_incomplete(&config) {
        create_log(
            &state,
            admin.0.id,
            "system",
            "smtp.send_test",
            "Failed to send test email: SMTP configuration incomplete. Please fill in host, username, password, and sender email.",
            "failed",
        )
        .await;
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "SMTP configuration incomplete. Please fill in host, username, password, and sender email.",
            })),
        )
            .into_response());
    }

    // nodemailer sendMail is not ported.
    tracing::warn!("smtp.send-test: nodemailer stack not ported to the Rust server");
    create_log(
        &state,
        admin.0.id,
        "system",
        "smtp.send_test",
        &format!("Failed to send test email to {to}: SMTP send is not supported by the Rust server"),
        "failed",
    )
    .await;
    Ok((
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": "SMTP send is not supported by the Rust server",
        })),
    )
        .into_response())
}
