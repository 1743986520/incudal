//! 套餐管理路由 — port of server/src/routes/packages.ts (mounted at /api/packages).
//!
//! Endpoint map (TS decorator -> Rust extractor):
//! - GET    /public                      (no auth)         -> public_list
//! - GET    /public/regions              (no auth)         -> public_regions
//! - GET    /                            authenticate      -> AuthUser
//! - GET    /hosting-zones               authenticate      -> AuthUser
//! - GET    /{id}                        authenticate      -> AuthUser
//! - POST   /                            authenticate      -> AuthUser
//! - PATCH  /{id}                        authenticate      -> AuthUser
//! - DELETE /{id}                        authenticate      -> AuthUser
//! - POST   /{id}/share                  authenticateUser  -> UserOnlyAuth
//! - DELETE /{id}/share/{userId}         authenticateUser  -> UserOnlyAuth
//! - PATCH  /{id}/shares/{shareId}       authenticateUser  -> UserOnlyAuth
//! - GET    /{id}/shares                 authenticateUser  -> UserOnlyAuth
//! - GET    /my-shares                   authenticateUser  -> UserOnlyAuth
//! - GET    /{id}/hosts-detail           authenticate      -> AuthUser
//! - GET    /{id}/owner-info             authenticateUser  -> UserOnlyAuth
//! - POST   /{id}/release-quota          authenticate      -> AuthUser
//! - GET    /{id}/plans                  authenticate      -> AuthUser
//! - GET    /{id}/plans/{planId}         authenticate      -> AuthUser
//! - POST   /{id}/plans                  authenticate      -> AuthUser
//! - PUT    /{id}/plans/{planId}         authenticate      -> AuthUser
//! - DELETE /{id}/plans/{planId}         authenticate      -> AuthUser
//! - GET    /regions                     authenticate      -> AuthUser
//!
//! Money units: PackagePlan.price / setupFee / trafficResetPrice are stored in
//! CENTS (fen); the TS serializes them with Number() for display and computes
//! monthlyPrice = price / billingCycle (still cents). In the /public endpoint
//! the inline plan objects keep `price`/`setupFee`/`slaGuarantee` as RAW Prisma
//! Decimals, which JSON.stringify renders as strings ("2500.00") — replicated.
//!
//! Reported deviations (non-portable service stacks; all failure-tolerant in TS):
//! - sendToChannel (telegram/webhook notifier) is not ported: release-quota
//!   finds the global notification channel and logs a warning where the TS
//!   dispatches the notification. TS swallows send failures anyway.
//! - reconcileTrafficStateForInstanceIds (services/traffic-scheduler.ts) is not
//!   ported: after quota/traffic syncs a warning is logged. TS wraps the call
//!   in try/catch and only logs failures, so behavior stays non-fatal.
//! - getCountryName uses Intl.DisplayNames(['en'], region) in TS; without ICU
//!   data in Rust it falls back to the special names (pc/xx) + uppercase code.
//! - AJV schema error bodies are reproduced message-for-message for common
//!   keywords; union-type AJV messages ("must be string or null") are
//!   best-effort.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use rust_decimal::{Decimal, RoundingStrategy};
use serde_json::{json, Map, Value};

use crate::auth::{AuthUser, UserOnlyAuth};
use crate::db;
use crate::error::{code, ApiError};
use crate::libs::validators;
use crate::response::num;
use crate::routes::users::create_log;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        // 公开 API（无需登录）
        .route("/public", get(public_list))
        .route("/public/regions", get(public_regions))
        // 需要登录的 API
        .route("/", get(list_packages).post(create_package))
        .route("/hosting-zones", get(hosting_zones))
        .route("/my-shares", get(my_shares))
        .route("/regions", get(regions))
        .route(
            "/{id}",
            get(get_package)
                .patch(update_package)
                .delete(delete_package),
        )
        .route("/{id}/share", post(share_package))
        .route("/{id}/share/{user_id}", delete(unshare_package))
        .route("/{id}/shares", get(list_shares))
        .route("/{id}/shares/{share_id}", patch(update_share_quota))
        .route("/{id}/hosts-detail", get(hosts_detail))
        .route("/{id}/owner-info", get(owner_info))
        .route("/{id}/release-quota", post(release_quota))
        .route("/{id}/plans", get(list_plans).post(create_plan))
        .route(
            "/{id}/plans/{plan_id}",
            get(get_plan)
                .put(update_plan)
                .delete(delete_plan_handler),
        )
}

// ===========================================================================
// constants (verbatim from packages.ts)
// ===========================================================================

const KVM_UNSUPPORTED_NETWORK_MODES: [&str; 2] = ["nat_ipv6_nat", "ipv6_nat"];
const MAX_PACKAGE_PLAN_NAME_LENGTH: usize = 50;
const PUBLIC_PACKAGE_MAX_INSTANCES_MIN: i64 = 1;
const PUBLIC_PACKAGE_MAX_INSTANCES_MAX: i64 = 5;
const MAX_PACKAGE_PLAN_PRICE_CENTS: f64 = 99999999.0;
const MAX_PACKAGE_PLAN_PRICE_YUAN: &str = "999999.99"; // (MAX/100).toFixed(2)
const MAX_DESTROY_TRAFFIC_LIMIT: i128 = 1024 * 1024 * 1024 * 1024 * 1024; // 1 PiB

/// lib/host-resource-usage.ts HOST_RESOURCE_INSTANCE_STATUSES.
const HOST_RESOURCE_INSTANCE_STATUSES: [&str; 4] = ["creating", "running", "stopped", "suspended"];
/// db/packages.ts NORMAL_PACKAGE_INSTANCE_STATUSES.
const NORMAL_PACKAGE_INSTANCE_STATUSES: [&str; 2] = ["running", "stopped"];
/// db/packages.ts PACKAGE_PREREQUISITE_LOCK_NAMESPACE.
const PACKAGE_PREREQUISITE_LOCK_NAMESPACE: i32 = 4201;

// ===========================================================================
// small shared helpers
// ===========================================================================

/// TS `Date` fields serialize as ISO strings through Fastify's JSON encoder.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// JS `Number(str)` for route params: Number('') = 0; NaN -> 400 INVALID_ID;
/// non-integral / out-of-i32 values mirror the Prisma Int validation failure (500).
fn js_number_id(raw: &str) -> Result<i32, ApiError> {
    let t = raw.trim();
    let v: f64 = if t.is_empty() {
        0.0
    } else {
        t.parse::<f64>()
            .map_err(|_| ApiError::bad_request(code::INVALID_ID))?
    };
    if v.is_nan() {
        return Err(ApiError::bad_request(code::INVALID_ID));
    }
    if !v.is_finite() || v.fract() != 0.0 || !(i32::MIN as f64..=i32::MAX as f64).contains(&v) {
        return Err(ApiError::internal(format!(
            "Prisma Int argument out of range: {v}"
        )));
    }
    Ok(v as i32)
}

/// JS Number(string) coercion.
fn js_number_str(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

/// JS Number(value) over a JSON value: missing (undefined) is NaN, null -> 0,
/// bool -> 0/1, strings parse (trimmed), objects -> NaN.
fn js_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => js_number_str(s),
        Some(Value::Bool(b)) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Some(Value::Null) => 0.0,
        Some(_) => f64::NAN,
    }
}

/// JS Number -> JSON number (Null when non-finite, like Fastify's serializer).
fn js_json_number(v: f64) -> Value {
    serde_json::Number::from_f64(v)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// JS Number formatting for interpolation inside strings: integers print
/// without ".0"; NaN/Infinity print as-is.
fn js_num_string(v: f64) -> String {
    if v.is_nan() {
        return "NaN".to_string();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if v == 0.0 {
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    format!("{v}")
}

/// JS parseInt(string, 10): leading integer parse, NaN when none.
fn js_parse_int(s: &str) -> Option<i64> {
    let t = s.trim_start();
    let bytes = t.as_bytes();
    let mut end = 0usize;
    if bytes
        .first()
        .map(|b| *b == b'-' || *b == b'+')
        .unwrap_or(false)
    {
        end += 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && (bytes[0] == b'-' || bytes[0] == b'+')) {
        return None;
    }
    t[..end].parse().ok()
}

/// decimal.js toFixed(8) equivalent for a Decimal.
fn fixed_dp(value: Decimal, dp: u32) -> String {
    let v = value.round_dp_with_strategy(dp, RoundingStrategy::MidpointAwayFromZero);
    let s = v.to_string();
    match s.split_once('.') {
        Some((int_part, frac)) => {
            let pad = dp as usize - frac.len();
            format!("{int_part}.{}{frac}", "0".repeat(pad))
        }
        None => format!("{s}.{}", "0".repeat(dp as usize)),
    }
}

/// packages.ts decimalString(value, field): Prisma.Decimal(String(value)) with
/// 8dp rounding; throws `${field} 必须是有效的非负数字` when unparseable/negative.
fn decimal_string(value: Option<&Value>, field: &str) -> Result<String, String> {
    let raw = match value {
        None | Some(Value::Null) => "0".to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(_) => return Err(format!("{field} 必须是有效的非负数字")),
    };
    let dec = Decimal::from_str(&raw)
        .ok()
        .filter(|d| *d >= Decimal::ZERO)
        .ok_or_else(|| format!("{field} 必须是有效的非负数字"))?;
    Ok(fixed_dp(dec, 8))
}

/// lib/traffic-multiplier.ts normalizeTrafficMultiplier over an f64.
fn normalize_traffic_multiplier_f(value: f64) -> Result<f64, String> {
    if !value.is_finite() || value < 0.001 || value > 100.0 {
        return Err("Traffic multiplier must be at least 0.001 and no more than 100".to_string());
    }
    Ok((value * 1000.0).round() / 1000.0)
}

/// normalizeTrafficMultiplier over a JSON value (null/undefined/'' -> 1).
fn normalize_traffic_multiplier_v(value: Option<&Value>) -> Result<f64, String> {
    match value {
        None | Some(Value::Null) => Ok(1.0),
        Some(Value::String(s)) if s.is_empty() => Ok(1.0),
        Some(_) => normalize_traffic_multiplier_f(js_number(value)),
    }
}

/// lib/traffic-multiplier.ts applyTrafficMultiplier (BigInt arithmetic -> i128).
fn apply_traffic_multiplier(limit: Option<i64>, multiplier: f64) -> Result<Option<i64>, ApiError> {
    let Some(limit) = limit else {
        return Ok(None);
    };
    let normalized =
        normalize_traffic_multiplier_f(multiplier).map_err(ApiError::internal)?;
    let scaled = (normalized * 1000.0).round() as i128;
    let result = limit as i128 * scaled / 1000;
    i64::try_from(result)
        .map(Some)
        .map_err(|_| ApiError::internal("traffic limit out of bigint range"))
}

fn validate_public_package_max_instances(value: f64) -> bool {
    value.is_finite()
        && value.fract() == 0.0
        && value >= PUBLIC_PACKAGE_MAX_INSTANCES_MIN as f64
        && value <= PUBLIC_PACKAGE_MAX_INSTANCES_MAX as f64
}

fn normalize_public_package_max_instances(value: Option<&Value>) -> i64 {
    let v = js_number(value);
    if validate_public_package_max_instances(v) {
        v as i64
    } else {
        PUBLIC_PACKAGE_MAX_INSTANCES_MIN
    }
}

/// packages.ts parseDestroyTrafficLimit. `None` = field absent -> DB default
/// (the TS returns undefined and Prisma applies the column default).
fn parse_destroy_traffic_limit(value: Option<&Value>) -> Result<Option<i64>, String> {
    let Some(v) = value else {
        return Ok(None);
    };
    let raw = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return Err(format!("Cannot convert {v} to a BigInt")),
    };
    let parsed: i128 = raw
        .trim()
        .parse::<i128>()
        .map_err(|_| format!("Cannot convert \"{raw}\" to a BigInt"))?;
    if parsed <= 0 || parsed > MAX_DESTROY_TRAFFIC_LIMIT {
        return Err("退款销毁流量上限必须大于 0 且不超过 1 PiB".to_string());
    }
    i64::try_from(parsed)
        .map(Some)
        .map_err(|_| "退款销毁流量上限必须大于 0 且不超过 1 PiB".to_string())
}

static INCUS_BANDWIDTH_PATTERN: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^\d+(?:\.\d+)?(?:bit|kbit|mbit|gbit|tbit|B|kB|MB|GB|TB)$")
            .expect("valid regex")
    });

/// services/traffic-bandwidth.ts isValidPlanTrafficLimitSpeed.
fn is_valid_plan_traffic_limit_speed(value: Option<&Value>) -> bool {
    let Some(Value::String(s)) = value else {
        return false;
    };
    if s.is_empty() || s == "0" {
        return false;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return i128::from_str(s).map(|n| n > 0).unwrap_or(true);
    }
    INCUS_BANDWIDTH_PATTERN.is_match(s)
}

/// packages.ts validatePackagePlanName (allows emoji, forbids control/dangerous chars).
fn validate_package_plan_name(value: Option<&Value>) -> Result<String, String> {
    let Some(Value::String(raw)) = value else {
        return Err("方案名称不能为空".to_string());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("方案名称不能为空".to_string());
    }
    // Array.from(str).length === code-point count.
    if trimmed.chars().count() > MAX_PACKAGE_PLAN_NAME_LENGTH {
        return Err(format!(
            "方案名称不能超过 {MAX_PACKAGE_PLAN_NAME_LENGTH} 个字符"
        ));
    }
    let has_control = trimmed
        .chars()
        .any(|c| ('\u{0000}'..='\u{001F}').contains(&c) || c == '\u{007F}');
    if has_control || validators::remove_dangerous_chars(trimmed) != trimmed {
        return Err("方案名称包含非法字符".to_string());
    }
    Ok(trimmed.to_string())
}

/// packages.ts validatePackagePlanPrice core (strict typeof number + integer cents).
fn validate_price_f64(n: f64) -> Result<f64, String> {
    if !n.is_finite() || n.fract() != 0.0 {
        return Err("价格必须是有效金额".to_string());
    }
    if n < 0.0 {
        return Err("价格不能为负数".to_string());
    }
    if n > MAX_PACKAGE_PLAN_PRICE_CENTS {
        return Err(format!("方案价格不能超过 ¥{MAX_PACKAGE_PLAN_PRICE_YUAN}"));
    }
    Ok(n)
}

/// packages.ts validatePackagePlanPrice over a JSON value (typeof checked).
fn validate_package_plan_price(value: Option<&Value>) -> Result<f64, String> {
    match value {
        Some(Value::Number(n)) => validate_price_f64(n.as_f64().unwrap_or(f64::NAN)),
        _ => Err("价格必须是有效金额".to_string()),
    }
}

/// packages.ts normalizeTrafficResetPrice (`price ?? 0` semantics: null -> 0).
fn normalize_traffic_reset_price(enabled: bool, price: Option<&Value>) -> Result<f64, String> {
    let value: Option<Value> = if enabled {
        match price {
            None | Some(Value::Null) => Some(Value::Number(0.into())),
            Some(v) => Some(v.clone()),
        }
    } else {
        Some(Value::Number(0.into()))
    };
    validate_package_plan_price(value.as_ref())
}

// ===========================================================================
// AJV-style body schema validation (Fastify JSON-schema error surface)
// ===========================================================================

/// Reproduces the app-level error handler for `error.validation`:
/// `400 { error: messages[0], code: 'VALIDATION_ERROR', details?: string[] }`.
fn schema_error_response(messages: Vec<String>) -> Response {
    let mut body = json!({
        "error": messages[0],
        "code": code::VALIDATION_ERROR,
    });
    if messages.len() > 1 {
        body["details"] = json!(messages);
    }
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

/// Raw AJV v8 messages for the keywords the app error handler does not remap.
fn ajv_msg(keyword: &str, limit: &str) -> String {
    match keyword {
        "minimum" => format!("must be >= {limit}"),
        "maximum" => format!("must be <= {limit}"),
        "enum" => "must be equal to one of the allowed values".to_string(),
        "minItems" => format!("must NOT have fewer than {limit} items"),
        "maxItems" => format!("must NOT have more than {limit} items"),
        _ => format!("must be {limit}"), // type
    }
}

#[derive(Default)]
struct PropSpec {
    js_type: &'static str, // "integer"|"number"|"string"|"boolean"|"array"|"object"|"integerOrNull"|"numberOrNull"|"stringOrNull"
    min_length: Option<usize>,
    max_length: Option<usize>,
    minimum: Option<f64>,
    maximum: Option<f64>,
    enum_values: &'static [&'static str],
    pattern: Option<&'static regex::Regex>,
    min_items: Option<usize>,
    max_items: Option<usize>,
    items_integer: bool,
}

/// Checks one property in AJV order (type first, then the declared constraints;
/// a type failure stops that property, exactly like AJV).
fn check_prop(messages: &mut Vec<String>, value: Option<&Value>, name: &str, spec: &PropSpec) {
    let Some(v) = value else {
        return; // absent non-required fields pass
    };
    let type_ok = match spec.js_type {
        "integer" => v.is_number() && v.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false),
        "number" => v.is_number(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "array" => v.is_array(),
        "object" => v.is_object(),
        "integerOrNull" => {
            v.is_null() || (v.is_number() && v.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false))
        }
        "numberOrNull" => v.is_null() || v.is_number(),
        "stringOrNull" => v.is_null() || v.is_string(),
        _ => true,
    };
    if !type_ok {
        let t = if spec.js_type.ends_with("OrNull") {
            format!("{} or null", spec.js_type.trim_end_matches("OrNull"))
        } else {
            spec.js_type.to_string()
        };
        messages.push(ajv_msg("type", &t));
        return;
    }
    if !spec.enum_values.is_empty() {
        let ok = v.as_str().map(|s| spec.enum_values.contains(&s)).unwrap_or(false);
        if !ok {
            messages.push(ajv_msg("enum", ""));
            return;
        }
    }
    if let Some(min) = spec.min_length {
        if v.as_str().map(|s| s.chars().count() < min).unwrap_or(false) {
            messages.push(format!("{name} is too short"));
        }
    }
    if let Some(max) = spec.max_length {
        if v.as_str().map(|s| s.chars().count() > max).unwrap_or(false) {
            messages.push(format!("{name} is too long"));
        }
    }
    if let Some(re) = spec.pattern {
        if !v.as_str().map(|s| re.is_match(s)).unwrap_or(false) {
            messages.push(format!("{name} format is invalid"));
        }
    }
    if let Some(min) = spec.minimum {
        if v.as_f64().map(|f| f < min).unwrap_or(false) {
            messages.push(ajv_msg("minimum", &js_num_string(min)));
        }
    }
    if let Some(max) = spec.maximum {
        if v.as_f64().map(|f| f > max).unwrap_or(false) {
            messages.push(ajv_msg("maximum", &js_num_string(max)));
        }
    }
    if let Some(min) = spec.min_items {
        if v.as_array().map(|a| a.len() < min).unwrap_or(false) {
            messages.push(ajv_msg("minItems", &min.to_string()));
        }
    }
    if let Some(max) = spec.max_items {
        if v.as_array().map(|a| a.len() > max).unwrap_or(false) {
            messages.push(ajv_msg("maxItems", &max.to_string()));
        }
    }
    if spec.items_integer {
        if let Some(items) = v.as_array() {
            for item in items {
                let ok = item.is_number()
                    && item.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false);
                if !ok {
                    messages.push(ajv_msg("type", "integer"));
                    break;
                }
            }
        }
    }
}

static DIGITS_ONLY: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| regex::Regex::new(r"^\d+$").expect("valid regex"));

const NETWORK_MODES: [&str; 5] = ["nat", "nat_ipv6", "nat_ipv6_nat", "ipv6_only", "ipv6_nat"];
const INSTANCE_TYPES: [&str; 2] = ["container", "vm"];

fn require_fields(messages: &mut Vec<String>, body: &Map<String, Value>, required: &[&str]) {
    for field in required {
        if !body.contains_key(*field) {
            messages.push(format!("{field} is required"));
        }
    }
}

/// Fastify schema for POST / (create package body).
fn validate_package_body_schema(body: &Value, required: &[&str]) -> Result<(), Response> {
    let Some(obj) = body.as_object() else {
        return Err(schema_error_response(vec!["body must be object".to_string()]));
    };
    let mut messages: Vec<String> = Vec::new();
    require_fields(&mut messages, obj, required);
    let g = |k: &str| obj.get(k);
    check_prop(&mut messages, g("name"), "name", &PropSpec { js_type: "string", min_length: Some(2), ..Default::default() });
    check_prop(&mut messages, g("description"), "description", &PropSpec { js_type: "string", ..Default::default() });
    check_prop(&mut messages, g("cpuMax"), "cpuMax", &PropSpec { js_type: "integer", minimum: Some(15.0), ..Default::default() });
    check_prop(&mut messages, g("memoryMax"), "memoryMax", &PropSpec { js_type: "integer", minimum: Some(128.0), ..Default::default() });
    check_prop(&mut messages, g("diskMax"), "diskMax", &PropSpec { js_type: "integer", minimum: Some(512.0), ..Default::default() });
    check_prop(&mut messages, g("bandwidthMax"), "bandwidthMax", &PropSpec { js_type: "integer", ..Default::default() });
    check_prop(&mut messages, g("networkMode"), "networkMode", &PropSpec { js_type: "string", enum_values: &NETWORK_MODES, ..Default::default() });
    check_prop(&mut messages, g("instanceType"), "instanceType", &PropSpec { js_type: "string", enum_values: &INSTANCE_TYPES, ..Default::default() });
    check_prop(&mut messages, g("hostIds"), "hostIds", &PropSpec { js_type: "array", min_items: Some(1), items_integer: true, ..Default::default() });
    check_prop(&mut messages, g("hostStoragePools"), "hostStoragePools", &PropSpec { js_type: "object", ..Default::default() });
    check_prop(&mut messages, g("hostTrafficMultipliers"), "hostTrafficMultipliers", &PropSpec { js_type: "object", ..Default::default() });
    check_prop(&mut messages, g("privileged"), "privileged", &PropSpec { js_type: "boolean", ..Default::default() });
    check_prop(&mut messages, g("nested"), "nested", &PropSpec { js_type: "boolean", ..Default::default() });
    check_prop(&mut messages, g("active"), "active", &PropSpec { js_type: "boolean", ..Default::default() });
    check_prop(
        &mut messages,
        g("monthlyTrafficLimit"),
        "monthlyTrafficLimit",
        &PropSpec {
            js_type: if required.contains(&"name") { "string" } else { "stringOrNull" },
            ..Default::default()
        },
    );
    check_prop(&mut messages, g("portLimit"), "portLimit", &PropSpec { js_type: "integer", minimum: Some(1.0), ..Default::default() });
    check_prop(&mut messages, g("snapshotLimit"), "snapshotLimit", &PropSpec { js_type: "integer", minimum: Some(0.0), ..Default::default() });
    check_prop(&mut messages, g("backupLimit"), "backupLimit", &PropSpec { js_type: "integer", minimum: Some(0.0), ..Default::default() });
    check_prop(&mut messages, g("siteLimit"), "siteLimit", &PropSpec { js_type: "integer", minimum: Some(0.0), ..Default::default() });
    check_prop(&mut messages, g("ioLimitMode"), "ioLimitMode", &PropSpec { js_type: "string", enum_values: &["throughput", "iops"], ..Default::default() });
    check_prop(&mut messages, g("limitsRead"), "limitsRead", &PropSpec { js_type: "string", ..Default::default() });
    check_prop(&mut messages, g("limitsWrite"), "limitsWrite", &PropSpec { js_type: "string", ..Default::default() });
    check_prop(&mut messages, g("limitsReadIops"), "limitsReadIops", &PropSpec { js_type: "integer", minimum: Some(0.0), ..Default::default() });
    check_prop(&mut messages, g("limitsWriteIops"), "limitsWriteIops", &PropSpec { js_type: "integer", minimum: Some(0.0), ..Default::default() });
    check_prop(&mut messages, g("limitsIngress"), "limitsIngress", &PropSpec { js_type: "string", ..Default::default() });
    check_prop(&mut messages, g("limitsEgress"), "limitsEgress", &PropSpec { js_type: "string", ..Default::default() });
    check_prop(&mut messages, g("limitsProcesses"), "limitsProcesses", &PropSpec { js_type: "integer", minimum: Some(0.0), ..Default::default() });
    check_prop(&mut messages, g("limitsCpuPriority"), "limitsCpuPriority", &PropSpec { js_type: "integer", minimum: Some(0.0), maximum: Some(10.0), ..Default::default() });
    check_prop(&mut messages, g("bootAutostart"), "bootAutostart", &PropSpec { js_type: "boolean", ..Default::default() });
    check_prop(&mut messages, g("bootAutostartPriority"), "bootAutostartPriority", &PropSpec { js_type: "integer", minimum: Some(0.0), maximum: Some(100.0), ..Default::default() });
    check_prop(&mut messages, g("bootAutostartDelay"), "bootAutostartDelay", &PropSpec { js_type: "integer", minimum: Some(5.0), maximum: Some(600.0), ..Default::default() });
    check_prop(&mut messages, g("bootHostShutdownTimeout"), "bootHostShutdownTimeout", &PropSpec { js_type: "integer", minimum: Some(30.0), maximum: Some(600.0), ..Default::default() });
    check_prop(&mut messages, g("globalShared"), "globalShared", &PropSpec { js_type: "boolean", ..Default::default() });
    check_prop(&mut messages, g("globalQuotaMultiplier"), "globalQuotaMultiplier", &PropSpec { js_type: "numberOrNull", ..Default::default() });
    check_prop(&mut messages, g("globalMaxInstances"), "globalMaxInstances", &PropSpec { js_type: "integerOrNull", ..Default::default() });
    check_prop(&mut messages, g("requiredPackageId"), "requiredPackageId", &PropSpec { js_type: "integerOrNull", minimum: Some(1.0), ..Default::default() });
    check_prop(&mut messages, g("allowInstanceDeletion"), "allowInstanceDeletion", &PropSpec { js_type: "boolean", ..Default::default() });
    check_prop(&mut messages, g("destroyTrafficLimit"), "destroyTrafficLimit", &PropSpec { js_type: "string", pattern: Some(&DIGITS_ONLY), max_length: Some(19), ..Default::default() });
    if !messages.is_empty() {
        return Err(schema_error_response(messages));
    }
    Ok(())
}

/// Fastify schema for POST /:id/release-quota.
fn validate_release_quota_schema(body: &Value) -> Result<(), Response> {
    let Some(obj) = body.as_object() else {
        return Err(schema_error_response(vec!["body must be object".to_string()]));
    };
    let mut messages: Vec<String> = Vec::new();
    require_fields(&mut messages, obj, &["hostIds", "cpuAdd", "memoryAdd"]);
    let g = |k: &str| obj.get(k);
    check_prop(&mut messages, g("hostIds"), "hostIds", &PropSpec { js_type: "array", min_items: Some(1), max_items: Some(100), items_integer: true, ..Default::default() });
    check_prop(&mut messages, g("cpuAdd"), "cpuAdd", &PropSpec { js_type: "integer", minimum: Some(0.0), maximum: Some(10000.0), ..Default::default() });
    check_prop(&mut messages, g("memoryAdd"), "memoryAdd", &PropSpec { js_type: "integer", minimum: Some(0.0), maximum: Some(1048576.0), ..Default::default() });
    check_prop(&mut messages, g("notify"), "notify", &PropSpec { js_type: "boolean", ..Default::default() });
    if !messages.is_empty() {
        return Err(schema_error_response(messages));
    }
    Ok(())
}

// ===========================================================================
// row structs
// ===========================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
struct OwnPackageRow {
    id: i32,
    user_id: i32,
    name: String,
    description: Option<String>,
    cpu_max: i32,
    memory_max: i32,
    disk_max: i32,
    bandwidth_max: Option<i32>,
    network_mode: String,
    instance_type: String,
    privileged: bool,
    nested: bool,
    active: bool,
    port_limit: i32,
    snapshot_limit: i32,
    backup_limit: i32,
    site_limit: i32,
    monthly_traffic_limit: Option<i64>,
    io_limit_mode: String,
    limits_read: String,
    limits_write: String,
    limits_read_iops: i32,
    limits_write_iops: i32,
    limits_ingress: String,
    limits_egress: String,
    limits_processes: i32,
    limits_cpu_priority: i32,
    boot_autostart: bool,
    boot_autostart_priority: i32,
    boot_autostart_delay: i32,
    boot_host_shutdown_timeout: i32,
    global_shared: bool,
    global_quota_multiplier: Option<Decimal>,
    global_max_instances: Option<i32>,
    required_package_id: Option<i32>,
    required_package_name: Option<String>,
    allow_instance_deletion: bool,
    destroy_traffic_limit: i64,
    created_at: DateTime<Utc>,
    owner_username: Option<String>,
    owner_email: Option<String>,
    owner_avatar_style: Option<String>,
    owner_avatar_badge_id: Option<String>,
}

const OWN_PACKAGE_SELECT: &str = "SELECT p.id, p.user_id, p.name, p.description, p.cpu_max, \
    p.memory_max, p.disk_max, p.bandwidth_max, p.network_mode::text AS network_mode, \
    p.instance_type::text AS instance_type, p.privileged, p.nested, p.active, \
    p.port_limit, p.snapshot_limit, p.backup_limit, p.site_limit, p.monthly_traffic_limit, \
    p.io_limit_mode, p.limits_read, p.limits_write, p.limits_read_iops, p.limits_write_iops, \
    p.limits_ingress, p.limits_egress, p.limits_processes, p.limits_cpu_priority, \
    p.boot_autostart, p.boot_autostart_priority, p.boot_autostart_delay, \
    p.boot_host_shutdown_timeout, p.global_shared, p.global_quota_multiplier, \
    p.global_max_instances, p.required_package_id, rp.name AS required_package_name, \
    p.allow_instance_deletion, p.destroy_traffic_limit, p.created_at, \
    u.username AS owner_username, u.email AS owner_email, u.avatar_style AS owner_avatar_style, \
    u.avatar_badge_id AS owner_avatar_badge_id \
    FROM packages p \
    LEFT JOIN users u ON u.id = p.user_id \
    LEFT JOIN packages rp ON rp.id = p.required_package_id";

/// SharedPackageInfo from db/package-shares.ts. `quota_multiplier` /
/// `max_instances` are only populated for friend shares and are intentionally
/// not emitted by formatSharedPackage (TS parity).
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
struct SharedPackageRow {
    id: i32,
    name: String,
    description: Option<String>,
    cpu_max: i32,
    memory_max: i32,
    disk_max: i32,
    bandwidth_max: Option<i32>,
    network_mode: String,
    instance_type: String,
    port_limit: i32,
    snapshot_limit: i32,
    backup_limit: i32,
    site_limit: i32,
    monthly_traffic_limit: Option<i64>,
    nested: bool,
    privileged: bool,
    allow_instance_deletion: bool,
    destroy_traffic_limit: i64,
    host_ids: Vec<i32>,
    owner_id: i32,
    owner_username: String,
    shared_at: DateTime<Utc>,
    is_global_shared: bool,
    quota_multiplier: Option<Decimal>,
    max_instances: Option<i32>,
    required_package_id: Option<i32>,
    required_package_name: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct PlanRow {
    id: i32,
    package_id: i32,
    name: String,
    description: Option<String>,
    cpu: i32,
    memory: i32,
    disk: i32,
    port_limit: i32,
    snapshot_limit: i32,
    backup_limit: i32,
    site_limit: i32,
    swap_size: i32,
    traffic_limit: i64,
    traffic_limit_speed: String,
    traffic_billing_mode: String,
    traffic_unit_price: Decimal,
    billing_mode: String,
    price: Decimal,
    billing_cycle: i32,
    setup_fee: Decimal,
    hourly_min_cpu: i32,
    hourly_cpu_unit_percent: i32,
    hourly_cpu_price_per_unit: Decimal,
    hourly_min_memory_mb: i32,
    hourly_memory_unit_mb: i32,
    hourly_memory_price_per_unit: Decimal,
    hourly_min_disk_mb: i32,
    hourly_disk_unit_mb: i32,
    hourly_disk_price_per_unit: Decimal,
    hourly_reserve_quantum: Decimal,
    traffic_reset_enabled: bool,
    traffic_reset_price: Decimal,
    is_active: bool,
    is_sold_out: bool,
    sort_order: i32,
    sla_guarantee: Option<Decimal>,
}

const PLAN_SELECT: &str = "SELECT id, package_id, name, description, cpu, memory, disk, \
    port_limit, snapshot_limit, backup_limit, site_limit, swap_size, traffic_limit, \
    traffic_limit_speed, traffic_billing_mode::text AS traffic_billing_mode, traffic_unit_price, \
    billing_mode::text AS billing_mode, price, billing_cycle, setup_fee, \
    hourly_min_cpu, hourly_cpu_unit_percent, hourly_cpu_price_per_unit, \
    hourly_min_memory_mb, hourly_memory_unit_mb, hourly_memory_price_per_unit, \
    hourly_min_disk_mb, hourly_disk_unit_mb, hourly_disk_price_per_unit, hourly_reserve_quantum, \
    traffic_reset_enabled, traffic_reset_price, is_active, is_sold_out, sort_order, sla_guarantee \
    FROM package_plans";

const PLAN_RETURNING: &str = "id, package_id, name, description, cpu, memory, disk, port_limit, \
    snapshot_limit, backup_limit, site_limit, swap_size, traffic_limit, traffic_limit_speed, \
    traffic_billing_mode::text AS traffic_billing_mode, traffic_unit_price, \
    billing_mode::text AS billing_mode, price, billing_cycle, setup_fee, \
    hourly_min_cpu, hourly_cpu_unit_percent, hourly_cpu_price_per_unit, \
    hourly_min_memory_mb, hourly_memory_unit_mb, hourly_memory_price_per_unit, \
    hourly_min_disk_mb, hourly_disk_unit_mb, hourly_disk_price_per_unit, hourly_reserve_quantum, \
    traffic_reset_enabled, traffic_reset_price, is_active, is_sold_out, sort_order, sla_guarantee";

/// db/package-plans.ts calculateMonthlyPrice (cents; f64 division like JS).
fn calculate_monthly_price_f64(plan: &PlanRow) -> f64 {
    let price = plan.price.to_f64().unwrap_or(0.0);
    let cycle = std::cmp::max(plan.billing_cycle, 1);
    price / cycle as f64
}

/// packages.ts serializePackagePlan (cents -> Number() at the boundary).
fn serialize_plan(plan: &PlanRow, instance_type: Option<&str>) -> Value {
    json!({
        "id": plan.id,
        "name": plan.name,
        "description": plan.description,
        "cpu": plan.cpu,
        "memory": plan.memory,
        "disk": plan.disk,
        "portLimit": plan.port_limit,
        "snapshotLimit": plan.snapshot_limit,
        "backupLimit": plan.backup_limit,
        "siteLimit": plan.site_limit,
        "swapSize": if instance_type == Some("vm") { 0 } else { plan.swap_size },
        "trafficLimit": plan.traffic_limit.to_string(),
        "trafficLimitSpeed": plan.traffic_limit_speed,
        "trafficBillingMode": plan.traffic_billing_mode,
        "trafficUnitPrice": num(plan.traffic_unit_price),
        "billingMode": plan.billing_mode,
        "price": num(plan.price),
        "billingCycle": plan.billing_cycle,
        "setupFee": num(plan.setup_fee),
        "hourlyMinCpu": plan.hourly_min_cpu,
        "hourlyCpuUnitPercent": plan.hourly_cpu_unit_percent,
        "hourlyCpuPricePerUnit": fixed_dp(plan.hourly_cpu_price_per_unit, 8),
        "hourlyMinMemoryMb": plan.hourly_min_memory_mb,
        "hourlyMemoryUnitMb": plan.hourly_memory_unit_mb,
        "hourlyMemoryPricePerUnit": fixed_dp(plan.hourly_memory_price_per_unit, 8),
        "hourlyMinDiskMb": plan.hourly_min_disk_mb,
        "hourlyDiskUnitMb": plan.hourly_disk_unit_mb,
        "hourlyDiskPricePerUnit": fixed_dp(plan.hourly_disk_price_per_unit, 8),
        "hourlyReserveQuantum": fixed_dp(plan.hourly_reserve_quantum, 8),
        "trafficResetEnabled": plan.traffic_reset_enabled,
        "trafficResetPrice": num(plan.traffic_reset_price),
        "monthlyPrice": js_json_number(calculate_monthly_price_f64(plan)),
        "isActive": plan.is_active,
        "isSoldOut": plan.is_sold_out,
        "sortOrder": plan.sort_order,
        "slaGuarantee": match plan.sla_guarantee {
            Some(d) if d != Decimal::ZERO => json!(num(d)),
            _ => Value::Null,
        },
    })
}

/// db/packages.ts summarizePackagePlans -> PackagePlanSummary.
fn plan_summary_json(plans: &[PlanRow]) -> Value {
    let available: Vec<&PlanRow> =
        plans.iter().filter(|p| p.is_active && !p.is_sold_out).collect();
    let sold_out_count = plans.iter().filter(|p| p.is_active && p.is_sold_out).count();
    let metric: Vec<&PlanRow> = if !available.is_empty() {
        available.clone()
    } else {
        plans.iter().collect()
    };
    let price_metric: Vec<&PlanRow> = metric
        .iter()
        .copied()
        .filter(|p| p.billing_mode != "hourly")
        .collect();

    let number_range = |mut values: Vec<f64>| -> (Value, Value) {
        if values.is_empty() {
            return (Value::Null, Value::Null);
        }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        (
            js_json_number(values[0]),
            js_json_number(values[values.len() - 1]),
        )
    };

    let (min_price, max_price) = number_range(
        price_metric
            .iter()
            .map(|p| p.price.to_f64().unwrap_or(0.0))
            .collect(),
    );
    let (min_monthly, max_monthly) = number_range(
        price_metric
            .iter()
            .map(|p| calculate_monthly_price_f64(p))
            .collect(),
    );
    let (min_cpu, max_cpu) = number_range(metric.iter().map(|p| p.cpu as f64).collect());
    let (min_memory, max_memory) = number_range(metric.iter().map(|p| p.memory as f64).collect());
    let (min_disk, max_disk) = number_range(metric.iter().map(|p| p.disk as f64).collect());

    // getBigIntStringRange: BigInt(value || '0'), invalid -> 0n, only > 0 kept.
    let bigint_range = |values: Vec<String>| -> (Value, Value) {
        let valid: Vec<i128> = values
            .into_iter()
            .map(|v| i128::from_str(v.trim()).unwrap_or(0))
            .filter(|v| *v > 0)
            .collect();
        if valid.is_empty() {
            return (Value::Null, Value::Null);
        }
        let min = valid.iter().min().unwrap();
        let max = valid.iter().max().unwrap();
        (json!(min.to_string()), json!(max.to_string()))
    };
    let (min_traffic, max_traffic) =
        bigint_range(metric.iter().map(|p| p.traffic_limit.to_string()).collect());
    let (min_speed, max_speed) = bigint_range(
        metric
            .iter()
            .map(|p| {
                if p.traffic_limit_speed.is_empty() {
                    "0".to_string()
                } else {
                    p.traffic_limit_speed.clone()
                }
            })
            .collect(),
    );

    json!({
        "total": plans.len(),
        "availableCount": available.len(),
        "soldOutCount": sold_out_count,
        "inactiveCount": plans.iter().filter(|p| !p.is_active).count(),
        "minPrice": min_price,
        "maxPrice": max_price,
        "minMonthlyPrice": min_monthly,
        "maxMonthlyPrice": max_monthly,
        "minCpu": min_cpu,
        "maxCpu": max_cpu,
        "minMemory": min_memory,
        "maxMemory": max_memory,
        "minDisk": min_disk,
        "maxDisk": max_disk,
        "minTrafficLimit": min_traffic,
        "maxTrafficLimit": max_traffic,
        "minTrafficLimitSpeed": min_speed,
        "maxTrafficLimitSpeed": max_speed,
    })
}

// ===========================================================================
// db helpers — packages (port of db/packages.ts)
// ===========================================================================

async fn fetch_own_packages(
    state: &SharedAppState,
    active_only: bool,
    user_id_eq: Option<i32>,
    owner_role: Option<&str>,
) -> Result<Vec<OwnPackageRow>, ApiError> {
    let mut sql = String::from(OWN_PACKAGE_SELECT);
    let mut clauses: Vec<String> = Vec::new();
    if active_only {
        clauses.push("p.active = true".to_string());
    }
    if user_id_eq.is_some() {
        clauses.push("p.user_id = $1".to_string());
    }
    if let Some(role) = owner_role {
        let op = if role == "admin" { "=" } else { "<>" };
        clauses.push(format!("u.role {op} $2::\"UserRole\""));
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY p.id ASC");

    let mut q = sqlx::query_as::<_, OwnPackageRow>(&sql);
    if let Some(uid) = user_id_eq {
        q = q.bind(uid);
    }
    if let Some(role) = owner_role {
        q = q.bind(role);
    }
    Ok(q.fetch_all(&state.db).await?)
}

async fn fetch_package_by_id(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<OwnPackageRow>, ApiError> {
    let sql = format!("{OWN_PACKAGE_SELECT} WHERE p.id = $1");
    Ok(sqlx::query_as::<_, OwnPackageRow>(&sql)
        .bind(id)
        .fetch_optional(&state.db)
        .await?)
}

async fn get_package_by_user_and_name(
    state: &SharedAppState,
    user_id: i32,
    name: &str,
) -> Result<Option<OwnPackageRow>, ApiError> {
    let sql = format!("{OWN_PACKAGE_SELECT} WHERE p.user_id = $1 AND p.name = $2");
    Ok(sqlx::query_as::<_, OwnPackageRow>(&sql)
        .bind(user_id)
        .bind(name)
        .fetch_optional(&state.db)
        .await?)
}

/// packageHosts rows (pool binding + traffic multiplier) grouped by package.
#[derive(Debug, Clone)]
struct PackageHostBinding {
    host_id: i32,
    storage_pool_name: Option<String>,
    traffic_multiplier: f64,
}

async fn fetch_package_host_bindings(
    state: &SharedAppState,
    package_ids: &[i32],
) -> Result<HashMap<i32, Vec<PackageHostBinding>>, ApiError> {
    if package_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(i32, i32, Option<String>, Decimal)> = sqlx::query_as(
        "SELECT package_id, host_id, storage_pool_name, traffic_multiplier \
         FROM package_hosts WHERE package_id = ANY($1) ORDER BY id ASC",
    )
    .bind(package_ids)
    .fetch_all(&state.db)
    .await?;
    let mut result: HashMap<i32, Vec<PackageHostBinding>> = HashMap::new();
    for (package_id, host_id, pool, multiplier) in rows {
        let m = normalize_traffic_multiplier_f(multiplier.to_f64().unwrap_or(1.0))
            .map_err(ApiError::internal)?;
        result.entry(package_id).or_default().push(PackageHostBinding {
            host_id,
            storage_pool_name: pool,
            traffic_multiplier: m,
        });
    }
    Ok(result)
}

/// (host_ids, host_storage_pools, host_traffic_multipliers) JSON triple.
fn bindings_json(bindings: &[PackageHostBinding]) -> (Value, Value, Value) {
    let host_ids: Vec<Value> = bindings.iter().map(|b| json!(b.host_id)).collect();
    let mut pools = Map::new();
    let mut multipliers = Map::new();
    for b in bindings {
        pools.insert(b.host_id.to_string(), json!(b.storage_pool_name));
        multipliers.insert(b.host_id.to_string(), json!(b.traffic_multiplier));
    }
    (json!(host_ids), Value::Object(pools), Value::Object(multipliers))
}

/// db/packages.ts getAllPackages row -> JSON object (snake_case mapping).
fn own_package_base_json(row: &OwnPackageRow, bindings: &[PackageHostBinding]) -> Map<String, Value> {
    let (host_ids, pools, multipliers) = bindings_json(bindings);
    let mut obj = Map::new();
    obj.insert("id".into(), json!(row.id));
    obj.insert("user_id".into(), json!(row.user_id));
    obj.insert("name".into(), json!(row.name));
    obj.insert("description".into(), json!(row.description));
    obj.insert("cpu_max".into(), json!(row.cpu_max));
    obj.insert("memory_max".into(), json!(row.memory_max));
    obj.insert("disk_max".into(), json!(row.disk_max));
    obj.insert("bandwidth_max".into(), json!(row.bandwidth_max));
    obj.insert("network_mode".into(), json!(row.network_mode));
    obj.insert("instance_type".into(), json!(row.instance_type));
    obj.insert("privileged".into(), json!(if row.privileged { 1 } else { 0 }));
    obj.insert("nested".into(), json!(if row.nested { 1 } else { 0 }));
    obj.insert("active".into(), json!(if row.active { 1 } else { 0 }));
    obj.insert("port_limit".into(), json!(row.port_limit));
    obj.insert("snapshot_limit".into(), json!(row.snapshot_limit));
    obj.insert("backup_limit".into(), json!(row.backup_limit));
    obj.insert("site_limit".into(), json!(row.site_limit));
    obj.insert(
        "monthly_traffic_limit".into(),
        match row.monthly_traffic_limit {
            Some(v) => json!(v.to_string()),
            None => Value::Null,
        },
    );
    obj.insert("io_limit_mode".into(), json!(row.io_limit_mode));
    obj.insert("limits_read".into(), json!(row.limits_read));
    obj.insert("limits_write".into(), json!(row.limits_write));
    obj.insert("limits_read_iops".into(), json!(row.limits_read_iops));
    obj.insert("limits_write_iops".into(), json!(row.limits_write_iops));
    obj.insert("limits_ingress".into(), json!(row.limits_ingress));
    obj.insert("limits_egress".into(), json!(row.limits_egress));
    obj.insert("limits_processes".into(), json!(row.limits_processes));
    obj.insert("limits_cpu_priority".into(), json!(row.limits_cpu_priority));
    obj.insert("boot_autostart".into(), json!(row.boot_autostart));
    obj.insert("boot_autostart_priority".into(), json!(row.boot_autostart_priority));
    obj.insert("boot_autostart_delay".into(), json!(row.boot_autostart_delay));
    obj.insert("boot_host_shutdown_timeout".into(), json!(row.boot_host_shutdown_timeout));
    obj.insert("global_shared".into(), json!(row.global_shared));
    // TS: value ? Number(value) : (value === null ? null : undefined) — a 0
    // multiplier is falsy and the key is omitted.
    match row.global_quota_multiplier {
        Some(d) if d != Decimal::ZERO => {
            obj.insert("global_quota_multiplier".into(), json!(num(d)));
        }
        Some(_) => {}
        None => {
            obj.insert("global_quota_multiplier".into(), Value::Null);
        }
    }
    // global_max_instances: value when non-null, key omitted otherwise.
    if let Some(v) = row.global_max_instances {
        obj.insert("global_max_instances".into(), json!(v));
    }
    obj.insert(
        "required_package_id".into(),
        row.required_package_id.map(|v| json!(v)).unwrap_or(Value::Null),
    );
    obj.insert(
        "required_package_name".into(),
        row.required_package_name.clone().map(|v| json!(v)).unwrap_or(Value::Null),
    );
    obj.insert("allow_instance_deletion".into(), json!(row.allow_instance_deletion));
    obj.insert("destroy_traffic_limit".into(), json!(row.destroy_traffic_limit.to_string()));
    obj.insert("created_at".into(), json!(iso(row.created_at)));
    obj.insert("owner_username".into(), json!(row.owner_username));
    obj.insert("is_own".into(), json!(true));
    obj.insert("host_ids".into(), host_ids);
    obj.insert("host_storage_pools".into(), pools);
    obj.insert("host_traffic_multipliers".into(), multipliers);
    obj
}

async fn get_normal_instance_counts_by_packages(
    state: &SharedAppState,
    package_ids: &[i32],
) -> Result<HashMap<i32, i64>, ApiError> {
    let mut valid: Vec<i32> = package_ids.to_vec();
    valid.retain(|id| *id > 0);
    valid.sort();
    valid.dedup();
    if valid.is_empty() {
        return Ok(HashMap::new());
    }
    let status_list = NORMAL_PACKAGE_INSTANCE_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let direct: Vec<(Option<i32>, i64)> = sqlx::query_as(&format!(
        "SELECT package_id, COUNT(*) FROM instances \
         WHERE package_id = ANY($1) AND status IN ({status_list}) GROUP BY package_id"
    ))
    .bind(&valid)
    .fetch_all(&state.db)
    .await?;
    let plan_only: Vec<(i32, i64)> = sqlx::query_as(&format!(
        "SELECT pp.package_id, COUNT(*) FROM instances i \
         JOIN package_plans pp ON pp.id = i.package_plan_id \
         WHERE i.package_id IS NULL AND pp.package_id = ANY($1) \
         AND i.status IN ({status_list}) GROUP BY pp.package_id"
    ))
    .bind(&valid)
    .fetch_all(&state.db)
    .await?;
    let mut result: HashMap<i32, i64> = HashMap::new();
    for (package_id, count) in direct {
        if let Some(pid) = package_id {
            result.insert(pid, count);
        }
    }
    for (package_id, count) in plan_only {
        *result.entry(package_id).or_insert(0) += count;
    }
    Ok(result)
}

async fn user_has_normal_instance_for_packages(
    state: &SharedAppState,
    user_id: i32,
    package_ids: &[i32],
) -> Result<HashMap<i32, bool>, ApiError> {
    let mut valid: Vec<i32> = package_ids.to_vec();
    valid.retain(|id| *id > 0);
    valid.sort();
    valid.dedup();
    let mut result: HashMap<i32, bool> = valid.iter().map(|id| (*id, false)).collect();
    if valid.is_empty() {
        return Ok(result);
    }
    let status_list = NORMAL_PACKAGE_INSTANCE_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let direct: Vec<(Option<i32>, i64)> = sqlx::query_as(&format!(
        "SELECT package_id, COUNT(*) FROM instances \
         WHERE user_id = $1 AND package_id = ANY($2) AND status IN ({status_list}) \
         GROUP BY package_id"
    ))
    .bind(user_id)
    .bind(&valid)
    .fetch_all(&state.db)
    .await?;
    let plan_only: Vec<(i32, i64)> = sqlx::query_as(&format!(
        "SELECT pp.package_id, COUNT(*) FROM instances i \
         JOIN package_plans pp ON pp.id = i.package_plan_id \
         WHERE i.user_id = $1 AND i.package_id IS NULL AND pp.package_id = ANY($2) \
         AND i.status IN ({status_list}) GROUP BY pp.package_id"
    ))
    .bind(user_id)
    .bind(&valid)
    .fetch_all(&state.db)
    .await?;
    for (package_id, count) in direct {
        if let Some(pid) = package_id {
            if count > 0 {
                result.insert(pid, true);
            }
        }
    }
    for (package_id, count) in plan_only {
        if count > 0 {
            result.insert(package_id, true);
        }
    }
    Ok(result)
}

async fn user_has_normal_instance_for_package(
    state: &SharedAppState,
    user_id: i32,
    package_id: i32,
) -> Result<bool, ApiError> {
    let status_list = NORMAL_PACKAGE_INSTANCE_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let row: (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM instances WHERE user_id = $1 \
         AND status IN ({status_list}) AND (package_id = $2 \
         OR package_plan_id IN (SELECT id FROM package_plans WHERE package_id = $2))"
    ))
    .bind(user_id)
    .bind(package_id)
    .fetch_one(&state.db)
    .await?;
    Ok(row.0 > 0)
}

async fn get_packages_depending_on_package(
    state: &SharedAppState,
    package_id: i32,
) -> Result<Vec<(i32, String)>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT id, name FROM packages WHERE required_package_id = $1 ORDER BY id ASC",
    )
    .bind(package_id)
    .fetch_all(&state.db)
    .await?)
}

async fn get_instance_count_by_package(
    state: &SharedAppState,
    package_id: i32,
) -> Result<i64, ApiError> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instances WHERE package_id = $1 AND status <> 'deleted'",
    )
    .bind(package_id)
    .fetch_one(&state.db)
    .await?;
    Ok(row.0)
}

// ---- prerequisite validation (db/packages.ts) ----

/// PACKAGE_PREREQUISITE_* failure carrying (code, message).
#[derive(Debug, Clone)]
struct PrereqError {
    code: &'static str,
    message: &'static str,
}

impl PrereqError {
    fn to_api(&self) -> ApiError {
        ApiError::with_message(self.code, StatusCode::BAD_REQUEST, self.message)
    }
    fn to_response(&self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": self.message, "code": self.code })),
        )
            .into_response()
    }
}

async fn validate_package_prerequisite_reference(
    exec: &mut sqlx::PgConnection,
    package_id: Option<i32>,
    required_package_id: Option<i32>,
    owner_user_id: Option<i32>,
) -> Result<(), PrereqError> {
    let Some(required) = required_package_id else {
        return Ok(());
    };
    if required <= 0 {
        return Err(PrereqError {
            code: "PACKAGE_PREREQUISITE_INVALID",
            message: "Required package is invalid",
        });
    }
    if Some(required) == package_id {
        return Err(PrereqError {
            code: "PACKAGE_PREREQUISITE_SELF",
            message: "Package cannot require itself",
        });
    }

    let mut cursor: Option<i32> = Some(required);
    let mut visited: HashSet<i32> = HashSet::new();
    while let Some(current) = cursor {
        if package_id == Some(current) {
            return Err(PrereqError {
                code: "PACKAGE_PREREQUISITE_CYCLE",
                message: "Package prerequisite cannot form a cycle",
            });
        }
        if visited.contains(&current) {
            return Err(PrereqError {
                code: "PACKAGE_PREREQUISITE_CYCLE",
                message: "Package prerequisite cannot form a cycle",
            });
        }
        visited.insert(current);
        let row: Option<(Option<i32>, i32)> = sqlx::query_as(
            "SELECT required_package_id, user_id FROM packages WHERE id = $1",
        )
        .bind(current)
        .fetch_optional(&mut *exec)
        .await
        .map_err(|_| PrereqError {
            code: "PACKAGE_PREREQUISITE_INVALID",
            message: "Required package does not exist",
        })?;
        let Some((next, owner)) = row else {
            return Err(PrereqError {
                code: "PACKAGE_PREREQUISITE_INVALID",
                message: "Required package does not exist",
            });
        };
        if let Some(expected) = owner_user_id {
            if owner != expected {
                return Err(PrereqError {
                    code: "PACKAGE_PREREQUISITE_SCOPE",
                    message: "Required package must belong to the same owner",
                });
            }
        }
        cursor = next;
    }
    Ok(())
}

/// validatePackagePrerequisiteReferenceLocked: its own Serializable tx + lock.
async fn validate_package_prerequisite_reference_locked(
    state: &SharedAppState,
    package_id: Option<i32>,
    required_package_id: Option<i32>,
    owner_user_id: Option<i32>,
) -> Result<(), ApiError> {
    let mut tx = state.db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await?;
    db::advisory_transaction_lock(&mut tx, PACKAGE_PREREQUISITE_LOCK_NAMESPACE, 1).await?;
    match validate_package_prerequisite_reference(
        &mut *tx,
        package_id,
        required_package_id,
        owner_user_id,
    )
    .await
    {
        Ok(()) => tx.commit().await.map_err(ApiError::from_sql),
        Err(e) => {
            let _ = tx.rollback().await;
            Err(e.to_api())
        }
    }
}

// ---- host / storage-pool validation for create/update ----

type NormalizedPools = HashMap<i32, Option<String>>;
type NormalizedMultipliers = HashMap<i32, f64>;

fn normalize_host_storage_pools(value: Option<&Value>) -> Result<NormalizedPools, String> {
    let mut result: NormalizedPools = HashMap::new();
    let Some(Value::Object(map)) = value else {
        return Ok(result);
    };
    for (key, pool_value) in map {
        let host_id = js_number_str(key);
        if host_id.is_nan() {
            return Err(format!("Invalid hostStoragePools key: {key}"));
        }
        let trimmed = match pool_value {
            Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
            _ => None,
        };
        result.insert(host_id as i32, trimmed);
    }
    Ok(result)
}

fn normalize_host_traffic_multipliers(value: Option<&Value>) -> Result<NormalizedMultipliers, String> {
    let mut result: NormalizedMultipliers = HashMap::new();
    let Some(Value::Object(map)) = value else {
        return Ok(result);
    };
    for (key, mult_value) in map {
        let host_id = js_number_str(key);
        if host_id.is_nan() {
            return Err(format!("Invalid hostTrafficMultipliers key: {key}"));
        }
        let m = normalize_traffic_multiplier_v(Some(mult_value))?;
        result.insert(host_id as i32, m);
    }
    Ok(result)
}

async fn validate_host_storage_pools(
    exec: &mut sqlx::PgConnection,
    host_ids: &[i32],
    pools: &NormalizedPools,
) -> Result<(), String> {
    for host_id in pools.keys() {
        if !host_ids.contains(host_id) {
            return Err(format!(
                "Storage pool mapping references an unbound host: {}",
                js_num_string(*host_id as f64)
            ));
        }
    }
    for (host_id, name) in pools.iter().filter_map(|(h, n)| n.as_ref().map(|n| (h, n))) {
        let row: Option<(i32,)> = sqlx::query_as(
            "SELECT id FROM storage_pools \
             WHERE host_id = $1 AND name = $2 AND purpose = 'instance_data'",
        )
        .bind(host_id)
        .bind(name)
        .fetch_optional(&mut *exec)
        .await
        .map_err(|e| format!("{e}"))?;
        if row.is_none() {
            return Err(format!(
                "Storage pool \"{name}\" is not available as a system disk pool on host {host_id}"
            ));
        }
    }
    Ok(())
}

fn validate_host_traffic_multipliers(
    host_ids: &[i32],
    multipliers: &NormalizedMultipliers,
) -> Result<(), String> {
    for host_id in multipliers.keys() {
        if !host_ids.contains(host_id) {
            return Err(format!(
                "Traffic multiplier mapping references an unbound host: {}",
                js_num_string(*host_id as f64)
            ));
        }
    }
    Ok(())
}

/// Resolved payload for db/packages.ts createPackage.
struct CreatePackageData {
    user_id: i32,
    name: String,
    description: Option<String>,
    cpu_max: i32,
    memory_max: i32,
    disk_max: i32,
    bandwidth_max: Option<i32>,
    network_mode: String,
    instance_type: String,
    privileged: bool,
    nested: bool,
    active: bool,
    port_limit: i32,
    snapshot_limit: i32,
    backup_limit: i32,
    site_limit: i32,
    monthly_traffic_limit: Option<i64>,
    io_limit_mode: String,
    limits_read: String,
    limits_write: String,
    limits_read_iops: i32,
    limits_write_iops: i32,
    limits_ingress: String,
    limits_egress: String,
    limits_processes: i32,
    limits_cpu_priority: i32,
    boot_autostart: bool,
    boot_autostart_priority: i32,
    boot_autostart_delay: i32,
    boot_host_shutdown_timeout: i32,
    global_shared: bool,
    global_max_instances: Option<i32>,
    required_package_id: Option<i32>,
    allow_instance_deletion: bool,
    destroy_traffic_limit: Option<i64>,
    host_ids: Vec<i32>,
    pools: NormalizedPools,
    multipliers: NormalizedMultipliers,
}

/// Error surface for create/update package failures (route catch blocks).
enum PackageOpError {
    /// PACKAGE_PREREQUISITE_*: `{ error: message, code }`.
    Prereq(PrereqError),
    /// Anything else: `{ error: message, code: 'INVALID_PACKAGE_CONFIG' }`.
    Config(String),
}

impl From<sqlx::Error> for PackageOpError {
    fn from(err: sqlx::Error) -> Self {
        PackageOpError::Config(format!("{err}"))
    }
}

impl From<PrereqError> for PackageOpError {
    fn from(e: PrereqError) -> Self {
        PackageOpError::Prereq(e)
    }
}

fn package_op_error_response(err: PackageOpError) -> Response {
    match err {
        PackageOpError::Prereq(e) => e.to_response(),
        PackageOpError::Config(message) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": message, "code": "INVALID_PACKAGE_CONFIG" })),
        )
            .into_response(),
    }
}

/// db/packages.ts createPackageUnchecked.
async fn create_package_db(
    exec: &mut sqlx::PgConnection,
    data: &CreatePackageData,
    is_admin: bool,
) -> Result<i32, PackageOpError> {
    if data.host_ids.is_empty() {
        return Err(PackageOpError::Config(
            "Package must bind at least one host".to_string(),
        ));
    }
    // Hosts must exist (admin: any host; user: own hosts).
    let count: (i64,) = if is_admin {
        sqlx::query_as("SELECT COUNT(*) FROM hosts WHERE id = ANY($1)").bind(&data.host_ids)
    } else {
        sqlx::query_as("SELECT COUNT(*) FROM hosts WHERE id = ANY($1) AND user_id = $2")
            .bind(&data.host_ids)
            .bind(data.user_id)
    }
    .fetch_one(&mut *exec)
    .await?;
    if count.0 != data.host_ids.len() as i64 {
        return Err(PackageOpError::Config(
            if is_admin {
                "Some hosts do not exist".to_string()
            } else {
                "All hosts must belong to the package owner".to_string()
            },
        ));
    }
    validate_host_storage_pools(&mut *exec, &data.host_ids, &data.pools)
        .await
        .map_err(PackageOpError::Config)?;
    validate_host_traffic_multipliers(&data.host_ids, &data.multipliers)
        .map_err(PackageOpError::Config)?;

    let id: (i32,) = sqlx::query_as(
        "INSERT INTO packages (user_id, name, description, cpu_max, memory_max, disk_max, \
         bandwidth_max, network_mode, instance_type, privileged, nested, active, \
         port_limit, snapshot_limit, backup_limit, site_limit, monthly_traffic_limit, \
         io_limit_mode, limits_read, limits_write, limits_read_iops, limits_write_iops, \
         limits_ingress, limits_egress, limits_processes, limits_cpu_priority, \
         boot_autostart, boot_autostart_priority, boot_autostart_delay, boot_host_shutdown_timeout, \
         global_shared, global_quota_multiplier, global_max_instances, required_package_id, \
         allow_instance_deletion, destroy_traffic_limit) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::\"NetworkMode\", $9::\"InstanceType\", \
         $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, \
         $27, $28, $29, $30, $31, $32, $33, $34, $35, $36) RETURNING id",
    )
    .bind(data.user_id)
    .bind(&data.name)
    .bind(data.description.clone())
    .bind(data.cpu_max)
    .bind(data.memory_max)
    .bind(data.disk_max)
    .bind(data.bandwidth_max)
    .bind(&data.network_mode)
    .bind(&data.instance_type)
    .bind(data.privileged)
    .bind(data.nested)
    .bind(data.active)
    .bind(data.port_limit)
    .bind(data.snapshot_limit)
    .bind(data.backup_limit)
    .bind(data.site_limit)
    .bind(data.monthly_traffic_limit)
    .bind(&data.io_limit_mode)
    .bind(&data.limits_read)
    .bind(&data.limits_write)
    .bind(data.limits_read_iops)
    .bind(data.limits_write_iops)
    .bind(&data.limits_ingress)
    .bind(&data.limits_egress)
    .bind(data.limits_processes)
    .bind(data.limits_cpu_priority)
    .bind(data.boot_autostart)
    .bind(data.boot_autostart_priority)
    .bind(data.boot_autostart_delay)
    .bind(data.boot_host_shutdown_timeout)
    .bind(data.global_shared)
    .bind(Option::<Decimal>::None) // globalQuotaMultiplier always null on create
    .bind(data.global_max_instances)
    .bind(data.required_package_id)
    .bind(data.allow_instance_deletion)
    .bind(data.destroy_traffic_limit.unwrap_or(5368709120))
    .fetch_one(&mut *exec)
    .await?;

    for host_id in &data.host_ids {
        let pool = data.pools.get(host_id).cloned().flatten();
        let multiplier = data.multipliers.get(host_id).copied().unwrap_or(1.0);
        sqlx::query(
            "INSERT INTO package_hosts (package_id, host_id, storage_pool_name, traffic_multiplier) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id.0)
        .bind(host_id)
        .bind(pool)
        .bind(Decimal::from_f64(multiplier).unwrap_or(Decimal::ONE))
        .execute(&mut *exec)
        .await?;
    }
    Ok(id.0)
}

/// Ordered bind list used to build dynamic UPDATE statements.
#[derive(Default)]
struct ParamList {
    values: Vec<ParamValue>,
}

enum ParamValue {
    Str(String),
    OptStr(Option<String>),
    I32(i32),
    OptI32(Option<i32>),
    I64(i64),
    OptI64(Option<i64>),
    Bool(bool),
    Dec(Decimal),
    OptDec(Option<Decimal>),
    Enum(String),
}

impl ParamList {
    fn push_str(&mut self, v: &str) {
        self.values.push(ParamValue::Str(v.to_string()));
    }
    fn push_opt_str(&mut self, v: Option<&str>) {
        self.values.push(ParamValue::OptStr(v.map(|s| s.to_string())));
    }
    fn push_i32(&mut self, v: i32) {
        self.values.push(ParamValue::I32(v));
    }
    fn push_opt_i32(&mut self, v: Option<i32>) {
        self.values.push(ParamValue::OptI32(v));
    }
    fn push_i64(&mut self, v: i64) {
        self.values.push(ParamValue::I64(v));
    }
    fn push_opt_i64(&mut self, v: Option<i64>) {
        self.values.push(ParamValue::OptI64(v));
    }
    fn push_bool(&mut self, v: bool) {
        self.values.push(ParamValue::Bool(v));
    }
    fn push_opt_dec(&mut self, v: Option<Decimal>) {
        self.values.push(ParamValue::OptDec(v));
    }
    fn push_enum(&mut self, v: &str) {
        self.values.push(ParamValue::Enum(v.to_string()));
    }
    fn bind_to(
        self,
        mut q: sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments> {
        for value in self.values {
            q = match value {
                ParamValue::Str(v) => q.bind(v),
                ParamValue::OptStr(v) => q.bind(v),
                ParamValue::I32(v) => q.bind(v),
                ParamValue::OptI32(v) => q.bind(v),
                ParamValue::I64(v) => q.bind(v),
                ParamValue::OptI64(v) => q.bind(v),
                ParamValue::Bool(v) => q.bind(v),
                ParamValue::Dec(v) => q.bind(v),
                ParamValue::OptDec(v) => q.bind(v),
                ParamValue::Enum(v) => q.bind(v),
            };
        }
        q
    }
    /// Variant for `query_as::<_, PlanRow>` statements (plan UPDATE ... RETURNING).
    fn bind_to_as(
        self,
        mut q: sqlx::query::QueryAs<
            '_,
            sqlx::Postgres,
            PlanRow,
            sqlx::postgres::PgArguments,
        >,
    ) -> sqlx::query::QueryAs<'_, sqlx::Postgres, PlanRow, sqlx::postgres::PgArguments> {
        for value in self.values {
            q = match value {
                ParamValue::Str(v) => q.bind(v),
                ParamValue::OptStr(v) => q.bind(v),
                ParamValue::I32(v) => q.bind(v),
                ParamValue::OptI32(v) => q.bind(v),
                ParamValue::I64(v) => q.bind(v),
                ParamValue::OptI64(v) => q.bind(v),
                ParamValue::Bool(v) => q.bind(v),
                ParamValue::Dec(v) => q.bind(v),
                ParamValue::OptDec(v) => q.bind(v),
                ParamValue::Enum(v) => q.bind(v),
            };
        }
        q
    }
}

/// Scalar column set for updatePackage. Option fields: None = not provided.
#[derive(Default)]
struct UpdatePackageData {
    name: Option<String>,
    description: Option<String>,
    cpu_max: Option<i32>,
    memory_max: Option<i32>,
    disk_max: Option<i32>,
    bandwidth_max: Option<i32>,
    network_mode: Option<String>,
    instance_type: Option<String>,
    privileged: Option<bool>,
    nested: Option<bool>,
    active: Option<bool>,
    port_limit: Option<i32>,
    snapshot_limit: Option<i32>,
    backup_limit: Option<i32>,
    site_limit: Option<i32>,
    monthly_traffic_limit: Option<Option<i64>>,
    io_limit_mode: Option<String>,
    limits_read: Option<String>,
    limits_write: Option<String>,
    limits_read_iops: Option<i32>,
    limits_write_iops: Option<i32>,
    limits_ingress: Option<String>,
    limits_egress: Option<String>,
    limits_processes: Option<i32>,
    limits_cpu_priority: Option<i32>,
    boot_autostart: Option<bool>,
    boot_autostart_priority: Option<i32>,
    boot_autostart_delay: Option<i32>,
    boot_host_shutdown_timeout: Option<i32>,
    global_shared: Option<bool>,
    global_quota_multiplier: Option<Option<Decimal>>,
    global_max_instances: Option<Option<i32>>,
    required_package_id: Option<Option<i32>>,
    allow_instance_deletion: Option<bool>,
    destroy_traffic_limit: Option<i64>,
    host_ids: Option<Vec<i32>>,
    pools: NormalizedPools,
    multipliers: NormalizedMultipliers,
    has_pools: bool,
    has_multipliers: bool,
}

/// db/packages.ts updatePackage: dynamic column update + package_hosts rewrite.
async fn update_package_db(
    state: &SharedAppState,
    package_id: i32,
    data: UpdatePackageData,
    is_admin: bool,
) -> Result<(), PackageOpError> {
    let needs_host_update =
        data.host_ids.is_some() || data.has_pools || data.has_multipliers;

    let mut tx = state.db.begin().await?;
    if data.required_package_id.is_some() {
        // Serializable tx guarded by the prerequisite lock (TS updatePackage).
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await?;
        db::advisory_transaction_lock(&mut tx, PACKAGE_PREREQUISITE_LOCK_NAMESPACE, 1).await?;
        let owner: Option<(i32,)> =
            sqlx::query_as("SELECT user_id FROM packages WHERE id = $1")
                .bind(package_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((owner_id,)) = owner else {
            let _ = tx.rollback().await;
            return Err(PackageOpError::Config("Package not found".to_string()));
        };
        validate_package_prerequisite_reference(
            &mut *tx,
            Some(package_id),
            data.required_package_id.unwrap_or(None),
            Some(owner_id),
        )
        .await?;
    }

    if needs_host_update {
        let current: Vec<(i32, Option<String>, Decimal)> = sqlx::query_as(
            "SELECT host_id, storage_pool_name, traffic_multiplier FROM package_hosts \
             WHERE package_id = $1 ORDER BY id ASC",
        )
        .bind(package_id)
        .fetch_all(&mut *tx)
        .await?;
        let current_pools: HashMap<i32, Option<String>> =
            current.iter().map(|(h, p, _)| (*h, p.clone())).collect();
        let current_multipliers: HashMap<i32, f64> = current
            .iter()
            .map(|(h, _, m)| {
                (
                    *h,
                    normalize_traffic_multiplier_f(m.to_f64().unwrap_or(1.0)).unwrap_or(1.0),
                )
            })
            .collect();

        let pkg_owner: Option<(i32,)> =
            sqlx::query_as("SELECT user_id FROM packages WHERE id = $1")
                .bind(package_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((pkg_owner_id,)) = pkg_owner else {
            let _ = tx.rollback().await;
            return Err(PackageOpError::Config("Package not found".to_string()));
        };

        let effective_host_ids: Vec<i32> = match &data.host_ids {
            Some(ids) => ids.clone(),
            None => current.iter().map(|(h, _, _)| *h).collect(),
        };
        if effective_host_ids.is_empty() {
            let _ = tx.rollback().await;
            return Err(PackageOpError::Config(
                "Package must bind at least one host".to_string(),
            ));
        }

        if let Some(host_ids) = &data.host_ids {
            let count: (i64,) = if is_admin {
                sqlx::query_as("SELECT COUNT(*) FROM hosts WHERE id = ANY($1)").bind(host_ids)
            } else {
                sqlx::query_as("SELECT COUNT(*) FROM hosts WHERE id = ANY($1) AND user_id = $2")
                    .bind(host_ids)
                    .bind(pkg_owner_id)
            }
            .fetch_one(&mut *tx)
            .await?;
            if count.0 != host_ids.len() as i64 {
                let _ = tx.rollback().await;
                return Err(PackageOpError::Config(
                    if is_admin {
                        "Some hosts do not exist".to_string()
                    } else {
                        "All hosts must belong to the package owner".to_string()
                    },
                ));
            }
        }

        validate_host_storage_pools(&mut *tx, &effective_host_ids, &data.pools)
            .await
            .map_err(PackageOpError::Config)?;
        validate_host_traffic_multipliers(&effective_host_ids, &data.multipliers)
            .map_err(PackageOpError::Config)?;

        if let Some(host_ids) = &data.host_ids {
            sqlx::query("DELETE FROM package_hosts WHERE package_id = $1")
                .bind(package_id)
                .execute(&mut *tx)
                .await?;
            for host_id in host_ids {
                let pool = data
                    .pools
                    .get(host_id)
                    .cloned()
                    .flatten()
                    .or_else(|| current_pools.get(host_id).cloned().flatten());
                let multiplier = data
                    .multipliers
                    .get(host_id)
                    .copied()
                    .or_else(|| current_multipliers.get(host_id).copied())
                    .unwrap_or(1.0);
                sqlx::query(
                    "INSERT INTO package_hosts (package_id, host_id, storage_pool_name, traffic_multiplier) \
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(package_id)
                .bind(host_id)
                .bind(pool)
                .bind(Decimal::from_f64(multiplier).unwrap_or(Decimal::ONE))
                .execute(&mut *tx)
                .await?;
            }
        } else {
            // Per-host updates for existing bindings (pools and/or multipliers).
            for (host_id, pool) in &data.pools {
                let result = sqlx::query(
                    "UPDATE package_hosts SET storage_pool_name = $3 \
                     WHERE package_id = $1 AND host_id = $2",
                )
                .bind(package_id)
                .bind(host_id)
                .bind(pool.clone())
                .execute(&mut *tx)
                .await?;
                if result.rows_affected() == 0 {
                    let _ = tx.rollback().await;
                    return Err(PackageOpError::Config(format!(
                        "Record to update not found: packageHost {package_id}:{host_id}"
                    )));
                }
            }
            for (host_id, multiplier) in &data.multipliers {
                let result = sqlx::query(
                    "UPDATE package_hosts SET traffic_multiplier = $3 \
                     WHERE package_id = $1 AND host_id = $2",
                )
                .bind(package_id)
                .bind(host_id)
                .bind(Decimal::from_f64(*multiplier).unwrap_or(Decimal::ONE))
                .execute(&mut *tx)
                .await?;
                if result.rows_affected() == 0 {
                    let _ = tx.rollback().await;
                    return Err(PackageOpError::Config(format!(
                        "Record to update not found: packageHost {package_id}:{host_id}"
                    )));
                }
            }
        }
    }

    // Scalar column updates (same param counter for placeholders and binds).
    let mut sets: Vec<String> = Vec::new();
    let mut binder = ParamList::default();
    macro_rules! set_col {
        ($col:expr, $bind:expr) => {{
            let idx = binder.values.len() + 1;
            sets.push(format!("{} = ${}", $col, idx));
            $bind;
        }};
    }
    if let Some(v) = data.name.as_deref() {
        set_col!("name", binder.push_str(v));
    }
    if let Some(v) = &data.description {
        set_col!("description", binder.push_opt_str(Some(v.as_str())));
    }
    if let Some(v) = data.cpu_max {
        set_col!("cpu_max", binder.push_i32(v));
    }
    if let Some(v) = data.memory_max {
        set_col!("memory_max", binder.push_i32(v));
    }
    if let Some(v) = data.disk_max {
        set_col!("disk_max", binder.push_i32(v));
    }
    if let Some(v) = data.bandwidth_max {
        set_col!("bandwidth_max", binder.push_i32(v));
    }
    if let Some(v) = &data.network_mode {
        set_col!("network_mode", binder.push_enum(v));
    }
    if let Some(v) = &data.instance_type {
        set_col!("instance_type", binder.push_enum(v));
    }
    if let Some(v) = data.privileged {
        set_col!("privileged", binder.push_bool(v));
    }
    if let Some(v) = data.nested {
        set_col!("nested", binder.push_bool(v));
    }
    if let Some(v) = data.active {
        set_col!("active", binder.push_bool(v));
    }
    if let Some(v) = data.port_limit {
        set_col!("port_limit", binder.push_i32(v));
    }
    if let Some(v) = data.snapshot_limit {
        set_col!("snapshot_limit", binder.push_i32(v));
    }
    if let Some(v) = data.backup_limit {
        set_col!("backup_limit", binder.push_i32(v));
    }
    if let Some(v) = data.site_limit {
        set_col!("site_limit", binder.push_i32(v));
    }
    if let Some(v) = data.monthly_traffic_limit {
        set_col!("monthly_traffic_limit", binder.push_opt_i64(v));
    }
    if let Some(v) = data.io_limit_mode.as_deref() {
        set_col!("io_limit_mode", binder.push_str(v));
    }
    if let Some(v) = data.limits_read.as_deref() {
        set_col!("limits_read", binder.push_str(v));
    }
    if let Some(v) = data.limits_write.as_deref() {
        set_col!("limits_write", binder.push_str(v));
    }
    if let Some(v) = data.limits_read_iops {
        set_col!("limits_read_iops", binder.push_i32(v));
    }
    if let Some(v) = data.limits_write_iops {
        set_col!("limits_write_iops", binder.push_i32(v));
    }
    if let Some(v) = data.limits_ingress.as_deref() {
        set_col!("limits_ingress", binder.push_str(v));
    }
    if let Some(v) = data.limits_egress.as_deref() {
        set_col!("limits_egress", binder.push_str(v));
    }
    if let Some(v) = data.limits_processes {
        set_col!("limits_processes", binder.push_i32(v));
    }
    if let Some(v) = data.limits_cpu_priority {
        set_col!("limits_cpu_priority", binder.push_i32(v));
    }
    if let Some(v) = data.boot_autostart {
        set_col!("boot_autostart", binder.push_bool(v));
    }
    if let Some(v) = data.boot_autostart_priority {
        set_col!("boot_autostart_priority", binder.push_i32(v));
    }
    if let Some(v) = data.boot_autostart_delay {
        set_col!("boot_autostart_delay", binder.push_i32(v));
    }
    if let Some(v) = data.boot_host_shutdown_timeout {
        set_col!("boot_host_shutdown_timeout", binder.push_i32(v));
    }
    if let Some(v) = data.global_shared {
        set_col!("global_shared", binder.push_bool(v));
    }
    if let Some(v) = data.global_quota_multiplier {
        set_col!("global_quota_multiplier", binder.push_opt_dec(v));
    }
    if let Some(v) = data.global_max_instances {
        set_col!("global_max_instances", binder.push_opt_i32(v));
    }
    if let Some(v) = data.required_package_id {
        set_col!("required_package_id", binder.push_opt_i32(v));
    }
    if let Some(v) = data.allow_instance_deletion {
        set_col!("allow_instance_deletion", binder.push_bool(v));
    }
    if let Some(v) = data.destroy_traffic_limit {
        set_col!("destroy_traffic_limit", binder.push_i64(v));
    }

    if !sets.is_empty() {
        let sql = format!(
            "UPDATE packages SET {} WHERE id = ${}",
            sets.join(", "),
            binder.values.len() + 1
        );
        binder
            .bind_to(sqlx::query(&sql))
            .bind(package_id)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(())
}

async fn delete_package_db(state: &SharedAppState, package_id: i32) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM packages WHERE id = $1")
        .bind(package_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

// ---- host resource usage + sold-out computation ----

#[derive(Debug, Clone)]
struct HostUsage {
    host_id: i32,
    host_status: String,
    cpu_allowance_max: i32,
    memory_max: i32,
    cpu_used: i64,
    memory_used: i64,
}

/// Per-package host bindings with instance usage aggregated per host.
async fn fetch_host_usage_for_packages(
    state: &SharedAppState,
    package_ids: &[i32],
) -> Result<HashMap<i32, Vec<HostUsage>>, ApiError> {
    if package_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let statuses = HOST_RESOURCE_INSTANCE_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let rows: Vec<(i32, i32, String, i32, i32, Option<i64>, Option<i64>)> = sqlx::query_as(&format!(
        "SELECT ph.package_id, h.id, h.status::text AS host_status, \
         h.cpu_allowance_max, h.memory_max, i.cpu, i.memory \
         FROM package_hosts ph \
         JOIN hosts h ON h.id = ph.host_id \
         LEFT JOIN instances i ON i.host_id = h.id AND i.status IN ({statuses}) \
         WHERE ph.package_id = ANY($1) ORDER BY ph.id ASC"
    ))
    .bind(package_ids)
    .fetch_all(&state.db)
    .await?;

    let mut result: HashMap<i32, Vec<HostUsage>> = HashMap::new();
    let mut index: HashMap<(i32, i32), usize> = HashMap::new();
    for (package_id, host_id, host_status, cpu_max, mem_max, cpu, memory) in rows {
        let list = result.entry(package_id).or_default();
        let entry_idx = match index.get(&(package_id, host_id)) {
            Some(i) => *i,
            None => {
                list.push(HostUsage {
                    host_id,
                    host_status: host_status.clone(),
                    cpu_allowance_max: cpu_max,
                    memory_max: mem_max,
                    cpu_used: 0,
                    memory_used: 0,
                });
                let i = list.len() - 1;
                index.insert((package_id, host_id), i);
                i
            }
        };
        let host = &mut list[entry_idx];
        host.host_status = host_status;
        host.cpu_used += cpu.unwrap_or(0);
        host.memory_used += memory.unwrap_or(0);
    }
    Ok(result)
}

/// db/storage-pools.ts getHostIdsWithInstanceDataPool.
async fn get_host_ids_with_instance_data_pool(
    state: &SharedAppState,
    host_ids: &[i32],
) -> Result<HashSet<i32>, ApiError> {
    if host_ids.is_empty() {
        return Ok(HashSet::new());
    }
    let rows: Vec<(i32,)> = sqlx::query_as(
        "SELECT DISTINCT host_id FROM storage_pools \
         WHERE host_id = ANY($1) AND purpose = 'instance_data'",
    )
    .bind(host_ids)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|(h,)| h).collect())
}

fn sold_out_for_package(
    hosts: Option<&Vec<HostUsage>>,
    plans: Option<&Vec<(i32, i32, bool)>>,
    pool_ready: &HashSet<i32>,
) -> bool {
    let Some(hosts) = hosts else {
        return true; // 没有绑定宿主机，视为售罄
    };
    if hosts.is_empty() {
        return true;
    }
    let plans = plans.cloned().unwrap_or_default();
    let available_plans: Vec<(i32, i32)> = plans
        .iter()
        .filter(|(_, _, sold_out)| !sold_out)
        .map(|(cpu, memory, _)| (*cpu, *memory))
        .collect();
    let (min_cpu, min_memory) = if !plans.is_empty() {
        if available_plans.is_empty() {
            return true; // 所有活跃方案都手动售罄
        }
        let min_cpu = available_plans.iter().map(|(c, _)| *c).min().unwrap();
        let min_memory = available_plans.iter().map(|(_, m)| *m).min().unwrap();
        (min_cpu, min_memory)
    } else {
        (15, 128) // 免费套餐最低配置
    };
    for host in hosts {
        if host.host_status != "online" {
            continue;
        }
        if host.cpu_allowance_max == 0
            || host.memory_max == 0
            || !pool_ready.contains(&host.host_id)
        {
            continue;
        }
        let cpu_available = host.cpu_allowance_max as i64 - host.cpu_used;
        let memory_available = host.memory_max as i64 - host.memory_used;
        if cpu_available >= min_cpu as i64 && memory_available >= min_memory as i64 {
            return false;
        }
    }
    true
}

/// db/packages.ts checkPackagesSoldOut / checkPackageSoldOut.
async fn compute_sold_out(
    state: &SharedAppState,
    package_ids: &[i32],
) -> Result<HashMap<i32, bool>, ApiError> {
    let mut result: HashMap<i32, bool> = HashMap::new();
    if package_ids.is_empty() {
        return Ok(result);
    }
    let host_usage = fetch_host_usage_for_packages(state, package_ids).await?;
    let plans: Vec<(i32, i32, i32, bool)> = sqlx::query_as(
        "SELECT package_id, cpu, memory, is_sold_out FROM package_plans \
         WHERE package_id = ANY($1) AND is_active",
    )
    .bind(package_ids)
    .fetch_all(&state.db)
    .await?;
    let mut plans_by_package: HashMap<i32, Vec<(i32, i32, bool)>> = HashMap::new();
    for (package_id, cpu, memory, sold_out) in plans {
        plans_by_package
            .entry(package_id)
            .or_default()
            .push((cpu, memory, sold_out));
    }
    let all_host_ids: HashSet<i32> = host_usage.values().flatten().map(|h| h.host_id).collect();
    let host_id_list: Vec<i32> = all_host_ids.into_iter().collect();
    let pool_ready = get_host_ids_with_instance_data_pool(state, &host_id_list).await?;

    for package_id in package_ids {
        let sold = sold_out_for_package(
            host_usage.get(package_id),
            plans_by_package.get(package_id),
            &pool_ready,
        );
        result.insert(*package_id, sold);
    }
    Ok(result)
}

async fn increase_host_quota(
    state: &SharedAppState,
    host_id: i32,
    cpu_add: i32,
    memory_add: i32,
) -> Result<Option<(i32, i32, i64, i64)>, ApiError> {
    let updated: Option<(i32, i32)> = sqlx::query_as(
        "UPDATE hosts SET cpu_allowance_max = cpu_allowance_max + $2, \
         memory_max = memory_max + $3 WHERE id = $1 \
         RETURNING cpu_allowance_max, memory_max",
    )
    .bind(host_id)
    .bind(cpu_add)
    .bind(memory_add)
    .fetch_optional(&state.db)
    .await?;
    let Some((cpu_allowance_max, memory_max)) = updated else {
        return Ok(None);
    };
    let statuses = HOST_RESOURCE_INSTANCE_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let agg: (Option<i64>, Option<i64>) = sqlx::query_as(&format!(
        "SELECT SUM(cpu), SUM(memory) FROM instances \
         WHERE host_id = $1 AND status IN ({statuses})"
    ))
    .bind(host_id)
    .fetch_one(&state.db)
    .await?;
    Ok(Some((
        cpu_allowance_max,
        memory_max,
        agg.0.unwrap_or(0),
        agg.1.unwrap_or(0),
    )))
}

// ===========================================================================
// db helpers — package shares (port of db/package-shares.ts)
// ===========================================================================

async fn is_user_blocked_by_hoster<'e, E>(
    exec: E,
    blocker_id: i32,
    blocked_user_id: i32,
) -> Result<bool, ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    if blocker_id == blocked_user_id {
        return Ok(false);
    }
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM hosting_user_blocks WHERE blocker_id = $1 AND blocked_user_id = $2",
    )
    .bind(blocker_id)
    .bind(blocked_user_id)
    .fetch_optional(exec)
    .await?;
    Ok(row.is_some())
}

async fn get_blocker_ids_for_user(
    state: &SharedAppState,
    user_id: i32,
) -> Result<Vec<i32>, ApiError> {
    let rows: Vec<(i32,)> =
        sqlx::query_as("SELECT blocker_id FROM hosting_user_blocks WHERE blocked_user_id = $1")
            .bind(user_id)
            .fetch_all(&state.db)
            .await?;
    Ok(rows.into_iter().map(|(b,)| b).collect())
}

async fn get_active_hosting_zone_owner_ids(state: &SharedAppState) -> Result<Vec<i32>, ApiError> {
    let rows: Vec<(i32,)> =
        sqlx::query_as("SELECT owner_id FROM hosting_zones WHERE active = true")
            .fetch_all(&state.db)
            .await?;
    Ok(rows.into_iter().map(|(b,)| b).collect())
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct HostingZoneRow {
    id: i32,
    name: String,
    owner_id: i32,
    owner_username: String,
    logo_url: String,
    sort_order: i32,
}

const HOSTING_ZONE_SELECT: &str = "SELECT z.id, z.name, z.owner_id, u.username AS owner_username, \
    z.logo_url, z.sort_order \
    FROM hosting_zones z JOIN users u ON u.id = z.owner_id";

async fn get_hosting_zones_for_viewer(
    state: &SharedAppState,
    viewer_id: Option<i32>,
) -> Result<Vec<HostingZoneRow>, ApiError> {
    let blocker_ids = match viewer_id {
        Some(id) => get_blocker_ids_for_user(state, id).await?,
        None => Vec::new(),
    };
    let mut sql = String::from(HOSTING_ZONE_SELECT);
    sql.push_str(" WHERE z.active = true");
    if !blocker_ids.is_empty() {
        sql.push_str(" AND z.owner_id <> ALL($1)");
    }
    sql.push_str(" ORDER BY z.sort_order ASC, z.id ASC");
    let mut q = sqlx::query_as::<_, HostingZoneRow>(&sql);
    if !blocker_ids.is_empty() {
        q = q.bind(&blocker_ids);
    }
    Ok(q.fetch_all(&state.db).await?)
}

async fn get_active_hosting_zone_by_id(
    state: &SharedAppState,
    zone_id: i64,
    viewer_id: Option<i32>,
) -> Result<Option<HostingZoneRow>, ApiError> {
    let sql = format!("{HOSTING_ZONE_SELECT} WHERE z.id = $1 AND z.active = true");
    let Some(zone) = sqlx::query_as::<_, HostingZoneRow>(&sql)
        .bind(zone_id)
        .fetch_optional(&state.db)
        .await?
    else {
        return Ok(None);
    };
    if let Some(viewer) = viewer_id {
        if is_user_blocked_by_hoster(&state.db, zone.owner_id, viewer).await? {
            return Ok(None);
        }
    }
    Ok(Some(zone))
}

const SHARED_PACKAGE_SELECT: &str = "SELECT p.id, p.name, p.description, p.cpu_max, p.memory_max, \
    p.disk_max, p.bandwidth_max, p.network_mode::text AS network_mode, \
    p.instance_type::text AS instance_type, p.port_limit, p.snapshot_limit, p.backup_limit, \
    p.site_limit, p.monthly_traffic_limit, p.nested, p.privileged, p.allow_instance_deletion, \
    p.destroy_traffic_limit, \
    (SELECT COALESCE(array_agg(ph.host_id ORDER BY ph.id), '{}') FROM package_hosts ph \
     WHERE ph.package_id = p.id) AS host_ids, \
    u.id AS owner_id, u.username AS owner_username, {shared_at} AS shared_at, \
    {is_global} AS is_global_shared, {quota_multiplier} AS quota_multiplier, \
    {max_instances} AS max_instances, p.required_package_id, rp.name AS required_package_name \
    FROM packages p \
    JOIN users u ON u.id = p.user_id \
    LEFT JOIN packages rp ON rp.id = p.required_package_id \
    {extra_join} \
    WHERE p.active = true AND u.role <> '' {extra_where}";

/// db/package-shares.ts getGlobalSharedPackages (official packages).
async fn get_global_shared_packages(
    state: &SharedAppState,
) -> Result<Vec<SharedPackageRow>, ApiError> {
    let sql = SHARED_PACKAGE_SELECT
        .replace("{shared_at}", "p.created_at")
        .replace("{is_global}", "true")
        .replace("{quota_multiplier}", "NULL::numeric")
        .replace("{max_instances}", "p.global_max_instances")
        .replace("{extra_join}", "")
        .replace("{extra_where}", "AND p.global_shared = true AND u.role = 'admin'")
        + " ORDER BY p.created_at DESC";
    Ok(sqlx::query_as::<_, SharedPackageRow>(&sql)
        .fetch_all(&state.db)
        .await?)
}

/// db/package-shares.ts getHostedMarketPackages.
async fn get_hosted_market_packages(
    state: &SharedAppState,
    viewer_id: Option<i32>,
    owner_id: Option<i32>,
    exclude_owner_ids: &[i32],
) -> Result<Vec<SharedPackageRow>, ApiError> {
    let blocker_ids = match viewer_id {
        Some(id) => get_blocker_ids_for_user(state, id).await?,
        None => Vec::new(),
    };
    let mut excluded: Vec<i32> = blocker_ids;
    for id in exclude_owner_ids {
        if !excluded.contains(id) {
            excluded.push(*id);
        }
    }
    if let Some(owner) = owner_id {
        if excluded.contains(&owner) {
            return Ok(Vec::new());
        }
    }

    let mut sql = SHARED_PACKAGE_SELECT
        .replace("{shared_at}", "p.created_at")
        .replace("{is_global}", "true")
        .replace("{quota_multiplier}", "NULL::numeric")
        .replace("{max_instances}", "p.global_max_instances")
        .replace("{extra_join}", "")
        .replace("{extra_where}", "AND p.global_shared = true")
        + " AND u.role <> 'admin' ORDER BY p.created_at DESC";
    if owner_id.is_some() {
        sql.push_str(" AND p.user_id = $1");
    } else if !excluded.is_empty() {
        sql.push_str(" AND p.user_id <> ALL($1)");
    }
    let mut q = sqlx::query_as::<_, SharedPackageRow>(&sql);
    if let Some(owner) = owner_id {
        q = q.bind(owner);
    } else if !excluded.is_empty() {
        q = q.bind(&excluded);
    }
    Ok(q.fetch_all(&state.db).await?)
}

/// db/package-shares.ts getSharedToUser (好友共享).
async fn get_shared_to_user(
    state: &SharedAppState,
    user_id: i32,
) -> Result<Vec<SharedPackageRow>, ApiError> {
    let blocker_ids = get_blocker_ids_for_user(state, user_id).await?;
    let mut sql = SHARED_PACKAGE_SELECT
        .replace("{shared_at}", "s.created_at")
        .replace("{is_global}", "false")
        .replace("{quota_multiplier}", "s.quota_multiplier")
        .replace("{max_instances}", "s.max_instances")
        .replace(
            "{extra_join}",
            "JOIN package_shares s ON s.package_id = p.id",
        )
        .replace("{extra_where}", "AND s.shared_to_id = $1")
        + " ORDER BY s.created_at DESC";
    let mut q = sqlx::query_as::<_, SharedPackageRow>(&sql).bind(user_id);
    if !blocker_ids.is_empty() {
        sql = sql.replace(
            " ORDER BY s.created_at DESC",
            " AND s.owner_id <> ALL($2) ORDER BY s.created_at DESC",
        );
        q = sqlx::query_as::<_, SharedPackageRow>(&sql)
            .bind(user_id)
            .bind(&blocker_ids);
    }
    Ok(q.fetch_all(&state.db).await?)
}

/// db/package-shares.ts canUserAccessPackage.
async fn can_user_access_package(
    state: &SharedAppState,
    user_id: i32,
    package_id: i32,
) -> Result<bool, ApiError> {
    let row: Option<(i32, bool, bool)> = sqlx::query_as(
        "SELECT user_id, active, global_shared FROM packages WHERE id = $1",
    )
    .bind(package_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((owner_id, active, global_shared)) = row else {
        return Ok(false);
    };
    if owner_id == user_id {
        return Ok(true);
    }
    if is_user_blocked_by_hoster(&state.db, owner_id, user_id).await? {
        return Ok(false);
    }
    if !active {
        return Ok(false);
    }
    if global_shared {
        return Ok(true);
    }
    let share: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM package_shares WHERE package_id = $1 AND shared_to_id = $2",
    )
    .bind(package_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(share.is_some())
}

/// db/package-shares.ts getPackageShareForUser (global-shared quota info only).
/// Returns (quotaMultiplier=null, maxInstances) when the package is a global
/// share owned by someone else and the viewer is not blocked.
async fn get_package_share_for_user(
    state: &SharedAppState,
    package_id: i32,
    user_id: i32,
) -> Result<Option<((), i32)>, ApiError> {
    let row: Option<(bool, Option<i32>, i32)> = sqlx::query_as(
        "SELECT global_shared, global_max_instances, user_id FROM packages WHERE id = $1",
    )
    .bind(package_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((global_shared, global_max_instances, owner_id)) = row else {
        return Ok(None);
    };
    if global_shared && owner_id != user_id {
        if is_user_blocked_by_hoster(&state.db, owner_id, user_id).await? {
            return Ok(None);
        }
        return Ok(Some((
            (),
            normalize_public_package_max_instances(global_max_instances.map(|v| json!(v)).as_ref())
                as i32,
        )));
    }
    Ok(None)
}

async fn get_shared_package_usage(
    state: &SharedAppState,
    package_id: i32,
    user_id: i32,
) -> Result<(i64, i64, i64), ApiError> {
    let row: (i64, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT COUNT(*), SUM(cpu), SUM(memory) FROM instances \
         WHERE user_id = $1 AND package_id = $2 AND status IN ('running','stopped')",
    )
    .bind(user_id)
    .bind(package_id)
    .fetch_one(&state.db)
    .await?;
    Ok((row.0, row.1.unwrap_or(0), row.2.unwrap_or(0)))
}

// ===========================================================================
// db helpers — package plans (port of db/package-plans.ts)
// ===========================================================================

async fn get_plans_by_package_id(
    state: &SharedAppState,
    package_id: i32,
    active_only: bool,
) -> Result<Vec<PlanRow>, ApiError> {
    let mut sql = String::from(PLAN_SELECT);
    sql.push_str(" WHERE package_id = $1");
    if active_only {
        sql.push_str(" AND is_active = true");
    }
    sql.push_str(" ORDER BY sort_order ASC");
    Ok(sqlx::query_as::<_, PlanRow>(&sql)
        .bind(package_id)
        .fetch_all(&state.db)
        .await?)
}

async fn get_plan_by_id(state: &SharedAppState, plan_id: i32) -> Result<Option<PlanRow>, ApiError> {
    let sql = format!("{PLAN_SELECT} WHERE id = $1");
    Ok(sqlx::query_as::<_, PlanRow>(&sql)
        .bind(plan_id)
        .fetch_optional(&state.db)
        .await?)
}

async fn get_plans_for_packages(
    state: &SharedAppState,
    package_ids: &[i32],
) -> Result<Vec<PlanRow>, ApiError> {
    if package_ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "{PLAN_SELECT} WHERE package_id = ANY($1) AND is_active = true ORDER BY sort_order ASC"
    );
    Ok(sqlx::query_as::<_, PlanRow>(&sql)
        .bind(package_ids)
        .fetch_all(&state.db)
        .await?)
}

/// packages.ts batchGetSerializedPlans.
async fn batch_get_serialized_plans(
    state: &SharedAppState,
    package_ids: &[i32],
    instance_types: &HashMap<i32, String>,
) -> Result<HashMap<i32, Vec<Value>>, ApiError> {
    let mut valid: Vec<i32> = package_ids.to_vec();
    valid.retain(|id| *id > 0);
    valid.sort();
    valid.dedup();
    let mut result: HashMap<i32, Vec<Value>> = HashMap::new();
    if valid.is_empty() {
        return Ok(result);
    }
    let plans = get_plans_for_packages(state, &valid).await?;
    for plan in plans {
        let instance_type = instance_types.get(&plan.package_id).map(|s| s.as_str());
        result
            .entry(plan.package_id)
            .or_default()
            .push(serialize_plan(&plan, instance_type));
    }
    Ok(result)
}

async fn is_plan_name_unique(
    state: &SharedAppState,
    package_id: i32,
    name: &str,
    exclude_id: Option<i32>,
) -> Result<bool, ApiError> {
    let row: Option<(i32,)> = match exclude_id {
        Some(exclude) => {
            sqlx::query_as(
                "SELECT id FROM package_plans WHERE package_id = $1 AND name = $2 AND id <> $3",
            )
            .bind(package_id)
            .bind(name)
            .bind(exclude)
            .fetch_optional(&state.db)
            .await?
        }
        None => {
            sqlx::query_as("SELECT id FROM package_plans WHERE package_id = $1 AND name = $2")
                .bind(package_id)
                .bind(name)
                .fetch_optional(&state.db)
                .await?
        }
    };
    Ok(row.is_none())
}

async fn can_delete_plan(state: &SharedAppState, plan_id: i32) -> Result<(bool, String), ApiError> {
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM instances WHERE package_plan_id = $1")
            .bind(plan_id)
            .fetch_one(&state.db)
            .await?;
    if count.0 > 0 {
        return Ok((false, format!("该方案下还有 {} 个实例，无法删除", count.0)));
    }
    Ok((true, String::new()))
}

// ===========================================================================
// traffic sync helpers (db/traffic.ts + db/package-plans.ts)
// ===========================================================================

/// db/traffic.ts syncPackageTrafficLimitsToInstances(packageId).
async fn sync_package_traffic_limits(
    state: &SharedAppState,
    package_id: i32,
) -> Result<Vec<i32>, ApiError> {
    let rows: Vec<(i32, i32, i64, String, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT i.id, i.host_id, i.monthly_traffic_used, \
         i.traffic_billing_mode::text AS mode, pp.traffic_limit AS plan_limit, \
         p.monthly_traffic_limit AS pkg_limit \
         FROM instances i \
         LEFT JOIN package_plans pp ON pp.id = i.package_plan_id \
         LEFT JOIN packages p ON p.id = i.package_id \
         WHERE i.status <> 'deleted' AND i.package_id = $1",
    )
    .bind(package_id)
    .fetch_all(&state.db)
    .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let bindings: Vec<(i32, Decimal)> = sqlx::query_as(
        "SELECT host_id, traffic_multiplier FROM package_hosts WHERE package_id = $1",
    )
    .bind(package_id)
    .fetch_all(&state.db)
    .await?;
    let mut multiplier_by_host: HashMap<i32, f64> = HashMap::new();
    for (host_id, m) in bindings {
        multiplier_by_host.entry(host_id).or_insert(
            normalize_traffic_multiplier_f(m.to_f64().unwrap_or(1.0)).unwrap_or(1.0),
        );
    }

    let mut updated: Vec<i32> = Vec::new();
    for (id, host_id, used, mode, plan_limit, pkg_limit) in rows {
        let base = plan_limit.or(pkg_limit);
        let multiplier = multiplier_by_host.get(&host_id).copied().unwrap_or(1.0);
        let new_limit = apply_traffic_multiplier(base, multiplier)?;
        let status = if mode == "usage" {
            "NORMAL"
        } else {
            match new_limit {
                Some(limit) if used > limit => "LIMITED",
                _ => "NORMAL",
            }
        };
        sqlx::query(
            "UPDATE instances SET monthly_traffic_limit = $2, \
             traffic_status = $3::\"TrafficStatus\" WHERE id = $1",
        )
        .bind(id)
        .bind(new_limit)
        .bind(status)
        .execute(&state.db)
        .await?;
        updated.push(id);
    }
    Ok(updated)
}

/// db/package-plans.ts syncPlanQuotaToInstances.
/// Returns (quota update count, traffic-updated instance ids).
async fn sync_plan_quota_to_instances(
    state: &SharedAppState,
    plan: &PlanRow,
    previous_swap_size: i32,
) -> Result<(i64, Vec<i32>), ApiError> {
    let pkg: Option<(String,)> =
        sqlx::query_as("SELECT instance_type::text FROM packages WHERE id = $1")
            .bind(plan.package_id)
            .fetch_optional(&state.db)
            .await?;
    let instance_type = pkg.map(|(t,)| t).unwrap_or_default();
    let bindings: Vec<(i32, Decimal)> = sqlx::query_as(
        "SELECT host_id, traffic_multiplier FROM package_hosts WHERE package_id = $1",
    )
    .bind(plan.package_id)
    .fetch_all(&state.db)
    .await?;
    let mut multiplier_by_host: HashMap<i32, f64> = HashMap::new();
    for (host_id, m) in bindings {
        multiplier_by_host.entry(host_id).or_insert(
            normalize_traffic_multiplier_f(m.to_f64().unwrap_or(1.0)).unwrap_or(1.0),
        );
    }

    let quota_count: i64 = if instance_type == "vm" {
        let r = sqlx::query(
            "UPDATE instances SET port_limit = $2, snapshot_limit = $3, backup_limit = $4, \
             site_limit = $5, swap_enabled = false, swap_size = NULL \
             WHERE package_plan_id = $1",
        )
        .bind(plan.id)
        .bind(plan.port_limit)
        .bind(plan.snapshot_limit)
        .bind(plan.backup_limit)
        .bind(plan.site_limit)
        .execute(&state.db)
        .await?;
        r.rows_affected() as i64
    } else {
        let enabled = sqlx::query(
            "UPDATE instances SET port_limit = $2, snapshot_limit = $3, backup_limit = $4, \
             site_limit = $5 WHERE package_plan_id = $1 AND swap_enabled = true",
        )
        .bind(plan.id)
        .bind(plan.port_limit)
        .bind(plan.snapshot_limit)
        .bind(plan.backup_limit)
        .bind(plan.site_limit)
        .execute(&state.db)
        .await?;
        let disabled = sqlx::query(
            "UPDATE instances SET port_limit = $2, snapshot_limit = $3, backup_limit = $4, \
             site_limit = $5 WHERE package_plan_id = $1 AND swap_enabled = false",
        )
        .bind(plan.id)
        .bind(plan.port_limit)
        .bind(plan.snapshot_limit)
        .bind(plan.backup_limit)
        .bind(plan.site_limit)
        .execute(&state.db)
        .await?;
        sqlx::query(
            "UPDATE instances SET swap_size = $2 WHERE package_plan_id = $1 \
             AND swap_enabled = false AND (swap_size IS NULL OR swap_size = $3)",
        )
        .bind(plan.id)
        .bind(plan.swap_size)
        .bind(previous_swap_size)
        .execute(&state.db)
        .await?;
        (enabled.rows_affected() + disabled.rows_affected()) as i64
    };

    // Traffic limits per instance (with host multipliers).
    let instances: Vec<(i32, i32, i64, String)> = sqlx::query_as(
        "SELECT id, host_id, monthly_traffic_used, traffic_billing_mode::text \
         FROM instances WHERE package_plan_id = $1",
    )
    .bind(plan.id)
    .fetch_all(&state.db)
    .await?;
    let mut traffic_ids: Vec<i32> = Vec::new();
    for (id, host_id, used, mode) in instances {
        let multiplier = multiplier_by_host.get(&host_id).copied().unwrap_or(1.0);
        let new_limit = apply_traffic_multiplier(Some(plan.traffic_limit), multiplier)?;
        let status = if mode == "usage" {
            "NORMAL"
        } else {
            match new_limit {
                Some(limit) if used > limit => "LIMITED",
                _ => "NORMAL",
            }
        };
        sqlx::query(
            "UPDATE instances SET monthly_traffic_limit = $2, \
             traffic_status = $3::\"TrafficStatus\" WHERE id = $1",
        )
        .bind(id)
        .bind(new_limit)
        .bind(status)
        .execute(&state.db)
        .await?;
        traffic_ids.push(id);
    }
    Ok((quota_count, traffic_ids))
}

// ===========================================================================
// traffic billing / hourly pricing validation (packages.ts)
// ===========================================================================

struct TrafficBilling {
    mode: &'static str,
    traffic_limit: i128,
    traffic_unit_price: f64,
}

/// packages.ts validateTrafficBilling. Err = the Chinese error message.
fn validate_traffic_billing(
    mode: Option<&Value>,
    traffic_limit: Option<&Value>,
    traffic_unit_price: Option<&Value>,
) -> Result<TrafficBilling, String> {
    let resolved_mode: Option<&'static str> = match mode {
        Some(Value::String(s)) if s == "usage" => Some("usage"),
        Some(Value::String(s)) if s == "package" => Some("package"),
        None | Some(Value::Null) => Some("package"),
        _ => None,
    };
    let Some(mode) = resolved_mode else {
        return Err("trafficBillingMode 必须为 package 或 usage".to_string());
    };

    // BigInt(input.trafficLimit) — numbers must be integral, strings parsed.
    let limit: i128 = match traffic_limit {
        Some(Value::Number(n)) => {
            let f = n.as_f64().unwrap_or(f64::NAN);
            if !f.is_finite() || f.fract() != 0.0 || f.abs() >= 9.3e18 {
                return Err("流量额度必须为有效整数".to_string());
            }
            f as i128
        }
        Some(Value::String(s)) => s
            .trim()
            .parse::<i128>()
            .map_err(|_| "流量额度必须为有效整数".to_string())?,
        _ => return Err("流量额度必须为有效整数".to_string()),
    };
    if (mode == "package" && limit <= 0) || (mode == "usage" && limit < 0) {
        return Err(if mode == "package" {
            "套餐流量必须大于 0".to_string()
        } else {
            "赠送流量不能为负数".to_string()
        });
    }

    let mut unit_price: f64 = if mode == "usage" {
        js_number(traffic_unit_price)
    } else {
        0.0
    };
    if mode == "usage"
        && (!unit_price.is_finite()
            || unit_price <= 0.0
            || unit_price > MAX_PACKAGE_PLAN_PRICE_CENTS)
    {
        return Err("按量计费的每 GB 单价必须大于 0".to_string());
    }
    if mode == "usage" {
        let hundredths = unit_price * 100.0;
        if (hundredths - hundredths.round()).abs() >= 1e-8 {
            return Err("按量计费的每 GB 单价最多支持 4 位人民币小数".to_string());
        }
        unit_price = hundredths.round() / 100.0;
    }
    Ok(TrafficBilling {
        mode,
        traffic_limit: limit,
        traffic_unit_price: unit_price,
    })
}

/// packages.ts normalizeHourlyPlanPricing. `input`/`fallback` are JSON objects
/// (`??` semantics: null falls through to the fallback); resources are the
/// effective cpu/memory/disk.
fn normalize_hourly_plan_pricing(
    input: Option<&Value>,
    fallback: Option<&Value>,
    resources: (f64, f64, f64),
) -> Result<HashMap<&'static str, Value>, String> {
    let pick = |key: &'static str| -> Option<&Value> {
        input
            .and_then(|v| v.as_object())
            .and_then(|o| o.get(key))
            .filter(|v| !v.is_null())
            .or_else(|| {
                fallback
                    .and_then(|v| v.as_object())
                    .and_then(|o| o.get(key))
                    .filter(|v| !v.is_null())
            })
    };
    let num_field = |key: &'static str, default: f64| -> f64 {
        match pick(key) {
            Some(_) => js_number(pick(key)),
            None => default,
        }
    };
    let dec_field = |key: &'static str,
                     default: &'static str,
                     field: &str|
     -> Result<String, String> {
        match pick(key) {
            Some(v) => decimal_string(Some(v), field),
            None => {
                let dec =
                    Decimal::from_str(default).map_err(|_| format!("{field} 必须是有效的非负数字"))?;
                Ok(fixed_dp(dec, 8))
            }
        }
    };

    let hourly_min_cpu = num_field("hourlyMinCpu", 15.0);
    let hourly_cpu_unit_percent = num_field("hourlyCpuUnitPercent", 5.0);
    let hourly_cpu_price_per_unit = dec_field("hourlyCpuPricePerUnit", "0", "CPU 单位价格")?;
    let hourly_min_memory_mb = num_field("hourlyMinMemoryMb", 128.0);
    let hourly_memory_unit_mb = num_field("hourlyMemoryUnitMb", 64.0);
    let hourly_memory_price_per_unit = dec_field("hourlyMemoryPricePerUnit", "0", "内存单位价格")?;
    let hourly_min_disk_mb = num_field("hourlyMinDiskMb", 512.0);
    let hourly_disk_unit_mb = num_field("hourlyDiskUnitMb", 512.0);
    let hourly_disk_price_per_unit = dec_field("hourlyDiskPricePerUnit", "0", "硬盘单位价格")?;
    let hourly_reserve_quantum = dec_field("hourlyReserveQuantum", "0.01", "预付款额度")?;

    let integer_fields = [
        hourly_min_cpu,
        hourly_cpu_unit_percent,
        hourly_min_memory_mb,
        hourly_memory_unit_mb,
        hourly_min_disk_mb,
        hourly_disk_unit_mb,
    ];
    if integer_fields
        .iter()
        .any(|v| !v.is_finite() || v.fract() != 0.0 || *v <= 0.0)
    {
        return Err("按小时计费的最低值和步长必须是正整数".to_string());
    }
    if hourly_min_cpu < 15.0 || hourly_min_memory_mb < 128.0 || hourly_min_disk_mb < 512.0 {
        return Err("按小时计费最低配置不能低于 CPU 15%、内存 128 MB、硬盘 512 MB".to_string());
    }
    let (cpu, memory, disk) = resources;
    if cpu < hourly_min_cpu || ((cpu - hourly_min_cpu) % hourly_cpu_unit_percent) != 0.0 {
        return Err("方案 CPU 不符合按小时计费的最低值或步长".to_string());
    }
    if memory < hourly_min_memory_mb
        || ((memory - hourly_min_memory_mb) % hourly_memory_unit_mb) != 0.0
    {
        return Err("方案内存不符合按小时计费的最低值或步长".to_string());
    }
    if disk < hourly_min_disk_mb || ((disk - hourly_min_disk_mb) % hourly_disk_unit_mb) != 0.0 {
        return Err("方案硬盘不符合按小时计费的最低值或步长".to_string());
    }
    let quantum =
        Decimal::from_str(&hourly_reserve_quantum).map_err(|_| "预付款额度必须大于 0".to_string())?;
    if quantum <= Decimal::ZERO {
        return Err("预付款额度必须大于 0".to_string());
    }

    Ok(HashMap::from([
        ("hourlyMinCpu", json!(hourly_min_cpu as i64)),
        ("hourlyCpuUnitPercent", json!(hourly_cpu_unit_percent as i64)),
        ("hourlyCpuPricePerUnit", json!(hourly_cpu_price_per_unit)),
        ("hourlyMinMemoryMb", json!(hourly_min_memory_mb as i64)),
        ("hourlyMemoryUnitMb", json!(hourly_memory_unit_mb as i64)),
        ("hourlyMemoryPricePerUnit", json!(hourly_memory_price_per_unit)),
        ("hourlyMinDiskMb", json!(hourly_min_disk_mb as i64)),
        ("hourlyDiskUnitMb", json!(hourly_disk_unit_mb as i64)),
        ("hourlyDiskPricePerUnit", json!(hourly_disk_price_per_unit)),
        ("hourlyReserveQuantum", json!(hourly_reserve_quantum)),
    ]))
}

// ===========================================================================
// misc service helpers
// ===========================================================================

/// packages.ts getCountryName — Intl.DisplayNames is not available in Rust;
/// special names + uppercase fallback (deviation noted in the module docs).
fn get_country_name(code: &str) -> String {
    let normalized = code.to_lowercase();
    match normalized.as_str() {
        "pc" => "Pacific Community".to_string(),
        "xx" => "Unknown".to_string(),
        _ => normalized.to_uppercase(),
    }
}

/// vip-levels.ts getDefaultVipBadgeStyle.
fn default_vip_badge_style(level: i64) -> Value {
    const STYLES: [(&str, &str); 10] = [
        ("#FEF3C7", "#92400E"),
        ("#D1FAE5", "#047857"),
        ("#DBEAFE", "#1D4ED8"),
        ("#EDE9FE", "#6D28D9"),
        ("#FFEDD5", "#C2410C"),
        ("#FCE7F3", "#BE185D"),
        ("#FFE4E6", "#BE123C"),
        ("#CFFAFE", "#0E7490"),
        ("#FAE8FF", "#A21CAF"),
        ("#FEF9C3", "#A16207"),
    ];
    let idx = ((level.max(1) - 1) % STYLES.len() as i64) as usize;
    let (bg, text) = STYLES[idx];
    json!({ "backgroundColor": bg, "textColor": text })
}

fn hex_color_ok(value: &Value) -> bool {
    static HEX: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^#[0-9a-fA-F]{6}$").expect("valid regex")
    });
    value.as_str().map(|s| HEX.is_match(s)).unwrap_or(false)
}

/// vip-levels.ts normalizeVipBadgeStyle over a benefits JSON value.
fn normalize_vip_badge_style(level: i64, value: Option<&Value>) -> Value {
    let fallback = default_vip_badge_style(level);
    let Some(style) = value.and_then(|v| v.as_object()) else {
        return fallback;
    };
    let bg = style.get("backgroundColor").filter(|v| hex_color_ok(v));
    let text = style.get("textColor").filter(|v| hex_color_ok(v));
    json!({
        "backgroundColor": bg.cloned().unwrap_or(fallback["backgroundColor"].clone()),
        "textColor": text.cloned().unwrap_or(fallback["textColor"].clone()),
    })
}

struct HostingVipRule {
    level: i64,
    enabled: bool,
    condition_mode: String,
    min_hosting_income: Option<Decimal>,
    min_hosting_instances: Option<i32>,
    badge_style: Value,
}

/// vip-levels.ts getVipRules('hosting').
async fn get_hosting_vip_rules(state: &SharedAppState) -> Result<Vec<HostingVipRule>, ApiError> {
    let rows: Vec<(i64, bool, String, Option<Decimal>, Option<i32>, Value)> = sqlx::query_as(
        "SELECT level, enabled, condition_mode::text AS condition_mode, min_hosting_income, \
         min_hosting_instances, benefits FROM vip_level_rules WHERE type = 'hosting' \
         ORDER BY level ASC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(level, enabled, condition_mode, income, instances, benefits)| HostingVipRule {
            level,
            enabled,
            condition_mode,
            min_hosting_income: income,
            min_hosting_instances: instances,
            badge_style: normalize_vip_badge_style(level, benefits.get("badgeStyle")),
        })
        .collect())
}

fn has_threshold(d: &Option<Decimal>) -> bool {
    match d {
        Some(v) => *v > Decimal::ZERO,
        None => false,
    }
}

/// vip-levels.ts calculateVipLevel('hosting', rules, stats).
fn calculate_hosting_vip_level(
    rules: &[HostingVipRule],
    total_hosting_income: f64,
    instance_count: i64,
) -> i64 {
    let mut best: i64 = 0;
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        let mut checks: Vec<bool> = Vec::new();
        if has_threshold(&rule.min_hosting_income) {
            checks.push(
                total_hosting_income >= rule.min_hosting_income.unwrap().to_f64().unwrap_or(0.0),
            );
        }
        if let Some(min_instances) = rule.min_hosting_instances {
            if min_instances > 0 {
                checks.push(instance_count >= min_instances as i64);
            }
        }
        if checks.is_empty() {
            continue;
        }
        let matched = if rule.condition_mode == "all" {
            checks.iter().all(|c| *c)
        } else {
            checks.iter().any(|c| *c)
        };
        if matched && rule.level > best {
            best = rule.level;
        }
    }
    best
}

fn get_vip_badge_style_for_level(rules: &[HostingVipRule], level: i64) -> Value {
    if level == 0 {
        return Value::Null;
    }
    rules
        .iter()
        .find(|r| r.level == level)
        .map(|r| r.badge_style.clone())
        .unwrap_or_else(|| default_vip_badge_style(level))
}

// ===========================================================================
// handlers — 公开 API
// ===========================================================================

#[derive(Debug, sqlx::FromRow)]
struct PublicPackageRow {
    id: i32,
    name: String,
    description: Option<String>,
    cpu_max: i32,
    memory_max: i32,
    disk_max: i32,
    monthly_traffic_limit: Option<i64>,
    network_mode: String,
    instance_type: String,
    privileged: bool,
    nested: bool,
    global_max_instances: Option<i32>,
    host_ids: Vec<i32>,
    owner_role: String,
}

/// GET /public — 门户市场页面套餐列表（未登录可访问）。
#[allow(clippy::too_many_lines)]
async fn public_list(
    State(state): State<SharedAppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let source = params.get("source").map(|s| s.as_str()).unwrap_or("all");
    let zone_owner_ids = get_active_hosting_zone_owner_ids(&state).await?;

    let mut clauses: Vec<String> = vec![
        "p.active = true".to_string(),
        "p.global_shared = true".to_string(),
    ];
    let mut bind_excluded_owners: Option<Vec<i32>> = None;
    match source {
        "official" => clauses.push("u.role = 'admin'".to_string()),
        "market" => {
            clauses.push("u.role <> 'admin'".to_string());
            if !zone_owner_ids.is_empty() {
                clauses.push("p.user_id <> ALL($1)".to_string());
                bind_excluded_owners = Some(zone_owner_ids.clone());
            }
        }
        _ => {
            if !zone_owner_ids.is_empty() {
                clauses.push("p.user_id <> ALL($1)".to_string());
                bind_excluded_owners = Some(zone_owner_ids.clone());
            }
        }
    }

    let mut sql = String::from(
        "SELECT p.id, p.name, p.description, p.cpu_max, p.memory_max, p.disk_max, \
         p.monthly_traffic_limit, p.network_mode::text AS network_mode, \
         p.instance_type::text AS instance_type, p.privileged, p.nested, p.global_max_instances, \
         (SELECT COALESCE(array_agg(ph.host_id ORDER BY ph.id), '{}') FROM package_hosts ph \
          WHERE ph.package_id = p.id) AS host_ids, \
         u.role::text AS owner_role \
         FROM packages p JOIN users u ON u.id = p.user_id",
    );
    sql.push_str(" WHERE ");
    sql.push_str(&clauses.join(" AND "));
    sql.push_str(" ORDER BY p.name ASC");

    let mut q = sqlx::query_as::<_, PublicPackageRow>(&sql);
    if let Some(excluded) = &bind_excluded_owners {
        q = q.bind(excluded);
    }
    let packages = q.fetch_all(&state.db).await?;

    let all_package_ids: Vec<i32> = packages.iter().map(|p| p.id).collect();
    let all_plans = get_plans_for_packages(&state, &all_package_ids).await?;
    let mut plans_by_package: HashMap<i32, Vec<PlanRow>> = HashMap::new();
    for plan in all_plans {
        plans_by_package.entry(plan.package_id).or_default().push(plan);
    }
    let all_host_ids: Vec<i32> = packages
        .iter()
        .flat_map(|p| p.host_ids.iter().copied())
        .collect();
    let hosts = fetch_online_host_usage(&state, &all_host_ids).await?;

    let mut items: Vec<Value> = Vec::new();
    for pkg in &packages {
        let plans = plans_by_package.get(&pkg.id).cloned().unwrap_or_default();
        let is_paid = !plans.is_empty();
        let available_plans: Vec<&PlanRow> =
            plans.iter().filter(|p| !p.is_sold_out).collect();
        let host_ids = &pkg.host_ids;
        let bound_hosts: Vec<&HostUsage> =
            host_ids.iter().filter_map(|id| hosts.get(id)).collect();

        let mut sold_out = is_paid && available_plans.is_empty();
        if !host_ids.is_empty() {
            if bound_hosts.is_empty() {
                sold_out = true;
            } else if !sold_out {
                let (min_cpu, min_memory) = if is_paid {
                    (
                        available_plans.iter().map(|p| p.cpu).min().unwrap_or(15) as i64,
                        available_plans.iter().map(|p| p.memory).min().unwrap_or(128) as i64,
                    )
                } else {
                    (15, 128)
                };
                let has_available = bound_hosts.iter().any(|h| {
                    (h.cpu_allowance_max as i64 - h.cpu_used) >= min_cpu
                        && (h.memory_max as i64 - h.memory_used) >= min_memory
                });
                sold_out = !has_available;
            }
        } else {
            sold_out = true;
        }

        let source_type = if pkg.owner_role == "admin" { "official" } else { "market" };
        let plan_values: Vec<Value> = plans
            .iter()
            .map(|p| {
                // The TS inline mapping keeps price/setupFee/slaGuarantee as raw
                // Prisma Decimals -> JSON strings.
                json!({
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "cpu": p.cpu,
                    "memory": p.memory,
                    "disk": p.disk,
                    "portLimit": p.port_limit,
                    "snapshotLimit": p.snapshot_limit,
                    "backupLimit": p.backup_limit,
                    "siteLimit": p.site_limit,
                    "swapSize": if pkg.instance_type == "vm" { 0 } else { p.swap_size },
                    "trafficLimit": p.traffic_limit.to_string(),
                    "trafficLimitSpeed": p.traffic_limit_speed,
                    "trafficBillingMode": p.traffic_billing_mode,
                    "trafficUnitPrice": num(p.traffic_unit_price),
                    "billingMode": p.billing_mode,
                    "price": p.price.to_string(),
                    "billingCycle": p.billing_cycle,
                    "setupFee": p.setup_fee.to_string(),
                    "isSoldOut": p.is_sold_out || sold_out,
                    "slaGuarantee": p.sla_guarantee
                        .map(|d| Value::String(d.to_string()))
                        .unwrap_or(Value::Null),
                    "monthlyPrice": js_json_number(
                        p.price.to_f64().unwrap_or(0.0)
                            / std::cmp::max(p.billing_cycle, 1) as f64,
                    ),
                })
            })
            .collect();

        items.push(json!({
            "id": pkg.id,
            "name": pkg.name,
            "description": pkg.description,
            "cpu_max": pkg.cpu_max,
            "memory_max": pkg.memory_max,
            "disk_max": pkg.disk_max,
            "monthly_traffic_limit": pkg.monthly_traffic_limit.map(|v| v.to_string()),
            "network_mode": pkg.network_mode,
            "instance_type": pkg.instance_type,
            "host_ids": host_ids,
            "privileged": pkg.privileged,
            "nested": pkg.nested,
            "global_quota_multiplier": null,
            "global_max_instances": normalize_public_package_max_instances(
                pkg.global_max_instances.map(|v| json!(v)).as_ref(),
            ),
            "required_package_id": null,
            "required_package_name": null,
            "sourceType": source_type,
            "soldOut": sold_out,
            "isPaid": is_paid,
            "plans": plan_values,
        }));
    }
    // 售罄的套餐排在最后（stable sort，与 TS Array.sort 一致）。
    items.sort_by_key(|item| item["soldOut"].as_bool().unwrap_or(false));

    Ok(Json(json!({
        "packages": items,
        "total": items.len(),
    })))
}

/// Online hosts with aggregated instance usage (for the /public sold-out check).
async fn fetch_online_host_usage(
    state: &SharedAppState,
    host_ids: &[i32],
) -> Result<HashMap<i32, HostUsage>, ApiError> {
    if host_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let statuses = HOST_RESOURCE_INSTANCE_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let rows: Vec<(i32, i32, i32, Option<i64>, Option<i64>)> = sqlx::query_as(&format!(
        "SELECT h.id, h.cpu_allowance_max, h.memory_max, i.cpu, i.memory \
         FROM hosts h \
         LEFT JOIN instances i ON i.host_id = h.id AND i.status IN ({statuses}) \
         WHERE h.id = ANY($1) AND h.status = 'online'"
    ))
    .bind(host_ids)
    .fetch_all(&state.db)
    .await?;
    let mut result: HashMap<i32, HostUsage> = HashMap::new();
    for (id, cpu_max, mem_max, cpu, memory) in rows {
        let entry = result.entry(id).or_insert_with(|| HostUsage {
            host_id: id,
            host_status: "online".to_string(),
            cpu_allowance_max: cpu_max,
            memory_max: mem_max,
            cpu_used: 0,
            memory_used: 0,
        });
        entry.cpu_used += cpu.unwrap_or(0);
        entry.memory_used += memory.unwrap_or(0);
    }
    Ok(result)
}

/// GET /public/regions — 门户市场地区列表（未登录可访问）。
async fn public_regions(
    State(state): State<SharedAppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let source = params.get("source").map(|s| s.as_str()).unwrap_or("all");
    let zone_owner_ids = get_active_hosting_zone_owner_ids(&state).await?;

    let mut clauses: Vec<String> = vec![
        "p.active = true".to_string(),
        "p.global_shared = true".to_string(),
    ];
    let mut bind_excluded: Option<Vec<i32>> = None;
    match source {
        "official" => clauses.push("u.role = 'admin'".to_string()),
        "market" => {
            clauses.push("u.role <> 'admin'".to_string());
            if !zone_owner_ids.is_empty() {
                clauses.push("p.user_id <> ALL($1)".to_string());
                bind_excluded = Some(zone_owner_ids.clone());
            }
        }
        _ => {
            if !zone_owner_ids.is_empty() {
                clauses.push("p.user_id <> ALL($1)".to_string());
                bind_excluded = Some(zone_owner_ids.clone());
            }
        }
    }

    let mut sql = String::from(
        "SELECT p.id, ph.host_id, h.country_code, h.location \
         FROM packages p \
         JOIN users u ON u.id = p.user_id \
         JOIN package_hosts ph ON ph.package_id = p.id \
         JOIN hosts h ON h.id = ph.host_id AND h.status = 'online'",
    );
    sql.push_str(" WHERE ");
    sql.push_str(&clauses.join(" AND "));

    let mut q = sqlx::query_as::<_, (i32, i32, String, Option<String>)>(&sql);
    if let Some(excluded) = &bind_excluded {
        q = q.bind(excluded);
    }
    let rows = q.fetch_all(&state.db).await?;

    // regionMap: code -> { name, packageIds set, hostIds set }
    let mut regions: HashMap<String, (String, HashSet<i32>, HashSet<i32>)> = HashMap::new();
    for (package_id, host_id, country_code, location) in rows {
        let code = country_code.to_uppercase();
        let entry = regions.entry(code.clone()).or_insert_with(|| {
            (
                location.unwrap_or_else(|| code.clone()),
                HashSet::new(),
                HashSet::new(),
            )
        });
        entry.1.insert(package_id);
        entry.2.insert(host_id);
    }
    let mut region_list: Vec<Value> = regions
        .into_iter()
        .map(|(code, (name, package_ids, host_ids))| {
            json!({
                "code": code,
                "name": name,
                "packageIds": package_ids.into_iter().collect::<Vec<_>>(),
                "hostCount": host_ids.len(),
            })
        })
        .collect();
    // regions.sort((a, b) => a.name.localeCompare(b.name, 'zh')) — approximated
    // with a case-insensitive alphabetical comparison (ICU zh collation is not
    // available in Rust; deviation noted in the module docs).
    region_list.sort_by(|a, b| {
        let an = a["name"].as_str().unwrap_or("").to_lowercase();
        let bn = b["name"].as_str().unwrap_or("").to_lowercase();
        an.cmp(&bn)
    });

    Ok(Json(json!({ "regions": region_list })))
}

// ===========================================================================
// handlers — 需要登录的 API
// ===========================================================================

/// formatSharedPackage from packages.ts (SharedPackageInfo -> response object).
fn format_shared_package(
    p: &SharedPackageRow,
    is_global_shared: bool,
    source_type: &str,
    required_instance_map: &HashMap<i32, bool>,
    zone: Option<&HostingZoneRow>,
) -> Value {
    let has_required = match p.required_package_id {
        Some(id) => required_instance_map.get(&id).copied().unwrap_or(false),
        None => true,
    };
    let mut obj = json!({
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "cpu_max": p.cpu_max,
        "memory_max": p.memory_max,
        "disk_max": p.disk_max,
        "bandwidth_max": p.bandwidth_max,
        "network_mode": p.network_mode,
        "instance_type": p.instance_type,
        "host_ids": p.host_ids,
        "privileged": if p.privileged { 1 } else { 0 },
        "nested": if p.nested { 1 } else { 0 },
        "active": 1,
        "monthly_traffic_limit": p.monthly_traffic_limit.map(|v| v.to_string()),
        "port_limit": p.port_limit,
        "snapshot_limit": p.snapshot_limit,
        "backup_limit": p.backup_limit,
        "site_limit": p.site_limit,
        "io_limit_mode": "throughput",
        "limits_read": "100MB",
        "limits_write": "100MB",
        "limits_read_iops": 500,
        "limits_write_iops": 500,
        "limits_ingress": "300Mbit",
        "limits_egress": "300Mbit",
        "limits_processes": 500,
        "limits_cpu_priority": 10,
    });
    // Built in two halves to stay under the serde_json json! recursion limit.
    let tail = json!({
        "boot_autostart": true,
        "boot_autostart_priority": 20,
        "boot_autostart_delay": 15,
        "boot_host_shutdown_timeout": 30,
        "allow_instance_deletion": p.allow_instance_deletion,
        "destroy_traffic_limit": p.destroy_traffic_limit.to_string(),
        "required_package_id": p.required_package_id,
        "required_package_name": p.required_package_name,
        "ownerId": p.owner_id,
        "ownerUsername": p.owner_username,
        "isOwn": false,
        "isShared": true,
        "isGlobalShared": is_global_shared,
        "sharedAt": iso(p.shared_at),
        "sourceType": source_type,
        "has_required_package_instance": has_required,
    });
    if let (Some(base), Some(tail)) = (obj.as_object_mut(), tail.as_object()) {
        for (k, v) in tail {
            base.insert(k.clone(), v.clone());
        }
    }
    if let Some(zone) = zone {
        obj["hostingZoneId"] = json!(zone.id);
        obj["hostingZoneName"] = json!(zone.name);
        obj["hostingZoneLogoUrl"] = json!(zone.logo_url);
    }
    obj
}

/// GET / — 获取套餐列表（authenticate）。
#[allow(clippy::too_many_lines)]
async fn list_packages(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let active_only = params.get("all").map(|s| s.as_str()) != Some("true");
    let source = params.get("source").map(|s| s.as_str()).unwrap_or("all");
    let scope = params.get("scope").map(|s| s.as_str());
    let filter_user_id = params.get("userId").map(|s| s.as_str());
    let is_admin = user.role == "admin";

    // ---- 管理员 scope 处理 ----
    if is_admin {
        if let Some(scope) = scope {
            match scope {
                "mine" => {
                    let own =
                        fetch_own_packages(&state, active_only, Some(user.id), None).await?;
                    let ids: Vec<i32> = own.iter().map(|p| p.id).collect();
                    let bindings = fetch_package_host_bindings(&state, &ids).await?;
                    let sold_out = compute_sold_out(&state, &ids).await?;
                    let counts = get_normal_instance_counts_by_packages(&state, &ids).await?;
                    let packages: Vec<Value> = own
                        .iter()
                        .map(|p| {
                            let mut obj = own_package_base_json(
                                p,
                                bindings.get(&p.id).map(|v| v.as_slice()).unwrap_or(&[]),
                            );
                            obj.insert("sourceType".into(), json!("own"));
                            obj.insert("isOwn".into(), json!(true));
                            obj.insert("isShared".into(), json!(false));
                            obj.insert(
                                "soldOut".into(),
                                json!(sold_out.get(&p.id).copied().unwrap_or(false)),
                            );
                            obj.insert(
                                "instance_count".into(),
                                json!(counts.get(&p.id).copied().unwrap_or(0)),
                            );
                            Value::Object(obj)
                        })
                        .collect();
                    return Ok(Json(json!({ "packages": packages, "total": packages.len() })));
                }
                "official" => {
                    let official =
                        fetch_own_packages(&state, active_only, None, Some("admin")).await?;
                    let ids: Vec<i32> = official.iter().map(|p| p.id).collect();
                    let bindings = fetch_package_host_bindings(&state, &ids).await?;
                    let sold_out = compute_sold_out(&state, &ids).await?;
                    let counts = get_normal_instance_counts_by_packages(&state, &ids).await?;
                    let packages: Vec<Value> = official
                        .iter()
                        .map(|p| {
                            let mut obj = own_package_base_json(
                                p,
                                bindings.get(&p.id).map(|v| v.as_slice()).unwrap_or(&[]),
                            );
                            obj.insert("sourceType".into(), json!("official"));
                            obj.insert("isOwn".into(), json!(p.user_id == user.id));
                            obj.insert("isShared".into(), json!(false));
                            obj.insert(
                                "soldOut".into(),
                                json!(sold_out.get(&p.id).copied().unwrap_or(false)),
                            );
                            obj.insert(
                                "instance_count".into(),
                                json!(counts.get(&p.id).copied().unwrap_or(0)),
                            );
                            Value::Object(obj)
                        })
                        .collect();
                    return Ok(Json(json!({ "packages": packages, "total": packages.len() })));
                }
                "hosted" => {
                    let mut filter_uid: Option<i32> = None;
                    if let Some(raw) = filter_user_id {
                        if let Some(parsed) = js_parse_int(raw) {
                            if parsed != user.id as i64
                                && parsed >= i32::MIN as i64
                                && parsed <= i32::MAX as i64
                            {
                                filter_uid = Some(parsed as i32);
                            }
                        }
                    }
                    let hosted =
                        fetch_own_packages(&state, active_only, filter_uid, Some("user")).await?;
                    let ids: Vec<i32> = hosted.iter().map(|p| p.id).collect();
                    let bindings = fetch_package_host_bindings(&state, &ids).await?;
                    let sold_out = compute_sold_out(&state, &ids).await?;
                    let counts = get_normal_instance_counts_by_packages(&state, &ids).await?;
                    let packages: Vec<Value> = hosted
                        .iter()
                        .map(|p| {
                            let (host_ids, pools, multipliers) = bindings_json(
                                bindings.get(&p.id).map(|v| v.as_slice()).unwrap_or(&[]),
                            );
                            json!({
                                "id": p.id,
                                "name": p.name,
                                "description": p.description,
                                "cpu_max": p.cpu_max,
                                "memory_max": p.memory_max,
                                "disk_max": p.disk_max,
                                "bandwidth_max": p.bandwidth_max,
                                "network_mode": p.network_mode,
                                "instance_type": p.instance_type,
                                "host_ids": host_ids,
                                "host_storage_pools": pools,
                                "host_traffic_multipliers": multipliers,
                                "privileged": if p.privileged { 1 } else { 0 },
                                "nested": if p.nested { 1 } else { 0 },
                                "active": if p.active { 1 } else { 0 },
                                "monthly_traffic_limit": p.monthly_traffic_limit.map(|v| v.to_string()),
                                "port_limit": p.port_limit,
                                "snapshot_limit": p.snapshot_limit,
                                "backup_limit": p.backup_limit,
                                "site_limit": p.site_limit,
                                "global_shared": p.global_shared,
                                "allow_instance_deletion": p.allow_instance_deletion,
                                "destroy_traffic_limit": p.destroy_traffic_limit.to_string(),
                                "required_package_id": p.required_package_id,
                                "required_package_name": p.required_package_name,
                                "sourceType": "hosted",
                                "isOwn": false,
                                "isShared": false,
                                "soldOut": sold_out.get(&p.id).copied().unwrap_or(false),
                                "instance_count": counts.get(&p.id).copied().unwrap_or(0),
                                "owner": {
                                    "id": p.user_id,
                                    "username": p.owner_username,
                                    "email": p.owner_email,
                                    "avatarStyle": p.owner_avatar_style.clone().unwrap_or_else(|| "bigSmile".to_string()),
                                    "avatarBadgeId": p.owner_avatar_badge_id,
                                }
                            })
                        })
                        .collect();
                    return Ok(Json(json!({ "packages": packages, "total": packages.len() })));
                }
                _ => {}
            }
        }
    }

    match source {
        "official" => {
            let global = get_global_shared_packages(&state).await?;
            let ids: Vec<i32> = global.iter().map(|p| p.id).collect();
            let sold_out = compute_sold_out(&state, &ids).await?;
            let required_ids: Vec<i32> =
                global.iter().filter_map(|p| p.required_package_id).collect();
            let required_map =
                user_has_normal_instance_for_packages(&state, user.id, &required_ids).await?;
            let instance_types: HashMap<i32, String> =
                global.iter().map(|p| (p.id, p.instance_type.clone())).collect();
            let plans_map = batch_get_serialized_plans(&state, &ids, &instance_types).await?;
            let packages: Vec<Value> = global
                .iter()
                .map(|p| {
                    let mut obj = format_shared_package(p, true, "official", &required_map, None);
                    obj["soldOut"] = json!(sold_out.get(&p.id).copied().unwrap_or(false));
                    obj["plans"] = Value::Array(plans_map.get(&p.id).cloned().unwrap_or_default());
                    obj
                })
                .collect();
            Ok(Json(json!({ "packages": packages, "total": packages.len() })))
        }
        "market" => {
            let zone_owner_ids = get_active_hosting_zone_owner_ids(&state).await?;
            let market =
                get_hosted_market_packages(&state, Some(user.id), None, &zone_owner_ids).await?;
            let ids: Vec<i32> = market.iter().map(|p| p.id).collect();
            let sold_out = compute_sold_out(&state, &ids).await?;
            let required_ids: Vec<i32> =
                market.iter().filter_map(|p| p.required_package_id).collect();
            let required_map =
                user_has_normal_instance_for_packages(&state, user.id, &required_ids).await?;
            let instance_types: HashMap<i32, String> =
                market.iter().map(|p| (p.id, p.instance_type.clone())).collect();
            let plans_map = batch_get_serialized_plans(&state, &ids, &instance_types).await?;
            let packages: Vec<Value> = market
                .iter()
                .map(|p| {
                    let mut obj = format_shared_package(p, true, "market", &required_map, None);
                    obj["soldOut"] = json!(sold_out.get(&p.id).copied().unwrap_or(false));
                    obj["plans"] = Value::Array(plans_map.get(&p.id).cloned().unwrap_or_default());
                    obj
                })
                .collect();
            Ok(Json(json!({ "packages": packages, "total": packages.len() })))
        }
        "zone" => {
            let zone_id =
                js_parse_int(params.get("zoneId").map(|s| s.as_str()).unwrap_or(""));
            let Some(zone_id) = zone_id.filter(|v| *v > 0 && *v <= i32::MAX as i64) else {
                return Ok(Json(json!({ "packages": [], "total": 0 })));
            };
            let Some(zone) = get_active_hosting_zone_by_id(&state, zone_id, Some(user.id)).await?
            else {
                return Ok(Json(json!({ "packages": [], "total": 0 })));
            };
            let zone_packages =
                get_hosted_market_packages(&state, Some(user.id), Some(zone.owner_id), &[])
                    .await?;
            let ids: Vec<i32> = zone_packages.iter().map(|p| p.id).collect();
            let sold_out = compute_sold_out(&state, &ids).await?;
            let required_ids: Vec<i32> =
                zone_packages.iter().filter_map(|p| p.required_package_id).collect();
            let required_map =
                user_has_normal_instance_for_packages(&state, user.id, &required_ids).await?;
            let instance_types: HashMap<i32, String> = zone_packages
                .iter()
                .map(|p| (p.id, p.instance_type.clone()))
                .collect();
            let plans_map = batch_get_serialized_plans(&state, &ids, &instance_types).await?;
            let packages: Vec<Value> = zone_packages
                .iter()
                .map(|p| {
                    let mut obj =
                        format_shared_package(p, true, "zone", &required_map, Some(&zone));
                    obj["soldOut"] = json!(sold_out.get(&p.id).copied().unwrap_or(false));
                    obj["plans"] = Value::Array(plans_map.get(&p.id).cloned().unwrap_or_default());
                    obj
                })
                .collect();
            Ok(Json(json!({ "packages": packages, "total": packages.len() })))
        }
        "friends" => {
            let friends = get_shared_to_user(&state, user.id).await?;
            let ids: Vec<i32> = friends.iter().map(|p| p.id).collect();
            let sold_out = compute_sold_out(&state, &ids).await?;
            let required_ids: Vec<i32> =
                friends.iter().filter_map(|p| p.required_package_id).collect();
            let required_map =
                user_has_normal_instance_for_packages(&state, user.id, &required_ids).await?;
            let instance_types: HashMap<i32, String> =
                friends.iter().map(|p| (p.id, p.instance_type.clone())).collect();
            let plans_map = batch_get_serialized_plans(&state, &ids, &instance_types).await?;
            let packages: Vec<Value> = friends
                .iter()
                .map(|p| {
                    let mut obj = format_shared_package(p, false, "friends", &required_map, None);
                    obj["soldOut"] = json!(sold_out.get(&p.id).copied().unwrap_or(false));
                    obj["plans"] = Value::Array(plans_map.get(&p.id).cloned().unwrap_or_default());
                    obj
                })
                .collect();
            Ok(Json(json!({ "packages": packages, "total": packages.len() })))
        }
        _ => {
            // source=all: own > friends > zone > market > official（去重合并）。
            let own = fetch_own_packages(
                &state,
                active_only,
                if is_admin { None } else { Some(user.id) },
                None,
            )
            .await?;
            let shared = get_shared_to_user(&state, user.id).await?;
            let global = get_global_shared_packages(&state).await?;
            let hosting_zones = get_hosting_zones_for_viewer(&state, Some(user.id)).await?;

            let own_ids: Vec<i32> = own.iter().map(|p| p.id).collect();
            let zone_owner_ids: Vec<i32> =
                hosting_zones.iter().map(|z| z.owner_id).collect();

            let own_counts = get_normal_instance_counts_by_packages(&state, &own_ids).await?;
            let market =
                get_hosted_market_packages(&state, Some(user.id), None, &zone_owner_ids).await?;
            let mut zone_packages_by_zone: Vec<(HostingZoneRow, Vec<SharedPackageRow>)> =
                Vec::new();
            for zone in &hosting_zones {
                let packages =
                    get_hosted_market_packages(&state, Some(user.id), Some(zone.owner_id), &[])
                        .await?;
                zone_packages_by_zone.push((zone.clone(), packages));
            }

            // 批量预计算 requiredPackageInstance 映射。
            let mut required_ids: Vec<i32> = Vec::new();
            for p in own.iter().filter_map(|p| p.required_package_id) {
                required_ids.push(p);
            }
            for list in [&shared, &global, &market] {
                for p in list.iter().filter_map(|p| p.required_package_id) {
                    required_ids.push(p);
                }
            }
            for (_, packages) in &zone_packages_by_zone {
                for p in packages.iter().filter_map(|p| p.required_package_id) {
                    required_ids.push(p);
                }
            }
            let required_map =
                user_has_normal_instance_for_packages(&state, user.id, &required_ids).await?;

            let mut added: HashSet<i32> = HashSet::new();
            let mut all_packages: Vec<Value> = Vec::new();

            // 1. 自己的套餐（最高优先级）
            let own_bindings = fetch_package_host_bindings(&state, &own_ids).await?;
            for p in &own {
                added.insert(p.id);
                let (host_ids, pools, multipliers) = bindings_json(
                    own_bindings.get(&p.id).map(|v| v.as_slice()).unwrap_or(&[]),
                );
                let mut obj = Map::new();
                obj.insert("id".into(), json!(p.id));
                obj.insert("name".into(), json!(p.name));
                obj.insert("description".into(), json!(p.description));
                obj.insert("cpu_max".into(), json!(p.cpu_max));
                obj.insert("memory_max".into(), json!(p.memory_max));
                obj.insert("disk_max".into(), json!(p.disk_max));
                obj.insert("bandwidth_max".into(), json!(p.bandwidth_max));
                obj.insert("network_mode".into(), json!(p.network_mode));
                obj.insert("instance_type".into(), json!(p.instance_type));
                obj.insert("host_ids".into(), host_ids);
                obj.insert("host_storage_pools".into(), pools);
                obj.insert("host_traffic_multipliers".into(), multipliers);
                obj.insert("privileged".into(), json!(if p.privileged { 1 } else { 0 }));
                obj.insert("nested".into(), json!(if p.nested { 1 } else { 0 }));
                obj.insert("active".into(), json!(if p.active { 1 } else { 0 }));
                obj.insert(
                    "monthly_traffic_limit".into(),
                    p.monthly_traffic_limit
                        .map(|v| json!(v.to_string()))
                        .unwrap_or(Value::Null),
                );
                obj.insert("port_limit".into(), json!(p.port_limit));
                obj.insert("snapshot_limit".into(), json!(p.snapshot_limit));
                obj.insert("backup_limit".into(), json!(p.backup_limit));
                obj.insert("site_limit".into(), json!(p.site_limit));
                obj.insert("global_shared".into(), json!(p.global_shared));
                obj.insert(
                    "io_limit_mode".into(),
                    json!(p.io_limit_mode),
                );
                obj.insert("limits_read".into(), json!(p.limits_read));
                obj.insert("limits_write".into(), json!(p.limits_write));
                obj.insert("limits_read_iops".into(), json!(p.limits_read_iops));
                obj.insert("limits_write_iops".into(), json!(p.limits_write_iops));
                obj.insert("limits_ingress".into(), json!(p.limits_ingress));
                obj.insert("limits_egress".into(), json!(p.limits_egress));
                obj.insert("limits_processes".into(), json!(p.limits_processes));
                obj.insert("limits_cpu_priority".into(), json!(p.limits_cpu_priority));
                obj.insert("boot_autostart".into(), json!(p.boot_autostart));
                obj.insert("boot_autostart_priority".into(), json!(p.boot_autostart_priority));
                obj.insert("boot_autostart_delay".into(), json!(p.boot_autostart_delay));
                obj.insert(
                    "boot_host_shutdown_timeout".into(),
                    json!(p.boot_host_shutdown_timeout),
                );
                obj.insert("allow_instance_deletion".into(), json!(p.allow_instance_deletion));
                obj.insert(
                    "destroy_traffic_limit".into(),
                    json!(p.destroy_traffic_limit.to_string()),
                );
                obj.insert(
                    "required_package_id".into(),
                    p.required_package_id.map(|v| json!(v)).unwrap_or(Value::Null),
                );
                obj.insert(
                    "required_package_name".into(),
                    p.required_package_name.clone().map(|v| json!(v)).unwrap_or(Value::Null),
                );
                obj.insert(
                    "has_required_package_instance".into(),
                    json!(match p.required_package_id {
                        Some(id) => required_map.get(&id).copied().unwrap_or(false),
                        None => true,
                    }),
                );
                obj.insert("ownerId".into(), json!(p.user_id));
                obj.insert("ownerUsername".into(), json!(p.owner_username));
                obj.insert("isOwn".into(), json!(true));
                obj.insert("isShared".into(), json!(false));
                obj.insert("sourceType".into(), json!("own"));
                obj.insert(
                    "instance_count".into(),
                    json!(own_counts.get(&p.id).copied().unwrap_or(0)),
                );
                all_packages.push(Value::Object(obj));
            }

            // 2. 好友分享的套餐
            for p in &shared {
                if added.contains(&p.id) {
                    continue;
                }
                added.insert(p.id);
                all_packages.push(format_shared_package(p, false, "friends", &required_map, None));
            }
            // 3. 托管专区套餐
            for (zone, packages) in &zone_packages_by_zone {
                for p in packages {
                    if added.contains(&p.id) {
                        continue;
                    }
                    added.insert(p.id);
                    all_packages
                        .push(format_shared_package(p, true, "zone", &required_map, Some(zone)));
                }
            }
            // 4. 托管市场套餐
            for p in &market {
                if added.contains(&p.id) {
                    continue;
                }
                added.insert(p.id);
                all_packages.push(format_shared_package(p, true, "market", &required_map, None));
            }
            // 5. 官方直营套餐
            for p in &global {
                if added.contains(&p.id) {
                    continue;
                }
                added.insert(p.id);
                all_packages.push(format_shared_package(p, true, "official", &required_map, None));
            }

            // 6/7. soldOut + plans
            let package_ids: Vec<i32> = all_packages
                .iter()
                .filter_map(|p| p["id"].as_i64().map(|v| v as i32))
                .collect();
            let mut instance_types: HashMap<i32, String> = HashMap::new();
            for p in &all_packages {
                if let (Some(id), Some(t)) = (p["id"].as_i64(), p["instance_type"].as_str()) {
                    instance_types.insert(id as i32, t.to_string());
                }
            }
            let sold_out = compute_sold_out(&state, &package_ids).await?;
            let plans_map =
                batch_get_serialized_plans(&state, &package_ids, &instance_types).await?;
            for p in all_packages.iter_mut() {
                let id = p["id"].as_i64().unwrap_or(0) as i32;
                p["soldOut"] = json!(sold_out.get(&id).copied().unwrap_or(false));
                p["plans"] = Value::Array(plans_map.get(&id).cloned().unwrap_or_default());
            }

            Ok(Json(json!({
                "packages": all_packages,
                "total": all_packages.len(),
            })))
        }
    }
}

/// GET /hosting-zones — 当前用户可见的托管专区列表。
async fn hosting_zones(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let zones = get_hosting_zones_for_viewer(&state, Some(user.id)).await?;
    let zones: Vec<Value> = zones
        .iter()
        .map(|z| {
            json!({
                "id": z.id,
                "name": z.name,
                "ownerId": z.owner_id,
                "ownerUsername": z.owner_username,
                "logoUrl": z.logo_url,
                "sortOrder": z.sort_order,
            })
        })
        .collect();
    Ok(Json(json!({ "zones": zones })))
}

/// GET /{id} — 获取套餐详情。
#[allow(clippy::too_many_lines)]
async fn get_package(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let package_id = js_number_id(&id)?;
    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;

    let can_access = can_user_access_package(&state, user.id, package_id).await?;
    let mut has_instance_with_package = false;
    if !can_access {
        has_instance_with_package = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM instances WHERE user_id = $1 AND package_id = $2",
        )
        .bind(user.id)
        .bind(package_id)
        .fetch_one(&state.db)
        .await?
            > 0;
    }

    let is_admin = user.role == "admin";
    if !can_access && !has_instance_with_package && !is_admin {
        tracing::warn!(
            "[PACKAGE_ACCESS_DENIED] GET /packages/{id} - packageId={package_id}, userId={}, username={}, pkgOwnerId={}, canAccess={can_access}, hasInstanceWithPackage={has_instance_with_package}, isAdmin={is_admin}",
            user.id,
            user.username,
            pkg.user_id,
        );
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let is_own = pkg.user_id == user.id;
    let can_manage_package = is_own || is_admin;

    let mut quota_info = json!({
        "maxInstances": null,
        "remainingInstances": null,
        "maxCpu": null,
        "remainingCpu": null,
        "maxMemory": null,
        "remainingMemory": null,
        "ownerUsername": null,
    });
    let mut quota_owner_username: Option<String> = None;
    if can_access {
        if !is_own {
            // 共享套餐：计算剩余配额（getPackageShareForUser 仅覆盖公开套餐）
            if let Some((_, max_instances)) =
                get_package_share_for_user(&state, package_id, user.id).await?
            {
                let (instance_count, _total_cpu, _total_memory) =
                    get_shared_package_usage(&state, package_id, user.id).await?;
                if let Some(owner_username) = &pkg.owner_username {
                    quota_owner_username = Some(owner_username.clone());
                }
                quota_info["maxInstances"] = json!(max_instances);
                quota_info["remainingInstances"] =
                    json!(std::cmp::max(0, max_instances as i64 - instance_count));
                // quotaMultiplier is always null for global shares -> CPU/内存无限制
            }
        } else {
            quota_owner_username = Some(user.username.clone());
        }
    } else if has_instance_with_package {
        if let Some(owner_username) = &pkg.owner_username {
            quota_owner_username = Some(owner_username.clone());
        }
    }
    quota_info["ownerUsername"] = match quota_owner_username {
        Some(name) => json!(name),
        None => Value::Null,
    };

    let has_required_package_instance = match pkg.required_package_id {
        Some(id) => user_has_normal_instance_for_package(&state, user.id, id).await?,
        None => true,
    };
    let plans = get_plans_by_package_id(&state, package_id, !can_manage_package).await?;
    let plan_summary = plan_summary_json(&plans);

    let bindings = fetch_package_host_bindings(&state, &[package_id]).await?;
    let (host_ids, pools, multipliers) =
        bindings_json(bindings.get(&package_id).map(|v| v.as_slice()).unwrap_or(&[]));

    let mut package = json!({
        "id": pkg.id,
        "name": pkg.name,
        "description": pkg.description,
        "cpu_max": pkg.cpu_max,
        "memory_max": pkg.memory_max,
        "disk_max": pkg.disk_max,
        "bandwidth_max": pkg.bandwidth_max,
        "network_mode": pkg.network_mode,
        "instance_type": pkg.instance_type,
        "host_ids": host_ids,
        "privileged": if can_manage_package { if pkg.privileged { 1 } else { 0 } } else { 0 },
        "nested": if can_manage_package { if pkg.nested { 1 } else { 0 } } else { 0 },
        "active": if pkg.active { 1 } else { 0 },
        "monthly_traffic_limit": pkg.monthly_traffic_limit.map(|v| v.to_string()),
        "port_limit": pkg.port_limit,
        "snapshot_limit": pkg.snapshot_limit,
        "backup_limit": pkg.backup_limit,
        "site_limit": pkg.site_limit,
        "io_limit_mode": pkg.io_limit_mode,
        "limits_read": pkg.limits_read,
        "limits_write": pkg.limits_write,
        "limits_read_iops": pkg.limits_read_iops,
        "limits_write_iops": pkg.limits_write_iops,
        "limits_ingress": pkg.limits_ingress,
        "limits_egress": pkg.limits_egress,
        "limits_processes": pkg.limits_processes,
        "limits_cpu_priority": pkg.limits_cpu_priority,
        "boot_autostart": pkg.boot_autostart,
        "boot_autostart_priority": pkg.boot_autostart_priority,
        "boot_autostart_delay": pkg.boot_autostart_delay,
        "boot_host_shutdown_timeout": pkg.boot_host_shutdown_timeout,
        "allow_instance_deletion": pkg.allow_instance_deletion,
        "destroy_traffic_limit": pkg.destroy_traffic_limit.to_string(),
        "required_package_id": pkg.required_package_id,
        "required_package_name": pkg.required_package_name,
        "has_required_package_instance": has_required_package_instance,
        "planSummary": plan_summary,
        "ownerId": pkg.user_id,
        "isOwn": is_own,
        "quotaInfo": quota_info,
    });
    if can_manage_package {
        package["host_storage_pools"] = pools;
        package["host_traffic_multipliers"] = multipliers;
        package["global_shared"] = json!(pkg.global_shared);
        package["global_quota_multiplier"] = json!(null);
        package["global_max_instances"] = if pkg.global_shared {
            json!(normalize_public_package_max_instances(
                pkg.global_max_instances.map(|v| json!(v)).as_ref()
            ))
        } else {
            json!(null)
        };
    }

    Ok(Json(json!({ "package": package })))
}

/// POST / — 创建套餐。
#[allow(clippy::too_many_lines)]
async fn create_package(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    if let Err(resp) = validate_package_body_schema(&body, &["name", "cpuMax", "memoryMax", "diskMax"]) {
        return Ok(resp);
    }

    let obj = body.as_object().cloned().unwrap_or_default();
    let g = |k: &str| obj.get(k);

    let name = g("name").and_then(Value::as_str).unwrap_or("").to_string();
    let description = g("description").and_then(Value::as_str).map(|s| s.to_string());
    let cpu_max = g("cpuMax").and_then(Value::as_i64).unwrap_or(0) as i32;
    let memory_max = g("memoryMax").and_then(Value::as_i64).unwrap_or(0) as i32;
    let disk_max = g("diskMax").and_then(Value::as_i64).unwrap_or(0) as i32;
    let bandwidth_max = g("bandwidthMax").and_then(Value::as_i64).map(|v| v as i32);
    let network_mode = g("networkMode")
        .and_then(Value::as_str)
        .unwrap_or("nat")
        .to_string();
    let instance_type = g("instanceType")
        .and_then(Value::as_str)
        .unwrap_or("container")
        .to_string();
    let host_ids: Vec<i32> = g("hostIds")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).map(|v| v as i32).collect())
        .unwrap_or_default();
    let privileged = g("privileged").and_then(Value::as_bool).unwrap_or(false);
    let nested = g("nested").and_then(Value::as_bool).unwrap_or(false);
    let active = g("active").and_then(Value::as_bool).unwrap_or(true);
    let port_limit = g("portLimit").and_then(Value::as_i64).map(|v| v as i32);
    let snapshot_limit = g("snapshotLimit").and_then(Value::as_i64).map(|v| v as i32);
    let backup_limit = g("backupLimit").and_then(Value::as_i64).map(|v| v as i32);
    let site_limit = g("siteLimit").and_then(Value::as_i64).map(|v| v as i32);
    let global_shared = g("globalShared").and_then(Value::as_bool).unwrap_or(false);
    let global_max_instances = g("globalMaxInstances").and_then(Value::as_i64).map(|v| v as i32);
    let required_package_id = match g("requiredPackageId") {
        Some(Value::Number(n)) => n.as_i64().map(|v| v as i32),
        _ => None,
    };
    let allow_instance_deletion =
        g("allowInstanceDeletion").and_then(Value::as_bool).unwrap_or(true);

    // 验证必须至少绑定一个宿主机
    if host_ids.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Package must bind at least one host", "code": "NO_HOSTS" })),
        )
            .into_response());
    }

    // KVM 网络模式校验
    if instance_type == "vm" && KVM_UNSUPPORTED_NETWORK_MODES.contains(&network_mode.as_str()) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "KVM packages do not support IPv4 NAT & IPv6 NAT or IPv6 NAT network modes",
                "code": "KVM_NETWORK_MODE_UNSUPPORTED"
            })),
        )
            .into_response());
    }

    let name_validation = validators::validate_name(&name, "Package name", 2, 64);
    if !name_validation.valid {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": name_validation.message })),
        )
            .into_response());
    }
    let name = name_validation.sanitized.unwrap_or(name);

    if let Some(desc) = &description {
        let desc_validation = validators::validate_text(desc, "Package description", 500);
        if !desc_validation.valid {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": desc_validation.message })),
            )
                .into_response());
        }
    }

    // 同一用户下名称唯一
    if get_package_by_user_and_name(&state, user.id, &name)
        .await?
        .is_some()
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Package name already exists", "code": "NAME_EXISTS" })),
        )
            .into_response());
    }

    // 前置套餐校验（独立 Serializable 事务 + advisory lock）
    validate_package_prerequisite_reference_locked(
        &state,
        None,
        required_package_id,
        Some(user.id),
    )
    .await?;

    if global_shared && !validate_public_package_max_instances(js_number(g("globalMaxInstances")))
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "公开套餐最大实例数必须是 1-5 之间的整数",
                "code": "INVALID_MAX_INSTANCES"
            })),
        )
            .into_response());
    }

    // BigInt(monthlyTrafficLimit) — outside the create try/catch in TS -> 500.
    let monthly_traffic_limit: Option<i64> = match g("monthlyTrafficLimit") {
        Some(Value::String(s)) if !s.is_empty() => Some(
            s.trim()
                .parse::<i64>()
                .map_err(|_| ApiError::internal(format!("Cannot convert {s} to a BigInt")))?,
        ),
        _ => None,
    };

    let pools =
        normalize_host_storage_pools(g("hostStoragePools")).map_err(ApiError::internal)?;
    let multipliers = normalize_host_traffic_multipliers(g("hostTrafficMultipliers"))
        .map_err(ApiError::internal)?;
    // parseDestroyTrafficLimit runs inside the create try/catch in TS ->
    // failures surface as 400 INVALID_PACKAGE_CONFIG.
    let destroy_traffic_limit = match parse_destroy_traffic_limit(g("destroyTrafficLimit")) {
        Ok(v) => v,
        Err(message) => {
            return Ok(package_op_error_response(PackageOpError::Config(message)));
        }
    };

    let data = CreatePackageData {
        user_id: user.id,
        name: name.clone(),
        description,
        cpu_max,
        memory_max,
        disk_max,
        bandwidth_max,
        network_mode: network_mode.clone(),
        instance_type: instance_type.clone(),
        privileged,
        nested,
        active,
        port_limit: port_limit.unwrap_or(20),
        snapshot_limit: snapshot_limit.unwrap_or(5),
        backup_limit: backup_limit.unwrap_or(3),
        site_limit: site_limit.unwrap_or(10),
        monthly_traffic_limit,
        io_limit_mode: g("ioLimitMode")
            .and_then(Value::as_str)
            .unwrap_or("throughput")
            .to_string(),
        limits_read: g("limitsRead").and_then(Value::as_str).unwrap_or("100MB").to_string(),
        limits_write: g("limitsWrite").and_then(Value::as_str).unwrap_or("100MB").to_string(),
        limits_read_iops: g("limitsReadIops")
            .and_then(Value::as_i64)
            .map(|v| v as i32)
            .unwrap_or(500),
        limits_write_iops: g("limitsWriteIops")
            .and_then(Value::as_i64)
            .map(|v| v as i32)
            .unwrap_or(500),
        limits_ingress: g("limitsIngress")
            .and_then(Value::as_str)
            .unwrap_or("300Mbit")
            .to_string(),
        limits_egress: g("limitsEgress")
            .and_then(Value::as_str)
            .unwrap_or("300Mbit")
            .to_string(),
        limits_processes: g("limitsProcesses")
            .and_then(Value::as_i64)
            .map(|v| v as i32)
            .unwrap_or(500),
        limits_cpu_priority: g("limitsCpuPriority")
            .and_then(Value::as_i64)
            .map(|v| v as i32)
            .unwrap_or(10),
        boot_autostart: g("bootAutostart").and_then(Value::as_bool).unwrap_or(true),
        boot_autostart_priority: g("bootAutostartPriority")
            .and_then(Value::as_i64)
            .map(|v| v as i32)
            .unwrap_or(20),
        boot_autostart_delay: g("bootAutostartDelay")
            .and_then(Value::as_i64)
            .map(|v| v as i32)
            .unwrap_or(15),
        boot_host_shutdown_timeout: g("bootHostShutdownTimeout")
            .and_then(Value::as_i64)
            .map(|v| v as i32)
            .unwrap_or(30),
        global_shared,
        global_max_instances: if global_shared { global_max_instances } else { None },
        required_package_id,
        allow_instance_deletion,
        destroy_traffic_limit,
        host_ids,
        pools,
        multipliers,
    };
    let is_admin = user.role == "admin";

    // TS: createPackage wraps in a Serializable tx only when a prerequisite is
    // set; either way errors become `400 INVALID_PACKAGE_CONFIG`.
    let mut tx = state.db.begin().await?;
    if data.required_package_id.is_some() {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await?;
        db::advisory_transaction_lock(&mut tx, PACKAGE_PREREQUISITE_LOCK_NAMESPACE, 1).await?;
        if let Err(e) = validate_package_prerequisite_reference(
            &mut *tx,
            None,
            data.required_package_id,
            Some(user.id),
        )
        .await
        {
            let _ = tx.rollback().await;
            return Ok(package_op_error_response(PackageOpError::Prereq(e)));
        }
    }
    let created = create_package_db(&mut tx, &data, is_admin).await;
    let id: i32 = match created {
        Ok(id) => {
            tx.commit().await.map_err(ApiError::from_sql)?;
            id
        }
        Err(e) => {
            let _ = tx.rollback().await;
            return Ok(package_op_error_response(e));
        }
    };

    create_log(
        &state,
        user.id,
        "package",
        "package.create",
        &format!(
            "Created package \"{}\" [CPU: {}%, Memory: {}MB, Disk: {}MB, instanceType: {}, network: {}, hosts: {}]",
            name,
            cpu_max,
            memory_max,
            disk_max,
            instance_type,
            network_mode,
            data.host_ids
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Package created",
            "package": { "id": id, "name": name }
        })),
    )
        .into_response())
}

/// PATCH /{id} — 更新套餐。
#[allow(clippy::too_many_lines)]
async fn update_package(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    if let Err(resp) = validate_package_body_schema(&body, &[]) {
        return Ok(resp);
    }

    let package_id = js_number_id(&id)?;
    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;

    if pkg.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let obj = body.as_object().cloned().unwrap_or_default();
    let g = |k: &str| obj.get(k);

    // 名称/描述校验（仅提供时）
    if let Some(name) = g("name").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let name_validation = validators::validate_name(name, "Package name", 2, 64);
        if !name_validation.valid {
            return Err(ApiError::bare(
                StatusCode::BAD_REQUEST,
                name_validation.message.unwrap_or_default(),
            ));
        }
    }
    if let Some(desc) = g("description").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let desc_validation = validators::validate_text(desc, "Package description", 500);
        if !desc_validation.valid {
            return Err(ApiError::bare(
                StatusCode::BAD_REQUEST,
                desc_validation.message.unwrap_or_default(),
            ));
        }
    }

    // 名称冲突检查（同一用户下）
    if let Some(name) = g("name").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        if name != pkg.name
            && get_package_by_user_and_name(&state, pkg.user_id, name)
                .await?
                .is_some()
        {
            return Err(ApiError::with_message(
                "NAME_EXISTS",
                StatusCode::BAD_REQUEST,
                "Package name already exists",
            ));
        }
    }

    // ---- updateData 组装（与 TS 一致的条件赋值） ----
    let mut data = UpdatePackageData {
        name: g("name").and_then(Value::as_str).map(|s| s.to_string()),
        description: g("description").and_then(Value::as_str).map(|s| s.to_string()),
        cpu_max: g("cpuMax").and_then(Value::as_i64).map(|v| v as i32),
        memory_max: g("memoryMax").and_then(Value::as_i64).map(|v| v as i32),
        disk_max: g("diskMax").and_then(Value::as_i64).map(|v| v as i32),
        bandwidth_max: g("bandwidthMax").and_then(Value::as_i64).map(|v| v as i32),
        network_mode: g("networkMode").and_then(Value::as_str).map(|s| s.to_string()),
        instance_type: g("instanceType").and_then(Value::as_str).map(|s| s.to_string()),
        privileged: g("privileged").and_then(Value::as_bool),
        nested: g("nested").and_then(Value::as_bool),
        active: g("active").and_then(Value::as_bool),
        port_limit: g("portLimit").and_then(Value::as_i64).map(|v| v as i32),
        snapshot_limit: g("snapshotLimit").and_then(Value::as_i64).map(|v| v as i32),
        backup_limit: g("backupLimit").and_then(Value::as_i64).map(|v| v as i32),
        site_limit: g("siteLimit").and_then(Value::as_i64).map(|v| v as i32),
        monthly_traffic_limit: match g("monthlyTrafficLimit") {
            // `monthlyTrafficLimit ? BigInt(...) : null` — '' is falsy -> null.
            Some(Value::String(s)) if !s.is_empty() => Some(Some(
                s.trim().parse::<i64>().map_err(|_| {
                    ApiError::internal(format!("Cannot convert {s} to a BigInt"))
                })?,
            )),
            Some(Value::String(_)) => Some(None),
            Some(Value::Null) => Some(None),
            _ => None,
        },
        io_limit_mode: g("ioLimitMode").and_then(Value::as_str).map(|s| s.to_string()),
        limits_read: g("limitsRead").and_then(Value::as_str).map(|s| s.to_string()),
        limits_write: g("limitsWrite").and_then(Value::as_str).map(|s| s.to_string()),
        limits_read_iops: g("limitsReadIops").and_then(Value::as_i64).map(|v| v as i32),
        limits_write_iops: g("limitsWriteIops").and_then(Value::as_i64).map(|v| v as i32),
        limits_ingress: g("limitsIngress").and_then(Value::as_str).map(|s| s.to_string()),
        limits_egress: g("limitsEgress").and_then(Value::as_str).map(|s| s.to_string()),
        limits_processes: g("limitsProcesses").and_then(Value::as_i64).map(|v| v as i32),
        limits_cpu_priority: g("limitsCpuPriority").and_then(Value::as_i64).map(|v| v as i32),
        boot_autostart: g("bootAutostart").and_then(Value::as_bool),
        boot_autostart_priority: g("bootAutostartPriority")
            .and_then(Value::as_i64)
            .map(|v| v as i32),
        boot_autostart_delay: g("bootAutostartDelay").and_then(Value::as_i64).map(|v| v as i32),
        boot_host_shutdown_timeout: g("bootHostShutdownTimeout")
            .and_then(Value::as_i64)
            .map(|v| v as i32),
        allow_instance_deletion: g("allowInstanceDeletion").and_then(Value::as_bool),
        host_ids: g("hostIds").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(Value::as_i64)
                .map(|v| v as i32)
                .collect::<Vec<i32>>()
        }),
        ..Default::default()
    };

    if let Some(limit) = g("destroyTrafficLimit") {
        match parse_destroy_traffic_limit(Some(limit)) {
            Ok(v) => data.destroy_traffic_limit = v,
            Err(message) => {
                return Err(ApiError::bare(StatusCode::BAD_REQUEST, message));
            }
        }
    }

    // KVM 网络模式校验（next 值回退到当前值）
    let next_instance_type = data
        .instance_type
        .clone()
        .unwrap_or_else(|| pkg.instance_type.clone());
    let next_network_mode = data
        .network_mode
        .clone()
        .unwrap_or_else(|| pkg.network_mode.clone());
    if next_instance_type == "vm"
        && KVM_UNSUPPORTED_NETWORK_MODES.contains(&next_network_mode.as_str())
    {
        return Err(ApiError::with_message(
            "KVM_NETWORK_MODE_UNSUPPORTED",
            StatusCode::BAD_REQUEST,
            "KVM packages do not support IPv4 NAT & IPv6 NAT or IPv6 NAT network modes",
        ));
    }

    // hostIds 必须至少一个（schema 已挡空数组；此处保留语义）
    if let Some(host_ids) = &data.host_ids {
        if host_ids.is_empty() {
            return Err(ApiError::with_message(
                "NO_HOSTS",
                StatusCode::BAD_REQUEST,
                "Package must bind at least one host",
            ));
        }
    }
    if let Some(pools) = g("hostStoragePools") {
        data.pools = normalize_host_storage_pools(Some(pools)).map_err(ApiError::internal)?;
        data.has_pools = true;
    }
    if let Some(multipliers) = g("hostTrafficMultipliers") {
        data.multipliers =
            normalize_host_traffic_multipliers(Some(multipliers)).map_err(ApiError::internal)?;
        data.has_multipliers = true;
    }

    // 全局共享配置
    let current_global_shared = pkg.global_shared;
    if let Some(global_shared) = g("globalShared").and_then(Value::as_bool) {
        data.global_shared = Some(global_shared);
        if !global_shared {
            data.global_quota_multiplier = Some(None);
            data.global_max_instances = Some(None);
        }
    }
    let will_be_global_shared = g("globalShared")
        .and_then(Value::as_bool)
        .unwrap_or(current_global_shared);
    if will_be_global_shared {
        data.global_quota_multiplier = Some(None);
        let next_max_instances = match g("globalMaxInstances") {
            Some(v) if !v.is_null() => normalize_public_package_max_instances(Some(v)),
            _ => normalize_public_package_max_instances(
                pkg.global_max_instances.map(|v| json!(v)).as_ref(),
            ),
        };
        if !validate_public_package_max_instances(next_max_instances as f64) {
            return Err(ApiError::with_message(
                "INVALID_MAX_INSTANCES",
                StatusCode::BAD_REQUEST,
                "公开套餐最大实例数必须是 1-5 之间的整数",
            ));
        }
        data.global_max_instances = Some(Some(next_max_instances as i32));
    } else if (g("globalQuotaMultiplier").is_some() || g("globalMaxInstances").is_some())
        && g("globalShared").is_none()
    {
        return Err(ApiError::with_message(
            "INVALID_GLOBAL_SHARED_STATE",
            StatusCode::BAD_REQUEST,
            "Cannot update globalQuotaMultiplier or globalMaxInstances when globalShared is false",
        ));
    }

    // 前置套餐（Some(None) = 显式 null -> 清除）
    if g("requiredPackageId").is_some() {
        data.required_package_id = match g("requiredPackageId") {
            Some(Value::Null) => Some(None),
            Some(v) => v.as_i64().map(|n| Some(n as i32)),
            None => None,
        };
    }

    // ---- shouldSync + updatePackage + traffic sync（错误 -> 400） ----
    let op_result: Result<(), PackageOpError> = async {
        let should_sync = should_sync_package_traffic_limits_after_update(
            &state,
            package_id,
            &pkg,
            &data,
        )
        .await
        .map_err(|e| PackageOpError::Config(format!("{e:?}")))?;
        update_package_db(&state, package_id, data, user.role == "admin").await?;
        if should_sync {
            sync_package_traffic_limits(&state, package_id)
                .await
                .map_err(|e| PackageOpError::Config(format!("{e:?}")))?;
            // reconcileTrafficStateForInstanceIds is not ported (traffic
            // scheduler service); the TS only logs failures, so a warning
            // preserves the non-fatal behavior.
            tracing::warn!(
                "[packages] package traffic limits synced for package #{package_id}; reconcileTrafficStateForInstanceIds not ported"
            );
        }
        Ok(())
    }
    .await;

    if let Err(e) = op_result {
        return Ok(package_op_error_response(e));
    }

    // ---- 变更日志 ----
    let mut pkg_changes: Vec<String> = Vec::new();
    if let Some(name) = g("name").and_then(Value::as_str) {
        if name != pkg.name {
            pkg_changes.push(format!("name -> \"{name}\""));
        }
    }
    if let Some(v) = g("cpuMax").and_then(Value::as_i64) {
        pkg_changes.push(format!("cpuMax -> {v}%"));
    }
    if let Some(v) = g("memoryMax").and_then(Value::as_i64) {
        pkg_changes.push(format!("memoryMax -> {v}MB"));
    }
    if let Some(v) = g("diskMax").and_then(Value::as_i64) {
        pkg_changes.push(format!("diskMax -> {v}MB"));
    }
    if let Some(v) = g("instanceType").and_then(Value::as_str) {
        pkg_changes.push(format!("instanceType -> {v}"));
    }
    if let Some(v) = g("active").and_then(Value::as_bool) {
        pkg_changes.push(format!("active -> {v}"));
    }
    if let Some(host_ids) = g("hostIds").and_then(Value::as_array) {
        pkg_changes.push(format!(
            "hosts -> [{}]",
            host_ids
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }

    create_log(
        &state,
        user.id,
        "package",
        "package.update",
        &format!(
            "Updated package \"{}\" [{}]",
            pkg.name,
            if pkg_changes.is_empty() {
                "minor changes".to_string()
            } else {
                pkg_changes.join(", ")
            }
        ),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Package updated" })).into_response())
}

/// packages.ts shouldSyncPackageTrafficLimitsAfterUpdate.
async fn should_sync_package_traffic_limits_after_update(
    state: &SharedAppState,
    package_id: i32,
    pkg: &OwnPackageRow,
    updates: &UpdatePackageData,
) -> Result<bool, ApiError> {
    if let Some(next_limit) = updates.monthly_traffic_limit {
        if pkg.monthly_traffic_limit != next_limit {
            return Ok(true);
        }
    }
    if updates.host_ids.is_none() && !updates.has_multipliers {
        return Ok(false);
    }

    let instance_hosts: Vec<(i32,)> = sqlx::query_as(
        "SELECT DISTINCT host_id FROM instances WHERE package_id = $1 AND status <> 'deleted'",
    )
    .bind(package_id)
    .fetch_all(&state.db)
    .await?;
    if instance_hosts.is_empty() {
        return Ok(false);
    }

    let bindings = fetch_package_host_bindings(state, &[package_id]).await?;
    let current_host_ids: HashSet<i32> = bindings
        .get(&package_id)
        .map(|list| list.iter().map(|b| b.host_id).collect())
        .unwrap_or_default();
    let next_host_ids: Option<HashSet<i32>> =
        updates.host_ids.as_ref().map(|ids| ids.iter().copied().collect());

    for (host_id,) in instance_hosts {
        let explicit = updates.multipliers.contains_key(&host_id);
        if !explicit
            && (next_host_ids.is_none() || !next_host_ids.as_ref().unwrap().contains(&host_id))
        {
            continue;
        }
        let current_multiplier = if current_host_ids.contains(&host_id) {
            bindings
                .get(&package_id)
                .and_then(|list| list.iter().find(|b| b.host_id == host_id))
                .map(|b| b.traffic_multiplier)
                .unwrap_or(1.0)
        } else {
            1.0
        };
        let next_multiplier = if explicit {
            normalize_traffic_multiplier_f(updates.multipliers[&host_id])
                .map_err(ApiError::internal)?
        } else {
            current_multiplier
        };
        if current_multiplier != next_multiplier {
            return Ok(true);
        }
    }
    Ok(false)
}

/// DELETE /{id} — 删除套餐。
async fn delete_package(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let package_id = js_number_id(&id)?;
    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;

    if pkg.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let dependents = get_packages_depending_on_package(&state, package_id).await?;
    if !dependents.is_empty() {
        let names: Vec<String> = dependents.iter().map(|(_, name)| name.clone()).collect();
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Package is required by other packages: {}", names.join(", ")),
                "code": "PACKAGE_PREREQUISITE_IN_USE",
                "details": format!("请先删除后置套餐：{}", names.join("、")),
            })),
        )
            .into_response());
    }

    let instance_count = get_instance_count_by_package(&state, package_id).await?;
    if instance_count > 0 {
        return Err(
            ApiError::new(code::PACKAGE_HAS_INSTANCES, StatusCode::BAD_REQUEST)
                .with_details(instance_count.to_string()),
        );
    }

    delete_package_db(&state, package_id).await?;

    // decrementUserQuotaUsed(request.user.id, 'package')
    let _ = sqlx::query(
        "UPDATE user_quotas SET package_used = package_used - 1 \
         WHERE user_id = $1 AND package_used > 0",
    )
    .bind(user.id)
    .execute(&state.db)
    .await;

    create_log(
        &state,
        user.id,
        "package",
        "package.delete",
        &format!(
            "Deleted package \"{}\" [CPU: {}%, Memory: {}MB]",
            pkg.name, pkg.cpu_max, pkg.memory_max
        ),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Package deleted" })).into_response())
}

// ===========================================================================
// handlers — 套餐共享 API
// ===========================================================================

/// POST /{id}/share — 共享套餐给好友。
async fn share_package(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let package_id = js_number_id(&id)?;
    let friend_id = match body.get("friendId").and_then(Value::as_i64) {
        Some(v) if v >= i32::MIN as i64 && v <= i32::MAX as i64 => v as i32,
        _ => return Err(ApiError::internal("Prisma Int argument validation failed")),
    };
    let quota_multiplier = body.get("quotaMultiplier").and_then(Value::as_f64);
    let max_instances = body.get("maxInstances").and_then(Value::as_i64).map(|v| v as i32);

    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    // 验证好友关系
    let are_friends: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM friendships WHERE status = 'accepted' \
         AND ((user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)))",
    )
    .bind(user.0.id)
    .bind(friend_id)
    .fetch_one(&state.db)
    .await?;
    if !are_friends {
        return Err(ApiError::bad_request(code::NOT_FRIENDS));
    }

    // 检查是否已共享（TS 复用 getPackageShareForUser：仅对公开套餐生效）
    let existing = get_package_share_for_user(&state, package_id, friend_id).await?;
    if existing.is_some() {
        return Err(ApiError::bad_request(code::PACKAGE_ALREADY_SHARED));
    }

    let quota_dec = quota_multiplier.and_then(Decimal::from_f64);
    let share: (i32,) = sqlx::query_as(
        "INSERT INTO package_shares (package_id, owner_id, shared_to_id, quota_multiplier, max_instances) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(package_id)
    .bind(user.0.id)
    .bind(friend_id)
    .bind(quota_dec)
    .bind(max_instances)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(json!({ "success": true, "shareId": share.0 })))
}

/// DELETE /{id}/share/{userId} — 取消套餐共享。
async fn unshare_package(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((id, user_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let package_id = js_number_id(&id)?;
    let target_user_id = js_number_id(&user_id)?;

    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let result = sqlx::query("DELETE FROM package_shares WHERE package_id = $1 AND shared_to_id = $2")
        .bind(package_id)
        .bind(target_user_id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "success": result.rows_affected() > 0 })))
}

/// PATCH /{id}/shares/{shareId} — 修改共享配额限制。
async fn update_share_quota(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path((id, share_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let package_id = js_number_id(&id)?;
    let share_id_num = js_number_id(&share_id)?;

    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    // updateMany where id + packageId；undefined 字段不更新。
    let mut sets: Vec<String> = Vec::new();
    let mut binder = ParamList::default();
    if let Some(v) = body.get("quotaMultiplier") {
        let idx = binder.values.len() + 1;
        sets.push(format!("quota_multiplier = ${idx}"));
        binder.push_opt_dec(v.as_f64().and_then(Decimal::from_f64));
    }
    if let Some(v) = body.get("maxInstances") {
        let idx = binder.values.len() + 1;
        sets.push(format!("max_instances = ${idx}"));
        binder.push_opt_i32(v.as_i64().map(|n| n as i32));
    }
    if sets.is_empty() {
        // No fields provided: the TS updateMany with empty data still matches,
        // so report success purely on existence.
        let exists: Option<(i32,)> = sqlx::query_as(
            "SELECT id FROM package_shares WHERE id = $1 AND package_id = $2",
        )
        .bind(share_id_num)
        .bind(package_id)
        .fetch_optional(&state.db)
        .await?;
        return Ok(Json(json!({ "success": exists.is_some() })));
    }
    let sql = format!(
        "UPDATE package_shares SET {} WHERE id = ${} AND package_id = ${}",
        sets.join(", "),
        binder.values.len() + 1,
        binder.values.len() + 2
    );
    let result = binder
        .bind_to(sqlx::query(&sql))
        .bind(share_id_num)
        .bind(package_id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found(code::SHARE_NOT_FOUND));
    }
    Ok(Json(json!({ "success": true })))
}

/// Shared JSON builder for GET /{id}/shares + GET /my-shares.
#[allow(clippy::type_complexity)]
fn share_row_json(
    (id, package_id, package_name, owner_id, owner_username, shared_to_id, shared_to_username, avatar_style, avatar_badge, quota_multiplier, max_instances, created_at): &(
        i32,
        i32,
        String,
        i32,
        String,
        i32,
        String,
        Option<String>,
        Option<String>,
        Option<Decimal>,
        Option<i32>,
        DateTime<Utc>,
    ),
) -> Value {
    json!({
        "id": id,
        "packageId": package_id,
        "packageName": package_name,
        "ownerId": owner_id,
        "ownerUsername": owner_username,
        "sharedToId": shared_to_id,
        "sharedToUsername": shared_to_username,
        "sharedToAvatarStyle": avatar_style,
        "sharedToAvatarBadgeId": avatar_badge,
        // TS: s.quotaMultiplier ? Number(...) : null — 0 is falsy -> null.
        "quotaMultiplier": match quota_multiplier {
            Some(d) if *d != Decimal::ZERO => json!(num(*d)),
            _ => Value::Null,
        },
        "maxInstances": max_instances,
        "createdAt": iso(*created_at),
    })
}

type ShareRowTuple = (
    i32,
    i32,
    String,
    i32,
    String,
    i32,
    String,
    Option<String>,
    Option<String>,
    Option<Decimal>,
    Option<i32>,
    DateTime<Utc>,
);

const SHARE_SELECT: &str = "SELECT s.id, s.package_id, p.name, s.owner_id, ou.username, \
    s.shared_to_id, tu.username, tu.avatar_style, tu.avatar_badge_id, s.quota_multiplier, \
    s.max_instances, s.created_at \
    FROM package_shares s \
    JOIN packages p ON p.id = s.package_id \
    JOIN users ou ON ou.id = s.owner_id \
    JOIN users tu ON tu.id = s.shared_to_id";

/// GET /{id}/shares — 获取套餐的共享列表。
async fn list_shares(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let package_id = js_number_id(&id)?;
    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.0.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let rows: Vec<ShareRowTuple> = sqlx::query_as(&format!(
        "{SHARE_SELECT} WHERE s.package_id = $1 ORDER BY s.created_at DESC"
    ))
    .bind(package_id)
    .fetch_all(&state.db)
    .await?;

    let shares: Vec<Value> = rows.iter().map(share_row_json).collect();
    Ok(Json(json!({ "shares": shares })))
}

/// GET /my-shares — 获取用户共享出去的所有套餐。
async fn my_shares(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    let rows: Vec<ShareRowTuple> = sqlx::query_as(&format!(
        "{SHARE_SELECT} WHERE s.owner_id = $1 ORDER BY s.created_at DESC"
    ))
    .bind(user.0.id)
    .fetch_all(&state.db)
    .await?;

    let shares: Vec<Value> = rows.iter().map(share_row_json).collect();
    Ok(Json(json!({ "shares": shares })))
}

// ===========================================================================
// handlers — 资源释放功能
// ===========================================================================

/// GET /{id}/hosts-detail — 套餐绑定的宿主机详情。
async fn hosts_detail(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let package_id = js_number_id(&id)?;
    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    // Aggregate per-host usage from live instances (HOST_RESOURCE_INSTANCE_STATUSES).
    let statuses = HOST_RESOURCE_INSTANCE_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let rows: Vec<(i32, String, String, i32, i32, Option<i64>, Option<i64>)> = sqlx::query_as(&format!(
        "SELECT h.id, h.name, h.country_code, h.cpu_allowance_max, h.memory_max, i.cpu, i.memory \
         FROM package_hosts ph \
         JOIN hosts h ON h.id = ph.host_id \
         LEFT JOIN instances i ON i.host_id = h.id AND i.status IN ({statuses}) \
         WHERE ph.package_id = $1 ORDER BY ph.id ASC"
    ))
    .bind(package_id)
    .fetch_all(&state.db)
    .await?;

    let mut hosts_json: Vec<Value> = Vec::new();
    let mut seen: HashMap<i32, usize> = HashMap::new();
    for (host_id, name, country_code, cpu_max, mem_max, cpu, memory) in rows {
        let idx = match seen.get(&host_id) {
            Some(i) => *i,
            None => {
                hosts_json.push(json!({
                    "id": host_id,
                    "name": name,
                    "countryCode": country_code,
                    "cpuAllowanceMax": cpu_max,
                    "memoryMax": mem_max,
                    "cpuUsed": 0,
                    "memoryUsed": 0,
                }));
                seen.insert(host_id, hosts_json.len() - 1);
                hosts_json.len() - 1
            }
        };
        let entry = &mut hosts_json[idx];
        entry["cpuUsed"] = json!(entry["cpuUsed"].as_i64().unwrap_or(0) + cpu.unwrap_or(0));
        entry["memoryUsed"] =
            json!(entry["memoryUsed"].as_i64().unwrap_or(0) + memory.unwrap_or(0));
    }

    Ok(Json(json!({
        "hosts": hosts_json,
        "packageName": pkg.name,
        "cpuMax": pkg.cpu_max,
        "memoryMax": pkg.memory_max,
    })))
}

async fn is_user_blocked_from_package(
    state: &SharedAppState,
    user_id: i32,
    package_id: i32,
) -> Result<bool, ApiError> {
    let owner: Option<(i32,)> = sqlx::query_as("SELECT user_id FROM packages WHERE id = $1")
        .bind(package_id)
        .fetch_optional(&state.db)
        .await?;
    let Some((owner_id,)) = owner else {
        return Ok(false);
    };
    if owner_id == user_id {
        return Ok(false);
    }
    is_user_blocked_by_hoster(&state.db, owner_id, user_id).await
}

/// GET /{id}/owner-info — 套餐所有者的托管信息。
async fn owner_info(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let package_id = js_number_id(&id)?;
    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;

    let owner_id = pkg.user_id;

    if owner_id != user.0.id && is_user_blocked_from_package(&state, user.0.id, package_id).await? {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let owner: Option<(i32, String, Option<String>, String, Option<String>, DateTime<Utc>, String)> =
        sqlx::query_as(
            "SELECT id, username, email, avatar_style, avatar_badge_id, created_at, role::text \
             FROM users WHERE id = $1",
        )
        .bind(owner_id)
        .fetch_optional(&state.db)
        .await?;

    // 套餐必须有所有者，且必须是普通用户的托管套餐
    let Some((owner_id, username, email, avatar_style, avatar_badge_id, created_at, role)) = owner
    else {
        return Err(ApiError::not_found(code::NOT_FOUND).with_details("该套餐不是托管套餐"));
    };
    if email.is_none() || role == "admin" {
        return Err(ApiError::not_found(code::NOT_FOUND).with_details("该套餐不是托管套餐"));
    }

    let host_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM hosts WHERE user_id = $1")
        .bind(owner_id)
        .fetch_one(&state.db)
        .await?;
    let instance_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instances i JOIN hosts h ON h.id = i.host_id \
         WHERE h.user_id = $1 AND i.status <> 'deleted'",
    )
    .bind(owner_id)
    .fetch_one(&state.db)
    .await?;
    let total_income: (Option<Decimal>,) = sqlx::query_as(
        "SELECT SUM(amount) FROM hosting_balance_logs WHERE user_id = $1 AND type = 'income'",
    )
    .bind(owner_id)
    .fetch_one(&state.db)
    .await?;

    let registered_days =
        (Utc::now().timestamp_millis() - created_at.timestamp_millis()) / (1000 * 60 * 60 * 24);

    let total_income_f64 = total_income.0.unwrap_or(Decimal::ZERO).to_f64().unwrap_or(0.0);
    let vip_rules = get_hosting_vip_rules(&state).await?;
    let vip_level = calculate_hosting_vip_level(&vip_rules, total_income_f64, instance_count.0);
    let vip_badge_style = get_vip_badge_style_for_level(&vip_rules, vip_level);

    Ok(Json(json!({
        "id": owner_id,
        "username": username,
        "email": email,
        "avatarStyle": avatar_style,
        "avatarBadgeId": avatar_badge_id,
        "hostCount": host_count.0,
        "instanceCount": instance_count.0,
        "registeredDays": registered_days,
        "vipLevel": vip_level,
        "vipBadgeStyle": vip_badge_style,
    })))
}

/// POST /{id}/release-quota — 释放配额。
async fn release_quota(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    if let Err(resp) = validate_release_quota_schema(&body) {
        return Ok(resp);
    }

    let package_id = js_number_id(&id)?;
    let obj = body.as_object().cloned().unwrap_or_default();
    let host_ids: Vec<i32> = obj
        .get("hostIds")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).map(|v| v as i32).collect())
        .unwrap_or_default();
    let cpu_add = obj.get("cpuAdd").and_then(Value::as_i64).unwrap_or(0) as i32;
    let memory_add = obj.get("memoryAdd").and_then(Value::as_i64).unwrap_or(0) as i32;
    let notify = obj.get("notify").and_then(Value::as_bool).unwrap_or(false);

    // 验证至少有一个配额大于 0
    if cpu_add <= 0 && memory_add <= 0 {
        return Err(ApiError::bare(
            StatusCode::BAD_REQUEST,
            "At least one quota must be greater than 0",
        ));
    }

    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    // 验证所有 hostIds 都属于该套餐
    let bindings = fetch_package_host_bindings(&state, &[package_id]).await?;
    let package_host_ids: Vec<i32> = bindings
        .get(&package_id)
        .map(|b| b.iter().map(|x| x.host_id).collect())
        .unwrap_or_default();
    let has_invalid = host_ids.iter().any(|hid| !package_host_ids.contains(hid));
    if has_invalid {
        return Err(ApiError::bare(
            StatusCode::BAD_REQUEST,
            "Some hosts are not bound to this package",
        ));
    }

    let mut results: Vec<Value> = Vec::new();
    for host_id in &host_ids {
        let Some((cpu_allowance_max, memory_max, cpu_used, memory_used)) =
            increase_host_quota(&state, *host_id, cpu_add, memory_add).await?
        else {
            continue; // TS: `if (!host) continue`
        };
        let host_info: Option<(String, String)> =
            sqlx::query_as("SELECT name, country_code FROM hosts WHERE id = $1")
                .bind(host_id)
                .fetch_optional(&state.db)
                .await?;
        let Some((name, country_code)) = host_info else {
            continue;
        };
        results.push(json!({
            "hostId": host_id,
            "hostName": name,
            "countryCode": if country_code.is_empty() { "us".to_string() } else { country_code },
            "cpuAllowanceMax": cpu_allowance_max,
            "memoryMax": memory_max,
            "cpuAvailable": cpu_allowance_max as i64 - cpu_used,
            "memoryAvailable": memory_max as i64 - memory_used,
        }));
    }

    create_log(
        &state,
        user.id,
        "package",
        "package.release_quota",
        &format!(
            "Released quota for package \"{}\": CPU +{}%, Memory +{}MB on {} host(s)",
            pkg.name,
            cpu_add,
            memory_add,
            host_ids.len()
        ),
        "success",
    )
    .await;

    // 通知（仅当 notify=true 且全局渠道存在时）— sendToChannel 通知栈未移植。
    if notify {
        let global_channel: Option<(i32,)> = sqlx::query_as(
            "SELECT id FROM notification_channels WHERE is_global = true LIMIT 1",
        )
        .fetch_optional(&state.db)
        .await?;
        if let Some((channel_id,)) = global_channel {
            tracing::warn!(
                "[packages] release-quota notification for package #{package_id} skipped (sendToChannel not ported), channel #{channel_id}"
            );
        }
    }

    Ok(Json(json!({
        "message": "Quota released successfully",
        "results": results,
    }))
    .into_response())
}

// ===========================================================================
// handlers — 套餐方案管理 API
// ===========================================================================

/// GET /{id}/plans — 获取套餐下的所有方案。
async fn list_plans(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let package_id = js_number_id(&id)?;
    let active_only = params.get("activeOnly").map(|s| s.as_str()) == Some("true");

    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;

    if pkg.user_id != user.id && user.role != "admin" {
        let can_access = can_user_access_package(&state, user.id, package_id).await?;
        if !can_access {
            return Err(ApiError::forbidden(code::FORBIDDEN));
        }
    }

    let plans = get_plans_by_package_id(&state, package_id, active_only).await?;
    let package_sold_out = compute_sold_out(&state, &[package_id]).await?;

    let plans_json: Vec<Value> = plans
        .iter()
        .map(|plan| {
            let mut v = serialize_plan(plan, Some(&pkg.instance_type));
            v["isSoldOut"] = json!(
                plan.is_sold_out || package_sold_out.get(&package_id).copied().unwrap_or(false)
            );
            v
        })
        .collect();

    Ok(Json(json!({ "plans": plans_json })))
}

/// GET /{id}/plans/{planId} — 获取单个套餐方案。
async fn get_plan(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, plan_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let package_id = js_number_id(&id)?;
    let plan_id_num = js_number_id(&plan_id)?;

    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let plan = get_plan_by_id(&state, plan_id_num).await?;
    if plan.as_ref().map(|p| p.package_id) != Some(package_id) {
        return Err(ApiError::bare(StatusCode::NOT_FOUND, "方案不存在"));
    }

    Ok(Json(json!({
        "plan": serialize_plan(plan.as_ref().unwrap(), Some(&pkg.instance_type)),
    })))
}

/// Numeric coercion helper for plan fields (JS comparisons coerce strings).
fn plan_num(obj: &Map<String, Value>, key: &str) -> Option<f64> {
    obj.get(key).map(|v| js_number(Some(v)))
}

/// Strict Prisma Int extraction: Some(None) when the field is present but not
/// a JSON integer (-> Prisma validation failure -> the 500 catch path).
fn plan_strict_i32(obj: &Map<String, Value>, key: &str) -> Option<Option<i32>> {
    match obj.get(key) {
        None => None,
        Some(Value::Number(n)) => n
            .as_i64()
            .filter(|v| *v >= i32::MIN as i64 && *v <= i32::MAX as i64)
            .map(|v| Some(v as i32)),
        Some(_) => Some(None),
    }
}

fn bad_json(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
}

/// POST /{id}/plans — 创建套餐方案。
#[allow(clippy::too_many_lines)]
async fn create_plan(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let package_id = js_number_id(&id)?;
    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let obj = body.as_object().cloned().unwrap_or_default();
    let g = |k: &str| obj.get(k);

    let normalized_swap_size: Option<f64> = if pkg.instance_type == "vm" {
        Some(0.0)
    } else {
        plan_num(&obj, "swapSize")
    };
    // TS: billingMode ?? 'package' — a non-string non-null value flows into
    // the package/hourly check below and fails there.
    let normalized_billing_mode: String = match g("billingMode") {
        None | Some(Value::Null) => "package".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            return Ok(bad_json("billingMode 必须为 package 或 hourly"));
        }
    };
    let normalized_billing_mode = normalized_billing_mode.as_str();

    if let Some(v) = g("isActive") {
        if !v.is_boolean() {
            return Ok(bad_json("isActive 必须为布尔值"));
        }
    }
    if let Some(v) = g("isSoldOut") {
        if !v.is_boolean() {
            return Ok(bad_json("isSoldOut 必须为布尔值"));
        }
    }
    if let Some(v) = g("trafficResetEnabled") {
        if !v.is_boolean() {
            return Ok(bad_json("trafficResetEnabled 必须为布尔值"));
        }
    }
    if normalized_billing_mode != "package" && normalized_billing_mode != "hourly" {
        return Ok(bad_json("billingMode 必须为 package 或 hourly"));
    }

    // 验证方案名称：允许 emoji，但仍禁止危险字符
    let plan_name = match validate_package_plan_name(g("name")) {
        Ok(name) => name,
        Err(message) => return Ok(bad_json(&message)),
    };

    // 名称唯一性
    if !is_plan_name_unique(&state, package_id, &plan_name, None).await? {
        return Ok(bad_json("该套餐下已存在同名方案"));
    }

    // 资源配置（JS 数字强转比较）
    let cpu = plan_num(&obj, "cpu").unwrap_or(f64::NAN);
    let memory = plan_num(&obj, "memory").unwrap_or(f64::NAN);
    let disk = plan_num(&obj, "disk").unwrap_or(f64::NAN);
    if cpu < 15.0 || cpu > 10000.0 {
        return Ok(bad_json("CPU 必须在 15-10000 之间"));
    }
    if memory < 128.0 || memory > 62144.0 {
        return Ok(bad_json("内存必须在 128-62144 MB 之间"));
    }
    if disk < 512.0 || disk > 104857600.0 {
        return Ok(bad_json("磁盘必须在 512 MB - 100 TB 之间"));
    }
    let resources = if normalized_billing_mode == "hourly" {
        (cpu, memory, disk)
    } else {
        (15.0, 128.0, 512.0)
    };
    let hourly_pricing = match normalize_hourly_plan_pricing(Some(&body), None, resources) {
        Ok(p) => p,
        Err(message) => return Ok(bad_json(&message)),
    };
    if let Some(swap) = normalized_swap_size {
        if swap < 0.0 || swap > 1048576.0 {
            return Ok(bad_json("SWAP 必须在 0-1048576 MB 之间"));
        }
    }
    let price_value = if normalized_billing_mode == "hourly" {
        Some(Value::Number(0.into()))
    } else {
        g("price").cloned()
    };
    let price_cents = match validate_package_plan_price(price_value.as_ref()) {
        Ok(v) => v,
        Err(message) => return Ok(bad_json(&message)),
    };
    // TS: `if (normalizedBillingMode === 'hourly' && price !== 0)` — strict
    // equality, so a missing/typed-differently price also fails here.
    if normalized_billing_mode == "hourly" {
        let price_is_zero = matches!(g("price"), Some(Value::Number(n)) if n.as_f64() == Some(0.0));
        if !price_is_zero {
            return Ok(bad_json("按小时计费方案的固定价格必须为 0"));
        }
    }
    let billing = match validate_traffic_billing(
        g("trafficBillingMode"),
        g("trafficLimit"),
        g("trafficUnitPrice"),
    ) {
        Ok(billing) => billing,
        Err(message) => return Ok(bad_json(&message)),
    };
    if !validate_traffic_billing_speed_ok(g("trafficLimitSpeed"), billing.mode) {
        return Ok(bad_json("套餐流量模式必须配置有效的超限速度"));
    }
    let effective_reset_enabled = if billing.mode == "usage" {
        false
    } else {
        g("trafficResetEnabled").and_then(Value::as_bool).unwrap_or(false)
    };
    let reset_price_value = if billing.mode == "usage" {
        Some(Value::Number(0.into()))
    } else {
        g("trafficResetPrice").cloned()
    };
    let normalized_reset_price =
        match normalize_traffic_reset_price(effective_reset_enabled, reset_price_value.as_ref()) {
            Ok(v) => v,
            Err(message) => return Ok(bad_json(&message)),
        };

    // SLA 保证值
    if let Some(sla) = g("slaGuarantee") {
        if !sla.is_null() {
            let sla_num = js_number(Some(sla));
            if sla_num < 1.0 || sla_num > 100.0 {
                return Ok(bad_json("SLA保证必须在 1-100 之间"));
            }
        }
    }

    // 用户托管节点的方案只能按月计费
    if user.role != "admin" {
        let actual_billing_cycle = if normalized_billing_mode == "hourly" {
            1.0
        } else {
            plan_num(&obj, "billingCycle").unwrap_or(1.0)
        };
        if actual_billing_cycle != 1.0 {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "用户托管节点的方案仅支持按月计费",
                    "code": "HOSTING_MONTHLY_ONLY"
                })),
            )
                .into_response());
        }
    }
    if normalized_billing_mode == "hourly" {
        if let Some(cycle) = plan_num(&obj, "billingCycle") {
            if cycle != 1.0 {
                return Ok(bad_json("按小时计费方案不支持季度或年度账期"));
            }
        }
    }

    // ---- 写入（TS catch -> 500 '创建方案失败'） ----
    let result: Result<(i32, String), ApiError> = (async {
        // Strict numeric extraction (Prisma Int inputs).
        let strict = |key: &str| -> Result<i32, ApiError> {
            match plan_strict_i32(&obj, key) {
                Some(Some(v)) => Ok(v),
                _ => Err(ApiError::internal("Prisma Int argument validation failed")),
            }
        };
        let cpu_i = strict("cpu")?;
        let memory_i = strict("memory")?;
        let disk_i = strict("disk")?;
        let port_limit = strict("portLimit")?;
        let snapshot_limit = strict("snapshotLimit")?;
        let backup_limit = strict("backupLimit")?;
        let site_limit = strict("siteLimit")?;
        let swap_size = if pkg.instance_type == "vm" { 0 } else { strict("swapSize")? };
        let billing_cycle = if normalized_billing_mode == "hourly" {
            1
        } else {
            match obj.get("billingCycle") {
                None => 1,
                Some(Value::Number(n)) => n
                    .as_i64()
                    .filter(|v| *v >= i32::MIN as i64 && *v <= i32::MAX as i64)
                    .map(|v| v as i32)
                    .ok_or_else(|| ApiError::internal("Prisma Int argument validation failed"))?,
                Some(_) => {
                    return Err(ApiError::internal("Prisma Int argument validation failed"))
                }
            }
        };
        let traffic_limit = i64::try_from(billing.traffic_limit)
            .map_err(|_| ApiError::internal("Prisma BigInt argument out of range"))?;
        let traffic_limit_speed = match g("trafficLimitSpeed") {
            None => "1Mbit".to_string(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err(ApiError::internal("Prisma String argument validation failed")),
        };
        let is_active = g("isActive").and_then(Value::as_bool).unwrap_or(true);
        let is_sold_out = g("isSoldOut").and_then(Value::as_bool).unwrap_or(false);
        let sort_order = match obj.get("sortOrder") {
            None => 0,
            Some(Value::Number(n)) => n
                .as_i64()
                .filter(|v| *v >= i32::MIN as i64 && *v <= i32::MAX as i64)
                .map(|v| v as i32)
                .ok_or_else(|| ApiError::internal("Prisma Int argument validation failed"))?,
            Some(_) => return Err(ApiError::internal("Prisma Int argument validation failed")),
        };
        let description = match g("description") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(ApiError::internal("Prisma String argument validation failed")),
        };
        let sla_guarantee: Option<Decimal> = match g("slaGuarantee") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let f = js_number(Some(v));
                if !f.is_finite() {
                    return Err(ApiError::internal("Prisma Decimal argument validation failed"));
                }
                Decimal::from_f64(f)
            }
        };

        let get_hourly_i = |key: &str, default: i64| -> Result<i32, ApiError> {
            match hourly_pricing.get(key) {
                Some(v) => v
                    .as_i64()
                    .map(|n| n as i32)
                    .ok_or_else(|| ApiError::internal("Prisma Int argument validation failed")),
                None => Ok(default as i32),
            }
        };
        let get_hourly_dec = |key: &str| -> Result<Decimal, ApiError> {
            match hourly_pricing.get(key) {
                Some(Value::String(s)) => Decimal::from_str(s)
                    .map_err(|_| ApiError::internal("Prisma Decimal validation failed")),
                _ => Err(ApiError::internal("Prisma Decimal validation failed")),
            }
        };

        let row: (i32, String) = sqlx::query_as(
            "INSERT INTO package_plans (package_id, name, description, cpu, memory, disk, \
             port_limit, snapshot_limit, backup_limit, site_limit, swap_size, \
             traffic_limit, traffic_limit_speed, traffic_billing_mode, traffic_unit_price, \
             billing_mode, price, billing_cycle, setup_fee, \
             hourly_min_cpu, hourly_cpu_unit_percent, hourly_cpu_price_per_unit, \
             hourly_min_memory_mb, hourly_memory_unit_mb, hourly_memory_price_per_unit, \
             hourly_min_disk_mb, hourly_disk_unit_mb, hourly_disk_price_per_unit, \
             hourly_reserve_quantum, traffic_reset_enabled, traffic_reset_price, \
             is_active, is_sold_out, sort_order, sla_guarantee) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
             $14::\"TrafficBillingMode\", $15, $16::\"InstanceBillingMode\", $17, $18, $19, \
             $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35) \
             RETURNING id, name",
        )
        .bind(package_id)
        .bind(&plan_name)
        .bind(description)
        .bind(cpu_i)
        .bind(memory_i)
        .bind(disk_i)
        .bind(port_limit)
        .bind(snapshot_limit)
        .bind(backup_limit)
        .bind(site_limit)
        .bind(swap_size)
        .bind(traffic_limit)
        .bind(&traffic_limit_speed)
        .bind(billing.mode)
        .bind(Decimal::from_f64(billing.traffic_unit_price).unwrap_or(Decimal::ZERO))
        .bind(normalized_billing_mode)
        .bind(
            Decimal::from_f64(if normalized_billing_mode == "hourly" { 0.0 } else { price_cents })
                .unwrap_or(Decimal::ZERO),
        )
        .bind(billing_cycle)
        .bind(Decimal::ZERO) // setupFee 开通费固定为 0
        .bind(get_hourly_i("hourlyMinCpu", 15)?)
        .bind(get_hourly_i("hourlyCpuUnitPercent", 5)?)
        .bind(get_hourly_dec("hourlyCpuPricePerUnit")?)
        .bind(get_hourly_i("hourlyMinMemoryMb", 128)?)
        .bind(get_hourly_i("hourlyMemoryUnitMb", 64)?)
        .bind(get_hourly_dec("hourlyMemoryPricePerUnit")?)
        .bind(get_hourly_i("hourlyMinDiskMb", 512)?)
        .bind(get_hourly_i("hourlyDiskUnitMb", 512)?)
        .bind(get_hourly_dec("hourlyDiskPricePerUnit")?)
        .bind(get_hourly_dec("hourlyReserveQuantum")?)
        .bind(effective_reset_enabled)
        .bind(Decimal::from_f64(normalized_reset_price).unwrap_or(Decimal::ZERO))
        .bind(is_active)
        .bind(is_sold_out)
        .bind(sort_order)
        .bind(sla_guarantee)
        .fetch_one(&state.db)
        .await?;
        Ok(row)
    })
    .await;

    match result {
        Ok((plan_id, plan_name)) => {
            create_log(
                &state,
                user.id,
                "package",
                "plan.create",
                &format!("Created plan \"{}\" for package \"{}\"", plan_name, pkg.name),
                "success",
            )
            .await;
            Ok(Json(json!({
                "id": plan_id,
                "name": plan_name,
                "message": "方案创建成功"
            }))
            .into_response())
        }
        Err(_) => Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "创建方案失败" })),
        )
            .into_response()),
    }
}

/// packages.ts validateTrafficBilling speed check (package mode only).
fn validate_traffic_billing_speed_ok(speed: Option<&Value>, mode: &str) -> bool {
    if mode != "package" {
        return true;
    }
    is_valid_plan_traffic_limit_speed(speed)
}

/// PUT /{id}/plans/{planId} — 更新套餐方案。
#[allow(clippy::too_many_lines)]
async fn update_plan(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, plan_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let package_id = js_number_id(&id)?;
    let plan_id_num = js_number_id(&plan_id)?;

    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let existing_plan = get_plan_by_id(&state, plan_id_num).await?;
    let existing_plan = match existing_plan {
        Some(p) if p.package_id == package_id => p,
        _ => return Err(ApiError::bare(StatusCode::NOT_FOUND, "方案不存在")),
    };

    let obj = body.as_object().cloned().unwrap_or_default();
    let g = |k: &str| obj.get(k);

    let normalized_swap_size: Option<f64> = if pkg.instance_type == "vm" {
        Some(0.0)
    } else {
        plan_num(&obj, "swapSize")
    };
    // TS: billingMode ?? existingPlan.billingMode — a non-string non-null
    // value flows into the package/hourly check below and fails there.
    let next_billing_mode: String = match g("billingMode") {
        None | Some(Value::Null) => existing_plan.billing_mode.clone(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            return Err(ApiError::bare(
                StatusCode::BAD_REQUEST,
                "billingMode 必须为 package 或 hourly",
            ));
        }
    };

    if let Some(v) = g("isActive") {
        if !v.is_boolean() {
            return Err(ApiError::bare(StatusCode::BAD_REQUEST, "isActive 必须为布尔值"));
        }
    }
    if let Some(v) = g("isSoldOut") {
        if !v.is_boolean() {
            return Err(ApiError::bare(StatusCode::BAD_REQUEST, "isSoldOut 必须为布尔值"));
        }
    }
    if let Some(v) = g("trafficResetEnabled") {
        if !v.is_boolean() {
            return Err(ApiError::bare(
                StatusCode::BAD_REQUEST,
                "trafficResetEnabled 必须为布尔值",
            ));
        }
    }
    if next_billing_mode != "package" && next_billing_mode != "hourly" {
        return Err(ApiError::bare(
            StatusCode::BAD_REQUEST,
            "billingMode 必须为 package 或 hourly",
        ));
    }

    let mut plan_name: Option<String> = None;
    if let Some(name_value) = g("name") {
        plan_name = Some(match validate_package_plan_name(Some(name_value)) {
            Ok(name) => name,
            Err(message) => return Err(ApiError::bare(StatusCode::BAD_REQUEST, message)),
        });
    }
    if let Some(name) = &plan_name {
        if name != &existing_plan.name
            && !is_plan_name_unique(&state, package_id, name, Some(plan_id_num)).await?
        {
            return Err(ApiError::bare(StatusCode::BAD_REQUEST, "该套餐下已存在同名方案"));
        }
    }

    // 资源配置（仅提供时校验）
    if let Some(cpu) = plan_num(&obj, "cpu") {
        if cpu < 15.0 || cpu > 10000.0 {
            return Err(ApiError::bare(StatusCode::BAD_REQUEST, "CPU 必须在 15-10000 之间"));
        }
    }
    if let Some(memory) = plan_num(&obj, "memory") {
        if memory < 128.0 || memory > 62144.0 {
            return Err(ApiError::bare(
                StatusCode::BAD_REQUEST,
                "内存必须在 128-62144 MB 之间",
            ));
        }
    }
    if let Some(disk) = plan_num(&obj, "disk") {
        if disk < 512.0 || disk > 104857600.0 {
            return Err(ApiError::bare(
                StatusCode::BAD_REQUEST,
                "磁盘必须在 512 MB - 100 TB 之间",
            ));
        }
    }
    let next_cpu = plan_num(&obj, "cpu").unwrap_or(existing_plan.cpu as f64);
    let next_memory = plan_num(&obj, "memory").unwrap_or(existing_plan.memory as f64);
    let next_disk = plan_num(&obj, "disk").unwrap_or(existing_plan.disk as f64);

    // hourly 定价：input -> existing plan fallback（?? 语义）
    let fallback_hourly = json!({
        "hourlyMinCpu": existing_plan.hourly_min_cpu,
        "hourlyCpuUnitPercent": existing_plan.hourly_cpu_unit_percent,
        "hourlyCpuPricePerUnit": existing_plan.hourly_cpu_price_per_unit.to_string(),
        "hourlyMinMemoryMb": existing_plan.hourly_min_memory_mb,
        "hourlyMemoryUnitMb": existing_plan.hourly_memory_unit_mb,
        "hourlyMemoryPricePerUnit": existing_plan.hourly_memory_price_per_unit.to_string(),
        "hourlyMinDiskMb": existing_plan.hourly_min_disk_mb,
        "hourlyDiskUnitMb": existing_plan.hourly_disk_unit_mb,
        "hourlyDiskPricePerUnit": existing_plan.hourly_disk_price_per_unit.to_string(),
        "hourlyReserveQuantum": existing_plan.hourly_reserve_quantum.to_string(),
    });
    let resources = if next_billing_mode == "hourly" {
        (next_cpu, next_memory, next_disk)
    } else {
        (15.0, 128.0, 512.0)
    };
    let hourly_pricing =
        match normalize_hourly_plan_pricing(Some(&body), Some(&fallback_hourly), resources) {
            Ok(p) => p,
            Err(message) => return Err(ApiError::bare(StatusCode::BAD_REQUEST, message)),
        };

    if let Some(swap) = normalized_swap_size {
        if swap < 0.0 || swap > 1048576.0 {
            return Err(ApiError::bare(
                StatusCode::BAD_REQUEST,
                "SWAP 必须在 0-1048576 MB 之间",
            ));
        }
    }
    let mut next_price_cents: Option<f64> = None;
    if g("price").is_some() || next_billing_mode == "hourly" {
        // nextPrice = hourly ? 0 : (price ?? Number(existingPlan.price))
        let next_price = if next_billing_mode == "hourly" {
            0.0
        } else {
            match g("price") {
                Some(v) if !v.is_null() => {
                    if !v.is_number() {
                        return Err(ApiError::bare(
                            StatusCode::BAD_REQUEST,
                            "价格必须是有效金额",
                        ));
                    }
                    v.as_f64().unwrap_or(f64::NAN)
                }
                _ => existing_plan.price.to_f64().unwrap_or(0.0),
            }
        };
        match validate_price_f64(next_price) {
            Ok(v) => next_price_cents = Some(v),
            Err(message) => return Err(ApiError::bare(StatusCode::BAD_REQUEST, message)),
        }
        if next_billing_mode == "hourly" {
            if let Some(price) = g("price") {
                // strict `price !== 0` — a non-JSON-number-0 value fails.
                let is_zero = matches!(price, Value::Number(n) if n.as_f64() == Some(0.0));
                if !is_zero {
                    return Err(ApiError::bare(
                        StatusCode::BAD_REQUEST,
                        "按小时计费方案的固定价格必须为 0",
                    ));
                }
            }
        }
    }

    // traffic billing（缺省回退到现有方案值，?? 语义）
    let pick = |key: &str, fallback: Value| -> Value {
        match g(key) {
            Some(v) if !v.is_null() => v.clone(),
            _ => fallback,
        }
    };
    let traffic_mode_value = pick(
        "trafficBillingMode",
        json!(existing_plan.traffic_billing_mode),
    );
    let traffic_limit_value =
        pick("trafficLimit", json!(existing_plan.traffic_limit.to_string()));
    let traffic_speed_value =
        pick("trafficLimitSpeed", json!(existing_plan.traffic_limit_speed));
    let traffic_unit_price_value = pick(
        "trafficUnitPrice",
        json!(existing_plan.traffic_unit_price.to_f64().unwrap_or(0.0)),
    );
    let billing = match validate_traffic_billing(
        Some(&traffic_mode_value),
        Some(&traffic_limit_value),
        Some(&traffic_unit_price_value),
    ) {
        Ok(billing) => billing,
        Err(message) => return Err(ApiError::bare(StatusCode::BAD_REQUEST, message)),
    };
    if !validate_traffic_billing_speed_ok(Some(&traffic_speed_value), billing.mode) {
        return Err(ApiError::bare(
            StatusCode::BAD_REQUEST,
            "套餐流量模式必须配置有效的超限速度",
        ));
    }
    let next_traffic_reset_enabled = if billing.mode == "usage" {
        false
    } else {
        match g("trafficResetEnabled") {
            Some(Value::Bool(b)) => *b,
            _ => existing_plan.traffic_reset_enabled,
        }
    };
    let next_traffic_reset_price = if billing.mode == "usage" {
        0.0
    } else {
        // trafficResetPrice ?? Number(existingPlan.trafficResetPrice)
        match g("trafficResetPrice") {
            Some(v) if !v.is_null() => {
                if !v.is_number() {
                    return Err(ApiError::bare(
                        StatusCode::BAD_REQUEST,
                        "价格必须是有效金额",
                    ));
                }
                v.as_f64().unwrap_or(f64::NAN)
            }
            _ => existing_plan.traffic_reset_price.to_f64().unwrap_or(0.0),
        }
    };
    // The error is only enforced when reset fields were provided.
    if g("trafficResetPrice").is_some() || g("trafficResetEnabled").is_some() {
        if let Err(message) = normalize_traffic_reset_price(
            next_traffic_reset_enabled,
            Some(&json!(next_traffic_reset_price)),
        ) {
            return Err(ApiError::bare(StatusCode::BAD_REQUEST, message));
        }
    }
    let normalized_reset_price = normalize_traffic_reset_price(
        next_traffic_reset_enabled,
        Some(&json!(next_traffic_reset_price)),
    )
    .unwrap_or(0.0);

    // SLA 保证值
    if let Some(sla) = g("slaGuarantee") {
        if !sla.is_null() {
            let sla_num = js_number(Some(sla));
            if sla_num < 1.0 || sla_num > 100.0 {
                return Err(ApiError::bare(
                    StatusCode::BAD_REQUEST,
                    "SLA保证必须在 1-100 之间",
                ));
            }
        }
    }

    // 用户托管节点的方案只能按月计费
    if user.role != "admin" {
        if let Some(cycle) = plan_num(&obj, "billingCycle") {
            if cycle != 1.0 {
                return Err(ApiError::with_message(
                    "HOSTING_MONTHLY_ONLY",
                    StatusCode::BAD_REQUEST,
                    "用户托管节点的方案仅支持按月计费",
                ));
            }
        }
    }
    if next_billing_mode == "hourly" {
        if let Some(cycle) = plan_num(&obj, "billingCycle") {
            if cycle != 1.0 {
                return Err(ApiError::bare(
                    StatusCode::BAD_REQUEST,
                    "按小时计费方案不支持季度或年度账期",
                ));
            }
        }
    }

    // ---- 写入（TS catch -> 500 '更新方案失败'） ----
    let outcome: Result<UpdatedPlan, ApiError> = (async {
        let mut dynamic = PlanUpdateBuilder::new();
        if let Some(name) = &plan_name {
            dynamic.push_str("name", name);
        }
        match g("description") {
            Some(Value::String(desc)) => dynamic.push_str("description", desc),
            Some(Value::Null) => dynamic.push_null("description"),
            Some(_) => return Err(ApiError::internal("Prisma String argument validation failed")),
            None => {}
        }
        macro_rules! strict_set {
            ($key:expr, $col:expr) => {
                match plan_strict_i32(&obj, $key) {
                    Some(Some(v)) => dynamic.push_i32($col, v),
                    Some(None) => {
                        return Err(ApiError::internal("Prisma Int argument validation failed"))
                    }
                    None => {}
                }
            };
        }
        strict_set!("cpu", "cpu");
        strict_set!("memory", "memory");
        strict_set!("disk", "disk");
        strict_set!("portLimit", "port_limit");
        strict_set!("snapshotLimit", "snapshot_limit");
        strict_set!("backupLimit", "backup_limit");
        strict_set!("siteLimit", "site_limit");
        if pkg.instance_type == "vm" {
            dynamic.push_i32("swap_size", 0);
        } else {
            strict_set!("swapSize", "swap_size");
        }
        if g("trafficLimit").is_some() {
            let limit_i64 = i64::try_from(billing.traffic_limit)
                .map_err(|_| ApiError::internal("Prisma BigInt argument out of range"))?;
            dynamic.push_i64("traffic_limit", limit_i64);
        }
        match g("trafficLimitSpeed") {
            Some(Value::String(speed)) => dynamic.push_str("traffic_limit_speed", speed),
            Some(_) => return Err(ApiError::internal("Prisma String argument validation failed")),
            None => {}
        }
        if g("trafficBillingMode").is_some() {
            dynamic.push_enum("traffic_billing_mode", billing.mode);
        }
        if g("trafficUnitPrice").is_some() || g("trafficBillingMode").is_some() {
            dynamic.push_dec(
                "traffic_unit_price",
                Decimal::from_f64(billing.traffic_unit_price).unwrap_or(Decimal::ZERO),
            );
        }
        if g("billingMode").is_some() {
            dynamic.push_enum("billing_mode", &next_billing_mode);
        }
        if g("price").is_some() || next_billing_mode == "hourly" {
            dynamic.push_dec(
                "price",
                Decimal::from_f64(if next_billing_mode == "hourly" {
                    0.0
                } else {
                    next_price_cents.unwrap_or(0.0)
                })
                .unwrap_or(Decimal::ZERO),
            );
        }
        if g("billingCycle").is_some() || next_billing_mode == "hourly" {
            let cycle = if next_billing_mode == "hourly" {
                1
            } else {
                match plan_strict_i32(&obj, "billingCycle") {
                    Some(Some(v)) => v,
                    _ => return Err(ApiError::internal("Prisma Int argument validation failed")),
                }
            };
            dynamic.push_i32("billing_cycle", cycle);
        }
        // Object.assign(updateData, hourlyPricing) — always writes all fields.
        let get_hourly_i = |key: &str, default: i64| -> Result<i32, ApiError> {
            match hourly_pricing.get(key) {
                Some(v) => v
                    .as_i64()
                    .map(|n| n as i32)
                    .ok_or_else(|| ApiError::internal("Prisma Int argument validation failed")),
                None => Ok(default as i32),
            }
        };
        let get_hourly_dec = |key: &str| -> Result<Decimal, ApiError> {
            match hourly_pricing.get(key) {
                Some(Value::String(s)) => Decimal::from_str(s)
                    .map_err(|_| ApiError::internal("Prisma Decimal validation failed")),
                _ => Err(ApiError::internal("Prisma Decimal validation failed")),
            }
        };
        dynamic.push_i32("hourly_min_cpu", get_hourly_i("hourlyMinCpu", 15)?);
        dynamic.push_i32("hourly_cpu_unit_percent", get_hourly_i("hourlyCpuUnitPercent", 5)?);
        dynamic.push_dec("hourly_cpu_price_per_unit", get_hourly_dec("hourlyCpuPricePerUnit")?);
        dynamic.push_i32("hourly_min_memory_mb", get_hourly_i("hourlyMinMemoryMb", 128)?);
        dynamic.push_i32("hourly_memory_unit_mb", get_hourly_i("hourlyMemoryUnitMb", 64)?);
        dynamic.push_dec(
            "hourly_memory_price_per_unit",
            get_hourly_dec("hourlyMemoryPricePerUnit")?,
        );
        dynamic.push_i32("hourly_min_disk_mb", get_hourly_i("hourlyMinDiskMb", 512)?);
        dynamic.push_i32("hourly_disk_unit_mb", get_hourly_i("hourlyDiskUnitMb", 512)?);
        dynamic.push_dec(
            "hourly_disk_price_per_unit",
            get_hourly_dec("hourlyDiskPricePerUnit")?,
        );
        dynamic.push_dec("hourly_reserve_quantum", get_hourly_dec("hourlyReserveQuantum")?);
        // setupFee 已废弃，不再接受更新
        if g("trafficResetEnabled").is_some() || g("trafficBillingMode").is_some() {
            dynamic.push_bool("traffic_reset_enabled", next_traffic_reset_enabled);
        }
        if g("trafficResetPrice").is_some()
            || g("trafficResetEnabled").is_some()
            || g("trafficBillingMode").is_some()
        {
            dynamic.push_dec(
                "traffic_reset_price",
                Decimal::from_f64(normalized_reset_price).unwrap_or(Decimal::ZERO),
            );
        }
        if let Some(v) = g("isActive").and_then(Value::as_bool) {
            dynamic.push_bool("is_active", v);
        }
        if let Some(v) = g("isSoldOut").and_then(Value::as_bool) {
            dynamic.push_bool("is_sold_out", v);
        }
        strict_set!("sortOrder", "sort_order");
        if let Some(v) = g("slaGuarantee") {
            if v.is_null() {
                dynamic.push_null("sla_guarantee");
            } else {
                let f = js_number(Some(v));
                if !f.is_finite() {
                    return Err(ApiError::internal("Prisma Decimal argument validation failed"));
                }
                dynamic.push_dec("sla_guarantee", Decimal::from_f64(f).unwrap_or(Decimal::ZERO));
            }
        }

        dynamic
            .execute(&state.db, plan_id_num)
            .await
            .map_err(ApiError::from_sql)
    })
    .await;

    let updated_plan = match outcome {
        Ok(plan) => plan,
        Err(_) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "更新方案失败" })),
            )
                .into_response());
        }
    };

    // 配额字段同步到关联实例
    let quota_changed = ["port_limit", "snapshot_limit", "backup_limit", "site_limit", "swap_size", "traffic_limit"]
        .iter()
        .any(|f| updated_plan.dirty.contains(f));
    if quota_changed {
        let sync = sync_plan_quota_to_instances(&state, &updated_plan.row, existing_plan.swap_size)
            .await;
        match sync {
            Ok((sync_count, instance_ids)) => {
                if sync_count > 0 {
                    if !instance_ids.is_empty() {
                        tracing::warn!(
                            "[packages] plan quota synced to {} instance(s); reconcileTrafficStateForInstanceIds not ported",
                            instance_ids.len()
                        );
                    }
                    create_log(
                        &state,
                        user.id,
                        "package",
                        "plan.sync_quota",
                        &format!(
                            "Synced quota to {} instance(s) for plan \"{}\"",
                            sync_count, updated_plan.row.name
                        ),
                        "success",
                    )
                    .await;
                }
            }
            Err(_) => {
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "更新方案失败" })),
                )
                    .into_response());
            }
        }
    }

    create_log(
        &state,
        user.id,
        "package",
        "plan.update",
        &format!(
            "Updated plan \"{}\" for package \"{}\"",
            updated_plan.row.name, pkg.name
        ),
        "success",
    )
    .await;

    Ok(Json(json!({
        "id": updated_plan.row.id,
        "name": updated_plan.row.name,
        "message": "方案更新成功"
    }))
    .into_response())
}

/// Dynamic plan UPDATE builder that also reports which columns were set.
struct PlanUpdateBuilder {
    sets: Vec<String>,
    values: ParamList,
    param_count: usize,
    dirty: HashSet<&'static str>,
}

impl PlanUpdateBuilder {
    fn new() -> Self {
        Self {
            sets: Vec::new(),
            values: ParamList::default(),
            param_count: 0,
            dirty: HashSet::new(),
        }
    }
    fn mark(&mut self, col: &'static str) -> usize {
        self.param_count += 1;
        self.sets.push(format!("{col} = ${}", self.param_count));
        self.dirty.insert(col);
        self.param_count
    }
    fn push_str(&mut self, col: &'static str, v: &str) {
        self.mark(col);
        self.values.push_str(v);
    }
    fn push_i32(&mut self, col: &'static str, v: i32) {
        self.mark(col);
        self.values.push_i32(v);
    }
    fn push_i64(&mut self, col: &'static str, v: i64) {
        self.mark(col);
        self.values.push_i64(v);
    }
    fn push_bool(&mut self, col: &'static str, v: bool) {
        self.mark(col);
        self.values.push_bool(v);
    }
    fn push_dec(&mut self, col: &'static str, v: Decimal) {
        self.mark(col);
        self.values.values.push(ParamValue::Dec(v));
    }
    /// Columns set to NULL consume no bind parameter but still count in the
    /// SET list (placeholders are assigned before this, so ordering holds).
    fn push_null(&mut self, col: &'static str) {
        self.sets.push(format!("{col} = NULL"));
        self.dirty.insert(col);
    }
    fn push_enum(&mut self, col: &'static str, v: &str) {
        let enum_name = match col {
            "traffic_billing_mode" => "TrafficBillingMode",
            "billing_mode" => "InstanceBillingMode",
            _ => "",
        };
        let idx = self.mark(col);
        self.sets[idx - 1] = format!("{col} = ${idx}::\"{enum_name}\"");
        self.values.push_enum(v);
    }
    async fn execute(self, pool: &sqlx::PgPool, plan_id: i32) -> Result<UpdatedPlan, sqlx::Error> {
        if self.sets.is_empty() {
            // Prisma update with empty data still requires the row to exist.
            let row = sqlx::query_as::<_, PlanRow>(&format!(
                "{PLAN_SELECT} WHERE id = $1"
            ))
            .bind(plan_id)
            .fetch_one(pool)
            .await?;
            return Ok(UpdatedPlan {
                row,
                dirty: self.dirty,
            });
        }
        let sql = format!(
            "UPDATE package_plans SET {} WHERE id = ${} RETURNING {PLAN_RETURNING}",
            self.sets.join(", "),
            self.param_count + 1
        );
        let row = self
            .values
            .bind_to_as(sqlx::query_as::<_, PlanRow>(&sql))
            .bind(plan_id)
            .fetch_one(pool)
            .await?;
        Ok(UpdatedPlan {
            row,
            dirty: self.dirty,
        })
    }
}

struct UpdatedPlan {
    row: PlanRow,
    dirty: HashSet<&'static str>,
}

/// DELETE /{id}/plans/{planId} — 删除套餐方案。
async fn delete_plan_handler(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path((id, plan_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let package_id = js_number_id(&id)?;
    let plan_id_num = js_number_id(&plan_id)?;

    let pkg = fetch_package_by_id(&state, package_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::PACKAGE_NOT_FOUND))?;
    if pkg.user_id != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let existing_plan = get_plan_by_id(&state, plan_id_num).await?;
    let existing_plan = match existing_plan {
        Some(p) if p.package_id == package_id => p,
        _ => return Err(ApiError::bare(StatusCode::NOT_FOUND, "方案不存在")),
    };

    let (can_delete, reason) = can_delete_plan(&state, plan_id_num).await?;
    if !can_delete {
        return Err(ApiError::bare(StatusCode::BAD_REQUEST, reason));
    }

    let deleted = sqlx::query("DELETE FROM package_plans WHERE id = $1")
        .bind(plan_id_num)
        .execute(&state.db)
        .await;

    match deleted {
        Ok(_) => {
            create_log(
                &state,
                user.id,
                "package",
                "plan.delete",
                &format!(
                    "Deleted plan \"{}\" from package \"{}\"",
                    existing_plan.name, pkg.name
                ),
                "success",
            )
            .await;
            Ok(Json(json!({ "message": "方案删除成功" })).into_response())
        }
        Err(_) => Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "删除方案失败" })),
        )
            .into_response()),
    }
}

// ===========================================================================
// GET /regions — 可用地区列表
// ===========================================================================

async fn regions(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let source = params.get("source").map(|s| s.as_str()).unwrap_or("official");

    if source == "friends" {
        // 好友共享需要特殊处理：从好友共享套餐中提取地区
        let friend_packages = get_shared_to_user(&state, user.id).await?;
        if friend_packages.is_empty() {
            return Ok(Json(json!({ "regions": [] })));
        }
        let host_ids: Vec<i32> = friend_packages
            .iter()
            .flat_map(|p| p.host_ids.iter().copied())
            .collect();
        let friend_package_ids: HashSet<i32> = friend_packages.iter().map(|p| p.id).collect();
        let rows: Vec<(String, Vec<i32>)> = sqlx::query_as(
            "SELECT h.country_code, COALESCE(array_agg(ph.package_id), '{}') AS package_ids \
             FROM hosts h JOIN package_hosts ph ON ph.host_id = h.id \
             WHERE h.id = ANY($1) AND h.status = 'online' GROUP BY h.id, h.country_code",
        )
        .bind(&host_ids)
        .fetch_all(&state.db)
        .await?;

        let mut region_packages: HashMap<String, HashSet<i32>> = HashMap::new();
        for (country_code, package_ids) in rows {
            let code = country_code.to_lowercase();
            for package_id in package_ids {
                if !friend_package_ids.contains(&package_id) {
                    continue;
                }
                region_packages.entry(code.clone()).or_default().insert(package_id);
            }
        }
        let mut region_list: Vec<Value> = region_packages
            .into_iter()
            .map(|(code, package_ids)| {
                json!({
                    "code": code,
                    "name": get_country_name(&code),
                    "packageCount": package_ids.len(),
                    "packageIds": package_ids.into_iter().collect::<Vec<_>>(),
                })
            })
            .collect();
        // regions.sort((a, b) => b.packageCount - a.packageCount)
        region_list.sort_by(|a, b| {
            let ac = a["packageCount"].as_i64().unwrap_or(0);
            let bc = b["packageCount"].as_i64().unwrap_or(0);
            bc.cmp(&ac)
        });
        return Ok(Json(json!({ "regions": region_list })));
    }

    // 官方/托管市场/托管专区：统一公开套餐逻辑
    let mut clauses: Vec<String> = vec![
        "p.active = true".to_string(),
        "EXISTS (SELECT 1 FROM package_plans pp WHERE pp.package_id = p.id AND pp.is_active = true)"
            .to_string(),
    ];
    let mut bind_excluded: Option<Vec<i32>> = None;
    let mut bind_owner: Option<i32> = None;
    match source {
        "official" => {
            clauses.push("p.global_shared = true".to_string());
            clauses.push("u.role = 'admin'".to_string());
        }
        "market" => {
            let mut excluded = get_blocker_ids_for_user(&state, user.id).await?;
            let zone_owner_ids = get_active_hosting_zone_owner_ids(&state).await?;
            for id in zone_owner_ids {
                if !excluded.contains(&id) {
                    excluded.push(id);
                }
            }
            clauses.push("p.global_shared = true".to_string());
            clauses.push("u.role <> 'admin'".to_string());
            if !excluded.is_empty() {
                clauses.push("p.user_id <> ALL($1)".to_string());
                bind_excluded = Some(excluded);
            }
        }
        "zone" => {
            let zone_id =
                js_parse_int(params.get("zoneId").map(|s| s.as_str()).unwrap_or(""));
            let Some(zone_id) = zone_id.filter(|v| *v > 0 && *v <= i32::MAX as i64) else {
                return Ok(Json(json!({ "regions": [] })));
            };
            let Some(zone) = get_active_hosting_zone_by_id(&state, zone_id, Some(user.id)).await?
            else {
                return Ok(Json(json!({ "regions": [] })));
            };
            clauses.push("p.global_shared = true".to_string());
            clauses.push("p.user_id = $1".to_string());
            bind_owner = Some(zone.owner_id);
            clauses.push("u.role <> 'admin'".to_string());
        }
        _ => {}
    }

    let mut sql = String::from(
        "SELECT p.id, h.country_code \
         FROM packages p \
         JOIN users u ON u.id = p.user_id \
         JOIN package_hosts ph ON ph.package_id = p.id \
         JOIN hosts h ON h.id = ph.host_id",
    );
    sql.push_str(" WHERE ");
    sql.push_str(&clauses.join(" AND "));

    let mut q = sqlx::query_as::<_, (i32, String)>(&sql);
    if let Some(owner) = bind_owner {
        q = q.bind(owner);
    }
    if let Some(excluded) = &bind_excluded {
        q = q.bind(excluded);
    }
    let rows = q.fetch_all(&state.db).await?;

    let mut region_packages: HashMap<String, HashSet<i32>> = HashMap::new();
    for (package_id, country_code) in rows {
        let code = country_code.to_lowercase();
        region_packages.entry(code).or_default().insert(package_id);
    }
    let mut region_list: Vec<Value> = region_packages
        .into_iter()
        .map(|(code, package_ids)| {
            json!({
                "code": code,
                "name": get_country_name(&code),
                "packageCount": package_ids.len(),
                "packageIds": package_ids.into_iter().collect::<Vec<_>>(),
            })
        })
        .collect();
    // 按套餐数量降序排列
    region_list.sort_by(|a, b| {
        let ac = a["packageCount"].as_i64().unwrap_or(0);
        let bc = b["packageCount"].as_i64().unwrap_or(0);
        bc.cmp(&ac)
    });

    Ok(Json(json!({ "regions": region_list })))
}
