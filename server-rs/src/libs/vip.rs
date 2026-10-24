//! Port of server/src/services/vip-levels.ts — VIP level rules, badge styles,
//! progress computation, overview assembly and rule replacement.
//!
//! Notes on the port:
//! - Thresholds are persisted as Decimal(10,2); matching/progress math mirrors
//!   the TS exactly: every rounding step goes through JS `Math.round(x*100)/100`
//!   arithmetic on f64 first (see `round_money_f64`), then converts to Decimal
//!   so the results are bit-compatible with the TS server.
//! - Benefits are opaque JSON objects (`benefits` jsonb column); only the
//!   `badgeStyle` and `benefitHall` keys are normalized (strict validation only
//!   on admin rule replacement, exactly like `sanitizeBenefits(level, v, strict)`).
//! - The TS config-cache (`invalidateCachedConfig`) is a process-local
//!   performance cache; this port always reads `system_configs` directly, which
//!   is observably equivalent (only fresher across replicas).
//! - `buildHostingVipSql` (raw SQL CASE builder for the admin hosting module)
//!   is NOT ported: no consumer among the ported routes.

use std::collections::{BTreeMap, HashMap, HashSet};

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde_json::{json, Map, Value};
use sqlx::PgPool;

use crate::error::ApiError;
use crate::response::{num, num_opt};

pub const MAX_VIP_LEVEL: i32 = 10;
const MAX_MONEY_THRESHOLD: f64 = 99999999.99;
const MAX_INSTANCE_THRESHOLD: f64 = 1000000.0;
const MAX_BENEFIT_POINTS: f64 = 1000000000.0;
const MAX_BENEFIT_INSTANCE_DAYS: f64 = 3650.0;
const MAX_BENEFIT_INSTANCE_QUANTITY: f64 = 10.0;
const USER_VIP_METRIC_CONFIG_KEY: &str = "user_vip_metric";
const USER_VIP_METRIC_LABEL: &str = "用户 VIP 统计口径";
const USER_VIP_METRIC_DESCRIPTION: &str =
    "用户 VIP 等级全局计算口径：totalRecharge=累计充值，totalConsume=累计消费";

// ===========================================================================
// JS number semantics (shared with the vip-benefits / user-invites ports)
// ===========================================================================

/// JS `Number(value)` for a JSON value. `None` means NaN. Objects/arrays are
/// NaN; `null` is 0; booleans are 0/1; strings use JS string-to-number parsing
/// (trimmed; "Infinity"/"-Infinity"; hex strings are NOT supported here).
pub fn js_to_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Null => Some(0.0),
        Value::String(s) => js_parse_number(s),
        _ => None,
    }
}

fn js_parse_number(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() {
        return Some(0.0);
    }
    match t {
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => {}
    }
    let lower = t.to_ascii_lowercase();
    if lower.contains("inf") || lower.contains("nan") {
        return None;
    }
    t.parse::<f64>().ok()
}

/// JS `Math.round`: halves round toward +Infinity.
pub fn js_round(v: f64) -> f64 {
    (v + 0.5).floor()
}

/// services/vip-levels.ts roundAmount / roundMoney: Math.round(v*100)/100
/// (no epsilon here, unlike lib/balance-transfer.ts roundMoney).
pub fn round_money_f64(v: f64) -> f64 {
    js_round(v * 100.0) / 100.0
}

/// Decimal from an already-2dp-rounded f64 (string round trip keeps the exact
/// digits, mirroring the Prisma Decimal conversion of the JS number).
pub fn dec2(v: f64) -> Decimal {
    use std::str::FromStr;
    Decimal::from_str(&format!("{v:.2}")).unwrap_or(Decimal::ZERO)
}

/// TS roundAmount applied to a DB Decimal: Decimal -> f64 (JS Number) ->
/// round -> Decimal.
pub fn round_amount_dec(value: Decimal) -> Decimal {
    dec2(round_money_f64(value.to_f64().unwrap_or(0.0)))
}

fn dec_f64(d: Decimal) -> f64 {
    d.to_f64().unwrap_or(0.0)
}

/// f64 -> JSON number with JS formatting (integral values print without ".0").
pub fn js_num_json(v: f64) -> Value {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 9_007_199_254_740_992.0 {
        Value::from(v as i64)
    } else if v.is_finite() {
        serde_json::Number::from_f64(v).map(Value::Number).unwrap_or(Value::Null)
    } else {
        Value::Null
    }
}

/// JS String(number) for interpolation (integral values print without ".0").
pub fn js_num_to_string(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    format!("{v}")
}

// ===========================================================================
// Types
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VipRuleType {
    User,
    Hosting,
}

impl VipRuleType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Hosting => "hosting",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "hosting" => Some(Self::Hosting),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVipMetric {
    TotalRecharge,
    TotalConsume,
}

impl UserVipMetric {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TotalRecharge => "totalRecharge",
            Self::TotalConsume => "totalConsume",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VipConditionMode {
    Any,
    All,
}

impl VipConditionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VipBadgeStyle {
    pub background_color: String,
    pub text_color: String,
}

impl VipBadgeStyle {
    pub fn to_json(&self) -> Value {
        json!({
            "backgroundColor": self.background_color,
            "textColor": self.text_color,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NormalizedVipRule {
    pub id: Option<i32>,
    pub rule_type: VipRuleType,
    pub level: i32,
    pub enabled: bool,
    pub condition_mode: VipConditionMode,
    pub min_recharge: Option<Decimal>,
    pub min_consume: Option<Decimal>,
    pub min_hosting_income: Option<Decimal>,
    pub min_hosting_instances: Option<i64>,
    pub benefits: Value,
    pub badge_style: VipBadgeStyle,
}

impl NormalizedVipRule {
    /// Serializes like the TS `NormalizedVipRule` interface (`id` omitted when
    /// absent, exactly like the TS optional field).
    pub fn to_json(&self) -> Value {
        let mut body = json!({
            "type": self.rule_type.as_str(),
            "level": self.level,
            "enabled": self.enabled,
            "conditionMode": self.condition_mode.as_str(),
            "minRecharge": num_opt(self.min_recharge),
            "minConsume": num_opt(self.min_consume),
            "minHostingIncome": num_opt(self.min_hosting_income),
            "minHostingInstances": self.min_hosting_instances,
            "benefits": self.benefits.clone(),
            "badgeStyle": self.badge_style.to_json(),
        });
        if let Some(id) = self.id {
            body["id"] = json!(id);
        }
        body
    }
}

#[derive(Debug, Clone)]
pub struct UserVipStats {
    pub total_recharge: Decimal,
    pub total_consume: Decimal,
}

#[derive(Debug, Clone)]
pub struct HostingVipStats {
    pub total_hosting_income: Decimal,
    pub instance_count: i64,
}

/// TS `UserVipStats | HostingVipStats` union parameter.
pub enum VipStats<'a> {
    User(&'a UserVipStats),
    Hosting(&'a HostingVipStats),
}

// ===========================================================================
// Normalization helpers
// ===========================================================================

fn get_record(value: &Value) -> Map<String, Value> {
    match value.as_object() {
        Some(map) if !value.is_array() => map.clone(),
        _ => Map::new(),
    }
}

fn hex_color(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7
        && bytes[0] == b'#'
        && bytes[1..].iter().all(|b| b.is_ascii_hexdigit())
}

fn normalize_hex_color(value: &Value, fallback: &str) -> String {
    match value.as_str() {
        Some(s) if hex_color(s) => s.to_string(),
        _ => fallback.to_string(),
    }
}

pub fn normalize_user_vip_metric(value: Option<&str>) -> UserVipMetric {
    if value == Some("totalConsume") {
        UserVipMetric::TotalConsume
    } else {
        UserVipMetric::TotalRecharge
    }
}

/// JS string.slice(0, n) by UTF-16 code units.
fn js_slice(s: &str, n: usize) -> String {
    let mut units = 0usize;
    let mut end = s.len();
    for (idx, ch) in s.char_indices() {
        if units >= n {
            end = idx;
            break;
        }
        units += ch.len_utf16();
    }
    if units < n {
        s.to_string()
    } else {
        s[..end].to_string()
    }
}

/// nullableMoney: null/undefined/'' -> None; finite 0..=99999999.99 rounded to
/// 2dp -> Some; anything else -> Err(message).
fn nullable_money(value: &Value) -> Result<Option<Decimal>, String> {
    if value.is_null() {
        return Ok(None);
    }
    if let Value::String(s) = value {
        if s.is_empty() {
            return Ok(None);
        }
    }
    let message = format!("Money threshold must be between 0 and {MAX_MONEY_THRESHOLD}");
    let Some(parsed) = js_to_number(value) else {
        return Err(message);
    };
    if !parsed.is_finite() || parsed < 0.0 || parsed > MAX_MONEY_THRESHOLD {
        return Err(message);
    }
    Ok(Some(dec2(round_money_f64(parsed))))
}

/// nullableCount: integer 0..=1000000 or None.
fn nullable_count(value: &Value) -> Result<Option<i64>, String> {
    if value.is_null() {
        return Ok(None);
    }
    if let Value::String(s) = value {
        if s.is_empty() {
            return Ok(None);
        }
    }
    let Some(parsed) = js_to_number(value) else {
        return Err(format!(
            "Instance threshold must be between 0 and {MAX_INSTANCE_THRESHOLD}"
        ));
    };
    if !parsed.is_finite() || parsed < 0.0 || parsed > MAX_INSTANCE_THRESHOLD {
        return Err(format!(
            "Instance threshold must be between 0 and {MAX_INSTANCE_THRESHOLD}"
        ));
    }
    if parsed.fract() != 0.0 {
        return Err("Instance threshold must be an integer".to_string());
    }
    Ok(Some(parsed as i64))
}

fn has_threshold(value: Option<Decimal>) -> bool {
    matches!(value, Some(d) if d > Decimal::ZERO)
}

// ---- badge styles ----

pub fn get_default_vip_badge_style(level: i32) -> VipBadgeStyle {
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
    let level = level.max(1);
    let (bg, fg) = STYLES[((level - 1) as usize) % STYLES.len()];
    VipBadgeStyle {
        background_color: bg.to_string(),
        text_color: fg.to_string(),
    }
}

pub fn normalize_vip_badge_style(level: i32, value: &Value) -> VipBadgeStyle {
    let fallback = get_default_vip_badge_style(level);
    if !value.is_object() {
        return fallback;
    }
    VipBadgeStyle {
        background_color: normalize_hex_color(&value["backgroundColor"], &fallback.background_color),
        text_color: normalize_hex_color(&value["textColor"], &fallback.text_color),
    }
}

pub fn get_vip_badge_style_for_level(
    rules: &[NormalizedVipRule],
    rule_type: VipRuleType,
    level: i32,
) -> Option<VipBadgeStyle> {
    if level == 0 {
        return None;
    }
    let rule = rules
        .iter()
        .find(|item| item.rule_type == rule_type && item.level == level);
    Some(match rule {
        Some(rule) => rule.badge_style.clone(),
        None => get_default_vip_badge_style(level),
    })
}

// ---- benefit hall config ----

fn normalize_benefit_money(value: &Value) -> f64 {
    let Some(parsed) = js_to_number(value) else {
        return 0.0;
    };
    if !parsed.is_finite() || parsed <= 0.0 {
        return 0.0;
    }
    round_money_f64(parsed).min(MAX_MONEY_THRESHOLD)
}

fn normalize_benefit_integer(value: &Value, max: f64) -> i64 {
    let Some(parsed) = js_to_number(value) else {
        return 0;
    };
    if !parsed.is_finite() || parsed <= 0.0 {
        return 0;
    }
    (parsed.floor().min(max)) as i64
}

fn normalize_benefit_id(value: &Value) -> Option<i64> {
    let parsed = js_to_number(value)?;
    if parsed.is_finite() && parsed.fract() == 0.0 && parsed > 0.0 {
        Some(parsed as i64)
    } else {
        None
    }
}

fn normalize_benefit_label(value: &Value) -> Option<String> {
    let s = value.as_str()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(js_slice(trimmed, 100))
    }
}

/// normalizeBenefitHallConfig — returns the normalized config JSON; `strict`
/// failures return the TS Error message.
fn normalize_benefit_hall_config(value: &Value, strict: bool) -> Result<Value, String> {
    let raw = get_record(value);
    let balance = get_record(raw.get("balance").unwrap_or(&Value::Null));
    let points = get_record(raw.get("points").unwrap_or(&Value::Null));
    let instance = get_record(raw.get("instance").unwrap_or(&Value::Null));

    let balance_amount = normalize_benefit_money(balance.get("amount").unwrap_or(&Value::Null));
    let points_amount = normalize_benefit_integer(points.get("amount").unwrap_or(&Value::Null), MAX_BENEFIT_POINTS);
    let package_id = normalize_benefit_id(instance.get("packageId").unwrap_or(&Value::Null));
    let plan_id = normalize_benefit_id(instance.get("planId").unwrap_or(&Value::Null));
    let days = normalize_benefit_integer(instance.get("days").unwrap_or(&Value::Null), MAX_BENEFIT_INSTANCE_DAYS);
    let quantity = normalize_benefit_integer(instance.get("quantity").unwrap_or(&Value::Null), MAX_BENEFIT_INSTANCE_QUANTITY);

    let balance_enabled = balance.get("enabled") == Some(&Value::Bool(true));
    let points_enabled = points.get("enabled") == Some(&Value::Bool(true));
    let instance_enabled = instance.get("enabled") == Some(&Value::Bool(true));

    if strict {
        if balance_enabled && balance_amount <= 0.0 {
            return Err("VIP benefit balance amount must be greater than 0".to_string());
        }
        if points_enabled && points_amount <= 0 {
            return Err("VIP benefit points amount must be a positive integer".to_string());
        }
        if instance_enabled && (package_id.is_none() || plan_id.is_none()) {
            return Err("VIP benefit instance requires a package and plan".to_string());
        }
        if instance_enabled
            && normalize_benefit_integer(instance.get("days").unwrap_or(&Value::Null), MAX_BENEFIT_INSTANCE_DAYS) <= 0
        {
            return Err("VIP benefit instance days must be a positive integer".to_string());
        }
        if instance_enabled
            && normalize_benefit_integer(instance.get("quantity").unwrap_or(&Value::Null), MAX_BENEFIT_INSTANCE_QUANTITY) <= 0
        {
            return Err("VIP benefit instance quantity must be a positive integer".to_string());
        }
    }

    Ok(json!({
        "balance": {
            "enabled": balance_enabled && balance_amount > 0.0,
            "amount": js_num_json(balance_amount),
        },
        "points": {
            "enabled": points_enabled && points_amount > 0,
            "amount": points_amount,
        },
        "instance": {
            "enabled": instance_enabled && package_id.is_some() && plan_id.is_some(),
            "packageId": package_id,
            "packageName": normalize_benefit_label(instance.get("packageName").unwrap_or(&Value::Null)),
            "planId": plan_id,
            "planName": normalize_benefit_label(instance.get("planName").unwrap_or(&Value::Null)),
            "days": if days > 0 { days } else { 30 },
            "quantity": if quantity > 0 { quantity } else { 1 },
        }
    }))
}

/// sanitizeBenefits: keeps unknown keys, normalizes badgeStyle + benefitHall.
fn sanitize_benefits(level: i32, benefits: &Value, strict: bool) -> Result<Value, String> {
    let mut map = get_record(benefits);
    let badge = normalize_vip_badge_style(level, &Value::Null);
    // TS computes badgeStyle from the *input* benefits first (inside
    // normalizeVipRule) — but sanitizeBenefits itself normalizes from
    // normalized.badgeStyle; the input badgeStyle is what lands in `map` here.
    let badge_from_input = map
        .get("badgeStyle")
        .map(|v| normalize_vip_badge_style(level, v))
        .unwrap_or(badge);
    let hall = normalize_benefit_hall_config(
        map.get("benefitHall").unwrap_or(&Value::Null),
        strict,
    )?;
    map.insert("badgeStyle".to_string(), badge_from_input.to_json());
    map.insert("benefitHall".to_string(), hall);
    Ok(Value::Object(map))
}

/// hasActiveCondition.
pub fn has_active_condition(rule_type: VipRuleType, rule: &NormalizedVipRule) -> bool {
    match rule_type {
        VipRuleType::User => {
            has_threshold(rule.min_recharge) || has_threshold(rule.min_consume)
        }
        VipRuleType::Hosting => {
            has_threshold(rule.min_hosting_income)
                || rule
                    .min_hosting_instances
                    .is_some_and(|v| v > 0)
        }
    }
}

/// sanitizeVipRuleInput — validation failures carry the TS Error message.
pub fn sanitize_vip_rule_input(
    rule_type: VipRuleType,
    input: &Value,
    user_metric: UserVipMetric,
) -> Result<NormalizedVipRule, String> {
    let level_raw = input.get("level");
    let level = match level_raw.and_then(js_to_number) {
        Some(v) if v.is_finite() && v.fract() == 0.0 => v,
        _ => f64::NAN,
    };
    if level.is_nan() || !(1.0..=MAX_VIP_LEVEL as f64).contains(&level) {
        return Err(format!("VIP level must be between 1 and {MAX_VIP_LEVEL}"));
    }
    let level = level as i32;

    let condition_mode = if input["conditionMode"] == json!("all") {
        VipConditionMode::All
    } else {
        VipConditionMode::Any
    };
    // TS: user rules force conditionMode 'any' (only the recharge OR consume
    // metric matching the global metric is active for user levels).
    let condition_mode = if rule_type == VipRuleType::User {
        VipConditionMode::Any
    } else {
        condition_mode
    };
    let enabled = input["enabled"] != Value::Bool(false);

    let benefits = sanitize_benefits(
        level,
        input.get("benefits").unwrap_or(&Value::Null),
        true,
    )?;

    let mut rule = NormalizedVipRule {
        id: None,
        rule_type,
        level,
        enabled,
        condition_mode,
        min_recharge: None,
        min_consume: None,
        min_hosting_income: None,
        min_hosting_instances: None,
        benefits,
        badge_style: get_default_vip_badge_style(level),
    };

    rule.min_recharge = if rule_type == VipRuleType::User
        && user_metric == UserVipMetric::TotalRecharge
    {
        nullable_money(input.get("minRecharge").unwrap_or(&Value::Null))?
    } else {
        None
    };
    rule.min_consume = if rule_type == VipRuleType::User
        && user_metric == UserVipMetric::TotalConsume
    {
        nullable_money(input.get("minConsume").unwrap_or(&Value::Null))?
    } else {
        None
    };
    rule.min_hosting_income = if rule_type == VipRuleType::Hosting {
        nullable_money(input.get("minHostingIncome").unwrap_or(&Value::Null))?
    } else {
        None
    };
    rule.min_hosting_instances = if rule_type == VipRuleType::Hosting {
        nullable_count(input.get("minHostingInstances").unwrap_or(&Value::Null))?
    } else {
        None
    };

    rule.badge_style = normalize_vip_badge_style(level, &rule.benefits["badgeStyle"]);

    if enabled && !has_active_condition(rule_type, &rule) {
        return Err(format!("VIP{level} requires at least one condition"));
    }

    Ok(rule)
}

// ===========================================================================
// Level matching
// ===========================================================================

fn get_rule_checks(rule_type: VipRuleType, rule: &NormalizedVipRule, stats: &VipStats) -> Vec<bool> {
    match (rule_type, stats) {
        (VipRuleType::User, VipStats::User(stats)) => {
            let mut checks = Vec::new();
            if has_threshold(rule.min_recharge) {
                checks.push(dec_f64(stats.total_recharge) >= dec_f64(rule.min_recharge.unwrap()));
            }
            if has_threshold(rule.min_consume) {
                checks.push(dec_f64(stats.total_consume) >= dec_f64(rule.min_consume.unwrap()));
            }
            checks
        }
        (VipRuleType::Hosting, VipStats::Hosting(stats)) => {
            let mut checks = Vec::new();
            if has_threshold(rule.min_hosting_income) {
                checks.push(
                    dec_f64(stats.total_hosting_income)
                        >= dec_f64(rule.min_hosting_income.unwrap()),
                );
            }
            if let Some(threshold) = rule.min_hosting_instances.filter(|v| *v > 0) {
                checks.push(stats.instance_count >= threshold);
            }
            checks
        }
        _ => Vec::new(),
    }
}

fn get_user_rule_checks(
    rule: &NormalizedVipRule,
    stats: &UserVipStats,
    user_metric: UserVipMetric,
) -> Vec<bool> {
    let mut checks = Vec::new();
    if user_metric == UserVipMetric::TotalRecharge && has_threshold(rule.min_recharge) {
        checks.push(dec_f64(stats.total_recharge) >= dec_f64(rule.min_recharge.unwrap()));
    }
    if user_metric == UserVipMetric::TotalConsume && has_threshold(rule.min_consume) {
        checks.push(dec_f64(stats.total_consume) >= dec_f64(rule.min_consume.unwrap()));
    }
    checks
}

fn has_user_metric_condition(rule: &NormalizedVipRule, user_metric: UserVipMetric) -> bool {
    match user_metric {
        UserVipMetric::TotalRecharge => has_threshold(rule.min_recharge),
        UserVipMetric::TotalConsume => has_threshold(rule.min_consume),
    }
}

pub fn is_vip_rule_matched(
    rule_type: VipRuleType,
    rule: &NormalizedVipRule,
    stats: &VipStats,
) -> bool {
    if !rule.enabled || !has_active_condition(rule_type, rule) {
        return false;
    }
    let checks = get_rule_checks(rule_type, rule, stats);
    if checks.is_empty() {
        return false;
    }
    if rule.condition_mode == VipConditionMode::All {
        checks.iter().all(|v| *v)
    } else {
        checks.iter().any(|v| *v)
    }
}

pub fn is_user_vip_rule_matched(
    rule: &NormalizedVipRule,
    stats: &UserVipStats,
    user_metric: UserVipMetric,
) -> bool {
    if !rule.enabled
        || rule.rule_type != VipRuleType::User
        || !has_user_metric_condition(rule, user_metric)
    {
        return false;
    }
    let checks = get_user_rule_checks(rule, stats, user_metric);
    !checks.is_empty() && checks.iter().any(|v| *v)
}

pub fn calculate_vip_level(
    rule_type: VipRuleType,
    rules: &[NormalizedVipRule],
    stats: &VipStats,
) -> i32 {
    rules
        .iter()
        .filter(|rule| rule.rule_type == rule_type && is_vip_rule_matched(rule_type, rule, stats))
        .map(|rule| rule.level)
        .max()
        .unwrap_or(0)
}

pub fn calculate_user_vip_level_by_metric(
    rules: &[NormalizedVipRule],
    stats: &UserVipStats,
    user_metric: UserVipMetric,
) -> i32 {
    rules
        .iter()
        .filter(|rule| is_user_vip_rule_matched(rule, stats, user_metric))
        .map(|rule| rule.level)
        .max()
        .unwrap_or(0)
}

// ===========================================================================
// Progress computation
// ===========================================================================

fn to_progress_percent(current: Decimal, target: Decimal) -> i64 {
    let c = dec_f64(current);
    let t = dec_f64(target);
    if !c.is_finite() || !t.is_finite() || t <= 0.0 {
        return 0;
    }
    js_round((c / t) * 100.0).clamp(0.0, 100.0) as i64
}

fn build_progress_condition(metric: &str, current: Decimal, target: Decimal) -> Value {
    let normalized_current = round_amount_dec(current.max(Decimal::ZERO));
    let normalized_target = round_amount_dec(target.max(Decimal::ZERO));
    let remaining =
        round_amount_dec((normalized_target - normalized_current).max(Decimal::ZERO));
    json!({
        "metric": metric,
        "current": num(normalized_current),
        "target": num(normalized_target),
        "remaining": num(remaining),
        "matched": normalized_current >= normalized_target,
        "progress": to_progress_percent(normalized_current, normalized_target),
    })
}

fn get_vip_progress_conditions(
    rule_type: VipRuleType,
    rule: &NormalizedVipRule,
    stats: &VipStats,
    user_metric: UserVipMetric,
) -> Vec<Value> {
    match (rule_type, stats) {
        (VipRuleType::User, VipStats::User(stats)) => {
            let mut conditions = Vec::new();
            if user_metric == UserVipMetric::TotalRecharge && has_threshold(rule.min_recharge) {
                conditions.push(build_progress_condition(
                    "totalRecharge",
                    stats.total_recharge,
                    rule.min_recharge.unwrap(),
                ));
            }
            if user_metric == UserVipMetric::TotalConsume && has_threshold(rule.min_consume) {
                conditions.push(build_progress_condition(
                    "totalConsume",
                    stats.total_consume,
                    rule.min_consume.unwrap(),
                ));
            }
            conditions
        }
        (VipRuleType::Hosting, VipStats::Hosting(stats)) => {
            let mut conditions = Vec::new();
            if has_threshold(rule.min_hosting_income) {
                conditions.push(build_progress_condition(
                    "totalHostingIncome",
                    stats.total_hosting_income,
                    rule.min_hosting_income.unwrap(),
                ));
            }
            if let Some(threshold) = rule.min_hosting_instances.filter(|v| *v > 0) {
                conditions.push(build_progress_condition(
                    "instanceCount",
                    Decimal::from(stats.instance_count),
                    Decimal::from(threshold),
                ));
            }
            conditions
        }
        _ => Vec::new(),
    }
}

/// calculateVipProgress — returns the VipLevelProgress JSON.
pub fn calculate_vip_progress(
    rule_type: VipRuleType,
    rules: &[NormalizedVipRule],
    current_level: i32,
    stats: &VipStats,
    user_metric: UserVipMetric,
) -> Value {
    let next_rule = rules
        .iter()
        .filter(|rule| {
            if rule.rule_type != rule_type
                || !rule.enabled
                || rule.level <= current_level
            {
                return false;
            }
            match rule_type {
                VipRuleType::User => has_user_metric_condition(rule, user_metric),
                VipRuleType::Hosting => has_active_condition(rule_type, rule),
            }
        })
        .min_by_key(|rule| rule.level);

    let user_metric_json = match rule_type {
        VipRuleType::User => json!(user_metric.as_str()),
        VipRuleType::Hosting => Value::Null,
    };

    let Some(next_rule) = next_rule else {
        return json!({
            "currentLevel": current_level,
            "nextLevel": Value::Null,
            "conditionMode": Value::Null,
            "userMetric": user_metric_json,
            "progress": if current_level > 0 { 100 } else { 0 },
            "isMaxLevel": current_level > 0,
            "conditions": [],
        });
    };

    let conditions = get_vip_progress_conditions(rule_type, next_rule, stats, user_metric);
    let progress = if conditions.is_empty() {
        0
    } else {
        let values: Vec<i64> = conditions
            .iter()
            .map(|c| c["progress"].as_i64().unwrap_or(0))
            .collect();
        if next_rule.condition_mode == VipConditionMode::All {
            values.into_iter().min().unwrap_or(0)
        } else {
            values.into_iter().max().unwrap_or(0)
        }
    };

    json!({
        "currentLevel": current_level,
        "nextLevel": next_rule.level,
        "conditionMode": next_rule.condition_mode.as_str(),
        "userMetric": user_metric_json,
        "progress": progress,
        "isMaxLevel": false,
        "conditions": conditions,
    })
}

// ===========================================================================
// DB access
// ===========================================================================

#[derive(Debug, sqlx::FromRow)]
struct VipLevelRuleRow {
    id: i32,
    #[sqlx(rename = "type")]
    rule_type: String,
    level: i32,
    enabled: bool,
    #[sqlx(rename = "condition_mode")]
    condition_mode: String,
    min_recharge: Option<Decimal>,
    min_consume: Option<Decimal>,
    min_hosting_income: Option<Decimal>,
    min_hosting_instances: Option<i32>,
    benefits: Value,
}

/// normalizeVipRule for a DB row (non-strict benefit normalization).
fn normalize_vip_rule_row(row: VipLevelRuleRow) -> NormalizedVipRule {
    let benefits = sanitize_benefits(row.level, &row.benefits, false)
        .unwrap_or_else(|_| Value::Object(Map::new()));
    let badge_style = normalize_vip_badge_style(row.level, &benefits["badgeStyle"]);
    NormalizedVipRule {
        id: Some(row.id),
        rule_type: VipRuleType::parse(&row.rule_type).unwrap_or(VipRuleType::User),
        level: row.level,
        enabled: row.enabled,
        condition_mode: if row.condition_mode == "all" {
            VipConditionMode::All
        } else {
            VipConditionMode::Any
        },
        min_recharge: row.min_recharge,
        min_consume: row.min_consume,
        min_hosting_income: row.min_hosting_income,
        min_hosting_instances: row.min_hosting_instances.map(|v| v as i64),
        benefits,
        badge_style,
    }
}

async fn vip_rules_on_conn(
    conn: &mut sqlx::PgConnection,
    rule_type: VipRuleType,
) -> Result<Vec<NormalizedVipRule>, sqlx::Error> {
    let rows = sqlx::query_as::<_, VipLevelRuleRow>(
        "SELECT id, type::text AS type, level, enabled, condition_mode::text AS condition_mode, \
         min_recharge, min_consume, min_hosting_income, min_hosting_instances, benefits \
         FROM vip_level_rules WHERE type = $1::\"VipLevelRuleType\" ORDER BY level ASC",
    )
    .bind(rule_type.as_str())
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(normalize_vip_rule_row).collect())
}

/// getVipRules(type, client = prisma) — pool variant.
pub async fn get_vip_rules(
    db: &PgPool,
    rule_type: VipRuleType,
) -> Result<Vec<NormalizedVipRule>, ApiError> {
    let mut conn = db.acquire().await?;
    Ok(vip_rules_on_conn(&mut *conn, rule_type).await?)
}

/// getVipRules(type, tx) — transaction variant.
pub async fn get_vip_rules_tx(
    conn: &mut sqlx::PgConnection,
    rule_type: VipRuleType,
) -> Result<Vec<NormalizedVipRule>, sqlx::Error> {
    vip_rules_on_conn(conn, rule_type).await
}

/// getUserVipMetric: system_configs['user_vip_metric'] normalized.
pub async fn get_user_vip_metric(db: &PgPool) -> Result<UserVipMetric, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT value FROM system_configs WHERE key = $1")
            .bind(USER_VIP_METRIC_CONFIG_KEY)
            .fetch_optional(db)
            .await?;
    let value = row.and_then(|(v,)| v);
    Ok(normalize_user_vip_metric(value.as_deref()))
}

async fn user_vip_stats_on_conn(
    conn: &mut sqlx::PgConnection,
    user_id: i32,
) -> Result<UserVipStats, sqlx::Error> {
    // db/balance.ts getUsersTotalConsumeMap([userId]).
    let (total_consume,): (Decimal,) = sqlx::query_as(
        "SELECT COALESCE(SUM( \
            CASE WHEN balance_before > balance_after THEN balance_before - balance_after \
                 ELSE ABS(amount) END), 0) \
         FROM balance_logs WHERE user_id = $1 AND type IN ('consume', 'hourly_consume')",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    // services/vip-levels.ts total recharge raw SQL.
    let (total_recharge,): (Decimal,) = sqlx::query_as(
        "SELECT COALESCE(SUM(COALESCE(actual_amount, amount)), 0) \
         FROM recharge_records WHERE user_id = $1 AND status = 'completed'",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(UserVipStats {
        total_recharge,
        total_consume,
    })
}

async fn hosting_vip_stats_on_conn(
    conn: &mut sqlx::PgConnection,
    user_id: i32,
) -> Result<HostingVipStats, sqlx::Error> {
    let (total_hosting_income,): (Decimal,) = sqlx::query_as(
        "SELECT COALESCE(SUM(amount), 0) FROM hosting_balance_logs \
         WHERE user_id = $1 AND type = 'income'",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    let (instance_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instances i JOIN hosts h ON h.id = i.host_id \
         WHERE h.user_id = $1 AND i.status <> 'deleted'",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(HostingVipStats {
        total_hosting_income,
        instance_count,
    })
}

/// getUserVipStats(userId, client = prisma) — pool variant.
pub async fn get_user_vip_stats(
    db: &PgPool,
    user_id: i32,
) -> Result<UserVipStats, ApiError> {
    let mut conn = db.acquire().await?;
    Ok(user_vip_stats_on_conn(&mut *conn, user_id).await?)
}

pub async fn get_user_vip_stats_tx(
    conn: &mut sqlx::PgConnection,
    user_id: i32,
) -> Result<UserVipStats, sqlx::Error> {
    user_vip_stats_on_conn(conn, user_id).await
}

/// calculateUserVipLevel / calculateHostingVipLevel helpers.
pub async fn calculate_user_vip_level(
    db: &PgPool,
    user_id: i32,
) -> Result<(i32, UserVipStats), ApiError> {
    let rules = get_vip_rules(db, VipRuleType::User).await?;
    let stats = get_user_vip_stats(db, user_id).await?;
    let metric = get_user_vip_metric(db).await?;
    Ok((
        calculate_user_vip_level_by_metric(&rules, &stats, metric),
        stats,
    ))
}

pub async fn calculate_hosting_vip_level(
    db: &PgPool,
    user_id: i32,
) -> Result<(i32, HostingVipStats), ApiError> {
    let mut conn = db.acquire().await?;
    let rules = vip_rules_on_conn(&mut *conn, VipRuleType::Hosting).await?;
    let stats = hosting_vip_stats_on_conn(&mut *conn, user_id).await?;
    Ok((
        calculate_vip_level(VipRuleType::Hosting, &rules, &VipStats::Hosting(&stats)),
        stats,
    ))
}

/// getVipOverview(userId) — the GET /api/vip-levels/me response body.
pub async fn get_vip_overview(db: &PgPool, user_id: i32) -> Result<Value, ApiError> {
    let user_vip_metric = get_user_vip_metric(db).await?;
    let mut conn = db.acquire().await?;
    let user_rules = vip_rules_on_conn(&mut *conn, VipRuleType::User).await?;
    let hosting_rules = vip_rules_on_conn(&mut *conn, VipRuleType::Hosting).await?;
    let user_stats = user_vip_stats_on_conn(&mut *conn, user_id).await?;
    let hosting_stats = hosting_vip_stats_on_conn(&mut *conn, user_id).await?;

    let user_vip_level =
        calculate_user_vip_level_by_metric(&user_rules, &user_stats, user_vip_metric);
    let hosting_vip_level =
        calculate_vip_level(VipRuleType::Hosting, &hosting_rules, &VipStats::Hosting(&hosting_stats));

    let user_badge = get_vip_badge_style_for_level(&user_rules, VipRuleType::User, user_vip_level);
    let hosting_badge =
        get_vip_badge_style_for_level(&hosting_rules, VipRuleType::Hosting, hosting_vip_level);

    Ok(json!({
        "userVipLevel": user_vip_level,
        "hostingVipLevel": hosting_vip_level,
        "userVipBadgeStyle": user_badge.map(|b| b.to_json()).unwrap_or(Value::Null),
        "hostingVipBadgeStyle": hosting_badge.map(|b| b.to_json()).unwrap_or(Value::Null),
        "userVipMetric": user_vip_metric.as_str(),
        "userStats": {
            "totalRecharge": num(user_stats.total_recharge),
            "totalConsume": num(user_stats.total_consume),
        },
        "hostingStats": {
            "totalHostingIncome": num(hosting_stats.total_hosting_income),
            "instanceCount": hosting_stats.instance_count,
        },
        "userVipProgress": calculate_vip_progress(
            VipRuleType::User,
            &user_rules,
            user_vip_level,
            &VipStats::User(&user_stats),
            user_vip_metric,
        ),
        "hostingVipProgress": calculate_vip_progress(
            VipRuleType::Hosting,
            &hosting_rules,
            hosting_vip_level,
            &VipStats::Hosting(&hosting_stats),
            user_vip_metric,
        ),
    }))
}

// ===========================================================================
// replaceVipRules
// ===========================================================================

/// Errors from replaceVipRules: validation messages (plain Error in TS) vs DB
/// failures. The TS route catches BOTH through the same try/catch and answers
/// `400 { error }`.
pub enum ReplaceVipRulesError {
    Validation(String),
    Db(ApiError),
}

impl From<ApiError> for ReplaceVipRulesError {
    fn from(e: ApiError) -> Self {
        Self::Db(e)
    }
}

impl From<sqlx::Error> for ReplaceVipRulesError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(ApiError::from_sql(e))
    }
}

struct BenefitInstanceRef {
    level: i32,
    package_id: i64,
    plan_id: i64,
}

fn collect_benefit_instance_refs(rules: &[NormalizedVipRule]) -> Vec<BenefitInstanceRef> {
    let mut refs = Vec::new();
    for rule in rules {
        let hall = normalize_benefit_hall_config(&rule.benefits["benefitHall"], false)
            .unwrap_or(Value::Null);
        let instance = &hall["instance"];
        if instance["enabled"] == Value::Bool(true) {
            if let (Some(package_id), Some(plan_id)) = (
                instance["packageId"].as_i64(),
                instance["planId"].as_i64(),
            ) {
                refs.push(BenefitInstanceRef {
                    level: rule.level,
                    package_id,
                    plan_id,
                });
            }
        }
    }
    refs
}

async fn validate_benefit_instance_refs(
    db: &PgPool,
    refs: &[BenefitInstanceRef],
) -> Result<(), ReplaceVipRulesError> {
    if refs.is_empty() {
        return Ok(());
    }

    let package_ids: Vec<i64> = refs.iter().map(|r| r.package_id).collect::<HashSet<_>>().into_iter().collect();
    let plan_ids: Vec<i64> = refs.iter().map(|r| r.plan_id).collect::<HashSet<_>>().into_iter().collect();

    let packages: Vec<(i32,)> =
        sqlx::query_as("SELECT id FROM packages WHERE active = true AND id = ANY($1)")
            .bind(&package_ids)
            .fetch_all(db)
            .await?;
    let plans: Vec<(i32, i32)> = sqlx::query_as(
        "SELECT id, package_id FROM package_plans WHERE is_active = true AND id = ANY($1)",
    )
    .bind(&plan_ids)
    .fetch_all(db)
    .await?;

    let existing_package_ids: HashSet<i32> = packages.into_iter().map(|(id,)| id).collect();
    let active_plan_package: HashMap<i32, i32> = plans.into_iter().collect();

    for reference in refs {
        if !existing_package_ids.contains(&(reference.package_id as i32)) {
            return Err(ReplaceVipRulesError::Validation(format!(
                "VIP{} benefit package does not exist or is disabled",
                reference.level
            )));
        }
        if active_plan_package.get(&(reference.plan_id as i32)).copied()
            != Some(reference.package_id as i32)
        {
            return Err(ReplaceVipRulesError::Validation(format!(
                "VIP{} benefit plan does not exist, is disabled, or does not belong to the selected package",
                reference.level
            )));
        }
    }
    Ok(())
}

/// replaceVipRules(type, inputs, userMetric) — sanitize, validate instance
/// refs, then transactionally upsert rules (+ persist the user metric).
pub async fn replace_vip_rules(
    db: &PgPool,
    rule_type: VipRuleType,
    inputs: &[Value],
    user_metric: Option<UserVipMetric>,
) -> Result<Vec<NormalizedVipRule>, ReplaceVipRulesError> {
    if inputs.len() > MAX_VIP_LEVEL as usize {
        return Err(ReplaceVipRulesError::Validation(format!(
            "At most {MAX_VIP_LEVEL} VIP rules can be saved"
        )));
    }

    let metric_to_save = if rule_type == VipRuleType::User {
        user_metric
    } else {
        None
    };
    let effective_user_metric = if rule_type == VipRuleType::User {
        match metric_to_save {
            Some(metric) => metric,
            None => get_user_vip_metric(db).await?,
        }
    } else {
        UserVipMetric::TotalRecharge
    };

    let mut by_level: BTreeMap<i32, NormalizedVipRule> = BTreeMap::new();
    for input in inputs {
        let rule = sanitize_vip_rule_input(rule_type, input, effective_user_metric)
            .map_err(ReplaceVipRulesError::Validation)?;
        by_level.insert(rule.level, rule);
    }
    let normalized_rules: Vec<NormalizedVipRule> = by_level.into_values().collect();

    validate_benefit_instance_refs(
        db,
        &collect_benefit_instance_refs(&normalized_rules),
    )
    .await?;

    let mut tx = db.begin().await?;

    if let Some(metric) = metric_to_save {
        sqlx::query(
            "INSERT INTO system_configs (key, value, type, label, description) \
             VALUES ($1, $2, 'string', $3, $4) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
        )
        .bind(USER_VIP_METRIC_CONFIG_KEY)
        .bind(metric.as_str())
        .bind(USER_VIP_METRIC_LABEL)
        .bind(USER_VIP_METRIC_DESCRIPTION)
        .execute(&mut *tx)
        .await?;
    }

    if normalized_rules.is_empty() {
        sqlx::query("DELETE FROM vip_level_rules WHERE type = $1::\"VipLevelRuleType\"")
            .bind(rule_type.as_str())
            .execute(&mut *tx)
            .await?;
    } else {
        let keep_levels: Vec<i32> = normalized_rules.iter().map(|rule| rule.level).collect();
        sqlx::query(
            "DELETE FROM vip_level_rules \
             WHERE type = $1::\"VipLevelRuleType\" AND NOT (level = ANY($2))",
        )
        .bind(rule_type.as_str())
        .bind(&keep_levels)
        .execute(&mut *tx)
        .await?;

        for rule in &normalized_rules {
            sqlx::query(
                "INSERT INTO vip_level_rules \
                 (type, level, enabled, condition_mode, min_recharge, min_consume, \
                  min_hosting_income, min_hosting_instances, benefits) \
                 VALUES ($1::\"VipLevelRuleType\", $2, $3, $4::\"VipLevelConditionMode\", \
                         $5, $6, $7, $8, $9) \
                 ON CONFLICT (type, level) DO UPDATE SET \
                   enabled = EXCLUDED.enabled, \
                   condition_mode = EXCLUDED.condition_mode, \
                   min_recharge = EXCLUDED.min_recharge, \
                   min_consume = EXCLUDED.min_consume, \
                   min_hosting_income = EXCLUDED.min_hosting_income, \
                   min_hosting_instances = EXCLUDED.min_hosting_instances, \
                   benefits = EXCLUDED.benefits, \
                   updated_at = NOW()",
            )
            .bind(rule_type.as_str())
            .bind(rule.level)
            .bind(rule.enabled)
            .bind(rule.condition_mode.as_str())
            .bind(rule.min_recharge)
            .bind(rule.min_consume)
            .bind(rule.min_hosting_income)
            .bind(rule.min_hosting_instances.map(|v| v as i32))
            .bind(&rule.benefits)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;

    Ok(get_vip_rules(db, rule_type).await?)
}

// ===========================================================================
// Tests (pure normalization/matching logic; no DB)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(min_recharge: Option<f64>, enabled: bool) -> NormalizedVipRule {
        NormalizedVipRule {
            id: Some(1),
            rule_type: VipRuleType::User,
            level: 3,
            enabled,
            condition_mode: VipConditionMode::Any,
            min_recharge: min_recharge.map(dec2),
            min_consume: None,
            min_hosting_income: None,
            min_hosting_instances: None,
            benefits: json!({}),
            badge_style: get_default_vip_badge_style(3),
        }
    }

    #[test]
    fn default_badge_styles_wrap_levels() {
        assert_eq!(
            get_default_vip_badge_style(1).background_color, "#FEF3C7"
        );
        assert_eq!(
            get_default_vip_badge_style(11).background_color,
            get_default_vip_badge_style(1).background_color
        );
        assert_eq!(get_default_vip_badge_style(0).background_color, "#FEF3C7");
    }

    #[test]
    fn badge_style_hex_validation() {
        let style = normalize_vip_badge_style(2, &json!({
            "backgroundColor": "#ABC123",
            "textColor": "nope"
        }));
        assert_eq!(style.background_color, "#ABC123");
        assert_eq!(style.text_color, get_default_vip_badge_style(2).text_color);
    }

    #[test]
    fn sanitize_input_rejects_bad_levels_and_unconditional_rules() {
        let err = sanitize_vip_rule_input(
            VipRuleType::User,
            &json!({ "level": 11 }),
            UserVipMetric::TotalRecharge,
        )
        .unwrap_err();
        assert_eq!(err, "VIP level must be between 1 and 10");

        let err = sanitize_vip_rule_input(
            VipRuleType::User,
            &json!({ "level": 2, "minRecharge": 0 }),
            UserVipMetric::TotalRecharge,
        )
        .unwrap_err();
        assert_eq!(err, "VIP2 requires at least one condition");

        let ok = sanitize_vip_rule_input(
            VipRuleType::User,
            &json!({ "level": 2, "minRecharge": "150.005" }),
            UserVipMetric::TotalRecharge,
        )
        .unwrap();
        // Math.round(150.005 * 100) / 100 === 150.01 in JS (float artifact);
        // the JS-arithmetic port reproduces it.
        assert_eq!(ok.min_recharge.unwrap(), dec2(round_money_f64(150.005)));
    }

    #[test]
    fn user_metric_matching_ignores_inactive_metric() {
        let r = rule(Some(100.0), true);
        let stats = UserVipStats {
            total_recharge: dec2(150.0),
            total_consume: dec2(999.0),
        };
        assert_eq!(
            calculate_user_vip_level_by_metric(&[r.clone()], &stats, UserVipMetric::TotalRecharge),
            3
        );
        // Consume metric ignores the recharge-only rule entirely.
        assert_eq!(
            calculate_user_vip_level_by_metric(&[r], &stats, UserVipMetric::TotalConsume),
            0
        );
    }

    #[test]
    fn progress_rounding_and_percent() {
        let style = calculate_vip_progress(
            VipRuleType::User,
            &[rule(Some(100.0), true)],
            1,
            &VipStats::User(&UserVipStats {
                total_recharge: dec2(33.336),
                total_consume: Decimal::ZERO,
            }),
            UserVipMetric::TotalRecharge,
        );
        let condition = &style["conditions"][0];
        assert_eq!(condition["current"], json!(33.34));
        assert_eq!(condition["remaining"], json!(66.66));
        assert_eq!(condition["progress"], json!(33));
        assert_eq!(style["isMaxLevel"], json!(false));
    }

    #[test]
    fn max_level_progress() {
        let style = calculate_vip_progress(
            VipRuleType::Hosting,
            &[],
            0,
            &VipStats::Hosting(&HostingVipStats {
                total_hosting_income: Decimal::ZERO,
                instance_count: 0,
            }),
            UserVipMetric::TotalRecharge,
        );
        assert_eq!(style["progress"], json!(0));
        assert_eq!(style["isMaxLevel"], json!(false));
        assert_eq!(style["conditionMode"], Value::Null);
    }

    #[test]
    fn strict_hall_config_requires_positive_amounts() {
        let err = normalize_benefit_hall_config(
            &json!({ "balance": { "enabled": true, "amount": 0 } }),
            true,
        )
        .unwrap_err();
        assert_eq!(err, "VIP benefit balance amount must be greater than 0");

        let hall = normalize_benefit_hall_config(
            &json!({ "instance": { "enabled": false, "packageId": 5 } }),
            true,
        )
        .unwrap();
        assert_eq!(hall["instance"]["enabled"], json!(false));
        assert_eq!(hall["instance"]["days"], json!(30));
        assert_eq!(hall["instance"]["quantity"], json!(1));
    }

    #[test]
    fn js_number_conversions() {
        assert_eq!(js_to_number(&json!("12.5")), Some(12.5));
        assert_eq!(js_to_number(&json!("")), Some(0.0));
        assert_eq!(js_to_number(&json!("abc")), None);
        assert_eq!(js_to_number(&json!(null)), Some(0.0));
        assert_eq!(js_to_number(&json!(true)), Some(1.0));
        assert_eq!(js_to_number(&json!({})), None);
        assert_eq!(js_num_json(10.0), json!(10));
        assert_eq!(js_num_json(10.5), json!(10.5));
        assert_eq!(js_num_to_string(0.1 + 0.2), "0.30000000000000004");
    }
}
