//! 流量统计 API — port of server/src/routes/traffic.ts (+ db/traffic.ts,
//! services/traffic-utils.ts helpers). Routes register with FULL /api paths
//! upstream (no shared prefix) and are merged into the top-level router.
//!
//! NOT ported yet (Wave D schedulers): reconcileTrafficStateForUser/
//! ForInstanceIds and runTrafficJob are warn-logged no-ops — the TS treats
//! reconciliation failures as warnings on these paths anyway. Traffic period
//! math uses the server's local timezone like the TS Date constructor.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{Datelike, Local, NaiveDate};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::{AdminAuth, AuthUser};
use crate::error::{code, ApiError};
use crate::libs::instance_common::iso;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/api/me/traffic", get(my_traffic))
        .route("/api/users/{userId}/traffic", get(admin_user_traffic))
        .route("/api/users/{userId}/traffic/limit", put(admin_user_limit))
        .route("/api/instances/{instanceId}/traffic", get(instance_traffic))
        .route("/api/instances/{instanceId}/traffic/history", get(instance_history))
        .route("/api/instances/{instanceId}/traffic/limit", put(admin_instance_limit))
        .route("/api/instances/{instanceId}/traffic/reset", post(reset_traffic))
        .route("/api/hosts/{hostId}/traffic/history", get(host_history))
        .route("/api/traffic/collect", post(collect_now))
        .route("/api/traffic/sync-package-limits", post(sync_package_limits))
}

// ==================== traffic-utils helpers ====================

fn format_bytes(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.2} {}", value, UNITS[unit])
}

fn big(value: Option<i64>) -> Value {
    match value {
        Some(v) => json!(v.to_string()),
        None => Value::Null,
    }
}

fn percentage(used: i64, limit: Option<i64>) -> f64 {
    match limit {
        Some(l) if l != 0 => ((used as f64 / l as f64) * 100.0).min(100.0),
        _ => 0.0,
    }
}

fn is_over_limit(used: i64, limit: Option<i64>) -> bool {
    matches!(limit, Some(l) if used >= l)
}

fn is_warning_threshold(used: i64, limit: Option<i64>) -> bool {
    match limit {
        Some(l) => used as i128 >= (l as i128 * 80) / 100,
        None => false,
    }
}

fn calculate_user_traffic_status(used: i64, limit: Option<i64>) -> &'static str {
    if is_over_limit(used, limit) {
        "LIMITED"
    } else if is_warning_threshold(used, limit) {
        "WARNING"
    } else {
        "NORMAL"
    }
}

fn calculate_instance_traffic_status(used: i64, limit: Option<i64>) -> &'static str {
    if is_over_limit(used, limit) {
        "LIMITED"
    } else {
        "NORMAL"
    }
}

/// getTrafficPeriod: period anchored on reset day 1-28, local time.
fn get_traffic_period(reset_day: i32) -> (NaiveDate, NaiveDate) {
    let day = reset_day.clamp(1, 28);
    let now = Local::now().date_naive();
    let (year, month) = (now.year(), now.month() as i32);
    if now.day() as i32 >= day {
        let start = NaiveDate::from_ymd_opt(year, month as u32, day as u32).unwrap_or(now);
        let (ny, nm) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
        let end = NaiveDate::from_ymd_opt(ny, nm as u32, day as u32).unwrap_or(now);
        (start, end)
    } else {
        let (py, pm) = if month == 1 { (year - 1, 12) } else { (year, month - 1) };
        let start = NaiveDate::from_ymd_opt(py, pm as u32, day as u32).unwrap_or(now);
        let end = NaiveDate::from_ymd_opt(year, month as u32, day as u32).unwrap_or(now);
        (start, end)
    }
}

fn format_local_date(date: NaiveDate) -> String {
    date.format("%Y-%m-%d").to_string()
}

fn warn_scheduler_not_ported(what: &str) {
    tracing::warn!("traffic scheduler not ported yet (Wave D): {what} skipped");
}

// ==================== rows ====================

#[derive(Debug, FromRow)]
struct QuotaRow {
    monthly_traffic_limit: Option<i64>,
    monthly_traffic_used: Option<i64>,
    extra_traffic_quota: Option<i64>,
    #[sqlx(rename = "traffic_status")]
    status: Option<String>,
}

async fn get_user_traffic_quota(
    state: &SharedAppState,
    user_id: i32,
) -> Result<Option<QuotaRow>, ApiError> {
    Ok(sqlx::query_as::<_, QuotaRow>(
        "SELECT monthly_traffic_limit, monthly_traffic_used, extra_traffic_quota, \
                traffic_status::text AS traffic_status \
         FROM user_quotas WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?)
}

#[derive(Debug, FromRow)]
struct InstanceTrafficRow {
    id: i32,
    name: String,
    user_id: i32,
    host_id: i32,
    package_plan_id: Option<i32>,
    monthly_traffic_limit: Option<i64>,
    monthly_traffic_used: Option<i64>,
    #[sqlx(rename = "traffic_status")]
    status: Option<String>,
    traffic_billing_mode: Option<String>,
    traffic_unit_price: Option<Decimal>,
    traffic_settled_bytes: Option<i64>,
    traffic_settled_cost: Option<Decimal>,
    next_traffic_billing_at: Option<chrono::DateTime<chrono::Utc>>,
    reset_enabled: Option<bool>,
    reset_price: Option<Decimal>,
}

const INSTANCE_TRAFFIC_COLUMNS: &str = "i.id, i.name, i.user_id, i.host_id, i.package_plan_id, \
    i.monthly_traffic_limit, i.monthly_traffic_used, i.traffic_status::text AS traffic_status, \
    i.traffic_billing_mode::text AS traffic_billing_mode, i.traffic_unit_price, \
    i.traffic_settled_bytes, i.traffic_settled_cost, i.next_traffic_billing_at, \
    pp.traffic_reset_enabled AS reset_enabled, pp.traffic_reset_price AS reset_price";

async fn get_instance_traffic_info(
    state: &SharedAppState,
    instance_id: i32,
) -> Result<Option<InstanceTrafficRow>, ApiError> {
    Ok(sqlx::query_as::<_, InstanceTrafficRow>(&format!(
        "SELECT {INSTANCE_TRAFFIC_COLUMNS} \
         FROM instances i LEFT JOIN package_plans pp ON pp.id = i.package_plan_id \
         WHERE i.id = $1"
    ))
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?)
}

fn used_of(row: &InstanceTrafficRow) -> i64 {
    row.monthly_traffic_used.unwrap_or(0)
}

fn limit_of(row: &InstanceTrafficRow) -> Option<i64> {
    row.monthly_traffic_limit
}

/// routes getTrafficResetInfo.
fn traffic_reset_info(
    instance: Option<&InstanceTrafficRow>,
    free_reset_allowed: bool,
) -> Value {
    let plan_reset_enabled = instance.and_then(|i| i.reset_enabled).unwrap_or(false);
    let price_cents: f64 = instance
        .and_then(|i| i.reset_price)
        .map(|d| d.to_f64().unwrap_or(0.0))
        .unwrap_or(0.0);
    let used = instance.map(used_of).unwrap_or(0);
    let has_plan = instance.map_or(false, |i| i.package_plan_id.is_some());

    if instance.and_then(|i| i.traffic_billing_mode.as_deref()) == Some("usage") {
        return json!({
            "resetAllowed": false, "resetPrice": 0, "resetPriceFormatted": null,
            "resetDisabledReason": "USAGE_BILLING",
        });
    }
    if free_reset_allowed {
        return json!({
            "resetAllowed": true, "resetPrice": 0,
            "resetPriceFormatted": "¥0.00",
            "resetDisabledReason": if used > 0 { Value::Null } else { json!("NO_USAGE") },
        });
    }
    if !has_plan {
        return json!({
            "resetAllowed": false, "resetPrice": 0, "resetPriceFormatted": null,
            "resetDisabledReason": "NO_PAID_PLAN",
        });
    }
    if !plan_reset_enabled {
        return json!({
            "resetAllowed": false, "resetPrice": 0, "resetPriceFormatted": null,
            "resetDisabledReason": "PLAN_DISABLED",
        });
    }
    json!({
        "resetAllowed": true,
        "resetPrice": price_cents,
        "resetPriceFormatted": format!("¥{:.2}", price_cents / 100.0),
        "resetDisabledReason": if used > 0 { Value::Null } else { json!("NO_USAGE") },
    })
}

// ==================== GET /api/me/traffic ====================

async fn my_traffic(
    State(state): State<SharedAppState>,
    user: crate::auth::UserOnlyAuth,
) -> Result<Json<Value>, ApiError> {
    let quota = get_user_traffic_quota(&state, user.0.id)
        .await?
        .ok_or_else(|| ApiError::bare(StatusCode::NOT_FOUND, "User quota not found"))?;
    Ok(Json(quota_json(&quota)))
}

fn quota_json(quota: &QuotaRow) -> Value {
    let used = quota.monthly_traffic_used.unwrap_or(0);
    let extra = quota.extra_traffic_quota.unwrap_or(0);
    let effective = quota.monthly_traffic_limit.map(|l| l + extra);
    json!({
        "monthlyUsed": big(Some(used)),
        "monthlyUsedFormatted": format_bytes(used),
        "monthlyLimit": big(effective),
        "monthlyLimitFormatted": effective.map(format_bytes).map(Value::String).unwrap_or(Value::Null),
        "extraQuota": big(Some(extra)),
        "trafficStatus": quota.status.clone().unwrap_or_else(|| "NORMAL".into()),
        "percentage": percentage(used, effective),
    })
}

// ==================== GET /api/users/:userId/traffic (admin) ====================

fn parse_int(raw: &str) -> Option<i32> {
    let s = raw.trim_start();
    let bytes = s.as_bytes();
    let mut end = 0usize;
    if bytes.first().map(|b| *b == b'-' || *b == b'+').unwrap_or(false) {
        end += 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && (bytes[0] == b'-' || bytes[0] == b'+')) {
        return None;
    }
    s[..end].parse().ok()
}

async fn admin_user_traffic(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = parse_int(&user_id)
        .ok_or_else(|| ApiError::bare(StatusCode::BAD_REQUEST, "Invalid user ID"))?;
    let quota = get_user_traffic_quota(&state, user_id)
        .await?
        .ok_or_else(|| ApiError::bare(StatusCode::NOT_FOUND, "User quota not found"))?;
    Ok(Json(quota_json(&quota)))
}

// ==================== PUT /api/users/:userId/traffic/limit (admin) ====================

#[derive(Deserialize)]
struct LimitBody {
    #[serde(rename = "monthlyLimit")]
    monthly_limit: Option<String>,
}

async fn admin_user_limit(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(user_id): Path<String>,
    body: Option<Json<LimitBody>>,
) -> Result<Json<Value>, ApiError> {
    let user_id = parse_int(&user_id)
        .ok_or_else(|| ApiError::bare(StatusCode::BAD_REQUEST, "Invalid user ID"))?;
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let limit: Option<i64> = match body.monthly_limit.as_deref() {
        Some(s) if !s.is_empty() => Some(
            s.parse::<i64>()
                .map_err(|_| ApiError::validation("monthlyLimit must be an integer"))?,
        ),
        _ => None,
    };

    sqlx::query("UPDATE user_quotas SET monthly_traffic_limit = $2 WHERE user_id = $1")
        .bind(user_id)
        .bind(limit)
        .execute(&state.db)
        .await?;

    if let Some(quota) = get_user_traffic_quota(&state, user_id).await? {
        let used = quota.monthly_traffic_used.unwrap_or(0);
        let extra = quota.extra_traffic_quota.unwrap_or(0);
        let effective = quota.monthly_traffic_limit.map(|l| l + extra);
        let status = calculate_user_traffic_status(used, effective);
        sqlx::query("UPDATE user_quotas SET traffic_status = $2::\"TrafficStatus\" WHERE user_id = $1")
            .bind(user_id)
            .bind(status)
            .execute(&state.db)
            .await?;
    }
    warn_scheduler_not_ported("reconcileTrafficStateForUser");

    Ok(Json(json!({ "success": true })))
}

// ==================== instance view permission ====================

async fn instance_view_ok(
    state: &SharedAppState,
    user: &AuthUser,
    instance: &InstanceTrafficRow,
) -> Result<bool, ApiError> {
    if user.role == "admin" || instance.user_id == user.id {
        return Ok(true);
    }
    let host_owner: Option<i32> = sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
        .bind(instance.host_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(host_owner == Some(user.id))
}

// ==================== GET /api/instances/:id/traffic ====================

async fn instance_traffic(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id)
        .ok_or_else(|| ApiError::bare(StatusCode::BAD_REQUEST, "Invalid instance ID"))?;
    let instance = get_instance_traffic_info(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::bare(StatusCode::NOT_FOUND, "Instance not found"))?;

    if !instance_view_ok(&state, &user, &instance).await? {
        return Err(ApiError::bare(StatusCode::FORBIDDEN, "Access denied"));
    }

    let host_reset_day: Option<i32> =
        sqlx::query_scalar("SELECT traffic_reset_day FROM hosts WHERE id = $1")
            .bind(instance.host_id)
            .fetch_optional(&state.db)
            .await?;
    let traffic_reset_day = host_reset_day.unwrap_or(1);
    let (period_start, period_end) = get_traffic_period(traffic_reset_day);

    let is_host_owner: bool = (|| async {
        let owner: Option<i32> = sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
            .bind(instance.host_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
        owner == Some(user.id)
    })()
    .await;
    let free_reset_allowed = user.role == "admin" || is_host_owner;
    let reset_info = traffic_reset_info(Some(&instance), free_reset_allowed);

    let used = used_of(&instance);
    let limit = limit_of(&instance);
    let overage = if used > limit.unwrap_or(0) {
        used - limit.unwrap_or(0)
    } else {
        0
    };
    let pending = if overage > instance.traffic_settled_bytes.unwrap_or(0) {
        overage - instance.traffic_settled_bytes.unwrap_or(0)
    } else {
        0
    };

    let mut body = json!({
        "monthlyUsed": big(Some(used)),
        "monthlyUsedFormatted": format_bytes(used),
        "monthlyLimit": big(limit),
        "monthlyLimitFormatted": if instance.traffic_billing_mode.as_deref() == Some("usage") {
            json!(format_bytes(limit.unwrap_or(0)))
        } else {
            limit.map(format_bytes).map(Value::String).unwrap_or(Value::Null)
        },
        "trafficStatus": instance.status.clone().unwrap_or_else(|| "NORMAL".into()),
        "percentage": percentage(used, limit),
        "trafficResetDay": traffic_reset_day,
        "periodStart": format_local_date(period_start),
        "periodEnd": format_local_date(period_end),
        "trafficBillingMode": instance.traffic_billing_mode.clone().unwrap_or_else(|| "package".into()),
        "trafficUnitPrice": crate::response::num(instance.traffic_unit_price.unwrap_or_default()),
        "includedTraffic": big(limit),
        "overageTraffic": big(Some(overage)),
        "settledTraffic": big(instance.traffic_settled_bytes),
        "settledTrafficCost": crate::response::num(instance.traffic_settled_cost.unwrap_or_default()),
        "pendingTraffic": big(Some(pending)),
        "nextTrafficBillingAt": instance.next_traffic_billing_at.map(iso).unwrap_or(Value::Null),
    });
    if let (Some(obj), Some(reset)) = (body.as_object_mut(), reset_info.as_object()) {
        for (k, v) in reset {
            obj.insert(k.clone(), v.clone());
        }
    }
    Ok(Json(body))
}

// ==================== GET /api/instances/:id/traffic/history ====================

#[derive(Debug, FromRow)]
struct DailyRow {
    date: NaiveDate,
    rx_total: i64,
    tx_total: i64,
}

async fn instance_history(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id)
        .ok_or_else(|| ApiError::bare(StatusCode::BAD_REQUEST, "Invalid instance ID"))?;
    let instance = get_instance_traffic_info(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::bare(StatusCode::NOT_FOUND, "Instance not found"))?;
    if !instance_view_ok(&state, &user, &instance).await? {
        return Err(ApiError::bare(StatusCode::FORBIDDEN, "Access denied"));
    }

    let host_reset_day: Option<i32> =
        sqlx::query_scalar("SELECT traffic_reset_day FROM hosts WHERE id = $1")
            .bind(instance.host_id)
            .fetch_optional(&state.db)
            .await?;
    let traffic_reset_day = host_reset_day.unwrap_or(1);
    let (period_start, period_end) = get_traffic_period(traffic_reset_day);

    let rows = sqlx::query_as::<_, DailyRow>(
        "SELECT date, rx_total, tx_total FROM daily_traffic \
         WHERE instance_id = $1 AND date >= $2 ORDER BY date ASC",
    )
    .bind(instance_id)
    .bind(period_start)
    .fetch_all(&state.db)
    .await?;

    let data: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "date": format_local_date(r.date),
                "rxTotal": big(Some(r.rx_total)),
                "txTotal": big(Some(r.tx_total)),
                "rxFormatted": format_bytes(r.rx_total),
                "txFormatted": format_bytes(r.tx_total),
                "total": big(Some(r.rx_total + r.tx_total)),
                "totalFormatted": format_bytes(r.rx_total + r.tx_total),
            })
        })
        .collect();

    Ok(Json(json!({
        "trafficResetDay": traffic_reset_day,
        "periodStart": format_local_date(period_start),
        "periodEnd": format_local_date(period_end),
        "data": data,
    })))
}

// ==================== PUT /api/instances/:id/traffic/limit (admin) ====================

async fn admin_instance_limit(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(instance_id): Path<String>,
    body: Option<Json<LimitBody>>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id)
        .ok_or_else(|| ApiError::bare(StatusCode::BAD_REQUEST, "Invalid instance ID"))?;
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let limit: Option<i64> = match body.monthly_limit.as_deref() {
        Some(s) if !s.is_empty() => Some(
            s.parse::<i64>()
                .map_err(|_| ApiError::validation("monthlyLimit must be an integer"))?,
        ),
        _ => None,
    };

    sqlx::query("UPDATE instances SET monthly_traffic_limit = $2 WHERE id = $1")
        .bind(instance_id)
        .bind(limit)
        .execute(&state.db)
        .await?;

    if let Some(instance) = get_instance_traffic_info(&state, instance_id).await? {
        let status = calculate_instance_traffic_status(used_of(&instance), limit_of(&instance));
        sqlx::query("UPDATE instances SET traffic_status = $2::\"TrafficStatus\" WHERE id = $1")
            .bind(instance_id)
            .bind(status)
            .execute(&state.db)
            .await?;
    }
    warn_scheduler_not_ported("reconcileTrafficStateForInstanceIds");

    Ok(Json(json!({ "success": true })))
}

// ==================== POST /api/instances/:id/traffic/reset ====================

async fn reset_traffic(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_int(&instance_id)
        .ok_or_else(|| ApiError::bare(StatusCode::BAD_REQUEST, "Invalid instance ID"))?;
    let instance = get_instance_traffic_info(&state, instance_id)
        .await?
        .ok_or_else(|| ApiError::bare(StatusCode::NOT_FOUND, "Instance not found"))?;

    let is_admin = user.role == "admin";
    let host_owner: Option<i32> = sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
        .bind(instance.host_id)
        .fetch_optional(&state.db)
        .await?;
    let is_host_owner = host_owner == Some(user.id);
    let is_owner = instance.user_id == user.id;

    if !is_admin && !is_host_owner && !is_owner {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    // Usage-billed traffic is monetary consumption, not a resettable quota.
    if instance.traffic_billing_mode.as_deref() == Some("usage") {
        return Err(ApiError::bad_request(code::TRAFFIC_RESET_NOT_ALLOWED));
    }

    if is_admin || is_host_owner {
        // 免费重置（管理员/宿主所有者）
        let result = sqlx::query(
            "UPDATE instances SET monthly_traffic_used = 0, traffic_status = 'NORMAL', \
             traffic_settled_bytes = 0, traffic_settled_cost = 0, version = version + 1 \
             WHERE id = $1 AND traffic_billing_mode != 'usage'",
        )
        .bind(instance_id)
        .execute(&state.db)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ApiError::bad_request(code::TRAFFIC_RESET_NOT_ALLOWED));
        }
        warn_scheduler_not_ported("reconcileTrafficStateForInstanceIds");
        crate::libs::instance_common::create_log_with_instance(
            &state,
            user.id,
            "instance",
            "traffic.reset",
            &format!("Reset instance \"{}\" traffic without charge", instance.name),
            "success",
            Some(instance_id),
        )
        .await;

        let updated = get_instance_traffic_info(&state, instance_id).await?;
        let traffic = updated.map(|u| {
            let mut body = json!({
                "monthlyUsed": big(Some(used_of(&u))),
                "monthlyUsedFormatted": format_bytes(used_of(&u)),
                "trafficStatus": u.status.clone().unwrap_or_else(|| "NORMAL".into()),
                "percentage": percentage(used_of(&u), limit_of(&u)),
            });
            if let (Some(obj), Some(reset)) =
                (body.as_object_mut(), traffic_reset_info(Some(&u), true).as_object())
            {
                for (k, v) in reset {
                    obj.insert(k.clone(), v.clone());
                }
            }
            body
        });
        return Ok(Json(json!({
            "success": true,
            "message": "Instance traffic reset completed",
            "chargedAmount": 0,
            "balanceAfter": null,
            "traffic": traffic,
        })));
    }

    // 所有者付费重置（事务）
    let result: Result<(Value, f64, Option<f64>), &'static str> = async {
        let mut tx = state.db.begin().await.map_err(|_| "INTERNAL")?;

        let fresh = get_instance_traffic_info_tx(&mut tx, instance_id)
            .await
            .map_err(|_| "INTERNAL")?
            .ok_or("INSTANCE_NOT_FOUND")?;
        if fresh.user_id != user.id {
            return Err("FORBIDDEN");
        }
        if fresh.traffic_billing_mode.as_deref() == Some("usage") {
            return Err("TRAFFIC_RESET_NOT_ALLOWED");
        }
        if fresh.package_plan_id.is_none() || !fresh.reset_enabled.unwrap_or(false) {
            return Err("TRAFFIC_RESET_NOT_ALLOWED");
        }
        if used_of(&fresh) <= 0 {
            return Err("TRAFFIC_RESET_NOT_NEEDED");
        }

        let price_cents = fresh.reset_price.map(|d| d.to_f64().unwrap_or(0.0)).unwrap_or(0.0);
        let charge_amount = (price_cents.max(0.0) * 100.0).round() / 100.0 / 100.0;
        // NOTE: TS Math.round(priceCents)/100 — priceCents 分转元
        let charge_amount = (price_cents.max(0.0).round()) / 100.0;

        let reset = sqlx::query(
            "UPDATE instances SET monthly_traffic_used = 0, traffic_status = 'NORMAL', \
             traffic_settled_bytes = 0, traffic_settled_cost = 0, version = version + 1 \
             WHERE id = $1 AND user_id = $2 AND status != 'deleted' \
               AND traffic_billing_mode != 'usage' AND monthly_traffic_used > 0",
        )
        .bind(instance_id)
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| "INTERNAL")?;
        if reset.rows_affected() != 1 {
            return Err("TRAFFIC_RESET_NOT_NEEDED");
        }

        let mut balance_after: Option<f64> = None;
        if charge_amount > 0.0 {
            let charged = Decimal::try_from(charge_amount).map_err(|_| "INTERNAL")?;
            let balance_update = sqlx::query(
                "UPDATE users SET balance = balance - $2 WHERE id = $1 AND balance >= $2",
            )
            .bind(user.id)
            .bind(charged)
            .execute(&mut *tx)
            .await
            .map_err(|_| "INTERNAL")?;
            if balance_update.rows_affected() != 1 {
                return Err("BALANCE_INSUFFICIENT");
            }
            let new_balance: Decimal = sqlx::query_scalar(
                "SELECT balance FROM users WHERE id = $1",
            )
            .bind(user.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| "USER_NOT_FOUND")?;
            balance_after = Some(new_balance.to_f64().unwrap_or(0.0));
            let balance_before = new_balance + charged;
            sqlx::query(
                "INSERT INTO balance_logs \
                 (user_id, type, amount, balance_before, balance_after, instance_id, remark) \
                 VALUES ($1, 'consume'::\"BalanceLogType\", $2, $3, $4, $5, $6)",
            )
            .bind(user.id)
            .bind(-charged)
            .bind(balance_before)
            .bind(new_balance)
            .bind(instance_id)
            .bind(format!("重置实例 {} 本周期流量", fresh.name))
            .execute(&mut *tx)
            .await
            .map_err(|_| "INTERNAL")?;
        } else {
            let new_balance: Option<Decimal> = sqlx::query_scalar(
                "SELECT balance FROM users WHERE id = $1",
            )
            .bind(user.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| "INTERNAL")?;
            balance_after = new_balance.map(|d| d.to_f64().unwrap_or(0.0));
        }

        let updated = get_instance_traffic_info_tx(&mut tx, instance_id)
            .await
            .map_err(|_| "INTERNAL")?
            .ok_or("INSTANCE_NOT_FOUND")?;

        tx.commit().await.map_err(|_| "INTERNAL")?;
        Ok((reset_traffic_json(&updated), charge_amount, balance_after))
    }
    .await;

    match result {
        Ok((traffic, charge_amount, balance_after)) => {
            warn_scheduler_not_ported("reconcileTrafficStateForInstanceIds");
            crate::libs::instance_common::create_log_with_instance(
                &state,
                user.id,
                "instance",
                "traffic.reset",
                &format!(
                    "Reset instance \"{}\" traffic with charge ¥{charge_amount:.2}",
                    instance.name
                ),
                "success",
                Some(instance_id),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": "Instance traffic reset completed",
                "chargedAmount": charge_amount,
                "balanceAfter": balance_after,
                "traffic": traffic,
            })))
        }
        Err("INSTANCE_NOT_FOUND") => Err(ApiError::bare(StatusCode::NOT_FOUND, "Instance not found")),
        Err("FORBIDDEN") => Err(ApiError::forbidden(code::FORBIDDEN)),
        Err("TRAFFIC_RESET_NOT_ALLOWED") => Err(ApiError::bad_request(code::TRAFFIC_RESET_NOT_ALLOWED)),
        Err("TRAFFIC_RESET_NOT_NEEDED") => Err(ApiError::bad_request(code::TRAFFIC_RESET_NOT_NEEDED)),
        Err("BALANCE_INSUFFICIENT") => Err(ApiError::bad_request(code::BALANCE_INSUFFICIENT)),
        Err(_) => Err(ApiError::internal("traffic reset failed")),
    }
}

async fn get_instance_traffic_info_tx(
    tx: &mut sqlx::PgConnection,
    instance_id: i32,
) -> Result<Option<InstanceTrafficRow>, sqlx::Error> {
    sqlx::query_as::<_, InstanceTrafficRow>(&format!(
        "SELECT {INSTANCE_TRAFFIC_COLUMNS} \
         FROM instances i LEFT JOIN package_plans pp ON pp.id = i.package_plan_id \
         WHERE i.id = $1"
    ))
    .bind(instance_id)
    .fetch_optional(tx)
    .await
}

fn reset_traffic_json(updated: &InstanceTrafficRow) -> Value {
    let mut body = json!({
        "monthlyUsed": big(Some(used_of(updated))),
        "monthlyUsedFormatted": format_bytes(used_of(updated)),
        "trafficStatus": updated.status.clone().unwrap_or_else(|| "NORMAL".into()),
        "percentage": percentage(used_of(updated), limit_of(updated)),
    });
    if let (Some(obj), Some(reset)) =
        (body.as_object_mut(), traffic_reset_info(Some(updated), false).as_object())
    {
        for (k, v) in reset {
            obj.insert(k.clone(), v.clone());
        }
    }
    body
}

// ==================== GET /api/hosts/:hostId/traffic/history ====================

async fn host_history(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(host_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let host_id = parse_int(&host_id)
        .ok_or_else(|| ApiError::bare(StatusCode::BAD_REQUEST, "Invalid host ID"))?;

    let host_row: Option<(i32, i32)> = sqlx::query_as(
        "SELECT user_id, traffic_reset_day FROM hosts WHERE id = $1",
    )
    .bind(host_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((host_owner, reset_day)) = host_row else {
        return Err(ApiError::bare(StatusCode::NOT_FOUND, "Host not found"));
    };
    let owner_id = host_owner;
    let reset_day_raw = reset_day;
    if user.role != "admin" && owner_id != user.id {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    let traffic_reset_day = reset_day_raw.max(1);
    let (period_start, period_end) = get_traffic_period(traffic_reset_day);

    let rows: Vec<DailyRow> = sqlx::query_as(
        "SELECT dt.date, COALESCE(SUM(dt.rx_total), 0)::bigint AS rx_total, \
                COALESCE(SUM(dt.tx_total), 0)::bigint AS tx_total \
         FROM daily_traffic dt JOIN instances i ON i.id = dt.instance_id \
         WHERE i.host_id = $1 AND i.status != 'deleted' AND dt.date >= $2 \
         GROUP BY dt.date ORDER BY dt.date ASC",
    )
    .bind(host_id)
    .bind(period_start)
    .fetch_all(&state.db)
    .await?;

    let (total_used, total_limit): (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT SUM(monthly_traffic_used), SUM(monthly_traffic_limit) FROM instances \
         WHERE host_id = $1 AND status != 'deleted'",
    )
    .bind(host_id)
    .fetch_one(&state.db)
    .await?;

    let data: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "date": format_local_date(r.date),
                "rxTotal": big(Some(r.rx_total)),
                "txTotal": big(Some(r.tx_total)),
                "rxFormatted": format_bytes(r.rx_total),
                "txFormatted": format_bytes(r.tx_total),
                "total": big(Some(r.rx_total + r.tx_total)),
                "totalFormatted": format_bytes(r.rx_total + r.tx_total),
            })
        })
        .collect();

    Ok(Json(json!({
        "trafficResetDay": traffic_reset_day,
        "periodStart": format_local_date(period_start),
        "periodEnd": format_local_date(period_end),
        "data": data,
        "summary": {
            "totalUsed": big(Some(total_used.unwrap_or(0))),
            "totalUsedFormatted": format_bytes(total_used.unwrap_or(0)),
            "totalLimit": big(Some(total_limit.unwrap_or(0))),
            "totalLimitFormatted": format_bytes(total_limit.unwrap_or(0)),
        },
    })))
}

// ==================== admin triggers ====================

async fn collect_now(
    State(_state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    warn_scheduler_not_ported("runTrafficJob");
    Ok(Json(json!({ "success": true, "message": "Traffic collection job started" })))
}

async fn sync_package_limits(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    // db syncPackageTrafficLimitsToInstances (no packageId → all packages)
    let instances: Vec<(i32, i32, Option<i32>, Option<i64>)> = sqlx::query_as(
        "SELECT i.id, i.host_id, i.package_id, \
                COALESCE(pp.traffic_limit, p.monthly_traffic_limit) AS base_limit \
         FROM instances i \
         LEFT JOIN packages p ON p.id = i.package_id \
         LEFT JOIN package_plans pp ON pp.id = i.package_plan_id \
         WHERE i.status != 'deleted' AND i.package_id IS NOT NULL",
    )
    .fetch_all(&state.db)
    .await?;

    let mut count = 0usize;
    let mut updated_ids: Vec<i32> = Vec::new();
    for (id, host_id, package_id, base_limit) in instances {
        let Some(package_id) = package_id else { continue };
        let multiplier: Decimal = sqlx::query_scalar(
            "SELECT traffic_multiplier FROM package_hosts WHERE package_id = $1 AND host_id = $2",
        )
        .bind(package_id)
        .bind(host_id)
        .fetch_optional(&state.db)
        .await?
        .unwrap_or(Decimal::ONE);
        // applyTrafficMultiplier: limit * multiplier (Decimal, truncated to int)
        let applied: Option<i64> = base_limit.map(|l| {
            let scaled = Decimal::from(l) * multiplier;
            scaled.floor().to_i64().unwrap_or(l)
        });
        sqlx::query("UPDATE instances SET monthly_traffic_limit = $2 WHERE id = $1")
            .bind(id)
            .bind(applied)
            .execute(&state.db)
            .await?;
        count += 1;
        updated_ids.push(id);
    }
    if !updated_ids.is_empty() {
        warn_scheduler_not_ported("reconcileTrafficStateForInstanceIds");
    }

    Ok(Json(json!({
        "success": true,
        "message": "Package traffic limits synced to instances",
        "updatedCount": count as i64,
    })))
}

#[allow(unused)]
fn unused(_: Response) {}
