//! 管理员统计 — port of server/src/routes/admin-statistics.ts.
//! GET /api/admin/statistics/overview (full absolute path, merged at top
//! level). Business timezone UTC+8 windows, 60s result cache.

use std::sync::Mutex;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Datelike, Duration, FixedOffset, TimeZone, Utc};
use once_cell::sync::Lazy;
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde_json::{json, Value};

use crate::auth::AdminAuth;
use crate::error::ApiError;
use crate::state::SharedAppState;

const DAILY_DAYS: i64 = 30;
const MONTHLY_MONTHS: i64 = 12;
const TZ_OFFSET_MINUTES: i64 = 8 * 60;

static OVERVIEW_CACHE: Lazy<Mutex<Option<(Value, std::time::Instant)>>> =
    Lazy::new(|| Mutex::new(None));

pub fn router() -> Router<SharedAppState> {
    Router::new().route(
        "/api/admin/statistics/overview",
        get(overview),
    )
}

fn business_offset() -> FixedOffset {
    FixedOffset::east_opt((TZ_OFFSET_MINUTES * 60) as i32).expect("valid offset")
}

fn business_now() -> DateTime<FixedOffset> {
    Utc::now().with_timezone(&business_offset())
}

/// Business-day start (local midnight) expressed in UTC.
fn business_day_start_utc(now: DateTime<FixedOffset>) -> DateTime<Utc> {
    let date = now.date_naive();
    business_offset()
        .with_ymd_and_hms(date.year(), date.month(), date.day(), 0, 0, 0)
        .single()
        .unwrap_or(now)
        .with_timezone(&Utc)
}

fn business_month_start_utc(year: i32, month: u32) -> DateTime<Utc> {
    business_offset()
        .with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .unwrap_or_else(|| Utc::now().with_timezone(&business_offset()))
        .with_timezone(&Utc)
}

fn shift_month(year: i32, month: i32, delta: i64) -> (i32, u32) {
    let total = year as i64 * 12 + (month as i64 - 1) + delta;
    let y = total.div_euclid(12);
    let m = total.rem_euclid(12) + 1;
    (y as i32, m as u32)
}

fn label_date(start_utc: DateTime<Utc>) -> String {
    (start_utc + Duration::minutes(TZ_OFFSET_MINUTES))
        .format("%Y-%m-%d")
        .to_string()
}

fn label_month(start_utc: DateTime<Utc>) -> String {
    (start_utc + Duration::minutes(TZ_OFFSET_MINUTES))
        .format("%Y-%m")
        .to_string()
}

fn daily_window() -> (DateTime<Utc>, DateTime<Utc>, Vec<String>) {
    let today_start = business_day_start_utc(business_now());
    let start = today_start - Duration::days(DAILY_DAYS - 1);
    let end = today_start + Duration::days(1);
    let labels = (0..DAILY_DAYS)
        .map(|i| label_date(start + Duration::days(i)))
        .collect();
    (start, end, labels)
}

fn monthly_window() -> (DateTime<Utc>, DateTime<Utc>, Vec<String>) {
    let now = business_now();
    let (year, month) = (now.year(), now.month() as i32);
    let (sy, sm) = shift_month(year, month, 1 - MONTHLY_MONTHS);
    let start = business_month_start_utc(sy, sm);
    let (ey, em) = shift_month(year, month, 1);
    let end = business_month_start_utc(ey, em);
    let labels = (0..MONTHLY_MONTHS)
        .map(|i| {
            let (y, m) = shift_month(year, month, 1 - MONTHLY_MONTHS + i);
            label_month(business_month_start_utc(y, m))
        })
        .collect();
    (start, end, labels)
}

async fn bucket_query(
    state: &SharedAppState,
    sql: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<(String, f64)>, ApiError> {
    let rows: Vec<(String, Decimal)> = sqlx::query_as(sql)
        .bind(start)
        .bind(end)
        .fetch_all(&state.db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(bucket, value)| (bucket, value.to_f64().unwrap_or(0.0)))
        .collect())
}

fn fill_series(rows: &[(String, f64)], labels: &[String], money: bool) -> Vec<Value> {
    labels
        .iter()
        .map(|label| {
            let value = rows
                .iter()
                .find(|(bucket, _)| bucket == label)
                .map(|(_, v)| *v)
                .unwrap_or(0.0);
            json!({
                "label": label,
                "value": if money { (value * 100.0).round() / 100.0 } else { value },
            })
        })
        .collect()
}

async fn scalar(state: &SharedAppState, sql: &str) -> Result<f64, ApiError> {
    let value: Option<Decimal> = sqlx::query_scalar(sql)
        .fetch_optional(&state.db)
        .await?;
    Ok(value.map(|d| d.to_f64().unwrap_or(0.0)).unwrap_or(0.0))
}

fn money(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

async fn overview(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Response, ApiError> {
    if let Some((cached, expires_at)) = OVERVIEW_CACHE.lock().unwrap().clone() {
        if std::time::Instant::now() < expires_at {
            return Ok((StatusCode::OK, Json(cached)).into_response());
        }
    }

    let (daily_start, daily_end, daily_labels) = daily_window();
    let (monthly_start, monthly_end, monthly_labels) = monthly_window();

    let (total_users, total_instances, active_instances, paid_instances, free_instances): (i64, i64, i64, i64, i64) = tokio::try_join!(
        scalar_count(&state, "SELECT COUNT(*) FROM users"),
        scalar_count(&state, "SELECT COUNT(*) FROM instances WHERE status::text != 'deleted'"),
        scalar_count(&state, "SELECT COUNT(*) FROM instances WHERE status::text NOT IN ('deleted','suspended')"),
        scalar_count(&state, "SELECT COUNT(*) FROM instances WHERE status::text != 'deleted' AND billing_mode::text = 'package' AND package_plan_id IS NOT NULL"),
        scalar_count(&state, "SELECT COUNT(*) FROM instances WHERE status::text != 'deleted' AND billing_mode::text = 'package' AND package_plan_id IS NULL"),
    )?;

    let (total_recharge, total_consume, total_aff, total_destroy_fee): (f64, f64, f64, f64) = tokio::try_join!(
        scalar(&state, "SELECT COALESCE(SUM(COALESCE(actual_amount, amount)), 0)::numeric FROM recharge_records WHERE status::text = 'completed'"),
        scalar(&state, "SELECT COALESCE(SUM(ABS(amount)), 0)::numeric FROM balance_logs WHERE type::text IN ('consume','hourly_consume','transfer_fee')"),
        scalar(&state, "SELECT COALESCE(SUM(amount), 0)::numeric FROM aff_logs WHERE type::text IN ('new_purchase','renew','refund')"),
        scalar(&state, "SELECT COALESCE(SUM(fee_amount), 0)::numeric FROM user_destroy_records"),
    )?;

    let daily_users = bucket_query(&state,
        "SELECT to_char(created_at + interval '8 hours', 'YYYY-MM-DD') AS bucket, COUNT(*)::int::numeric AS value \
         FROM users WHERE created_at >= $1 AND created_at < $2 GROUP BY 1 ORDER BY 1",
        daily_start, daily_end).await?;
    let monthly_users = bucket_query(&state,
        "SELECT to_char(created_at + interval '8 hours', 'YYYY-MM') AS bucket, COUNT(*)::int::numeric AS value \
         FROM users WHERE created_at >= $1 AND created_at < $2 GROUP BY 1 ORDER BY 1",
        monthly_start, monthly_end).await?;
    let daily_instances = bucket_query(&state,
        "SELECT to_char(created_at + interval '8 hours', 'YYYY-MM-DD') AS bucket, COUNT(*)::int::numeric AS value \
         FROM instances WHERE created_at >= $1 AND created_at < $2 GROUP BY 1 ORDER BY 1",
        daily_start, daily_end).await?;
    let monthly_instances = bucket_query(&state,
        "SELECT to_char(created_at + interval '8 hours', 'YYYY-MM') AS bucket, COUNT(*)::int::numeric AS value \
         FROM instances WHERE created_at >= $1 AND created_at < $2 GROUP BY 1 ORDER BY 1",
        monthly_start, monthly_end).await?;
    let daily_recharge = bucket_query(&state,
        "SELECT to_char(COALESCE(completed_at, created_at) + interval '8 hours', 'YYYY-MM-DD') AS bucket, \
                COALESCE(SUM(COALESCE(actual_amount, amount)), 0)::numeric AS value \
         FROM recharge_records WHERE status::text = 'completed' AND COALESCE(completed_at, created_at) >= $1 \
           AND COALESCE(completed_at, created_at) < $2 GROUP BY 1 ORDER BY 1",
        daily_start, daily_end).await?;
    let monthly_recharge = bucket_query(&state,
        "SELECT to_char(COALESCE(completed_at, created_at) + interval '8 hours', 'YYYY-MM') AS bucket, \
                COALESCE(SUM(COALESCE(actual_amount, amount)), 0)::numeric AS value \
         FROM recharge_records WHERE status::text = 'completed' AND COALESCE(completed_at, created_at) >= $1 \
           AND COALESCE(completed_at, created_at) < $2 GROUP BY 1 ORDER BY 1",
        monthly_start, monthly_end).await?;
    let daily_consume = bucket_query(&state,
        "SELECT to_char(created_at + interval '8 hours', 'YYYY-MM-DD') AS bucket, COALESCE(SUM(ABS(amount)), 0)::numeric AS value \
         FROM balance_logs WHERE type::text IN ('consume','hourly_consume','transfer_fee') AND created_at >= $1 AND created_at < $2 GROUP BY 1 ORDER BY 1",
        daily_start, daily_end).await?;
    let monthly_consume = bucket_query(&state,
        "SELECT to_char(created_at + interval '8 hours', 'YYYY-MM') AS bucket, COALESCE(SUM(ABS(amount)), 0)::numeric AS value \
         FROM balance_logs WHERE type::text IN ('consume','hourly_consume','transfer_fee') AND created_at >= $1 AND created_at < $2 GROUP BY 1 ORDER BY 1",
        monthly_start, monthly_end).await?;
    let daily_aff = bucket_query(&state,
        "SELECT to_char(created_at + interval '8 hours', 'YYYY-MM-DD') AS bucket, COALESCE(SUM(amount), 0)::numeric AS value \
         FROM aff_logs WHERE type::text IN ('new_purchase','renew','refund') AND created_at >= $1 AND created_at < $2 GROUP BY 1 ORDER BY 1",
        daily_start, daily_end).await?;
    let monthly_aff = bucket_query(&state,
        "SELECT to_char(created_at + interval '8 hours', 'YYYY-MM') AS bucket, COALESCE(SUM(amount), 0)::numeric AS value \
         FROM aff_logs WHERE type::text IN ('new_purchase','renew','refund') AND created_at >= $1 AND created_at < $2 GROUP BY 1 ORDER BY 1",
        monthly_start, monthly_end).await?;
    let daily_destroy = bucket_query(&state,
        "SELECT to_char(destroyed_at + interval '8 hours', 'YYYY-MM-DD') AS bucket, COALESCE(SUM(fee_amount), 0)::numeric AS value \
         FROM user_destroy_records WHERE destroyed_at >= $1 AND destroyed_at < $2 GROUP BY 1 ORDER BY 1",
        daily_start, daily_end).await?;
    let monthly_destroy = bucket_query(&state,
        "SELECT to_char(destroyed_at + interval '8 hours', 'YYYY-MM') AS bucket, COALESCE(SUM(fee_amount), 0)::numeric AS value \
         FROM user_destroy_records WHERE destroyed_at >= $1 AND destroyed_at < $2 GROUP BY 1 ORDER BY 1",
        monthly_start, monthly_end).await?;

    let result = json!({
        "meta": {
            "timezone": "Asia/Shanghai",
            "dailyDays": DAILY_DAYS,
            "monthlyMonths": MONTHLY_MONTHS,
        },
        "users": {
            "total": total_users,
            "dailyNewUsers": fill_series(&daily_users, &daily_labels, false),
            "monthlyNewUsers": fill_series(&monthly_users, &monthly_labels, false),
        },
        "instances": {
            "total": total_instances,
            "active": active_instances,
            "paid": paid_instances,
            "free": free_instances,
            "dailyCreatedInstances": fill_series(&daily_instances, &daily_labels, false),
            "monthlyCreatedInstances": fill_series(&monthly_instances, &monthly_labels, false),
        },
        "billing": {
            "totals": {
                "recharge": money(total_recharge),
                "consume": money(total_consume),
                "aff": money(total_aff),
                "destroyFee": money(total_destroy_fee),
            },
            "dailyRecharge": fill_series(&daily_recharge, &daily_labels, true),
            "monthlyRecharge": fill_series(&monthly_recharge, &monthly_labels, true),
            "dailyConsume": fill_series(&daily_consume, &daily_labels, true),
            "monthlyConsume": fill_series(&monthly_consume, &monthly_labels, true),
            "dailyAff": fill_series(&daily_aff, &daily_labels, true),
            "monthlyAff": fill_series(&monthly_aff, &monthly_labels, true),
            "dailyDestroyFee": fill_series(&daily_destroy, &daily_labels, true),
            "monthlyDestroyFee": fill_series(&monthly_destroy, &monthly_labels, true),
        },
    });

    *OVERVIEW_CACHE.lock().unwrap() = Some((
        result.clone(),
        std::time::Instant::now() + std::time::Duration::from_secs(60),
    ));
    Ok((StatusCode::OK, Json(result)).into_response())
}

async fn scalar_count(state: &SharedAppState, sql: &str) -> Result<i64, ApiError> {
    let (count,): (i64,) = sqlx::query_as(sql).fetch_one(&state.db).await?;
    Ok(count)
}
