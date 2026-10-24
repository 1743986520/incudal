//! Billing settlement subset used by the host routes.
//! Port of the parts of db/billing-operations.ts / db/billing-records.ts /
//! lib/billing-calc.ts / lib/billing-coupon-match.ts that hosts.ts exercises:
//! refund quotes, max-refundable caps, privileged deletion settlement, hourly
//! deletion completion, and hosted-balance deduction.
//!
//! Money is f64 in the TS layer and Decimal in the DB; this port keeps f64 for
//! the quote math (same rounding via 2dp strings) and Decimal for persisted
//! balances, mirroring the TS Number(decimal) boundaries.
//!
//! All helpers run on `&mut PgConnection`: pool callers acquire a connection
//! first, settlement callers pass their transaction (`&mut *tx`) so the reads
//! stay inside the serializable transaction exactly like the TS.

use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::db::advisory_lock_namespace;
use crate::error::{code, ApiError};

pub const INSTANCE_OPERATION_LOCK: i32 = advisory_lock_namespace::INSTANCE_OPERATION;
pub const USER_BALANCE_LOCK: i32 = advisory_lock_namespace::USER_BALANCE;
pub const HOSTING_BALANCE_LOG_LOCK: i32 = advisory_lock_namespace::HOSTING_BALANCE_LOG;

/// roundCurrency: 2dp, half-away-from-zero like Number(v.toFixed(2)).
pub fn round_currency(value: f64) -> f64 {
    let formatted = format!("{value:.2}");
    formatted.parse::<f64>().unwrap_or(0.0)
}

/// getCycleDays: 1->31, 3->93, 6->186, 12->372, other N->N*31.
pub fn get_cycle_days(billing_cycle: i64) -> i64 {
    match billing_cycle {
        1 => 31,
        3 => 93,
        6 => 186,
        12 => 372,
        other => other * 31,
    }
}

/// calculateRemainingDays: ceil of remaining ms in days, min 0.
pub fn calculate_remaining_days(expires_at_ms: i64, now_ms: i64) -> i64 {
    let remaining_ms = expires_at_ms - now_ms;
    if remaining_ms <= 0 {
        return 0;
    }
    ((remaining_ms + 24 * 60 * 60 * 1000 - 1) / (24 * 60 * 60 * 1000)).max(0)
}

/// calculateRemainingValue: daily price x remaining days, 2dp.
pub fn calculate_remaining_value(
    price: f64,
    billing_cycle: i64,
    remaining_days: i64,
    discount_rate: f64,
) -> f64 {
    let effective_price = if discount_rate > 0.0 {
        round_currency(price * (1.0 - discount_rate))
    } else {
        price
    };
    let daily_price = effective_price / get_cycle_days(billing_cycle) as f64;
    round_currency(daily_price * remaining_days as f64)
}

fn to_f(d: Option<Decimal>) -> f64 {
    d.and_then(|v| rust_decimal::prelude::ToPrimitive::to_f64(&v))
        .unwrap_or(0.0)
}

pub fn dec_from_f64(value: f64) -> Result<Decimal, ApiError> {
    use std::str::FromStr;
    Decimal::from_str(&format!("{value:.2}"))
        .map_err(|_| ApiError::internal("decimal conversion failed"))
}

fn js_integer(v: Option<i64>) -> bool {
    v.is_some()
}

fn same_date(
    a: Option<chrono::DateTime<chrono::Utc>>,
    b: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            let day = |t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%d").to_string();
            day(a) == day(b)
        }
        (None, None) => true,
        _ => false,
    }
}

// ==================== lineage ====================

type LineageSeed = (i32, i32, String, Option<chrono::DateTime<chrono::Utc>>);

async fn lineage_seed(
    conn: &mut sqlx::PgConnection,
    instance_id: i32,
) -> Result<Option<LineageSeed>, ApiError> {
    let row: Option<LineageSeed> =
        sqlx::query_as("SELECT id, user_id, name, expires_at FROM instances WHERE id = $1")
            .bind(instance_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(ApiError::from_sql)?;
    Ok(row)
}

/// getInstanceBillingLineageIds: walk instance_migrated inbox messages to find
/// the pre-migration instance chain, oldest first.
pub async fn get_instance_billing_lineage_ids(
    conn: &mut sqlx::PgConnection,
    instance_id: i32,
) -> Result<Vec<i32>, ApiError> {
    let mut lineage: Vec<i32> = Vec::new();
    let mut visited: std::collections::HashSet<i32> = std::collections::HashSet::new();

    let mut current = lineage_seed(conn, instance_id).await?;
    while let Some((id, user_id, name, expires_at)) = current.clone() {
        if visited.contains(&id) {
            break;
        }
        lineage.insert(0, id);
        visited.insert(id);

        let predecessor =
            resolve_immediate_migrated_billing_source(conn, id, user_id, &name, expires_at).await?;
        match predecessor {
            Some(prev) if !visited.contains(&prev) => {
                current = lineage_seed(conn, prev).await?;
            }
            _ => break,
        }
    }

    if lineage.is_empty() {
        lineage.push(instance_id);
    }
    Ok(lineage)
}

async fn resolve_immediate_migrated_billing_source(
    conn: &mut sqlx::PgConnection,
    seed_id: i32,
    seed_user_id: i32,
    seed_name: &str,
    seed_expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Option<i32>, ApiError> {
    let messages: Vec<(i32, Value, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, data, created_at FROM inbox_messages \
         WHERE user_id = $1 AND event_type = 'instance_migrated' ORDER BY created_at DESC",
    )
    .bind(seed_user_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(ApiError::from_sql)?;

    for (_message_id, data, created_at) in messages {
        let message_instance_id = data.get("instanceId").and_then(Value::as_i64);
        let old_host_id = data.get("oldHostId").and_then(Value::as_i64);
        let new_host_id = data.get("newHostId").and_then(Value::as_i64);

        if !js_integer(message_instance_id) || message_instance_id != Some(seed_id as i64) {
            continue;
        }
        let Some(old_host_id) = old_host_id else {
            continue;
        };
        if js_integer(new_host_id) {
            let seed_host_id: Option<i32> =
                sqlx::query_scalar("SELECT host_id FROM instances WHERE id = $1")
                    .bind(seed_id)
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(ApiError::from_sql)?;
            if let Some(seed_host_id) = seed_host_id {
                if new_host_id != Some(seed_host_id as i64) {
                    continue;
                }
            }
        }

        let expected_name = data
            .get("instanceName")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(seed_name)
            .to_string();
        let window_start = created_at - chrono::Duration::minutes(30);
        let window_end = created_at + chrono::Duration::minutes(30);

        let deleted_candidates: Vec<(i32, Option<chrono::DateTime<chrono::Utc>>)> =
            sqlx::query_as(
                "SELECT id, expires_at FROM instances \
                 WHERE user_id = $1 AND host_id = $2 AND name = $3 AND status = 'deleted' \
                 AND id <> $4 AND updated_at >= $5 AND updated_at <= $6",
            )
            .bind(seed_user_id)
            .bind(old_host_id as i32)
            .bind(&expected_name)
            .bind(seed_id)
            .bind(window_start)
            .bind(window_end)
            .fetch_all(&mut *conn)
            .await
            .map_err(ApiError::from_sql)?;

        if deleted_candidates.is_empty() {
            continue;
        }

        let mut record_counts: Vec<i64> = Vec::new();
        for (candidate_id, _) in &deleted_candidates {
            let count: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM instance_billing_records WHERE instance_id = $1",
            )
            .bind(candidate_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(ApiError::from_sql)?;
            record_counts.push(count.0);
        }

        if deleted_candidates.len() == 1 {
            return Ok(Some(deleted_candidates[0].0));
        }

        let preferred: Vec<usize> = deleted_candidates
            .iter()
            .enumerate()
            .filter(|(_, (_, expires_at))| same_date(*expires_at, seed_expires_at))
            .map(|(i, _)| i)
            .collect();
        if preferred.len() == 1 {
            return Ok(Some(deleted_candidates[preferred[0]].0));
        }

        let with_records: Vec<usize> = (0..deleted_candidates.len())
            .filter(|i| record_counts[*i] > 0)
            .collect();
        if with_records.len() == 1 {
            return Ok(Some(deleted_candidates[with_records[0]].0));
        }

        let final_candidates = if preferred.is_empty() {
            (0..deleted_candidates.len()).collect::<Vec<_>>()
        } else {
            preferred
        };
        if final_candidates.len() == 1 {
            return Ok(Some(deleted_candidates[final_candidates[0]].0));
        }
    }
    Ok(None)
}

// ==================== max refundable ====================

pub struct MaxRefundableInfo {
    pub max_refundable: f64,
    pub last_payment_amount: f64,
}

/// getMaxRefundableForClient: historical consumption minus historical refunds,
/// across the whole billing lineage.
pub async fn get_max_refundable(
    conn: &mut sqlx::PgConnection,
    instance_id: i32,
) -> Result<MaxRefundableInfo, ApiError> {
    let lineage = get_instance_billing_lineage_ids(conn, instance_id).await?;
    let instance_ids = if lineage.is_empty() { vec![instance_id] } else { lineage };

    let (total_consumed,): (Option<Decimal>,) = sqlx::query_as(
        "SELECT COALESCE(SUM(amount), 0) FROM instance_billing_records \
         WHERE instance_id = ANY($1) AND type IN ('newPurchase', 'renew', 'upgrade') AND amount > 0",
    )
    .bind(&instance_ids)
    .fetch_one(&mut *conn)
    .await
    .map_err(ApiError::from_sql)?;

    let refund_rows: Vec<(Option<Decimal>,)> = sqlx::query_as(
        "SELECT amount FROM instance_billing_records \
         WHERE instance_id = ANY($1) AND type = 'refund'",
    )
    .bind(&instance_ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(ApiError::from_sql)?;
    let total_refunded: f64 = refund_rows.iter().map(|(a,)| to_f(*a).abs()).sum();

    let last_payment: Option<(Option<Decimal>,)> = sqlx::query_as(
        "SELECT amount FROM instance_billing_records \
         WHERE instance_id = ANY($1) AND type IN ('newPurchase', 'renew') AND amount > 0 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&instance_ids)
    .fetch_optional(&mut *conn)
    .await
    .map_err(ApiError::from_sql)?;

    Ok(MaxRefundableInfo {
        max_refundable: round_currency((to_f(total_consumed) - total_refunded).max(0.0)),
        last_payment_amount: to_f(last_payment.and_then(|(a,)| a)),
    })
}

// ==================== coupon match + value breakdown ====================

/// matchCouponUsagesToBillingRecords: nearest-created-time pairing of coupon
/// usages to paid billing records with identical paid-cent amounts.
fn match_coupon_usages_to_billing_records(
    records: &[(String, f64, i64)],
    usages: &[(String, f64, f64, i64)],
) -> std::collections::HashMap<usize, usize> {
    struct Candidate {
        record_index: usize,
        usage_index: usize,
        distance: i64,
    }
    let mut candidates: Vec<Candidate> = Vec::new();

    for (record_index, (record_type, amount, created_at)) in records.iter().enumerate() {
        let usage_type = match record_type.as_str() {
            "newPurchase" => "purchase",
            "renew" => "renewal",
            _ => continue,
        };
        for (usage_index, (utype, original_price, discount_amount, usage_created_at)) in
            usages.iter().enumerate()
        {
            if utype != usage_type {
                continue;
            }
            let paid_cents = ((original_price - discount_amount) * 100.0).round() as i64;
            if paid_cents != (amount * 100.0).round() as i64 {
                continue;
            }
            candidates.push(Candidate {
                record_index,
                usage_index,
                distance: (created_at - usage_created_at).abs(),
            });
        }
    }

    candidates.sort_by(|a, b| {
        a.distance
            .cmp(&b.distance)
            .then(a.record_index.cmp(&b.record_index))
            .then(a.usage_index.cmp(&b.usage_index))
    });

    let mut matched = std::collections::HashMap::new();
    let mut used_usages = std::collections::HashSet::new();
    for candidate in candidates {
        if matched.contains_key(&candidate.record_index)
            || used_usages.contains(&candidate.usage_index)
        {
            continue;
        }
        matched.insert(candidate.record_index, candidate.usage_index);
        used_usages.insert(candidate.usage_index);
    }
    matched
}

pub struct BillingValueBreakdown {
    pub has_positive_billing_records: bool,
    pub total_user_value: f64,
    pub total_hosted_value: f64,
    pub remaining_user_value: f64,
    pub remaining_hosted_value: f64,
}

/// getBillingValueBreakdownForClient: net remaining user/hosted service value
/// across the billing lineage, with refunds FIFO-allocated and official coupon
/// original-price subsidy included in the hosted value.
pub async fn get_billing_value_breakdown(
    conn: &mut sqlx::PgConnection,
    instance_id: i32,
) -> Result<BillingValueBreakdown, ApiError> {
    let lineage = get_instance_billing_lineage_ids(conn, instance_id).await?;
    let instance_ids = if lineage.is_empty() { vec![instance_id] } else { lineage };

    let billing_records: Vec<(String, Option<Decimal>, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT type::text AS type, amount, period_start, period_end, created_at \
             FROM instance_billing_records \
             WHERE instance_id = ANY($1) AND type IN ('newPurchase', 'renew', 'upgrade') AND amount > 0 \
             ORDER BY period_start ASC, created_at ASC",
        )
        .bind(&instance_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(ApiError::from_sql)?;

    let refund_rows: Vec<(Option<Decimal>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT amount, created_at FROM instance_billing_records \
         WHERE instance_id = ANY($1) AND type = 'refund' AND amount < 0 ORDER BY created_at ASC",
    )
    .bind(&instance_ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(ApiError::from_sql)?;

    let coupon_usages: Vec<(String, Option<Decimal>, Option<Decimal>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT type::text AS type, original_price, discount_amount, created_at \
             FROM official_coupon_usages WHERE instance_id = ANY($1) \
             ORDER BY created_at ASC, id ASC",
        )
        .bind(&instance_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(ApiError::from_sql)?;

    let records: Vec<(String, f64, i64)> = billing_records
        .iter()
        .map(|(t, amount, _, _, created)| {
            (t.clone(), to_f(*amount).max(0.0), created.timestamp_millis())
        })
        .collect();
    let usages: Vec<(String, f64, f64, i64)> = coupon_usages
        .iter()
        .map(|(t, o, d, c)| (t.clone(), to_f(*o), to_f(*d), c.timestamp_millis()))
        .collect();
    let usage_matches = match_coupon_usages_to_billing_records(&records, &usages);

    struct PeriodValue {
        user_amount: f64,
        hosted_amount: f64,
        net_user_amount: f64,
        net_hosted_amount: f64,
        period_start: i64,
        period_end: i64,
    }

    let mut values: Vec<PeriodValue> = billing_records
        .iter()
        .enumerate()
        .map(|(record_index, (_, amount, period_start, period_end, _))| {
            let user_amount = to_f(*amount).max(0.0);
            let usage_index = usage_matches.get(&record_index).copied();
            let coupon_usage = usage_index.map(|i| &coupon_usages[i]);
            let original_price = coupon_usage
                .map(|(_, o, _, _)| to_f(*o))
                .unwrap_or(user_amount);
            let hosted_amount = if original_price.is_finite() && original_price > 0.0 {
                original_price
            } else {
                user_amount
            };
            PeriodValue {
                user_amount,
                hosted_amount,
                net_user_amount: user_amount,
                net_hosted_amount: hosted_amount,
                period_start: period_start.map(|d| d.timestamp_millis()).unwrap_or(0),
                period_end: period_end.map(|d| d.timestamp_millis()).unwrap_or(0),
            }
        })
        .collect();

    let mut remaining_refund: f64 = refund_rows
        .iter()
        .map(|(a, _)| to_f(*a).abs())
        .filter(|v| v.is_finite())
        .sum();
    for value in values.iter_mut() {
        if remaining_refund <= 0.0 {
            break;
        }
        let refunded_user_amount = value.net_user_amount.min(remaining_refund);
        value.net_user_amount = (value.net_user_amount - refunded_user_amount).max(0.0);
        value.net_hosted_amount = if value.user_amount > 0.0 {
            value.hosted_amount * (value.net_user_amount / value.user_amount)
        } else {
            0.0
        };
        remaining_refund -= refunded_user_amount;
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut total_user_value = 0.0f64;
    let mut total_hosted_value = 0.0f64;
    let mut remaining_user_value = 0.0f64;
    let mut remaining_hosted_value = 0.0f64;

    for value in &values {
        total_user_value += value.net_user_amount;
        total_hosted_value += value.net_hosted_amount;

        let total_ms = value.period_end - value.period_start;
        if total_ms <= 0 || value.period_end <= now_ms {
            continue;
        }
        let remaining_ratio =
            ((value.period_end - now_ms).max(0) as f64 / total_ms as f64).min(1.0);
        remaining_user_value += value.net_user_amount * remaining_ratio;
        remaining_hosted_value += value.net_hosted_amount * remaining_ratio;
    }

    Ok(BillingValueBreakdown {
        has_positive_billing_records: !values.is_empty(),
        total_user_value: round_currency(total_user_value),
        total_hosted_value: round_currency(total_hosted_value),
        remaining_user_value: round_currency(remaining_user_value),
        remaining_hosted_value: round_currency(remaining_hosted_value),
    })
}

// ==================== refund quote ====================

pub struct InstanceRefundQuote {
    pub remaining_days: i64,
    pub remaining_value: f64,
    pub refundable_value: f64,
    pub max_refundable: f64,
    pub is_paid: bool,
}

/// calculateInstanceRemainingRefundQuote. `instance` =
/// (id, billing_price, billing_cycle, expires_at).
pub async fn calculate_instance_remaining_refund_quote(
    conn: &mut sqlx::PgConnection,
    instance: (i32, Option<Decimal>, Option<i32>, Option<chrono::DateTime<chrono::Utc>>),
) -> Result<InstanceRefundQuote, ApiError> {
    let (id, billing_price, billing_cycle, expires_at) = instance;
    let is_paid = billing_price.is_some() && expires_at.is_some() && billing_cycle.is_some();

    if !is_paid {
        return Ok(InstanceRefundQuote {
            remaining_days: 0,
            remaining_value: 0.0,
            refundable_value: 0.0,
            max_refundable: 0.0,
            is_paid: false,
        });
    }

    let now = chrono::Utc::now();
    let expires_at = expires_at.unwrap_or(now);
    if expires_at <= now {
        return Ok(InstanceRefundQuote {
            remaining_days: 0,
            remaining_value: 0.0,
            refundable_value: 0.0,
            max_refundable: 0.0,
            is_paid: true,
        });
    }

    let remaining_days =
        calculate_remaining_days(expires_at.timestamp_millis(), now.timestamp_millis());
    let max_info = get_max_refundable(conn, id).await?;
    let breakdown = get_billing_value_breakdown(conn, id).await?;

    let price_f = to_f(billing_price);
    let cycle = billing_cycle.unwrap_or(1) as i64;

    let mut remaining_value = breakdown.remaining_user_value;

    // Fallback for instances without positive billing records: daily-price
    // proration on billingPrice with the AFF discount rate.
    if !breakdown.has_positive_billing_records && billing_price.is_some() && billing_cycle.is_some()
    {
        let binding: Option<(Option<Decimal>, Option<bool>)> = sqlx::query_as(
            "SELECT ac.discount_rate, ac.enabled FROM aff_bindings ab \
             JOIN aff_codes ac ON ac.id = ab.aff_code_id WHERE ab.instance_id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(ApiError::from_sql)?;
        let discount_rate = binding
            .and_then(|(rate, enabled)| {
                if enabled.unwrap_or(false) {
                    Some(to_f(rate))
                } else {
                    None
                }
            })
            .unwrap_or(0.0);

        remaining_value = calculate_remaining_value(price_f, cycle, remaining_days, discount_rate);
    }

    let refundable_value = round_currency(remaining_value.min(max_info.max_refundable));
    Ok(InstanceRefundQuote {
        remaining_days,
        remaining_value: round_currency(remaining_value),
        refundable_value,
        max_refundable: max_info.max_refundable,
        is_paid: true,
    })
}

/// calculateInstanceRefund (host-owner deletion: no fee).
pub async fn calculate_instance_refund(
    conn: &mut sqlx::PgConnection,
    instance: (i32, Option<Decimal>, Option<i32>, Option<chrono::DateTime<chrono::Utc>>),
) -> Result<InstanceRefundQuote, ApiError> {
    calculate_instance_remaining_refund_quote(conn, instance).await
}

// ==================== hosted balance deduction ====================

struct HostedIncomeOwner {
    user_id: i32,
    #[allow(dead_code)]
    host_name: String,
}

/// resolveHostedIncomeOwner with allowHistoricalFallback.
async fn resolve_hosted_income_owner(
    conn: &mut sqlx::PgConnection,
    host_id: i32,
    instance_id: i32,
) -> Result<Option<HostedIncomeOwner>, ApiError> {
    let row: Option<(i32, String, String)> = sqlx::query_as(
        "SELECT h.user_id, h.name, u.role::text AS role \
         FROM hosts h JOIN users u ON u.id = h.user_id WHERE h.id = $1",
    )
    .bind(host_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(ApiError::from_sql)?;

    let Some((user_id, host_name, role)) = row else {
        return Ok(None);
    };
    if role != "admin" {
        return Ok(Some(HostedIncomeOwner { user_id, host_name }));
    }

    let latest: Option<i32> = sqlx::query_scalar(
        "SELECT user_id FROM hosting_balance_logs \
         WHERE related_id = $1 AND type = 'income' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(instance_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(ApiError::from_sql)?;

    let Some(historical_owner) = latest else {
        return Ok(None);
    };
    let name: Option<String> =
        sqlx::query_scalar("SELECT name FROM hosts WHERE user_id = $1 ORDER BY id LIMIT 1")
            .bind(historical_owner)
            .fetch_optional(&mut *conn)
            .await
            .map_err(ApiError::from_sql)?;
    Ok(Some(HostedIncomeOwner {
        user_id: historical_owner,
        host_name: name.unwrap_or_default(),
    }))
}

/// createHostingLogWithSnapshot.
async fn create_hosting_log_with_snapshot(
    conn: &mut sqlx::PgConnection,
    user_id: i32,
    action_type: &str,
    amount: f64,
    instance_id: i32,
    frozen: bool,
    remark: &str,
) -> Result<(), ApiError> {
    let row: Option<(Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT u.username, u.email, u.avatar_style, i.name, h.name, p.name, pp.name \
             FROM instances i \
             LEFT JOIN users u ON u.id = i.user_id \
             LEFT JOIN hosts h ON h.id = i.host_id \
             LEFT JOIN packages p ON p.id = i.package_id \
             LEFT JOIN package_plans pp ON pp.id = i.package_plan_id \
             WHERE i.id = $1",
        )
        .bind(instance_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(ApiError::from_sql)?;

    let (buyer_name, buyer_email, buyer_avatar, inst_name, host_name, package_name, plan_name) =
        row.unwrap_or((None, None, None, None, None, None, None));

    sqlx::query(
        "INSERT INTO hosting_balance_logs \
         (user_id, type, action_type, amount, frozen, unfreeze_at, related_id, remark, \
          snapshot_buyer_name, snapshot_buyer_email, snapshot_buyer_avatar, \
          snapshot_instance_name, snapshot_host_name, snapshot_package_name, snapshot_plan_name) \
         VALUES ($1, 'deduction'::\"HostingBalanceType\", $2::\"HostingActionType\", $3, $4, NULL, $5, $6, \
                 $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(user_id)
    .bind(action_type)
    .bind(dec_from_f64(amount)?)
    .bind(frozen)
    .bind(instance_id)
    .bind(remark)
    .bind(buyer_name)
    .bind(buyer_email)
    .bind(buyer_avatar)
    .bind(inst_name)
    .bind(host_name)
    .bind(package_name)
    .bind(plan_name)
    .execute(&mut *conn)
    .await
    .map_err(ApiError::from_sql)?;
    Ok(())
}

pub struct HostingBalanceDeduction {
    #[allow(dead_code)]
    pub host_owner_id: i32,
    pub deducted_amount: f64,
}

/// deductHostingBalance: frozen income first, then hosting balance, then panel
/// balance, with a `deduction` audit log when anything was deducted.
pub async fn deduct_hosting_balance(
    conn: &mut sqlx::PgConnection,
    host_id: i32,
    amount: f64,
    instance_id: i32,
    remark: &str,
) -> Result<Option<HostingBalanceDeduction>, ApiError> {
    let Some(owner) = resolve_hosted_income_owner(conn, host_id, instance_id).await? else {
        return Ok(None);
    };
    let host_owner_id = owner.user_id;

    // Lock the hosting balance ledger for this owner (busy -> surface error,
    // the TS throws '托管余额正在处理，请稍后重试'). Transaction-scoped like TS
    // tryAdvisoryTransactionLock.
    let locked: (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1::int, $2::bigint)")
        .bind(HOSTING_BALANCE_LOG_LOCK)
        .bind(host_owner_id as i64)
        .fetch_one(&mut *conn)
        .await
        .map_err(ApiError::from_sql)?;
    if !locked.0 {
        return Err(ApiError::with_message(
            code::RESOURCE_BUSY,
            axum::http::StatusCode::CONFLICT,
            "托管余额正在处理，请稍后重试",
        ));
    }

    let mut remaining = amount;
    let mut from_frozen = 0.0f64;
    let mut from_available = 0.0f64;
    let mut from_balance = 0.0f64;

    // Step 1: deduct from frozen income logs (FIFO).
    let frozen_logs: Vec<(i32, Decimal)> = sqlx::query_as(
        "SELECT id, amount FROM hosting_balance_logs \
         WHERE user_id = $1 AND related_id = $2 AND type = 'income' AND frozen = true \
         ORDER BY created_at ASC",
    )
    .bind(host_owner_id)
    .bind(instance_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(ApiError::from_sql)?;

    for (log_id, log_amount) in frozen_logs {
        if remaining <= 0.0 {
            break;
        }
        let log_amount_f = to_f(Some(log_amount));
        let deduct = log_amount_f.min(remaining);
        if deduct >= log_amount_f {
            sqlx::query("DELETE FROM hosting_balance_logs WHERE id = $1")
                .bind(log_id)
                .execute(&mut *conn)
                .await
                .map_err(ApiError::from_sql)?;
        } else {
            sqlx::query("UPDATE hosting_balance_logs SET amount = amount - $2 WHERE id = $1")
                .bind(log_id)
                .bind(dec_from_f64(deduct)?)
                .execute(&mut *conn)
                .await
                .map_err(ApiError::from_sql)?;
        }
        from_frozen += deduct;
        remaining -= deduct;
    }

    // Step 2: hosting balance.
    if remaining > 0.0 {
        let available: Option<(Option<Decimal>,)> = sqlx::query_as(
            "SELECT hosting_balance FROM users WHERE id = $1",
        )
        .bind(host_owner_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(ApiError::from_sql)?;
        let available_f = to_f(available.and_then(|(b,)| b));
        let deduct = available_f.min(remaining);
        if deduct > 0.0 {
            let updated = sqlx::query(
                "UPDATE users SET hosting_balance = hosting_balance - $2 \
                 WHERE id = $1 AND hosting_balance >= $2",
            )
            .bind(host_owner_id)
            .bind(dec_from_f64(deduct)?)
            .execute(&mut *conn)
            .await
            .map_err(ApiError::from_sql)?;
            if updated.rows_affected() == 1 {
                from_available = deduct;
                remaining -= deduct;
            }
        }

        // Step 3: panel balance.
        if remaining > 0.0 {
            let current: Option<(Option<Decimal>,)> =
                sqlx::query_as("SELECT balance FROM users WHERE id = $1")
                    .bind(host_owner_id)
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(ApiError::from_sql)?;
            let available_balance = to_f(current.and_then(|(b,)| b));
            let deduct = available_balance.min(remaining);
            if deduct > 0.0 {
                let updated: Option<(Decimal,)> = sqlx::query_as(
                    "UPDATE users SET balance = balance - $2 WHERE id = $1 AND balance >= $2 \
                     RETURNING balance",
                )
                .bind(host_owner_id)
                .bind(dec_from_f64(deduct)?)
                .fetch_optional(&mut *conn)
                .await
                .map_err(ApiError::from_sql)?;
                if let Some((balance_after,)) = updated {
                    let balance_after_f = to_f(Some(balance_after));
                    let balance_before = round_currency(balance_after_f + deduct);
                    sqlx::query(
                        "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, instance_id, remark) \
                         VALUES ($1, 'hosting_deduction'::\"BalanceLogType\", $2, $3, $4, $5, '托管实例销毁扣款：用户退款需从面板余额补扣')",
                    )
                    .bind(host_owner_id)
                    .bind(dec_from_f64(-deduct)?)
                    .bind(dec_from_f64(balance_before)?)
                    .bind(dec_from_f64(balance_after_f)?)
                    .bind(instance_id)
                    .execute(&mut *conn)
                    .await
                    .map_err(ApiError::from_sql)?;
                    from_balance = deduct;
                    remaining -= deduct;
                } else {
                    tracing::warn!(
                        "[HostingBalance] 面板余额并发变化，跳过本次补扣: hostOwnerId={host_owner_id}, instanceId={instance_id}"
                    );
                }
            }
        }
    }

    let total_deducted = from_frozen + from_available + from_balance;
    if total_deducted > 0.0 {
        let mut parts: Vec<String> = Vec::new();
        if from_frozen > 0.0 {
            parts.push(format!("冻结抵扣 ¥{from_frozen:.2}"));
        }
        if from_available > 0.0 {
            parts.push(format!("托管余额扣除 ¥{from_available:.2}"));
        }
        if from_balance > 0.0 {
            parts.push(format!("面板余额补扣 ¥{from_balance:.2}"));
        }
        create_hosting_log_with_snapshot(
            conn,
            host_owner_id,
            "destroy",
            -total_deducted,
            instance_id,
            false,
            &format!("{remark}（{}）", parts.join("，")),
        )
        .await?;
    }

    Ok(Some(HostingBalanceDeduction {
        host_owner_id,
        deducted_amount: total_deducted,
    }))
}

// ==================== privileged deletion settlement ====================

/// calculateHostedRefundAmountForClient (allowHistorical default true).
async fn calculate_hosted_refund_amount(
    conn: &mut sqlx::PgConnection,
    instance_id: i32,
    requested_user_refund: f64,
) -> Result<f64, ApiError> {
    if !requested_user_refund.is_finite() || requested_user_refund <= 0.0 {
        return Ok(0.0);
    }
    let breakdown = get_billing_value_breakdown(conn, instance_id).await?;
    if !breakdown.has_positive_billing_records {
        return Ok(round_currency(requested_user_refund));
    }
    let use_historical = breakdown.remaining_user_value <= 0.0
        || requested_user_refund > breakdown.remaining_user_value;
    let (base_user, base_hosted) = if use_historical {
        (breakdown.total_user_value, breakdown.total_hosted_value)
    } else {
        (
            breakdown.remaining_user_value,
            breakdown.remaining_hosted_value,
        )
    };
    if base_user <= 0.0 || base_hosted <= 0.0 {
        return Ok(0.0);
    }
    let ratio = (requested_user_refund / base_user).clamp(0.0, 1.0);
    Ok(round_currency(base_hosted * ratio))
}

/// settlePrivilegedDeletionBilling: refund capped by lineage-max, plus hosted
/// income clawback. Serializable transaction like the TS $transaction.
pub async fn settle_privileged_deletion_billing(
    pool: &PgPool,
    instance_id: i32,
    instance_user_id: i32,
    instance_host_id: i32,
    instance_name: &str,
    requested_refund_amount: f64,
    remark: &str,
) -> Result<f64, ApiError> {
    let mut tx = pool.begin().await.map_err(ApiError::from_sql)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
    crate::db::advisory_transaction_lock(&mut tx, INSTANCE_OPERATION_LOCK, instance_id as i64)
        .await
        .map_err(ApiError::from_sql)?;
    crate::db::advisory_transaction_lock(&mut tx, USER_BALANCE_LOCK, instance_user_id as i64)
        .await
        .map_err(ApiError::from_sql)?;

    let deletion_state: Option<(bool,)> =
        sqlx::query_as("SELECT deletion_remote_deleted FROM instances WHERE id = $1")
            .bind(instance_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;
    match deletion_state {
        Some((true,)) => {}
        _ => {
            return Err(ApiError::with_message(
                code::INTERNAL_ERROR,
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "REMOTE_DELETION_NOT_CONFIRMED",
            ))
        }
    }

    let max_info = get_max_refundable(&mut tx, instance_id).await?;
    let refund_amount = round_currency(requested_refund_amount.clamp(0.0, max_info.max_refundable));
    let hosted_refund_amount = if refund_amount > 0.0 {
        calculate_hosted_refund_amount(&mut tx, instance_id, refund_amount).await?
    } else {
        0.0
    };

    if refund_amount > 0.0 {
        let current: Option<(Decimal,)> =
            sqlx::query_as("SELECT balance FROM users WHERE id = $1")
                .bind(instance_user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(ApiError::from_sql)?;
        let Some((balance,)) = current else {
            return Err(ApiError::internal(format!(
                "User {instance_user_id} not found during privileged deletion refund"
            )));
        };
        let old_balance = to_f(Some(balance));
        let new_balance = round_currency(old_balance + refund_amount);
        sqlx::query("UPDATE users SET balance = balance + $2 WHERE id = $1")
            .bind(instance_user_id)
            .bind(dec_from_f64(refund_amount)?)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::from_sql)?;

        let log: (i32,) = sqlx::query_as(
            "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, instance_id, remark) \
             VALUES ($1, 'refund'::\"BalanceLogType\", $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(instance_user_id)
        .bind(dec_from_f64(refund_amount)?)
        .bind(dec_from_f64(old_balance)?)
        .bind(dec_from_f64(new_balance)?)
        .bind(instance_id)
        .bind(remark)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;

        sqlx::query(
            "INSERT INTO instance_billing_records \
             (instance_id, user_id, type, amount, months, period_start, period_end, balance_log_id, remark) \
             VALUES ($1, $2, 'refund'::\"BillingRecordType\", $3, 0, now(), now(), $4, $5)",
        )
        .bind(instance_id)
        .bind(instance_user_id)
        .bind(dec_from_f64(-refund_amount)?)
        .bind(log.0)
        .bind(remark)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;

        deduct_hosting_balance(
            &mut tx,
            instance_host_id,
            hosted_refund_amount,
            instance_id,
            &format!("删除托管实例退款扣除：{instance_name}"),
        )
        .await?;
    }

    sqlx::query(
        "UPDATE instances SET deletion_billing_pending = false, deletion_remote_deleted = true, \
         deletion_billing_mode = NULL, deletion_refundable_value = NULL, deletion_fee_waiver = false \
         WHERE id = $1",
    )
    .bind(instance_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;

    tx.commit().await.map_err(ApiError::from_sql)?;
    Ok(refund_amount)
}

/// completeHourlyDeletionBilling: finalize the deletion marker after the
/// hourly account close.
pub async fn complete_hourly_deletion_billing(
    pool: &PgPool,
    instance_id: i32,
) -> Result<(), ApiError> {
    let mut tx = pool.begin().await.map_err(ApiError::from_sql)?;
    crate::db::advisory_transaction_lock(&mut tx, INSTANCE_OPERATION_LOCK, instance_id as i64)
        .await
        .map_err(ApiError::from_sql)?;

    let state: Option<(bool, bool, Option<String>)> = sqlx::query_as(
        "SELECT deletion_billing_pending, deletion_remote_deleted, deletion_billing_mode \
         FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;

    let Some((pending, remote_deleted, mode)) = state else {
        return Ok(());
    };
    if !pending {
        return Ok(());
    }
    if !remote_deleted {
        return Err(ApiError::with_message(
            code::INTERNAL_ERROR,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "REMOTE_DELETION_NOT_CONFIRMED",
        ));
    }
    if mode.as_deref() != Some("hourly_close") {
        return Err(ApiError::with_message(
            code::INTERNAL_ERROR,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "INVALID_HOURLY_DELETION_BILLING_MODE",
        ));
    }

    sqlx::query(
        "UPDATE instances SET deletion_billing_pending = false, deletion_remote_deleted = true, \
         deletion_billing_mode = NULL, deletion_refundable_value = NULL, deletion_fee_waiver = false \
         WHERE id = $1",
    )
    .bind(instance_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from_sql)?;
    tx.commit().await.map_err(ApiError::from_sql)?;
    Ok(())
}

// ==================== create billing ====================

pub struct CreateBillingResult {
    pub price: f64,
    pub billing_cycle: i64,
    pub setup_fee: f64,
    pub total_price: f64,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// calculateCreateBilling: plan price is stored in cents; no setup fee.
/// `plan` = (price, billing_cycle).
pub fn calculate_create_billing(
    plan: (Decimal, i32),
    now: chrono::DateTime<chrono::Utc>,
) -> Result<CreateBillingResult, ApiError> {
    let (price, billing_cycle) = plan;
    let price_f = rust_decimal::prelude::ToPrimitive::to_f64(&price).unwrap_or(0.0) / 100.0;
    let expires_at = add_months(now, billing_cycle as i64);
    Ok(CreateBillingResult {
        price: price_f,
        billing_cycle: billing_cycle as i64,
        setup_fee: 0.0,
        total_price: price_f,
        expires_at,
    })
}

/// JS addMonths semantics used by billing (day-of-month clamping).
pub fn add_months(from: chrono::DateTime<chrono::Utc>, months: i64) -> chrono::DateTime<chrono::Utc> {
    use chrono::Timelike;
    use chrono::Datelike;
    let mut year = from.year() as i64;
    let mut month = from.month() as i64 + months;
    while month > 12 {
        month -= 12;
        year += 1;
    }
    while month < 1 {
        month += 12;
        year -= 1;
    }
    let day = from.day();
    let days = days_in_month(year, month);
    let day = day.min(days);
    chrono::NaiveDate::from_ymd_opt(year as i32, month as u32, day)
        .and_then(|d| d.and_hms_opt(from.hour(), from.minute(), from.second()))
        .map(|d| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(d, chrono::Utc))
        .unwrap_or(from)
}

fn days_in_month(year: i64, month: i64) -> u32 {
    let next_month = if month == 12 { 1 } else { month + 1 };
    let next_year = if month == 12 { year + 1 } else { year };
    let last_of_month =
        chrono::NaiveDate::from_ymd_opt(next_year as i32, next_month as u32, 1)
            .expect("valid date")
            .pred_opt()
            .expect("valid date");
    chrono::Datelike::day(&last_of_month)
}
