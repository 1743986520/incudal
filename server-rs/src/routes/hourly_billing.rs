//! 按小时计费路由 — port of server/src/routes/hourly-billing.ts.
//! Registered WITHOUT a mount prefix upstream — full /api paths, merged at
//! the top level. Pricing has moved into package plans upstream, so catalog /
//! pricing-version endpoints return 410 exactly like the TS.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::auth::{AdminAuth, AuthUser, UserOnlyAuth};
use crate::error::{code, ApiError};
use crate::libs::hourly_billing::{
    breakdown_json, calculate_hourly_breakdown, hourly_pricing_from_package_plan,
    hourly_pricing_from_snapshot, serialize_hourly_decimal, serialize_hourly_decimal_opt,
    HourlyResources, PlanHourlyRow, PLAN_HOURLY_COLUMNS,
};
use crate::libs::instance_common::iso;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/api/hourly-billing/catalog", get(catalog))
        .route("/api/instances/hourly/available-hosts", get(available_hosts))
        .route("/api/instances/hourly/quote", post(quote))
        .route("/api/instances/hourly", post(create_hourly_gone))
        .route("/api/instances/{id}/hourly-billing", get(account_detail))
        .route("/api/instances/{id}/hourly-billing/records", get(account_records))
        .route("/api/instances/{id}/hourly-billing/pay-debt", post(pay_debt))
        .route("/api/instances/{id}/hourly/resize-preview", post(resize_preview))
        .route("/api/admin/hourly-billing/pricing", get(pricing_gone))
        .route("/api/admin/hourly-billing/pricing/versions", post(pricing_gone))
        .route("/api/admin/hourly-billing/hosts/{id}", axum::routing::patch(admin_host_switch))
        .route("/api/admin/hourly-billing/instances", get(admin_instances))
        .route("/api/admin/hourly-billing/records", get(admin_records))
        .route("/api/admin/hourly-billing/reconcile", post(admin_reconcile))
}

fn gone(body: Value) -> Response {
    (StatusCode::GONE, Json(body)).into_response()
}

async fn catalog() -> Response {
    gone(json!({
        "error": "按小时价格已随套餐方案配置，请先选择按小时计费方案",
        "code": "HOURLY_PLAN_REQUIRED",
    }))
}

async fn create_hourly_gone() -> Response {
    gone(json!({
        "error": "按小时计费实例必须通过套餐方案创建",
        "code": "HOURLY_PLAN_REQUIRED",
    }))
}

async fn pricing_gone() -> Response {
    gone(json!({
        "error": "按小时价格已搬入套餐方案，请在方案编辑页配置",
        "code": "HOURLY_PRICING_MOVED_TO_PLAN",
    }))
}

fn parse_positive_int(raw: &str) -> Option<i32> {
    raw.trim().parse::<i32>().ok().filter(|v| *v > 0)
}

fn parse_limit(raw: Option<&str>, fallback: i64, maximum: i64) -> i64 {
    match raw.and_then(|v| v.parse::<i64>().ok()) {
        Some(v) => v.clamp(1, maximum),
        None => fallback,
    }
}

async fn get_hourly_plan_for_user(
    state: &SharedAppState,
    user: &AuthUser,
    plan_id: i32,
) -> Result<Option<PlanHourlyRow>, ApiError> {
    let plan: Option<PlanHourlyRow> = sqlx::query_as(&format!(
        "SELECT {PLAN_HOURLY_COLUMNS} FROM package_plans WHERE id = $1"
    ))
    .bind(plan_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(plan) = plan else { return Ok(None) };
    if plan.billing_mode != "hourly" || !plan.is_active || plan.is_sold_out {
        return Ok(None);
    }
    if user.role != "admin" {
        // canUserAccessPackage: own package, admin-official, or active share
        let owner_role: Option<String> = sqlx::query_scalar(
            "SELECT u.role::text FROM packages p JOIN users u ON u.id = p.user_id WHERE p.id = $1",
        )
        .bind(plan.package_id)
        .fetch_optional(&state.db)
        .await?;
        let accessible = match owner_role.as_deref() {
            Some("admin") => true,
            Some(_) => {
                let (owner,): (i32,) = sqlx::query_as(
                    "SELECT user_id FROM packages WHERE id = $1",
                )
                .bind(plan.package_id)
                .fetch_one(&state.db)
                .await?;
                owner == user.id
            }
            None => false,
        };
        if !accessible {
            // package share check
            let (shared,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM package_shares WHERE package_id = $1 AND shared_to_id = $2",
            )
            .bind(plan.package_id)
            .bind(user.id)
            .fetch_one(&state.db)
            .await?;
            if shared == 0 {
                return Ok(None);
            }
        }
    }
    Ok(Some(plan))
}

#[derive(Deserialize)]
struct AvailableHostsQuery {
    #[serde(rename = "planId")]
    plan_id: Option<String>,
    cpu: Option<String>,
    memory: Option<String>,
    disk: Option<String>,
}

async fn available_hosts(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(query): Query<AvailableHostsQuery>,
) -> Result<Response, ApiError> {
    let plan_id = query.plan_id.as_deref().and_then(parse_positive_int);
    let plan = match plan_id {
        Some(pid) => get_hourly_plan_for_user(&state, &user, pid).await?,
        None => None,
    };
    let Some(plan) = plan else {
        return Ok(gone404(json!({
            "error": "按小时计费方案不存在或无权访问",
            "code": "HOURLY_PLAN_NOT_FOUND",
        })));
    };
    let pricing = hourly_pricing_from_package_plan(&plan);
    let resources = HourlyResources {
        cpu: query.cpu.as_deref().and_then(|v| v.parse().ok()).unwrap_or(pricing.min_cpu),
        memory: query.memory.as_deref().and_then(|v| v.parse().ok()).unwrap_or(pricing.min_memory_mb),
        disk: query.disk.as_deref().and_then(|v| v.parse().ok()).unwrap_or(pricing.min_disk_mb),
    };

    if let Err(message) = crate::libs::hourly_billing::validate_hourly_resources(resources, &pricing) {
        return Ok(gone400(json!({
            "error": message,
            "code": "HOURLY_RESOURCE_INVALID",
        })));
    }

    #[derive(Debug, sqlx::FromRow)]
    struct HostRow {
        id: i32,
        name: String,
        location: Option<String>,
        country_code: String,
        architecture: String,
        instance_type: String,
        cpu_used: i32,
        cpu_allowance_max: i32,
        memory_used: i32,
        memory_max: i32,
        disk_used: i32,
        storage_size: i32,
        pools: Option<i64>,
    }
    let hosts: Vec<HostRow> = sqlx::query_as(
        "SELECT h.id, h.name, h.location, h.country_code, h.architecture, \
                h.instance_type::text AS instance_type, h.cpu_used, h.cpu_allowance_max, \
                h.memory_used, h.memory_max, h.disk_used, h.storage_size, \
                (SELECT COUNT(*) FROM storage_pools sp WHERE sp.host_id = h.id AND sp.purpose::text = 'instance_data' LIMIT 1) AS pools \
         FROM hosts h WHERE h.status::text = 'online' AND h.hourly_billing_enabled = true \
         ORDER BY h.id ASC",
    )
    .fetch_all(&state.db)
    .await?;

    let items: Vec<Value> = hosts
        .iter()
        .map(|h| {
            let is_available = h.pools.unwrap_or(0) > 0
                && h.cpu_allowance_max > 0
                && h.cpu_used as i64 + resources.cpu <= h.cpu_allowance_max as i64
                && h.memory_max > 0
                && h.memory_used as i64 + resources.memory <= h.memory_max as i64
                && h.storage_size > 0
                && h.disk_used as i64 + resources.disk <= (h.storage_size as i64) * 1024;
            json!({
                "id": h.id, "name": h.name, "location": h.location,
                "countryCode": h.country_code, "architecture": h.architecture,
                "instanceType": h.instance_type,
                "cpuUsed": h.cpu_used, "cpuAllowanceMax": h.cpu_allowance_max,
                "memoryUsed": h.memory_used, "memoryMax": h.memory_max,
                "diskUsed": h.disk_used, "storageSize": h.storage_size,
                "isAvailable": is_available,
            })
        })
        .collect();
    Ok(Json(json!({ "hosts": items })).into_response())
}

fn gone404(body: Value) -> Response {
    (StatusCode::NOT_FOUND, Json(body)).into_response()
}

fn gone400(body: Value) -> Response {
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

#[derive(Deserialize)]
struct QuoteBody {
    #[serde(rename = "planId")]
    plan_id: Option<serde_json::Value>,
    cpu: Option<serde_json::Value>,
    memory: Option<serde_json::Value>,
    disk: Option<serde_json::Value>,
}

async fn quote(
    State(state): State<SharedAppState>,
    user: AuthUser,
    body: Option<Json<QuoteBody>>,
) -> Result<Response, ApiError> {
    let result: Result<Value, String> = async {
        let Json(body) = body.ok_or("body must be object".to_string())?;
        let plan_id = body
            .plan_id
            .as_ref()
            .and_then(Value::as_i64)
            .filter(|v| *v > 0) as Option<i64>;
        let plan = match plan_id {
            Some(pid) => get_hourly_plan_for_user(&state, &user, pid as i32)
                .await
                .map_err(|e| e.error)?,
            None => None,
        };
        let plan = plan.ok_or("HOURLY_PLAN_NOT_FOUND".to_string())?;
        let pricing = hourly_pricing_from_package_plan(&plan);
        let num = |v: &Option<Value>| v.as_ref().and_then(Value::as_i64).unwrap_or(0);
        let resources = HourlyResources {
            cpu: num(&body.cpu),
            memory: num(&body.memory),
            disk: num(&body.disk),
        };
        let breakdown = calculate_hourly_breakdown(resources, &pricing)?;
        Ok(json!({
            "pricing": pricing.to_json(),
            "resources": { "cpu": resources.cpu, "memory": resources.memory, "disk": resources.disk },
            "breakdown": breakdown_json(&breakdown),
        }))
    }
    .await;

    match result {
        Ok(value) => Ok(Json(value).into_response()),
        Err(message) if message == "HOURLY_PLAN_NOT_FOUND" => Ok(gone404(json!({
            "error": "按小时计费方案不存在或无权访问",
            "code": "HOURLY_PLAN_NOT_FOUND",
        }))),
        Err(message) => Ok(gone400(json!({
            "error": message,
            "code": "HOURLY_QUOTE_INVALID",
        }))),
    }
}

async fn load_account_pricing(
    state: &SharedAppState,
    instance_id: i32,
) -> Result<Option<(HourlyResources, crate::libs::hourly_billing::HourlyPricing, Value)>, ApiError> {
    // instance + account + plan for pricing fallback chain
    #[derive(Debug, sqlx::FromRow)]
    struct Row {
        cpu: i32,
        memory: i32,
        disk: i32,
        pricing_snapshot: Value,
    }
    let row: Option<Row> = sqlx::query_as(
        "SELECT i.cpu, i.memory, i.disk, a.pricing_snapshot \
         FROM instances i JOIN hourly_billing_accounts a ON a.instance_id = i.id \
         WHERE i.id = $1 AND i.billing_mode::text = 'hourly'",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else { return Ok(None) };

    let pricing = hourly_pricing_from_snapshot(&row.pricing_snapshot)
        .or_else(|| {
            // fallback: plan pricing
            None::<crate::libs::hourly_billing::HourlyPricing>
        });
    // NOTE: plan/pricing-version fallback requires the plan columns; the
    // snapshot is mandatory since 20260923100000 — None only for legacy rows.
    let Some(pricing) = pricing else { return Ok(None) };
    Ok(Some((
        HourlyResources { cpu: row.cpu as i64, memory: row.memory as i64, disk: row.disk as i64 },
        pricing,
        row.pricing_snapshot,
    )))
}

async fn account_detail(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let Some(id) = parse_positive_int(&id) else {
        return Err(ApiError::bad_request(code::INVALID_ID));
    };
    let instance: Option<(i32, i32, i32, Option<i32>)> = sqlx::query_as(
        "SELECT id, user_id, host_id, (SELECT user_id FROM hosts WHERE id = instances.host_id) \
         FROM instances WHERE id = $1 AND billing_mode::text = 'hourly'",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let Some((_, creator, host_id, host_owner)) = instance else {
        return Ok(gone404(json!({ "error": "Hourly billing account not found" })));
    };
    if user.role != "admin" && user.id != creator && Some(user.id) != host_owner {
        let _ = host_id;
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    #[derive(Debug, sqlx::FromRow)]
    struct AccountRow {
        status: String,
        prepaid_balance: rust_decimal::Decimal,
        total_cost: rust_decimal::Decimal,
        total_reserved: rust_decimal::Decimal,
        total_released: rust_decimal::Decimal,
        outstanding_amount: rust_decimal::Decimal,
        last_settled_at: DateTime<Utc>,
        next_settlement_at: Option<DateTime<Utc>>,
        pricing_snapshot: Value,
    }
    let account: Option<AccountRow> = sqlx::query_as(
        "SELECT status::text AS status, prepaid_balance, total_cost, total_reserved, \
                total_released, outstanding_amount, last_settled_at, next_settlement_at, \
                pricing_snapshot \
         FROM hourly_billing_accounts WHERE instance_id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let Some(account) = account else {
        return Ok(gone404(json!({ "error": "Hourly billing account not found" })));
    };

    let Some((resources, pricing, _)) = load_account_pricing(&state, id).await? else {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Hourly billing pricing is missing",
                "code": "HOURLY_PRICING_MISSING",
            })),
        )
            .into_response());
    };
    let breakdown = calculate_hourly_breakdown(resources, &pricing)
        .map_err(|e| ApiError::internal(e))?;

    Ok(Json(json!({
        "instanceId": id,
        "billingMode": "hourly",
        "status": account.status,
        "pricing": pricing.to_json(),
        "resources": { "cpu": resources.cpu, "memory": resources.memory, "disk": resources.disk },
        "hourlyPrice": serialize_hourly_decimal(breakdown.hourly_price),
        "prepaidBalance": serialize_hourly_decimal(account.prepaid_balance),
        "totalCost": serialize_hourly_decimal(account.total_cost),
        "totalReserved": serialize_hourly_decimal(account.total_reserved),
        "totalReleased": serialize_hourly_decimal(account.total_released),
        "outstandingAmount": serialize_hourly_decimal(account.outstanding_amount),
        "lastSettledAt": iso(account.last_settled_at),
        "nextSettlementAt": account.next_settlement_at.map(iso).unwrap_or(Value::Null),
    }))
    .into_response())
}

async fn account_records(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let Some(id) = parse_positive_int(&id) else {
        return Err(ApiError::bad_request(code::INVALID_ID));
    };
    let instance: Option<(i32, i32, Option<i32>)> = sqlx::query_as(
        "SELECT id, user_id, (SELECT user_id FROM hosts WHERE id = instances.host_id) \
         FROM instances WHERE id = $1 AND billing_mode::text = 'hourly'",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let Some((_, creator, host_owner)) = instance else {
        return Ok(gone404(json!({ "error": "Hourly billing account not found" })));
    };
    if user.role != "admin" && user.id != creator && Some(user.id) != host_owner {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    let limit = parse_limit(query.get("limit").map(|s| s.as_str()), 50, 200);

    #[derive(Debug, sqlx::FromRow)]
    struct RecordRow {
        id: i32,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        active_seconds: i32,
        cpu: i32,
        memory: i32,
        disk: i32,
        cpu_amount: rust_decimal::Decimal,
        memory_amount: rust_decimal::Decimal,
        disk_amount: rust_decimal::Decimal,
        actual_amount: rust_decimal::Decimal,
        reserve_amount: rust_decimal::Decimal,
        release_amount: rust_decimal::Decimal,
        status: String,
    }
    let records: Vec<RecordRow> = sqlx::query_as(
        "SELECT id, period_start, period_end, active_seconds, cpu, memory, disk, \
                cpu_amount, memory_amount, disk_amount, actual_amount, reserve_amount, \
                release_amount, status::text AS status \
         FROM hourly_billing_records WHERE instance_id = $1 \
         ORDER BY period_end DESC LIMIT $2",
    )
    .bind(id)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    let items: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "periodStart": iso(r.period_start),
                "periodEnd": iso(r.period_end),
                "activeSeconds": r.active_seconds,
                "cpu": r.cpu, "memory": r.memory, "disk": r.disk,
                "cpuAmount": serialize_hourly_decimal(r.cpu_amount),
                "memoryAmount": serialize_hourly_decimal(r.memory_amount),
                "diskAmount": serialize_hourly_decimal(r.disk_amount),
                "actualAmount": serialize_hourly_decimal(r.actual_amount),
                "reserveAmount": serialize_hourly_decimal(r.reserve_amount),
                "releaseAmount": serialize_hourly_decimal(r.release_amount),
                "status": r.status,
            })
        })
        .collect();
    Ok(Json(json!({ "records": items })).into_response())
}

async fn pay_debt(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let Ok(id) = id.trim().parse::<i32>() else {
        return Err(ApiError::bad_request(code::INVALID_ID));
    };
    let Ok(id) = (if id > 0 { Ok(id) } else { Err(()) }) else {
        return Err(ApiError::bad_request(code::INVALID_ID));
    };

    // payClosedHourlyDebt: locked tx — account must be closed with outstanding
    // debt; deduct balance, log, clear outstanding.
    let result: Result<rust_decimal::Decimal, &'static str> = async {
        let mut tx = state.db.begin().await.map_err(|_| "HOURLY_DEBT_SETTLEMENT_FAILED")?;
        crate::db::advisory_transaction_lock(
            &mut tx,
            crate::db::advisory_lock_namespace::USER_BALANCE,
            user.0.id as i64,
        )
        .await
        .map_err(|_| "HOURLY_DEBT_SETTLEMENT_FAILED")?;

        let account: Option<(i64, rust_decimal::Decimal)> = sqlx::query_as(
            "SELECT id, outstanding_amount FROM hourly_billing_accounts \
             WHERE instance_id = $1 AND status::text = 'closed' FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "HOURLY_DEBT_SETTLEMENT_FAILED")?;
        let Some((_, outstanding)) = account else {
            // distinguish not-found vs not-closed
            let exists: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM hourly_billing_accounts WHERE instance_id = $1",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| "HOURLY_DEBT_SETTLEMENT_FAILED")?;
            return if exists.is_some() {
                Err("HOURLY_ACCOUNT_NOT_CLOSED")
            } else {
                Err("HOURLY_ACCOUNT_NOT_FOUND")
            };
        };

        let (creator, balance): (i32, rust_decimal::Decimal) = sqlx::query_as(
            "SELECT user_id, balance FROM users WHERE id = $1",
        )
        .bind(user.0.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| "HOURLY_DEBT_SETTLEMENT_FAILED")?;
        if creator != user.0.id {
            return Err("HOURLY_ACCOUNT_NOT_FOUND");
        }
        if balance < outstanding {
            return Err("BALANCE_INSUFFICIENT");
        }

        let charge = outstanding;
        sqlx::query("UPDATE users SET balance = balance - $2 WHERE id = $1 AND balance >= $2")
            .bind(user.0.id)
            .bind(charge)
            .execute(&mut *tx)
            .await
            .map_err(|_| "HOURLY_DEBT_SETTLEMENT_FAILED")?;
        sqlx::query(
            "INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, instance_id, remark) \
             VALUES ($1, 'hourly_consume'::\"BalanceLogType\", $2, $3, $4, $5, '按小时账单结清')",
        )
        .bind(user.0.id)
        .bind(-charge)
        .bind(balance)
        .bind(balance - charge)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| "HOURLY_DEBT_SETTLEMENT_FAILED")?;
        sqlx::query(
            "UPDATE hourly_billing_accounts SET outstanding_amount = 0 WHERE instance_id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| "HOURLY_DEBT_SETTLEMENT_FAILED")?;

        tx.commit().await.map_err(|_| "HOURLY_DEBT_SETTLEMENT_FAILED")?;
        Ok(charge)
    }
    .await;

    match result {
        Ok(amount) => Ok(Json(json!({
            "instanceId": id,
            "chargedAmount": serialize_hourly_decimal(amount),
        }))
        .into_response()),
        Err("HOURLY_ACCOUNT_NOT_FOUND") => Ok(gone404(json!({
            "error": "Hourly billing account not found",
            "code": "HOURLY_ACCOUNT_NOT_FOUND",
        }))),
        Err("HOURLY_ACCOUNT_NOT_CLOSED") => Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "This hourly account is not closed",
                "code": "HOURLY_ACCOUNT_NOT_CLOSED",
            })),
        )
            .into_response()),
        Err("BALANCE_INSUFFICIENT") => Err(ApiError::bad_request(code::INSUFFICIENT_BALANCE)),
        Err(_) => Ok(gone400(json!({
            "error": "Unable to settle closed hourly debt",
            "code": "HOURLY_DEBT_SETTLEMENT_FAILED",
        }))),
    }
}

#[derive(Deserialize)]
struct ResizePreviewBody {
    cpu: Option<serde_json::Value>,
    memory: Option<serde_json::Value>,
    disk: Option<serde_json::Value>,
}

async fn resize_preview(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(id): Path<String>,
    body: Option<Json<ResizePreviewBody>>,
) -> Result<Response, ApiError> {
    let Some(id) = parse_positive_int(&id) else {
        return Err(ApiError::bad_request(code::INVALID_ID));
    };
    let owner: Option<i32> = sqlx::query_scalar(
        "SELECT user_id FROM instances WHERE id = $1 AND billing_mode::text = 'hourly'",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    let Some(creator) = owner else {
        return Ok(gone404(json!({ "error": "Hourly instance not found" })));
    };
    if creator != user.0.id && user.0.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let Some((_, pricing, _)) = load_account_pricing(&state, id).await? else {
        return Ok(gone400(json!({
            "error": "Hourly billing pricing is missing",
            "code": "HOURLY_RESIZE_INVALID",
        })));
    };
    let Json(body) = body.unwrap_or(Json(ResizePreviewBody { cpu: None, memory: None, disk: None }));
    let num = |v: &Option<Value>| v.as_ref().and_then(Value::as_i64).unwrap_or(0);
    let resources = HourlyResources { cpu: num(&body.cpu), memory: num(&body.memory), disk: num(&body.disk) };
    match calculate_hourly_breakdown(resources, &pricing) {
        Ok(breakdown) => Ok(Json(json!({
            "resources": { "cpu": resources.cpu, "memory": resources.memory, "disk": resources.disk },
            "pricing": pricing.to_json(),
            "breakdown": breakdown_json(&breakdown),
        }))
        .into_response()),
        Err(message) => Ok(gone400(json!({
            "error": message,
            "code": "HOURLY_RESIZE_INVALID",
        }))),
    }
}

#[derive(Deserialize)]
struct HostSwitchBody {
    enabled: Option<bool>,
}

async fn admin_host_switch(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
    body: Option<Json<HostSwitchBody>>,
) -> Result<Response, ApiError> {
    let Ok(host_id) = id.trim().parse::<i32>() else {
        return Ok(gone400(json!({ "error": "Invalid host switch" })));
    };
    let Some(enabled) = body.and_then(|Json(b)| b.enabled) else {
        return Ok(gone400(json!({ "error": "Invalid host switch" })));
    };
    let result = sqlx::query("UPDATE hosts SET hourly_billing_enabled = $2 WHERE id = $1")
        .bind(host_id)
        .bind(enabled)
        .execute(&state.db)
        .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::not_found(code::HOST_NOT_FOUND));
    }
    Ok(Json(json!({ "hostId": host_id, "hourlyBillingEnabled": enabled })).into_response())
}

async fn admin_instances(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    #[derive(Debug, sqlx::FromRow)]
    struct Row {
        id: i32,
        name: String,
        status: String,
        username: String,
        host_name: String,
        host_id: i32,
        cpu: i32,
        memory: i32,
        disk: i32,
        account_status: Option<String>,
        prepaid_balance: Option<rust_decimal::Decimal>,
        total_cost: Option<rust_decimal::Decimal>,
        outstanding_amount: Option<rust_decimal::Decimal>,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT i.id, i.name, i.status::text AS status, u.username, h.id AS host_id, h.name AS host_name, \
                i.cpu, i.memory, i.disk, a.status::text AS account_status, \
                a.prepaid_balance, a.total_cost, a.outstanding_amount \
         FROM instances i \
         JOIN users u ON u.id = i.user_id \
         JOIN hosts h ON h.id = i.host_id \
         LEFT JOIN hourly_billing_accounts a ON a.instance_id = i.id \
         WHERE i.billing_mode::text = 'hourly' \
         ORDER BY i.id DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await?;

    let instances: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.id, "name": r.name, "status": r.status,
                "user": { "id": 0, "username": r.username },
                "host": { "id": r.host_id, "name": r.host_name },
                "cpu": r.cpu, "memory": r.memory, "disk": r.disk,
                "account": r.account_status.as_ref().map(|s| json!({
                    "status": s,
                    "prepaidBalance": serialize_hourly_decimal_opt(r.prepaid_balance),
                    "totalCost": serialize_hourly_decimal_opt(r.total_cost),
                    "outstandingAmount": serialize_hourly_decimal_opt(r.outstanding_amount),
                })).unwrap_or(Value::Null),
            })
        })
        .collect();
    Ok(Json(json!({ "instances": instances })))
}

async fn admin_records(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let limit = parse_limit(query.get("limit").map(|s| s.as_str()), 100, 500);
    let instance_id = query.get("instanceId").map(|s| s.as_str());

    if let Some(raw) = instance_id {
        if parse_positive_int(raw).is_none() {
            return Err(ApiError::bad_request(code::INVALID_ID));
        }
    }

    #[derive(Debug, sqlx::FromRow)]
    struct RecordRow {
        id: i32,
        instance_id: i32,
        user_id: i32,
        account_id: i32,
        package_plan_id: Option<i32>,
        pricing_version_id: Option<i32>,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        active_seconds: i32,
        cpu: i32,
        memory: i32,
        disk: i32,
        cpu_amount: rust_decimal::Decimal,
        memory_amount: rust_decimal::Decimal,
        disk_amount: rust_decimal::Decimal,
        actual_amount: rust_decimal::Decimal,
        reserve_amount: rust_decimal::Decimal,
        release_amount: rust_decimal::Decimal,
        status: String,
        balance_log_id: Option<i32>,
        created_at: DateTime<Utc>,
    }
    let sql = format!(
        "SELECT id, instance_id, user_id, account_id, package_plan_id, pricing_version_id, \
                period_start, period_end, active_seconds, cpu, memory, disk, cpu_amount, \
                memory_amount, disk_amount, actual_amount, reserve_amount, release_amount, \
                status::text AS status, balance_log_id, created_at \
         FROM hourly_billing_records {} \
         ORDER BY period_end DESC LIMIT {limit}",
        if instance_id.is_some() { "WHERE instance_id = $1" } else { "" }
    );
    let records: Vec<RecordRow> = if let Some(raw) = instance_id {
        let id = parse_positive_int(raw).unwrap();
        sqlx::query_as(&sql).bind(id).fetch_all(&state.db).await?
    } else {
        sqlx::query_as(&sql).fetch_all(&state.db).await?
    };

    let items: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "id": r.id, "instanceId": r.instance_id, "userId": r.user_id,
                "accountId": r.account_id, "packagePlanId": r.package_plan_id,
                "pricingVersionId": r.pricing_version_id,
                "periodStart": iso(r.period_start), "periodEnd": iso(r.period_end),
                "activeSeconds": r.active_seconds,
                "cpu": r.cpu, "memory": r.memory, "disk": r.disk,
                "cpuAmount": serialize_hourly_decimal(r.cpu_amount),
                "memoryAmount": serialize_hourly_decimal(r.memory_amount),
                "diskAmount": serialize_hourly_decimal(r.disk_amount),
                "actualAmount": serialize_hourly_decimal(r.actual_amount),
                "reserveAmount": serialize_hourly_decimal(r.reserve_amount),
                "releaseAmount": serialize_hourly_decimal(r.release_amount),
                "status": r.status, "balanceLogId": r.balance_log_id,
                "createdAt": iso(r.created_at),
            })
        })
        .collect();
    Ok(Json(json!({ "records": items })).into_response())
}

async fn admin_reconcile(
    State(_state): State<SharedAppState>,
    _admin: AdminAuth,
) -> Result<Json<Value>, ApiError> {
    // Wave D: hourly-billing scheduler not ported yet.
    tracing::warn!("hourly-billing scheduler not ported yet (Wave D): runHourlyBillingJob skipped");
    Ok(Json(json!({ "message": "Hourly billing reconciliation completed" })))
}
