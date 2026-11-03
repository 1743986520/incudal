//! 实例核心路由 — port of server/src/routes/instances.ts (read + power + task
//! surface this pass; create/ports/clone/change-host/config/suspend/delete/
//! sync-status/retry-provision/reassign-ipv6/available-hosts stay NOT_PORTED —
//! see PORTING.md roadmap).
//!
//! Mounted at /api/instances; merges the snapshots/ip-addresses/proxy-sites
//! routers that share the prefix upstream (KEEP the three .merge calls).

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::{AuthUser, UserOnlyAuth};
use crate::error::{code, ApiError};
use crate::libs::crypto::decrypt_sensitive_data;
use crate::libs::incus::cloud_init_status::{
    detect_cloud_init_status, get_cached_cloud_init_status, persist_cloud_init_status,
    CloudInitDetectionTarget, CloudInitStatusResponse, InstanceCloudInitRecord,
};
use crate::libs::incus::incus_instances::get_instance_state;
use crate::libs::incus::incus_traffic::get_traffic_counters_from_state;
use crate::libs::incus::incus_utils::map_instance_status;
use crate::libs::instance_common::{
    check_transfer_lock, create_log_with_instance, ensure_instance_not_suspended,
    get_host_for_incus, get_incus_client_for_host, get_instance_with_permission, iso,
};
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list))
        .route("/dashboard-summary", get(dashboard_summary))
        .route("/{id}", get(detail))
        .route("/{id}/order", axum::routing::patch(reorder))
        .route("/{id}/password", get(password))
        .route("/{id}/stats", get(stats))
        .route("/{id}/start", axum::routing::post(power_start))
        .route("/{id}/stop", axum::routing::post(power_stop))
        .route("/{id}/restart", axum::routing::post(power_restart))
        .route("/{id}/task", get(instance_task))
        .route("/tasks/{taskId}", get(task_detail).delete(cancel_task))
        .route("/tasks/{taskId}/recover", axum::routing::post(recover_task))
        .route("/{id}/suspend", axum::routing::post(suspend_instance))
        .route("/{id}/unsuspend", axum::routing::post(unsuspend_instance))
        .route("/{id}/sync-status", axum::routing::post(sync_status))
        .route("/{id}/cloud-init-status", get(cloud_init_status))
        .route(
            "/{id}/cloud-init-status/manual-complete",
            axum::routing::post(cloud_init_manual_complete),
        )
        .fallback(crate::routes::not_ported_handler)
        .merge(crate::routes::snapshots::router())
        .merge(crate::routes::ip_addresses::router())
        .merge(crate::routes::proxy_sites::router())
}

fn parse_id_str(raw: &str) -> Result<i32, ApiError> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request(code::INVALID_ID))
}

/// 409 task-in-progress body with the TS's taskId/taskType/status fields.
fn task_conflict_response(id: i32, task_type: &str, status: &str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": "Instance has an active task",
            "code": "TASK_IN_PROGRESS",
            "taskId": id,
            "taskType": task_type,
            "status": status,
        })),
    )
        .into_response()
}

// ==================== shared helpers ====================

/// db/images.ts getImageDisplayName(s): batch system_images lookup.
async fn image_display_names(
    state: &SharedAppState,
    aliases: &[String],
) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if aliases.is_empty() {
        return map;
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT remote_alias, name FROM system_images WHERE remote_alias = ANY($1)",
    )
    .bind(aliases)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for (alias, name) in rows {
        map.insert(alias, name);
    }
    map
}

/// host_ip_address resolution: host.ip_address, else URL hostname.
fn host_ip_address_of(ip_address: Option<&str>, url: Option<&str>) -> Option<String> {
    if let Some(ip) = ip_address.filter(|s| !s.is_empty()) {
        return Some(ip.to_string());
    }
    let url = url?;
    let parsed = url::Url::parse(url).ok()?;
    let hostname = parsed.host_str()?;
    Some(hostname.trim_start_matches('[').trim_end_matches(']').to_string())
}

#[derive(Debug, Clone)]
struct ActiveTask {
    id: i32,
    task_type: String,
    status: String,
}

async fn get_active_task_for_instance(
    state: &SharedAppState,
    instance_id: i32,
) -> Result<Option<ActiveTask>, ApiError> {
    let row: Option<(i32, String, String)> = sqlx::query_as(
        "SELECT id, task_type::text AS task_type, status::text AS status FROM instance_tasks \
         WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING') \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|(id, task_type, status)| ActiveTask { id, task_type, status }))
}

/// db/instance-tasks.ts getTaskQueuePosition.
async fn get_task_queue_position(state: &SharedAppState, task_id: i32, host_id: i32) -> i64 {
    let created_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT created_at FROM instance_tasks WHERE id = $1")
            .bind(task_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let Some(created_at) = created_at else { return 0 };
    let (position,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instance_tasks \
         WHERE host_id = $1 AND status = 'PENDING' AND created_at <= $2",
    )
    .bind(host_id)
    .bind(created_at)
    .fetch_one(&state.db)
    .await
    .unwrap_or((0,));
    position
}

// ===========================================================================
// GET / — 实例列表
// ===========================================================================

#[derive(Deserialize)]
struct ListQuery {
    page: Option<String>,
    #[serde(rename = "pageSize")]
    page_size: Option<String>,
    search: Option<String>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
    #[serde(rename = "hostId")]
    host_id: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    status: Option<String>,
    #[serde(rename = "sortBy")]
    sort_by: Option<String>,
    #[serde(rename = "sortOrder")]
    sort_order: Option<String>,
}

#[derive(Debug, FromRow)]
struct ListRow {
    id: i32,
    incus_id: String,
    name: String,
    user_id: i32,
    host_id: i32,
    package_id: Option<i32>,
    display_order: i32,
    icon_badge_id: Option<String>,
    image: String,
    status: String,
    cpu: i32,
    memory: i32,
    disk: i32,
    ipv4: Option<String>,
    ipv6: Option<String>,
    network_mode: String,
    port_limit: Option<i32>,
    snapshot_limit: Option<i32>,
    backup_limit: Option<i32>,
    site_limit: Option<i32>,
    monthly_traffic_limit: Option<i64>,
    monthly_traffic_used: Option<i64>,
    expires_at: Option<DateTime<Utc>>,
    auto_renew: Option<bool>,
    created_at: DateTime<Utc>,
    package_plan_id: Option<i32>,
    billing_mode: Option<String>,
    billing_price: Option<Decimal>,
    host_name: Option<String>,
    host_country_code: Option<String>,
    host_nat_public_ip: Option<String>,
    host_nat_public_ipv6: Option<String>,
    host_ipv6_gateway: Option<String>,
    host_ip_address: Option<String>,
    host_url: Option<String>,
    username: Option<String>,
    user_email: Option<String>,
    user_avatar_style: Option<String>,
    user_avatar_badge_id: Option<String>,
    package_name: Option<String>,
    package_instance_type: Option<String>,
    allow_instance_deletion: Option<bool>,
}

const LIST_COLUMNS: &str = "i.id, i.incus_id, i.name, i.user_id, i.host_id, i.package_id, \
    i.display_order, i.icon_badge_id, i.image, i.status::text AS status, i.cpu, i.memory, i.disk, \
    i.ipv4, i.ipv6, i.network_mode::text AS network_mode, i.port_limit, i.snapshot_limit, \
    i.backup_limit, i.site_limit, i.monthly_traffic_limit, i.monthly_traffic_used, i.expires_at, \
    i.auto_renew, i.created_at, i.package_plan_id, i.billing_mode::text AS billing_mode, \
    i.billing_price, h.name AS host_name, h.country_code AS host_country_code, \
    h.nat_public_ip AS host_nat_public_ip, h.nat_public_ipv6 AS host_nat_public_ipv6, \
    h.ipv6_gateway AS host_ipv6_gateway, h.ip_address AS host_ip_address, h.url AS host_url, \
    u.username, u.email AS user_email, u.avatar_style AS user_avatar_style, \
    u.avatar_badge_id AS user_avatar_badge_id, p.name AS package_name, \
    p.instance_type::text AS package_instance_type, p.allow_instance_deletion";

async fn list(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let mut params: HashMap<String, String> = HashMap::new();
    if let Some(p) = &query.page {
        params.insert("page".into(), p.clone());
    }
    if let Some(ps) = &query.page_size {
        params.insert("pageSize".into(), ps.clone());
    }
    let pagination = crate::response::parse_pagination(&params, 20, None);
    let search = query.search.clone().unwrap_or_default();

    // 查询权限：管理员全部；hostId 需节点所有者；否则只看自己
    let mut show_user_info = false;
    let filter_user_id: Option<i32>;
    let filter_host_id: Option<i32>;

    if user.role == "admin" {
        show_user_info = true;
        filter_user_id = query.user_id.as_deref().and_then(|v| v.parse().ok());
        filter_host_id = query.host_id.as_deref().and_then(|v| v.parse().ok());
    } else if let Some(host_raw) = query.host_id.as_deref().and_then(|v| v.parse::<i32>().ok()) {
        filter_host_id = Some(host_raw);
        let host_owner: Option<i32> = sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
            .bind(host_raw)
            .fetch_optional(&state.db)
            .await?;
        if host_owner == Some(user.id) {
            show_user_info = true;
            filter_user_id = None;
        } else {
            filter_user_id = Some(user.id);
        }
    } else {
        filter_user_id = Some(user.id);
        filter_host_id = None;
    }

    let status_filter = match query.status.as_deref() {
        Some("deleted") => "i.status::text = 'deleted'".to_string(),
        Some(s) => format!("i.status::text = '{}'", s.replace('\'', "''")),
        None => "i.status::text != 'deleted'".to_string(),
    };
    let mut clauses = vec![status_filter];
    if let Some(uid) = filter_user_id {
        clauses.push(format!("i.user_id = {uid}"));
    }
    if let Some(hid) = filter_host_id {
        clauses.push(format!("i.host_id = {hid}"));
    }
    if let Some(cc) = &query.country_code {
        clauses.push(format!("h.country_code = '{}'", cc.to_lowercase().replace('\'', "''")));
    }
    if !search.trim().is_empty() {
        let term = search.trim().replace('\'', "''");
        let numeric = search
            .trim()
            .parse::<i64>()
            .ok()
            .filter(|n| n.to_string() == search.trim());
        let mut conditions = format!(
            "(i.name ILIKE '%{term}%' OR i.incus_id ILIKE '%{term}%' OR i.ipv4 ILIKE '%{term}%' \
              OR i.ipv6 ILIKE '%{term}%' OR u.username ILIKE '%{term}%' OR u.email ILIKE '%{term}%')"
        );
        if let Some(n) = numeric {
            conditions.push_str(&format!(
                " OR i.id = {n} OR EXISTS (SELECT 1 FROM port_mappings pm \
                  WHERE pm.instance_id = i.id AND pm.public_port = {n})"
            ));
        }
        clauses.push(conditions);
    }
    let where_sql = clauses.join(" AND ");

    let order_sql = if query.sort_by.as_deref() == Some("createdAt") {
        let dir = if query.sort_order.as_deref() == Some("asc") { "ASC" } else { "DESC" };
        format!("i.created_at {dir}, i.id ASC")
    } else if filter_user_id.is_some() {
        "i.display_order ASC, i.created_at DESC, i.id ASC".to_string()
    } else {
        "i.created_at DESC, i.id ASC".to_string()
    };

    let rows = sqlx::query_as::<_, ListRow>(&format!(
        "SELECT {LIST_COLUMNS} FROM instances i \
         JOIN hosts h ON h.id = i.host_id \
         JOIN users u ON u.id = i.user_id \
         LEFT JOIN packages p ON p.id = i.package_id \
         WHERE {where_sql} ORDER BY {order_sql} LIMIT {} OFFSET {}",
        pagination.take, pagination.skip
    ))
    .fetch_all(&state.db)
    .await?;
    let (total,): (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM instances i \
         JOIN hosts h ON h.id = i.host_id \
         JOIN users u ON u.id = i.user_id \
         LEFT JOIN packages p ON p.id = i.package_id \
         WHERE {where_sql}"
    ))
    .fetch_one(&state.db)
    .await?;

    // availableCountries（按 baseWhere：status + userId，不含 countryCode/hostId）
    let country_rows: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT DISTINCT h.country_code FROM hosts h \
         JOIN instances i ON i.host_id = h.id \
         WHERE i.status::text != 'deleted' \
           AND ($1::int IS NULL OR i.user_id = $1) \
         ORDER BY 1",
    )
    .bind(filter_user_id)
    .fetch_all(&state.db)
    .await?;
    let mut available_countries: Vec<String> = country_rows
        .iter()
        .map(|c| c.0.clone().unwrap_or_else(|| "us".into()).to_lowercase())
        .collect();
    available_countries.sort();
    available_countries.dedup();

    let aliases: Vec<String> = rows.iter().map(|r| r.image.clone()).collect();
    let display_names = image_display_names(&state, &aliases).await;

    let items: Vec<Value> = rows
        .iter()
        .map(|i| {
            let host_ip = host_ip_address_of(i.host_ip_address.as_deref(), i.host_url.as_deref());
            let mut response = json!({
                "id": i.id,
                "name": i.name,
                "incusId": i.incus_id,
                "status": i.status,
                "image": i.image,
                "imageName": display_names.get(&i.image).cloned().map(Value::String).unwrap_or(Value::Null),
                "cpu": i.cpu,
                "memory": i.memory,
                "disk": i.disk,
                "ipv4": i.ipv4,
                "ipv6": i.ipv6,
                "host": {
                    "name": i.host_name.clone().unwrap_or_else(|| "unknown".into()),
                    "country_code": i.host_country_code.clone().unwrap_or_else(|| "us".into()),
                    "nat_public_ip": i.host_nat_public_ip,
                    "ip_address": i.host_ip_address,
                },
                "hostCountryCode": i.host_country_code.clone().unwrap_or_else(|| "us".into()),
                "networkMode": i.network_mode,
                "natPublicIp": i.host_nat_public_ip,
                "hostNatPublicIpv6": i.host_nat_public_ipv6,
                "hostIpv6Gateway": i.host_ipv6_gateway,
                "hostIpAddress": host_ip,
                "displayOrder": i.display_order,
                "createdAt": iso(i.created_at),
                "expiresAt": i.expires_at.map(iso).unwrap_or(Value::Null),
                "expires_at": i.expires_at.map(iso).unwrap_or(Value::Null),
                "autoRenew": i.auto_renew.unwrap_or(false),
                "iconBadgeId": i.icon_badge_id,
                "packageName": i.package_name,
                "packagePlanId": i.package_plan_id,
                "billingMode": i.billing_mode.clone().unwrap_or_else(|| "package".into()),
                "billingPrice": i.billing_price.map(crate::response::num),
                "monthlyTrafficLimit": i.monthly_traffic_limit.map(|v| Value::String(v.to_string())).unwrap_or(Value::Null),
                "monthlyTrafficUsed": Value::String(i.monthly_traffic_used.unwrap_or(0).to_string()),
                "allow_instance_deletion": i.allow_instance_deletion.unwrap_or(true),
                "portLimit": i.port_limit,
                "snapshotLimit": i.snapshot_limit,
                "backupLimit": i.backup_limit,
                "siteLimit": i.site_limit,
                "instanceType": if i.package_instance_type.as_deref() == Some("vm") { "vm" } else { "container" },
            });
            if show_user_info {
                let obj = response.as_object_mut().unwrap();
                obj.insert("username".into(), json!(i.username));
                obj.insert("userEmail".into(), json!(i.user_email));
                obj.insert("userAvatarStyle".into(), json!(i.user_avatar_style));
                obj.insert("userAvatarBadgeId".into(), json!(i.user_avatar_badge_id));
                obj.insert("userId".into(), json!(i.user_id));
                obj.insert("hostId".into(), json!(i.host_id));
            }
            response
        })
        .collect();

    Ok(Json(json!({
        "instances": items,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
        "totalPages": (total + pagination.page_size - 1) / pagination.page_size.max(1),
        "availableCountries": available_countries,
    })))
}

// ===========================================================================
// PATCH /:id/order
// ===========================================================================

#[derive(Deserialize)]
struct OrderBody {
    action: Option<String>,
}

async fn reorder(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<OrderBody>>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id_str(&id)?;
    if instance_id <= 0 {
        return Err(ApiError::bad_request(code::INVALID_ID));
    }
    let Json(body) = body.ok_or_else(|| ApiError::validation("body must be object"))?;
    let action = body
        .action
        .as_deref()
        .filter(|a| ["top", "up", "down", "bottom"].contains(a))
        .ok_or_else(|| ApiError::validation("action must be equal to one of the allowed values"))?;

    let mut tx = state.db.begin().await?;
    let ordered: Vec<(i32,)> = sqlx::query_as(
        "SELECT id FROM instances WHERE user_id = $1 AND status::text != 'deleted' \
         ORDER BY display_order ASC, created_at DESC, id ASC",
    )
    .bind(user.id)
    .fetch_all(&mut *tx)
    .await?;
    let ordered: Vec<i32> = ordered.into_iter().map(|(id,)| id).collect();

    let Some(current_index) = ordered.iter().position(|id| *id == instance_id) else {
        let _ = tx.rollback().await;
        return Err(ApiError::forbidden(code::FORBIDDEN));
    };

    let mut target_index = match action {
        "top" => 0,
        "up" => current_index.saturating_sub(1),
        "down" => current_index + 1,
        _ => ordered.len().saturating_sub(1),
    };
    target_index = target_index.min(ordered.len() - 1);
    if target_index == current_index {
        tx.commit().await?;
        return Ok(Json(json!({ "message": "Instance order updated", "updated": 0 })));
    }

    let mut next_order = ordered.clone();
    let moved = next_order.remove(current_index);
    next_order.insert(target_index, moved);
    for (index, instance) in next_order.iter().enumerate() {
        sqlx::query("UPDATE instances SET display_order = $2 WHERE id = $1")
            .bind(instance)
            .bind((index * 1000) as i32)
            .execute(&mut *tx)
            .await?;
    }
    let updated = next_order.len();
    tx.commit().await?;

    Ok(Json(json!({ "message": "Instance order updated", "updated": updated })))
}

// ===========================================================================
// GET /dashboard-summary
// ===========================================================================

async fn dashboard_summary(
    State(state): State<SharedAppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let base_user_filter: Option<i32> = if user.role == "admin" { None } else { Some(user.id) };

    let status_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status::text, COUNT(*) FROM instances \
         WHERE status::text != 'deleted' AND ($1::int IS NULL OR user_id = $1) \
         GROUP BY 1",
    )
    .bind(base_user_filter)
    .fetch_all(&state.db)
    .await?;

    #[derive(Debug, FromRow)]
    struct RecentRow {
        id: i32,
        name: String,
        status: String,
        image: String,
        ipv4: Option<String>,
        ipv6: Option<String>,
        network_mode: String,
        cpu: i32,
        memory: i32,
        disk: i32,
        display_order: i32,
        icon_badge_id: Option<String>,
        package_plan_id: Option<i32>,
        billing_mode: Option<String>,
        billing_price: Option<Decimal>,
        monthly_traffic_limit: Option<i64>,
        monthly_traffic_used: Option<i64>,
        expires_at: Option<DateTime<Utc>>,
        auto_renew: Option<bool>,
        created_at: DateTime<Utc>,
        host_name: Option<String>,
        host_country_code: Option<String>,
        host_nat_public_ip: Option<String>,
        host_nat_public_ipv6: Option<String>,
        host_ipv6_gateway: Option<String>,
        host_ip_address: Option<String>,
        host_url: Option<String>,
        package_name: Option<String>,
        package_instance_type: Option<String>,
        allow_instance_deletion: Option<bool>,
    }
    let recent: Vec<RecentRow> = sqlx::query_as(
        "SELECT i.id, i.name, i.status::text AS status, i.image, i.ipv4, i.ipv6, \
                i.network_mode::text AS network_mode, i.cpu, i.memory, i.disk, i.display_order, \
                i.icon_badge_id, i.package_plan_id, i.billing_mode::text AS billing_mode, \
                i.billing_price, i.monthly_traffic_limit, i.monthly_traffic_used, i.expires_at, \
                i.auto_renew, i.created_at, h.name AS host_name, h.country_code AS host_country_code, \
                h.nat_public_ip AS host_nat_public_ip, h.nat_public_ipv6 AS host_nat_public_ipv6, \
                h.ipv6_gateway AS host_ipv6_gateway, h.ip_address AS host_ip_address, h.url AS host_url, \
                p.name AS package_name, p.instance_type::text AS package_instance_type, \
                p.allow_instance_deletion \
         FROM instances i JOIN hosts h ON h.id = i.host_id \
         LEFT JOIN packages p ON p.id = i.package_id \
         WHERE i.status::text != 'deleted' AND ($1::int IS NULL OR i.user_id = $1) \
         ORDER BY i.display_order ASC, i.created_at DESC, i.id ASC LIMIT 5",
    )
    .bind(base_user_filter)
    .fetch_all(&state.db)
    .await?;

    let (vm_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM instances i JOIN packages p ON p.id = i.package_id \
         WHERE i.status::text != 'deleted' AND ($1::int IS NULL OR i.user_id = $1) \
           AND p.instance_type::text = 'vm'",
    )
    .bind(base_user_filter)
    .fetch_one(&state.db)
    .await?;

    let mut stats = json!({ "total": 0, "running": 0, "stopped": 0, "creating": 0, "error": 0, "suspended": 0 });
    for (status, count) in &status_rows {
        let key = status.to_lowercase();
        if let Some(obj) = stats.as_object_mut() {
            if obj.contains_key(&key) {
                obj.insert(key, json!(count));
            }
            let total = obj.get("total").and_then(Value::as_i64).unwrap_or(0);
            obj.insert("total".into(), json!(total + count));
        }
    }

    let aliases: Vec<String> = recent.iter().map(|r| r.image.clone()).collect();
    let display_names = image_display_names(&state, &aliases).await;

    let recent_instances: Vec<Value> = recent
        .iter()
        .map(|i| {
            json!({
                "id": i.id,
                "name": i.name,
                "status": i.status,
                "image": i.image,
                "imageName": display_names.get(&i.image).cloned().map(Value::String).unwrap_or(Value::Null),
                "ipv4": i.ipv4,
                "ipv6": i.ipv6,
                "networkMode": i.network_mode,
                "cpu": i.cpu, "memory": i.memory, "disk": i.disk,
                "displayOrder": i.display_order,
                "iconBadgeId": i.icon_badge_id,
                "packagePlanId": i.package_plan_id,
                "billingMode": i.billing_mode.clone().unwrap_or_else(|| "package".into()),
                "billingPrice": i.billing_price.map(crate::response::num),
                "monthlyTrafficLimit": i.monthly_traffic_limit.map(|v| Value::String(v.to_string())).unwrap_or(Value::Null),
                "monthlyTrafficUsed": Value::String(i.monthly_traffic_used.unwrap_or(0).to_string()),
                "expiresAt": i.expires_at.map(iso).unwrap_or(Value::Null),
                "expires_at": i.expires_at.map(iso).unwrap_or(Value::Null),
                "autoRenew": i.auto_renew.unwrap_or(false),
                "createdAt": iso(i.created_at),
                "host": {
                    "name": i.host_name.clone().unwrap_or_else(|| "unknown".into()),
                    "country_code": i.host_country_code.clone().unwrap_or_else(|| "us".into()),
                    "nat_public_ip": i.host_nat_public_ip,
                },
                "hostCountryCode": i.host_country_code.clone().unwrap_or_else(|| "us".into()),
                "natPublicIp": i.host_nat_public_ip,
                "hostNatPublicIpv6": i.host_nat_public_ipv6,
                "hostIpv6Gateway": i.host_ipv6_gateway,
                "hostIpAddress": host_ip_address_of(i.host_ip_address.as_deref(), i.host_url.as_deref()),
                "packageName": i.package_name,
                "instanceType": if i.package_instance_type.as_deref() == Some("vm") { "vm" } else { "container" },
                "allow_instance_deletion": i.allow_instance_deletion.unwrap_or(true),
            })
        })
        .collect();

    let total = stats.get("total").and_then(Value::as_i64).unwrap_or(0);
    Ok(Json(json!({
        "stats": stats,
        "instanceTypeStats": {
            "vm": vm_count,
            "container": (total - vm_count).max(0),
        },
        "recentInstances": recent_instances,
    })))
}

// ===========================================================================
// GET /:id — 实例详情
// ===========================================================================

async fn detail(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id_str(&id)?;
    let instance = get_instance_with_permission(&state, &user, instance_id).await?;

    let port_mappings: Vec<(i32, String, i32, i32, Option<String>)> = sqlx::query_as(
        "SELECT id, protocol::text AS protocol, public_port, private_port, remark \
         FROM port_mappings WHERE instance_id = $1 ORDER BY id ASC",
    )
    .bind(instance_id)
    .fetch_all(&state.db)
    .await?;

    #[derive(Debug, FromRow)]
    struct DetailHost {
        id: i32,
        user_id: i32,
        name: String,
        country_code: String,
        nat_public_ip: Option<String>,
        nat_public_ipv6: Option<String>,
        ipv6_gateway: Option<String>,
        ip_address: Option<String>,
        url: String,
        announcement: Option<String>,
        storage_driver: String,
        nat_port_start: Option<i32>,
        nat_port_end: Option<i32>,
        enable_resource_pool: bool,
    }
    let host: DetailHost = sqlx::query_as(
        "SELECT id, user_id, name, country_code, nat_public_ip, nat_public_ipv6, ipv6_gateway, \
                ip_address, url, announcement, storage_driver::text AS storage_driver, \
                nat_port_start, nat_port_end, enable_resource_pool \
         FROM hosts WHERE id = $1",
    )
    .bind(instance.host_id)
    .fetch_one(&state.db)
    .await?;

    let nat_public_ip = host.nat_public_ip.clone();
    let host_ip_address = host_ip_address_of(host.ip_address.as_deref(), Some(&host.url));
    let mut host_ipv6_address: Option<String> = None;
    if matches!(instance.network_mode.as_str(), "nat_ipv6_nat" | "ipv6_nat") {
        if let Some(v6) = &host.nat_public_ipv6 {
            host_ipv6_address = Some(v6.clone());
        }
        if host_ipv6_address.is_none() {
            if let Some(ip) = host_ip_address.as_ref().filter(|ip| ip.contains(':')) {
                host_ipv6_address = Some(ip.clone());
            }
        }
        if host_ipv6_address.is_none() {
            host_ipv6_address = host.ipv6_gateway.clone();
        }
        if host_ipv6_address.is_none() {
            let alias: Option<String> = sqlx::query_scalar(
                "SELECT address FROM host_address_aliases \
                 WHERE host_id = $1 AND kind::text = 'ipv6' LIMIT 1",
            )
            .bind(host.id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
            host_ipv6_address = alias;
        }
        if host_ipv6_address.is_none() {
            if let Some(hostname) = host_ip_address_of(None, Some(&host.url)) {
                if hostname.contains(':') {
                    host_ipv6_address = Some(hostname);
                }
            }
        }
    }

    let current_port_count = port_mappings.len() as i64;
    let (current_snapshot_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM snapshots WHERE instance_id = $1")
            .bind(instance_id)
            .fetch_one(&state.db)
            .await?;
    let (current_backup_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM backups WHERE instance_id = $1 AND status::text != 'deleted'",
    )
    .bind(instance_id)
    .fetch_one(&state.db)
    .await?;
    let (current_site_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM proxy_sites WHERE instance_id = $1")
            .bind(instance_id)
            .fetch_one(&state.db)
            .await?;

    // package info（instance 级 quota 覆盖套餐）
    let pkg: Option<(String, Option<String>, Option<i32>, Option<String>, Option<String>, Option<bool>)> =
        match instance.package_id {
            Some(pid) => sqlx::query_as(
                "SELECT name, instance_type::text, site_limit, limits_ingress, limits_egress, \
                        allow_instance_deletion FROM packages WHERE id = $1",
            )
            .bind(pid)
            .fetch_optional(&state.db)
            .await?,
            None => None,
        };
    let (pkg_name, pkg_instance_type, pkg_site_limit, pkg_limits_ingress, pkg_limits_egress, pkg_allow_deletion) =
        match &pkg {
            Some(p) => (
                Some(p.0.clone()),
                p.1.clone(),
                p.2,
                p.3.clone(),
                p.4.clone(),
                p.5,
            ),
            None => (None, None, None, None, None, None),
        };
    let effective_site_limit = instance.site_limit.or(pkg_site_limit).unwrap_or(10);

    // instance extra columns（InstanceRow 未覆盖的字段）
    let extra: Option<(
        Option<String>,
        Option<String>,
        Option<i32>,
        Option<Decimal>,
        Option<i32>,
        Option<bool>,
        Option<i32>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<i32>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT ipv4, ipv6, ssh_port, billing_price, billing_cycle, auto_renew, suspended_by, \
                suspended_at, expires_at, icon_badge_id, suspend_reason, limits_ingress \
         FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?;
    let (
        inst_ipv4,
        inst_ipv6,
        ssh_port,
        billing_price,
        billing_cycle,
        auto_renew,
        suspended_by,
        suspended_at,
        expires_at,
        icon_badge_id,
        suspend_reason,
        inst_limits_ingress,
    ) = extra.unwrap_or((
        None, None, None, None, None, None, None, None, None, None, None, None,
    ));
    let inst_limits_egress: Option<String> =
        sqlx::query_scalar("SELECT limits_egress FROM instances WHERE id = $1")
            .bind(instance_id)
            .fetch_one(&state.db)
            .await?;
    #[derive(Debug, FromRow)]
    struct TrafficRow {
        monthly_traffic_limit: Option<i64>,
        monthly_traffic_used: Option<i64>,
    }
    let traffic: Option<TrafficRow> = sqlx::query_as(
        "SELECT monthly_traffic_limit, monthly_traffic_used FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?;
    let (monthly_traffic_limit, monthly_traffic_used) = traffic
        .map(|t| (t.monthly_traffic_limit, t.monthly_traffic_used))
        .unwrap_or((None, None));
    let created_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT created_at FROM instances WHERE id = $1")
            .bind(instance_id)
            .fetch_one(&state.db)
            .await?;

    // plan + AFF 绑定（resolveInstanceRenewalDiscount 的读取面）
    let mut plan_name: Option<String> = None;
    let mut plan_price: Option<f64> = None;
    let mut billing_cycle_out: Option<i32> = billing_cycle;
    let mut has_aff_binding = false;
    let mut aff_binding_code: Option<String> = None;
    let mut aff_supersedes = false;
    if let Some(plan_id) = instance.package_plan_id {
        let plan: Option<(String, Decimal, i32)> = sqlx::query_as(
            "SELECT name, price, billing_cycle FROM package_plans WHERE id = $1",
        )
        .bind(plan_id)
        .fetch_optional(&state.db)
        .await?;
        if let Some((name, price, cycle)) = plan {
            plan_name = Some(name);
            plan_price = Some(price.to_f64().unwrap_or(0.0) / 100.0);
            billing_cycle_out = Some(cycle);
        }
        let binding: Option<(bool, String)> = sqlx::query_as(
            "SELECT ab.supersedes_official_coupon, ac.code \
             FROM aff_bindings ab JOIN aff_codes ac ON ac.id = ab.aff_code_id \
             WHERE ab.instance_id = $1",
        )
        .bind(instance_id)
        .fetch_optional(&state.db)
        .await?;
        if let Some((supersedes, aff_code)) = binding {
            has_aff_binding = true;
            aff_binding_code = Some(aff_code);
            aff_supersedes = supersedes;
        }
    }

    let is_host_owner = host.user_id == user.id;
    let is_admin = user.role == "admin";
    let mut is_hosted_instance = host.name.to_lowercase().starts_with("peer");

    let effective_port_limit = instance.port_limit.unwrap_or(20);
    let effective_snapshot_limit = instance.snapshot_limit.unwrap_or(5);
    let effective_backup_limit = instance.backup_limit.unwrap_or(3);
    let remaining = |limit: i64, used: i64| -> i64 {
        if limit == 0 { 0 } else { (limit - used).max(0) }
    };

    let image_name = image_display_names(&state, &[instance.image.clone()])
        .await
        .get(&instance.image)
        .cloned();
    let instance_type = if pkg_instance_type.as_deref() == Some("vm") { "vm" } else { "container" };

    let port_items: Vec<Value> = port_mappings
        .iter()
        .map(|(id, protocol, public_port, private_port, remark)| {
            json!({
                "id": id, "protocol": protocol,
                "public_port": public_port, "private_port": private_port, "remark": remark,
            })
        })
        .collect();

    let mut response = json!({
        "id": instance.id,
        "incusId": instance.incus_id,
        "name": instance.name,
        "status": instance.status,
        "image": instance.image,
        "imageName": image_name.map(Value::String).unwrap_or(Value::Null),
        "cpu": instance.cpu,
        "memory": instance.memory,
        "disk": instance.disk,
        "ipv4": inst_ipv4,
        "ipv6": inst_ipv6,
        "host": {
            "name": host.name,
            "country_code": host.country_code,
            "storageDriver": host.storage_driver,
        },
        "hostCountryCode": host.country_code,
        "network_mode": instance.network_mode,
        "instance_type": instance_type,
        "instanceType": instance_type,
        "iconBadgeId": icon_badge_id,
        "ssh_port": ssh_port,
        "port_limit": instance.port_limit,
        "snapshot_limit": instance.snapshot_limit,
        "backup_limit": instance.backup_limit,
        "monthlyTrafficLimit": monthly_traffic_limit.map(|v| Value::String(v.to_string())).unwrap_or(Value::Null),
        "remaining_quota": {
            "port": remaining(effective_port_limit as i64, current_port_count),
            "snapshot": remaining(effective_snapshot_limit as i64, current_snapshot_count),
            "backup": remaining(effective_backup_limit as i64, current_backup_count),
            "site": remaining(effective_site_limit as i64, current_site_count),
        },
        "quota_usage": {
            "port": current_port_count, "snapshot": current_snapshot_count,
            "backup": current_backup_count, "site": current_site_count,
        },
        "effective_quota_limit": {
            "port": effective_port_limit, "snapshot": effective_snapshot_limit,
            "backup": effective_backup_limit, "site": effective_site_limit,
        },
        "port_mappings": port_items,
        "created_at": iso(created_at),
        "package_id": instance.package_id,
        "packageName": pkg_name,
        "packagePlanId": instance.package_plan_id,
        "billingMode": "package",
        "planId": instance.package_plan_id,
        "planName": plan_name,
        "planPrice": plan_price,
        "billingPrice": billing_price.map(crate::response::num),
        "billingCycle": billing_cycle_out,
        "affDiscountRate": Value::Null,
        "hasAffBinding": has_aff_binding,
        "affBindingCode": aff_binding_code,
        "affSupersedesOfficialCoupon": aff_supersedes,
        "officialRenewalCouponCode": Value::Null,
        "officialRenewalDiscountPercent": 0,
        "isHostedInstance": is_hosted_instance,
        "hostAnnouncement": host.announcement,
        "limitsIngress": inst_limits_ingress.or(pkg_limits_ingress),
        "limitsEgress": inst_limits_egress.or(pkg_limits_egress),
        "expires_at": expires_at.map(iso).unwrap_or(Value::Null),
        "suspended_at": suspended_at.map(iso).unwrap_or(Value::Null),
        "suspended_by": suspended_by,
        "suspend_reason": suspend_reason,
        "autoRenew": auto_renew.unwrap_or(false),
        "allow_instance_deletion": pkg_allow_deletion.unwrap_or(true),
        "enableResourcePool": host.enable_resource_pool,
    });

    // 所有者/管理员可见的敏感字段（TS 分支合并）
    let obj = response.as_object_mut().unwrap();
    let owner_sensitive = instance.user_id == user.id || is_host_owner || is_admin;
    if instance.user_id == user.id {
        obj.insert("user_id".into(), json!(instance.user_id));
        obj.insert("isInstanceOwner".into(), json!(true));
    }
    if owner_sensitive {
        if let Some(ip) = &nat_public_ip {
            obj.insert("nat_public_ip".into(), json!(ip));
        }
        if let Some(ip) = &host_ip_address {
            obj.insert("host_ip_address".into(), json!(ip));
        }
        if let Some(ip) = &host_ipv6_address {
            obj.insert("host_ipv6_address".into(), json!(ip));
        }
        obj.insert("hostId".into(), json!(instance.host_id));
    }
    if instance.user_id == user.id {
        if let (Some(start), Some(end)) = (host.nat_port_start, host.nat_port_end) {
            obj.insert("port_range_start".into(), json!(start));
            obj.insert("port_range_end".into(), json!(end));
        }
    }
    if is_host_owner || is_admin {
        obj.insert("isHostOwner".into(), json!(true));
        obj.insert("isInstanceOwner".into(), json!(instance.user_id == user.id));
        obj.insert("isAdmin".into(), json!(is_admin));
    }

    // 用户托管节点：节点所有者详情
    let host_owner: Option<(
        i32,
        String,
        Option<String>,
        String,
        Option<String>,
        DateTime<Utc>,
        String,
    )> = sqlx::query_as(
        "SELECT id, username, email, avatar_style, avatar_badge_id, created_at, role::text \
         FROM users WHERE id = $1",
    )
    .bind(host.user_id)
    .fetch_optional(&state.db)
    .await?;
    if let Some((owner_id, username, email, avatar_style, avatar_badge_id, owner_created_at, owner_role)) =
        host_owner
    {
        if owner_role == "user" {
            is_hosted_instance = true;
            if let Some(obj) = response.as_object_mut() {
                obj.insert("isHostedInstance".into(), json!(true));
            }
        }
        if owner_role != "admin" && email.is_some() {
            let (host_count, instance_count, total_income): (i64, i64, Option<Decimal>) =
                sqlx::query_as(
                    "SELECT (SELECT COUNT(*) FROM hosts WHERE user_id = $1), \
                            (SELECT COUNT(*) FROM instances i JOIN hosts h ON h.id = i.host_id \
                             WHERE h.user_id = $1 AND i.status::text != 'deleted'), \
                            (SELECT SUM(amount) FROM hosting_balance_logs \
                             WHERE user_id = $1 AND type::text = 'income')",
                )
                .bind(owner_id)
                .fetch_one(&state.db)
                .await?;
            let registered_days = (Utc::now() - owner_created_at).num_days();
            // VIP 等级计算用 libs::vip（托管规则）
            let vip_rules = crate::libs::vip::get_vip_rules(&state.db, crate::libs::vip::VipRuleType::Hosting)
                .await
                .unwrap_or_default();
            let hosting_stats = crate::libs::vip::HostingVipStats {
                total_hosting_income: total_income.unwrap_or_default(),
                instance_count,
            };
            let vip_level = crate::libs::vip::calculate_vip_level(
                crate::libs::vip::VipRuleType::Hosting,
                &vip_rules,
                &crate::libs::vip::VipStats::Hosting(&hosting_stats),
            );
            let vip_badge = crate::libs::vip::get_vip_badge_style_for_level(
                &vip_rules,
                crate::libs::vip::VipRuleType::Hosting,
                vip_level,
            );
            if let Some(obj) = response.as_object_mut() {
                obj.insert(
                    "hostOwnerInfo".into(),
                    json!({
                        "id": owner_id,
                        "username": username,
                        "email": email,
                        "avatarStyle": avatar_style,
                        "avatarBadgeId": avatar_badge_id,
                        "hostCount": host_count,
                        "instanceCount": instance_count,
                        "registeredDays": registered_days,
                        "vipLevel": vip_level,
                        "vipBadgeStyle": vip_badge.as_ref().map(|b| json!({
                            "backgroundColor": b.background_color,
                            "textColor": b.text_color,
                        })).unwrap_or(Value::Null),
                    }),
                );
            }
        }
    }

    Ok(Json(json!({ "instance": response })))
}

// ===========================================================================
// GET /:id/password
// ===========================================================================

async fn password(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id_str(&id)?;
    let row: Option<(i32, Option<String>)> = sqlx::query_as(
        "SELECT user_id, root_password FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((owner, root_password)) = row else {
        return Err(ApiError::not_found(code::INSTANCE_NOT_FOUND));
    };
    // AUTH004: 查看密码仅限实例所有者和管理员
    if owner != user.id && user.role != "admin" {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }
    let decrypted = root_password
        .map(|enc| {
            decrypt_sensitive_data(&state.config.encryption_key, &enc)
                .map(Value::String)
                .unwrap_or(Value::Null)
        })
        .unwrap_or(Value::Null);
    Ok(Json(json!({ "rootPassword": decrypted })))
}

// ===========================================================================
// GET /:id/stats
// ===========================================================================

async fn stats(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id_str(&id)?;
    let instance = get_instance_with_permission(&state, &user, instance_id).await?;

    let empty_stats = |memory: i32, disk: i32, status: Option<&str>| {
        let mut body = json!({
            "stats": {
                "memory": { "usage": 0, "limit": memory, "usagePercent": 0 },
                "disk": { "usage": 0, "limit": disk, "usagePercent": 0 },
                "network": { "bytesReceived": 0, "bytesSent": 0 },
            }
        });
        if let Some(status) = status {
            body["status"] = json!(status);
        }
        body
    };

    if instance.status != "running" {
        return Ok(Json(empty_stats(instance.memory, instance.disk, None)));
    }

    let result: Result<Value, ApiError> = async {
        let host = get_host_for_incus(&state, instance.host_id)
            .await?
            .ok_or_else(|| ApiError::internal("Host not found"))?;
        let client = get_incus_client_for_host(&state, &host).await?;
        let state_value = get_instance_state(&client, &instance.incus_id)
            .await
            .map_err(|e| ApiError::internal(format!("{e}")))?;

        // 被动状态同步
        if let Some(status_str) = state_value.get("status").and_then(Value::as_str) {
            let incus_status = map_instance_status(status_str);
            if incus_status != "unknown" && instance.status != incus_status {
                tracing::info!(
                    "[StatusSync] Passive sync: Instance {} status {} → {}",
                    instance.id, instance.status, incus_status
                );
                sqlx::query("UPDATE instances SET status = $2::\"InstanceStatus\" WHERE id = $1")
                    .bind(instance_id)
                    .bind(incus_status)
                    .execute(&state.db)
                    .await?;
            }
        }

        let memory_usage = state_value
            .get("memory")
            .and_then(|m| m.get("usage"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let memory_limit = instance.memory as f64 * 1024.0 * 1024.0;
        let memory_percent = if memory_limit > 0.0 {
            ((memory_usage / memory_limit) * 100.0).round() as i64
        } else {
            0
        };
        let disk_usage = state_value
            .get("disk")
            .and_then(|d| d.get("root"))
            .and_then(|r| r.get("usage"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let disk_limit = instance.disk as f64 * 1024.0 * 1024.0;
        let disk_percent = if disk_limit > 0.0 {
            ((disk_usage / disk_limit) * 100.0).round() as i64
        } else {
            0
        };
        let counters = get_traffic_counters_from_state(&instance.incus_id, &state_value);

        let current_status: String =
            sqlx::query_scalar("SELECT status::text FROM instances WHERE id = $1")
                .bind(instance_id)
                .fetch_one(&state.db)
                .await
                .unwrap_or_else(|_| instance.status.clone());

        Ok(json!({
            "stats": {
                "memory": {
                    "usage": (memory_usage / 1024.0 / 1024.0).round() as i64,
                    "limit": instance.memory,
                    "usagePercent": memory_percent.min(100),
                },
                "disk": {
                    "usage": (disk_usage / 1024.0 / 1024.0).round() as i64,
                    "limit": instance.disk,
                    "usagePercent": disk_percent.min(100),
                },
                "network": {
                    "bytesReceived": counters.rx_bytes.to_string(),
                    "bytesSent": counters.tx_bytes.to_string(),
                },
            },
            "status": current_status,
        }))
    }
    .await;

    match result {
        Ok(value) => Ok(Json(value)),
        Err(err) => {
            tracing::error!("获取实例资源状态失败: {err:?}");
            Ok(Json(empty_stats(instance.memory, instance.disk, Some(&instance.status))))
        }
    }
}

// ===========================================================================
// POST /:id/start | /stop | /restart
// ===========================================================================

async fn power_action(
    state: &SharedAppState,
    user: &AuthUser,
    instance_id: i32,
    action: &str,
) -> Result<Response, Response> {
    let instance = get_instance_with_permission(state, user, instance_id)
        .await
        .map_err(|e| e.into_response())?;

    match action {
        "start" => {
            if instance.status == "running" {
                return Err(ApiError::bad_request(code::INSTANCE_ALREADY_RUNNING).into_response());
            }
            ensure_instance_not_suspended(&instance).map_err(|e| e.into_response())?;
        }
        "stop" => {
            if instance.status == "suspended" {
                // 节点所有者可停止封停实例（维护）
                let host_owner: Option<i32> =
                    sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
                        .bind(instance.host_id)
                        .fetch_optional(&state.db)
                        .await
                        .map_err(|e| ApiError::from_sql(e).into_response())?;
                if host_owner != Some(user.id) {
                    ensure_instance_not_suspended(&instance).map_err(|e| e.into_response())?;
                }
            }
            if instance.status == "stopped" {
                return Err(ApiError::bad_request(code::INSTANCE_ALREADY_STOPPED).into_response());
            }
        }
        "restart" => {
            ensure_instance_not_suspended(&instance).map_err(|e| e.into_response())?;
        }
        _ => unreachable!(),
    }

    check_transfer_lock(state, instance_id)
        .await
        .map_err(|e| e.into_response())?;

    if let Some(active) = get_active_task_for_instance(state, instance_id)
        .await
        .map_err(|e| e.into_response())?
    {
        return Err(task_conflict_response(active.id, &active.task_type, &active.status));
    }

    let task: Result<(i32, String), sqlx::Error> = sqlx::query_as(
        "INSERT INTO instance_tasks (instance_id, host_id, user_id, task_type, status) \
         VALUES ($1, $2, $3, $4::\"InstanceTaskType\", 'PENDING'::\"InstanceTaskStatus\") \
         RETURNING id, status::text AS status",
    )
    .bind(instance_id)
    .bind(instance.host_id)
    .bind(user.id)
    .bind(action)
    .fetch_one(&state.db)
    .await;
    let task = match task {
        Ok(task) => task,
        Err(e) => {
            // 与 TS createInstanceTaskGuarded 相同：唯一约束冲突回读活跃任务
            let unique_violation = e
                .as_database_error()
                .and_then(|d| d.code().map(|c| c.into_owned()))
                .map(|c| c == "23505")
                .unwrap_or(false);
            if unique_violation {
                if let Ok(Some(active)) = get_active_task_for_instance(state, instance_id).await {
                    return Err(task_conflict_response(active.id, &active.task_type, &active.status));
                }
            }
            return Err(ApiError::from_sql(e).into_response());
        }
    };

    create_log_with_instance(
        state,
        user.id,
        "instance",
        &format!("instance.{action}"),
        &format!("Queued {action} task for instance \"{}\"", instance.name),
        "success",
        Some(instance_id),
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "message": format!("Instance {action} task queued"),
            "taskId": task.0,
            "status": task.1,
        })),
    )
        .into_response())
}

macro_rules! power_handler {
    ($name:ident, $action:literal) => {
        async fn $name(
            State(state): State<SharedAppState>,
            user: AuthUser,
            Path(id): Path<String>,
        ) -> Response {
            match parse_id_str(&id) {
                Ok(instance_id) => match power_action(&state, &user, instance_id, $action).await {
                    Ok(response) | Err(response) => response,
                },
                Err(e) => e.into_response(),
            }
        }
    };
}

power_handler!(power_start, "start");
power_handler!(power_stop, "stop");
power_handler!(power_restart, "restart");

// ===========================================================================
// task endpoints
// ===========================================================================

#[derive(Debug, FromRow)]
struct TaskRow {
    id: i32,
    instance_id: i32,
    host_id: i32,
    user_id: i32,
    task_type: String,
    status: String,
    progress: Option<String>,
    error: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    new_instance_id: Option<i32>,
    execution_token: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
}

const TASK_COLUMNS: &str = "id, instance_id, host_id, user_id, task_type::text AS task_type, \
    status::text AS status, progress, error, created_at, started_at, finished_at, \
    new_instance_id, execution_token, lease_expires_at";

async fn get_task_by_id(state: &SharedAppState, task_id: i32) -> Result<Option<TaskRow>, ApiError> {
    Ok(sqlx::query_as::<_, TaskRow>(&format!(
        "SELECT {TASK_COLUMNS} FROM instance_tasks WHERE id = $1"
    ))
    .bind(task_id)
    .fetch_optional(&state.db)
    .await?)
}

async fn instance_task(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id_str(&id)?;
    get_instance_with_permission(&state, &user, instance_id).await?;

    let Some(task) = get_active_task_for_instance(&state, instance_id).await? else {
        return Ok(Json(json!({ "task": null })));
    };
    let host_id: i32 = sqlx::query_scalar("SELECT host_id FROM instance_tasks WHERE id = $1")
        .bind(task.id)
        .fetch_one(&state.db)
        .await?;
    let queue_position = if task.status == "PENDING" {
        get_task_queue_position(&state, task.id, host_id).await
    } else {
        0
    };
    let details: Option<(Option<String>, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<String>)> = sqlx::query_as(
        "SELECT progress, started_at, finished_at, error FROM instance_tasks WHERE id = $1",
    )
    .bind(task.id)
    .fetch_optional(&state.db)
    .await?;
    let (progress, started_at, finished_at, error) =
        details.map(|(a, b, c, d)| (a, b, c, d)).unwrap_or((None, None, None, None));
    let created_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT created_at FROM instance_tasks WHERE id = $1")
            .bind(task.id)
            .fetch_one(&state.db)
            .await?;

    Ok(Json(json!({
        "task": {
            "id": task.id,
            "taskType": task.task_type,
            "status": task.status,
            "progress": progress,
            "error": error,
            "queuePosition": queue_position,
            "createdAt": iso(created_at),
            "startedAt": started_at.map(iso).unwrap_or(Value::Null),
            "finishedAt": finished_at.map(iso).unwrap_or(Value::Null),
        }
    })))
}

async fn task_detail(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(task_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let task_id = parse_id_str(&task_id)?;
    let Some(task) = get_task_by_id(&state, task_id).await? else {
        return Err(ApiError::with_message("TASK_NOT_FOUND", StatusCode::NOT_FOUND, "Task not found"));
    };

    let mut has_permission = task.user_id == user.id || user.role == "admin";
    if !has_permission {
        let host_owner: Option<i32> = sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
            .bind(task.host_id)
            .fetch_optional(&state.db)
            .await?;
        has_permission = host_owner == Some(user.id);
    }
    if !has_permission {
        return Err(ApiError::forbidden(code::FORBIDDEN));
    }

    let queue_position = if task.status == "PENDING" {
        get_task_queue_position(&state, task.id, task.host_id).await
    } else {
        0
    };
    let instance_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM instances WHERE id = $1")
            .bind(task.instance_id)
            .fetch_optional(&state.db)
            .await?;

    Ok(Json(json!({
        "task": {
            "id": task.id,
            "instanceId": task.instance_id,
            "instanceName": instance_name,
            "taskType": task.task_type,
            "status": task.status,
            "progress": task.progress,
            "error": task.error,
            "queuePosition": queue_position,
            "createdAt": iso(task.created_at),
            "startedAt": task.started_at.map(iso).unwrap_or(Value::Null),
            "finishedAt": task.finished_at.map(iso).unwrap_or(Value::Null),
            "newInstanceId": task.new_instance_id,
        }
    })))
}

/// canRecoverInstanceTask: PROCESSING requires admin force + expired lease;
/// PENDING is recoverable via force or after 15 minutes.
fn can_recover_task(task: &TaskRow, now: DateTime<Utc>, force: bool) -> bool {
    if task.status == "PROCESSING" {
        let lease_expired = task.lease_expires_at.map(|t| t <= now).unwrap_or(true);
        return force && lease_expired;
    }
    force || (now - task.created_at).num_milliseconds() >= 15 * 60 * 1000
}

fn conflict_extra(error: &str, code_str: &str, extra: Value) -> Response {
    let mut body = json!({
        "error": error,
        "code": code_str,
    });
    if let (Some(obj), Some(extra_obj)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in extra_obj {
            obj.insert(k.clone(), v.clone());
        }
    }
    (StatusCode::CONFLICT, Json(body)).into_response()
}

#[derive(Deserialize)]
struct RecoverBody {
    force: Option<bool>,
}

async fn recover_task(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(task_id): Path<String>,
    body: Option<Json<RecoverBody>>,
) -> Response {
    let task_id = match parse_id_str(&task_id) {
        Ok(id) if id > 0 => id,
        _ => return ApiError::bad_request(code::INVALID_ID).into_response(),
    };
    let task = match get_task_by_id(&state, task_id).await {
        Ok(Some(task)) => task,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Task not found", "code": "TASK_NOT_FOUND" })),
            )
                .into_response()
        }
        Err(e) => return e.into_response(),
    };

    let host_owner: Option<i32> = match sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
        .bind(task.host_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(owner) => owner,
        Err(e) => return ApiError::from_sql(e).into_response(),
    };
    let is_admin = user.role == "admin";
    let has_permission = task.user_id == user.id || is_admin || host_owner == Some(user.id);
    if !has_permission {
        return ApiError::forbidden(code::FORBIDDEN).into_response();
    }
    if !matches!(task.status.as_str(), "PENDING" | "PROCESSING") {
        return conflict_extra(
            "Task is not active",
            "TASK_NOT_ACTIVE",
            json!({ "currentStatus": task.status }),
        );
    }

    let now = Utc::now();
    let force = is_admin && body.map(|Json(b)| b.force).unwrap_or(Some(false)) == Some(true);
    if !can_recover_task(&task, now, force) {
        if task.status == "PROCESSING" {
            let lease_active = task.lease_expires_at.map(|t| t > now).unwrap_or(false);
            return if lease_active {
                conflict_extra(
                    "Task execution lease is still active",
                    "TASK_LEASE_ACTIVE",
                    json!({ "recoverableAt": task.lease_expires_at.map(iso).unwrap_or(Value::Null) }),
                )
            } else {
                conflict_extra(
                    "Task execution is quarantined; an administrator must confirm the old worker has stopped and use force recovery",
                    "TASK_EXECUTION_QUARANTINED",
                    json!({ "recoverableAt": task.lease_expires_at.map(iso).unwrap_or(Value::Null) }),
                )
            };
        }
        let stale_after = chrono::Duration::milliseconds(15 * 60 * 1000);
        let recoverable_at = task.created_at + stale_after;
        return conflict_extra(
            "Task is still within the normal execution window",
            "TASK_NOT_STALE",
            json!({ "recoverableAt": iso(recoverable_at) }),
        );
    }

    let message = format!("任务异常，由 {} 手动解除", if is_admin { "管理员" } else { "用户" });
    let recovered = if task.status == "PROCESSING" {
        sqlx::query(
            "UPDATE instance_tasks SET status = 'FAILED', progress = 'recovered', \
             error = $3, finished_at = now(), execution_token = NULL, lease_expires_at = NULL \
             WHERE id = $1 AND status = 'PROCESSING' AND execution_token IS NOT DISTINCT FROM $2 \
               AND (lease_expires_at IS NULL OR lease_expires_at <= now())",
        )
        .bind(task_id)
        .bind(&task.execution_token)
        .bind(&message)
        .execute(&state.db)
        .await
    } else {
        sqlx::query(
            "UPDATE instance_tasks SET status = 'FAILED', progress = 'recovered', \
             error = $2, finished_at = now(), execution_token = NULL, lease_expires_at = NULL \
             WHERE id = $1 AND status = 'PENDING'",
        )
        .bind(task_id)
        .bind(&message)
        .execute(&state.db)
        .await
    };
    match recovered {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return conflict_extra(
                "Task state changed; refresh and retry",
                "TASK_STATE_CHANGED",
                json!({}),
            )
        }
        Err(e) => return ApiError::from_sql(e).into_response(),
    }

    create_log_with_instance(
        &state,
        user.id,
        "instance",
        "task.recover",
        &format!(
            "Recovered stuck {} task #{} for instance #{}",
            task.task_type, task.id, task.instance_id
        ),
        "success",
        Some(task.instance_id),
    )
    .await;

    Json(json!({
        "message": "Stuck task recovered",
        "task": { "id": task.id, "status": "FAILED" },
    }))
    .into_response()
}

async fn cancel_task(
    State(state): State<SharedAppState>,
    user: UserOnlyAuth,
    Path(task_id): Path<String>,
) -> Response {
    let task_id = match parse_id_str(&task_id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let task = match get_task_by_id(&state, task_id).await {
        Ok(Some(task)) => task,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Task not found", "code": "TASK_NOT_FOUND" })),
            )
                .into_response()
        }
        Err(e) => return e.into_response(),
    };

    if task.user_id != user.0.id {
        return ApiError::forbidden(code::FORBIDDEN).into_response();
    }
    if task.status != "PENDING" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "只能取消等待中的任务",
                "code": "TASK_CANNOT_CANCEL",
                "currentStatus": task.status,
            })),
        )
            .into_response();
    }

    let result = sqlx::query(
        "UPDATE instance_tasks SET status = 'FAILED', error = '用户取消', finished_at = now() \
         WHERE id = $1 AND status = 'PENDING'",
    )
    .bind(task_id)
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "取消任务失败", "code": "CANCEL_FAILED" })),
            )
                .into_response()
        }
        Err(e) => return ApiError::from_sql(e).into_response(),
    }

    create_log_with_instance(
        &state,
        user.0.id,
        "instance",
        "task.cancel",
        &format!(
            "Cancelled {} task #{} for instance #{}",
            task.task_type, task.id, task.instance_id
        ),
        "success",
        Some(task.instance_id),
    )
    .await;

    Json(json!({
        "message": "Task cancelled",
        "task": { "id": task_id, "status": "FAILED" },
    }))
    .into_response()
}

// ===========================================================================
// cloud-init
// ===========================================================================

fn cloud_init_json(result: &CloudInitStatusResponse) -> Value {
    json!({
        "ready": result.ready,
        "state": result.state,
        "source": result.source,
        "manualOverride": result.manual_override,
        "message": result.message,
        "detectedAt": result.detected_at,
    })
}

async fn cloud_init_status(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let instance_id = parse_id_str(&id)?;
    let instance = get_instance_with_permission(&state, &user, instance_id).await?;

    if instance.status != "running" {
        return Err(ApiError::with_message(
            "INSTANCE_NOT_RUNNING",
            StatusCode::BAD_REQUEST,
            "Instance must be running to check cloud-init status",
        ));
    }
    if instance.incus_id.is_empty() {
        return Err(ApiError::with_message(
            "INSTANCE_NOT_PROVISIONED",
            StatusCode::BAD_REQUEST,
            "Instance is not fully provisioned",
        ));
    }

    // 缓存（instance 行字段）
    let record: Option<(
        Option<String>,
        Option<String>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT cloud_init_state, cloud_init_source, cloud_init_last_checked_at, \
                cloud_init_completed_at, cloud_init_manual_completed_at \
         FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await?;
    if let Some((ci_state, ci_source, checked_at, completed_at, manual_at)) = record {
        let rec = InstanceCloudInitRecord {
            id: instance_id as i64,
            image: instance.image.clone(),
            cloud_init_state: ci_state,
            cloud_init_source: ci_source,
            cloud_init_last_checked_at: checked_at.map(|d| d.to_rfc3339()),
            cloud_init_completed_at: completed_at.map(|d| d.to_rfc3339()),
            cloud_init_manual_completed_at: manual_at.map(|d| d.to_rfc3339()),
            cloud_init_manual_completed_by: None,
        };
        if let Some(cached) = get_cached_cloud_init_status(&rec) {
            return Ok(Json(cloud_init_json(&cached)));
        }
    }

    let host = get_host_for_incus(&state, instance.host_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::HOST_NOT_FOUND))?;

    let result = {
        let client = get_incus_client_for_host(&state, &host).await?;
        detect_cloud_init_status(
            &client,
            &CloudInitDetectionTarget {
                id: instance_id as i64,
                image: instance.image.clone(),
                incus_id: instance.incus_id.clone(),
            },
        )
        .await
    };
    let _ = persist_cloud_init_status(&state.db, instance_id as i64, &result, None).await;
    Ok(Json(cloud_init_json(&result)))
}

async fn cloud_init_manual_complete(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Response {
    let instance_id = match parse_id_str(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let instance = match get_instance_with_permission(&state, &user, instance_id).await {
        Ok(instance) => instance,
        Err(e) => return e.into_response(),
    };

    if instance.status != "running" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Instance must be running to manually complete cloud-init",
                "code": "INSTANCE_NOT_RUNNING",
            })),
        )
            .into_response();
    }
    if let Ok(Some(active)) = get_active_task_for_instance(&state, instance_id).await {
        return task_conflict_response(active.id, &active.task_type, &active.status);
    }
    if instance.incus_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Instance is not fully provisioned",
                "code": "INSTANCE_NOT_PROVISIONED",
            })),
        )
            .into_response();
    }

    let result = CloudInitStatusResponse {
        ready: true,
        state: "manual".into(),
        source: "manual".into(),
        manual_override: true,
        message: "Cloud-init marked complete manually".into(),
        detected_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    };
    if let Err(e) = persist_cloud_init_status(&state.db, instance_id as i64, &result, Some(user.id as i64)).await {
        return ApiError::from_sql(e).into_response();
    }
    create_log_with_instance(
        &state,
        user.id,
        "instance",
        "instance.cloud_init_manual_complete",
        &format!(
            "Manually marked cloud-init as completed for instance \"{}\"",
            instance.name
        ),
        "success",
        Some(instance_id),
    )
    .await;
    Json(cloud_init_json(&result)).into_response()
}

/// instances.billing_mode lookup (InstanceRow does not carry it).
async fn instance_billing_mode(state: &SharedAppState, instance_id: i32) -> Option<String> {
    sqlx::query_scalar("SELECT billing_mode::text FROM instances WHERE id = $1")
        .bind(instance_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
}

// ===========================================================================
// POST /:id/suspend — 封停实例（仅宿主机所有者和管理员）
// ===========================================================================

#[derive(Deserialize)]
struct SuspendBody {
    reason: Option<String>,
}

async fn suspend_instance(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<SuspendBody>>,
) -> Response {
    let instance_id = match parse_id_str(&id) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let reason = body
        .and_then(|Json(b)| b.reason)
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty());

    let instance = match crate::libs::instance_common::get_instance_by_id(&state, instance_id).await
    {
        Ok(Some(i)) => i,
        Ok(None) => return ApiError::not_found(code::INSTANCE_NOT_FOUND).into_response(),
        Err(e) => return e.into_response(),
    };

    let (host_owner, host_name): (Option<i32>, Option<String>) = match sqlx::query_as(
        "SELECT user_id, name FROM hosts WHERE id = $1",
    )
    .bind(instance.host_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(row) => row.map(|(u, n)| (Some(u), Some(n))).unwrap_or((None, None)),
        Err(e) => return ApiError::from_sql(e).into_response(),
    };
    let is_host_owner = host_owner == Some(user.id);
    let is_admin = user.role == "admin";

    // 封停权限：仅管理员和宿主机所有者
    if !is_admin && !is_host_owner {
        return ApiError::forbidden(code::FORBIDDEN).into_response();
    }
    // 已封停的实例不能重复封停
    if instance.status == "suspended" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Instance is already suspended",
                "code": "INSTANCE_ALREADY_SUSPENDED",
            })),
        )
            .into_response();
    }
    // 不能封停已删除的实例
    if instance.status == "deleted" {
        return ApiError::not_found(code::INSTANCE_NOT_FOUND).into_response();
    }

    // 小时计费分支依赖 Wave D 的结算核心（settleInTransaction）；在没有它
    // 的情况下放行会释放预付款而不计已用时长（金钱漏洞），故明确拒绝。
    if instance_billing_mode(&state, instance_id).await.as_deref() == Some("hourly") {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "Hourly billing settlement is not yet ported to the Rust server",
                "code": "NOT_PORTED",
            })),
        )
            .into_response();
    }

    // 如果实例正在运行，先关机（Incus 调用在事务外）
    if instance.status == "running" {
        match get_host_for_incus(&state, instance.host_id).await {
            Ok(Some(host)) => match get_incus_client_for_host(&state, &host).await {
                Ok(client) => {
                    if let Err(err) = crate::libs::incus::incus_instances::stop_instance(
                        &client,
                        &instance.incus_id,
                        true,
                        crate::libs::incus::incus_instances::BusyRetryOptions {
                            allow_cancel_busy_update: false,
                            busy_update_cancel_after_ms: None,
                        },
                    )
                    .await
                    {
                        tracing::error!("[Suspend] Failed to stop instance {instance_id}: {err}");
                        // 继续封停流程，即使关机失败（非小时计费）
                    }
                }
                Err(e) => {
                    tracing::error!("[Suspend] incus client unavailable: {e:?}");
                }
            },
            Ok(None) => {}
            Err(e) => return e.into_response(),
        }
    }

    // 执行封停（advisory lock 4106 事务由版本递增保护；状态条件更新）
    let suspend_result = sqlx::query(
        "UPDATE instances SET status = 'suspended', suspended_at = now(), suspended_by = $2, \
         suspend_reason = $3, version = version + 1 \
         WHERE id = $1 AND status::text != 'deleted' AND status::text != 'suspended'",
    )
    .bind(instance_id)
    .bind(user.id)
    .bind(reason.clone().unwrap_or_default())
    .execute(&state.db)
    .await;
    match suspend_result {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => {
            return ApiError::not_found(code::INSTANCE_NOT_FOUND).into_response();
        }
        Err(e) => return ApiError::from_sql(e).into_response(),
    }

    create_log_with_instance(
        &state,
        user.id,
        "instance",
        "instance.suspend",
        &format!(
            "Suspended instance \"{}\"{}",
            instance.name,
            reason
                .as_ref()
                .map(|r| format!(" (reason: {r})"))
                .unwrap_or_default()
        ),
        "success",
        Some(instance_id),
    )
    .await;

    // 站内信通知实例所有者
    if instance.user_id != user.id {
        crate::routes::users::create_inbox_notification(
            &state,
            instance.user_id,
            "instance_suspended",
            "⛔ 实例已被封停",
            &format!(
                "实例「{}」（节点：{}）已被封停{}",
                instance.name,
                host_name.clone().unwrap_or_default(),
                reason
                    .as_ref()
                    .map(|r| format!("，原因：{r}"))
                    .unwrap_or_default()
            ),
            json!({
                "instanceName": instance.name,
                "hostName": host_name.clone().unwrap_or_default(),
                "suspendReason": reason.unwrap_or_default(),
            }),
        )
        .await;
    }

    (
        StatusCode::OK,
        Json(json!({ "message": "Instance suspended successfully" })),
    )
        .into_response()
}

// ===========================================================================
// POST /:id/unsuspend — 解封。管理员/宿主所有者可直接解封；小時/流量欠款
// 自助路徑依賴 Wave D 結算核心（結算+補繳），回 NOT_PORTED。
// ===========================================================================

async fn unsuspend_instance(
    State(state): State<SharedAppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Response {
    let instance_id = match parse_id_str(&id) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let instance = match crate::libs::instance_common::get_instance_by_id(&state, instance_id).await
    {
        Ok(Some(i)) => i,
        Ok(None) => return ApiError::not_found(code::INSTANCE_NOT_FOUND).into_response(),
        Err(e) => return e.into_response(),
    };

    let host_owner: Option<i32> = match sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
        .bind(instance.host_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => return ApiError::from_sql(e).into_response(),
    };
    let is_host_owner = host_owner == Some(user.id);
    let is_admin = user.role == "admin";
    let is_instance_owner = instance.user_id == user.id;

    if !is_admin && !is_host_owner && !is_instance_owner {
        return ApiError::forbidden(code::FORBIDDEN).into_response();
    }
    // 只能解封已封停的实例
    if instance.status != "suspended" {
        return ApiError::bad_request(code::INSTANCE_NOT_SUSPENDED).into_response();
    }

    // 到期封停：到期时间仍在过去则不允许解封
    if instance.suspend_reason.as_deref() == Some("expired") {
        let expires_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT expires_at FROM instances WHERE id = $1")
                .bind(instance_id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        if let Some(expires_at) = expires_at {
            if expires_at <= Utc::now() {
                return ApiError::new(code::INSTANCE_SUSPENDED_EXPIRED, StatusCode::FORBIDDEN)
                    .into_response();
            }
        }
    }

    // 小时/流量欠款自助解封依赖 Wave D 結算核心（結算+補繳），明確拒絕。
    if instance_billing_mode(&state, instance_id).await.as_deref() == Some("hourly")
        && instance.suspend_reason.as_deref() == Some("hourly_billing_insufficient_balance")
    {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "Hourly billing settlement is not yet ported to the Rust server",
                "code": "NOT_PORTED",
            })),
        )
            .into_response();
    }
    if instance.suspend_reason.as_deref() == Some("traffic_billing_insufficient_balance") {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "Traffic billing settlement is not yet ported to the Rust server",
                "code": "NOT_PORTED",
            })),
        )
            .into_response();
    }

    // 执行解封（解封后设为 stopped，清空封停字段，version+1）
    let result = sqlx::query(
        "UPDATE instances SET status = 'stopped', suspended_at = NULL, suspended_by = NULL, \
         suspend_reason = NULL, version = version + 1 \
         WHERE id = $1 AND status = 'suspended'",
    )
    .bind(instance_id)
    .execute(&state.db)
    .await;
    match result {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => {
            return ApiError::with_message(
                "INSTANCE_NOT_SUSPENDED",
                StatusCode::BAD_REQUEST,
                "实例未被封停或正在删除",
            )
            .into_response()
        }
        Err(e) => return ApiError::from_sql(e).into_response(),
    }

    create_log_with_instance(
        &state,
        user.id,
        "instance",
        "instance.unsuspend",
        &format!("Unsuspended instance \"{}\"", instance.name),
        "success",
        Some(instance_id),
    )
    .await;

    if instance.user_id != user.id {
        let host_name: Option<String> =
            sqlx::query_scalar("SELECT name FROM hosts WHERE id = $1")
                .bind(instance.host_id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        crate::routes::users::create_inbox_notification(
            &state,
            instance.user_id,
            "instance_unsuspended",
            "✅ 实例已解除封停",
            &format!(
                "实例「{}」（节点：{}）已解除封停",
                instance.name,
                host_name.clone().unwrap_or_default()
            ),
            json!({
                "instanceName": instance.name,
                "hostName": host_name.unwrap_or_default(),
            }),
        )
        .await;
    }

    (
        StatusCode::OK,
        Json(json!({ "message": "Instance unsuspended successfully" })),
    )
        .into_response()
}

// ===========================================================================
// POST /:id/sync-status — 从 Incus 同步状态与内网 IP
// ===========================================================================

async fn sync_status(State(state): State<SharedAppState>, user: AuthUser, Path(id): Path<String>) -> Response {
    let instance_id = match parse_id_str(&id) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let instance = match crate::libs::instance_common::get_instance_by_id(&state, instance_id).await
    {
        Ok(Some(i)) => i,
        Ok(None) => return ApiError::not_found(code::INSTANCE_NOT_FOUND).into_response(),
        Err(e) => return e.into_response(),
    };

    #[derive(Debug, FromRow)]
    struct SyncHost {
        caddy_enabled: bool,
        nat_public_ip: Option<String>,
        ip_address: Option<String>,
        caddy_port: i32,
        caddy_username: Option<String>,
        caddy_password: Option<String>,
    }
    let host: Option<SyncHost> = match sqlx::query_as(
        "SELECT caddy_enabled, nat_public_ip, ip_address, caddy_port, caddy_username, caddy_password \
         FROM hosts WHERE id = $1",
    )
    .bind(instance.host_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(v) => v,
        Err(e) => return ApiError::from_sql(e).into_response(),
    };
    let host_owner: Option<i32> = match sqlx::query_scalar("SELECT user_id FROM hosts WHERE id = $1")
        .bind(instance.host_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => return ApiError::from_sql(e).into_response(),
    };
    let is_instance_owner = instance.user_id == user.id;
    let is_host_owner = host_owner == Some(user.id);
    let is_admin = user.role == "admin";
    if !is_instance_owner && !is_host_owner && !is_admin {
        return ApiError::forbidden(code::FORBIDDEN).into_response();
    }
    if host.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "节点不存在" })),
        )
            .into_response();
    }

    let host_for_client = match get_host_for_incus(&state, instance.host_id).await {
        Ok(Some(h)) => h,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "节点不存在" })),
            )
                .into_response()
        }
        Err(e) => return e.into_response(),
    };
    let client = match get_incus_client_for_host(&state, &host_for_client).await {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": format!("无法连接到节点: {e:?}") })),
            )
                .into_response()
        }
    };

    let inst_ips: Option<(Option<String>, Option<String>)> = match sqlx::query_as(
        "SELECT ipv4, ipv6 FROM instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(v) => v,
        Err(e) => return ApiError::from_sql(e).into_response(),
    };
    let (inst_ipv4, inst_ipv6) = inst_ips.unwrap_or((None, None));

    let outcome: Result<Value, String> = async {
        let state_value = get_instance_state(&client, &instance.incus_id)
            .await
            .map_err(|e| e.to_string())?;
        let incus_instance = crate::libs::incus::incus_instances::get_instance(&client, &instance.incus_id)
            .await
            .map_err(|e| e.to_string())?;

        let incus_status_raw = state_value
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| "无法获取实例状态".to_string())?;
        let incus_status = map_instance_status(incus_status_raw);
        if incus_status == "unknown" {
            return Err(format!("未知状态: {incus_status_raw}"));
        }

        let current_status = instance.status.clone();
        let status_changed = current_status != incus_status;
        if status_changed {
            sqlx::query("UPDATE instances SET status = $2::\"InstanceStatus\" WHERE id = $1")
                .bind(instance_id)
                .bind(incus_status)
                .execute(&state.db)
                .await
                .map_err(|e| e.to_string())?;
        }

        // 同步内网 IPv4/IPv6；变更对比在本端计算（persist 不返回差异）
        let sync_target = crate::libs::incus::managed_instance_provision::InstanceNetworkSyncTarget {
            id: instance_id as i64,
            name: Some(instance.name.clone()),
            host_id: Some(instance.host_id as i64),
            network_mode: Some(instance.network_mode.clone()),
            ipv4: inst_ipv4.clone(),
            ipv6: inst_ipv6.clone(),
        };
        let devices_value = Value::Object(incus_instance.devices.clone());
        let expanded_devices_value = Value::Object(incus_instance.expanded_devices.clone());
        let resolved =
            crate::libs::incus::managed_instance_provision::resolve_instance_network_addresses(
                &sync_target,
                Some(&devices_value),
                Some(&expanded_devices_value),
                Some(&state_value),
            );
        let ipv4_changed = resolved.ipv4 != inst_ipv4;
        let old_ipv4 = inst_ipv4.clone();
        let new_ipv4 = resolved.ipv4.clone();
        let ipv6_changed = resolved.ipv6 != inst_ipv6;
        let old_ipv6 = inst_ipv6.clone();
        let new_ipv6 = resolved.ipv6.clone();
        crate::libs::incus::managed_instance_provision::persist_resolved_instance_network_addresses(
            &state.db,
            &sync_target,
            &resolved,
        )
        .await
        .map_err(|e| e.to_string())?;

        // IPv4 变化 → 更新 Caddy 反代站点
        let mut proxy_sites_updated: i64 = 0;
        if ipv4_changed {
            if let Some(new_ipv4) = &new_ipv4 {
                if let Some(host) = &host {
                    if host.caddy_enabled {
                        if let (Some(target), Some(username), Some(password)) = (
                            host.nat_public_ip.clone().or(host.ip_address.clone()),
                            &host.caddy_username,
                            &host.caddy_password,
                        ) {
                            if let Ok(caddy) = crate::libs::host_caddy::CaddyClient::new(
                                &target,
                                host.caddy_port as i64,
                                username,
                                password,
                            ) {
                                let sites: Vec<(String, i32, bool)> = sqlx::query_as(
                                    "SELECT domain, target_port, https_enabled FROM proxy_sites \
                                     WHERE instance_id = $1 AND status::text = 'active' AND enabled = true",
                                )
                                .bind(instance_id)
                                .fetch_all(&state.db)
                                .await
                                .unwrap_or_default();
                                for (domain, target_port, https_enabled) in sites {
                                    if caddy.delete_site(&domain).await.is_ok()
                                        && caddy
                                            .add_site(&domain, new_ipv4, target_port as i64, https_enabled)
                                            .await
                                            .is_ok()
                                    {
                                        proxy_sites_updated += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(json!({
            "success": true,
            "statusChanged": status_changed,
            "from": if status_changed { Some(current_status) } else { None },
            "to": if status_changed { Some(incus_status.to_string()) } else { None },
            "currentStatus": incus_status,
            "ipv4Changed": ipv4_changed,
            "oldIpv4": if ipv4_changed { old_ipv4 } else { None },
            "newIpv4": if ipv4_changed { new_ipv4 } else { None },
            "ipv6Changed": ipv6_changed,
            "oldIpv6": if ipv6_changed { old_ipv6 } else { None },
            "newIpv6": if ipv6_changed { new_ipv6 } else { None },
            "proxySitesUpdated": if ipv4_changed { Some(proxy_sites_updated) } else { None },
        }))
    }
    .await;

    match outcome {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(message) => {
            if message.contains("not found") || message.contains("Instance not found") {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "实例在节点上不存在" })),
                )
                    .into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": format!("同步失败: {message}") })),
                )
                    .into_response()
            }
        }
    }
}
