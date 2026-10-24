//! Host address registry: input/resolved alias bookkeeping, conflict sync, and
//! resolution logging.
//! Port of services/host-address-monitor.ts + db/host-addresses.ts — only the
//! pieces the host create/update routes need (the cron poll/backfill jobs stay
//! with the scheduler port).
//!
//! Locking: the TS uses the Redis-backed distributed lock
//! `host-address-registry` (60s expire, 10s wait). The Rust port takes a
//! transaction-scoped Postgres advisory lock in a dedicated namespace instead
//! (the Redis SharedState has no blocking lock primitive), which preserves the
//! serializes-create/update-with-conflict-check semantics for the API routes.
//! Namespace 4114 is reserved here because db.rs (shared file) cannot gain a
//! new constant.

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::error::{code, ApiError};

pub const HOST_ADDRESS_REGISTRY_LOCK_NAMESPACE: i32 = 4114;
pub const HOST_ADDRESS_REGISTRY_LOCK_KEY: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedAddress {
    pub address: String,
    /// 'ipv4' | 'ipv6' | 'domain'
    pub kind: String,
}

/// Mirrors HostAddressSnapshot.
#[derive(Debug, Clone)]
pub struct HostAddressSnapshot {
    pub input: NormalizedAddress,
    pub resolved: Vec<NormalizedAddress>,
    /// input + resolved aliases (in TS insertion order).
    pub aliases: Vec<NormalizedAddress>,
}

/// Mirrors HostAddressRegistryError: carries the wire error code + details.
#[derive(Debug, Clone)]
pub struct HostAddressRegistryError {
    pub error_code: &'static str,
    pub details: Option<String>,
}

impl HostAddressRegistryError {
    pub fn to_api_error(&self) -> ApiError {
        let mut err = ApiError::new(self.error_code, axum::http::StatusCode::BAD_REQUEST);
        if let Some(details) = &self.details {
            err = err.with_details(details.clone());
        }
        err
    }
}

fn normalize_address(input: &str) -> NormalizedAddress {
    static BRACKETS: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\[|\]$"#).expect("valid regex"));
    let trimmed = BRACKETS.replace_all(input.trim(), "");
    match trimmed.parse::<std::net::IpAddr>() {
        // `Address4.correctForm()` / `Address6.correctForm()` emit the
        // canonical compressed form for both families.
        Ok(ip) => NormalizedAddress {
            address: ip.to_string(),
            kind: if ip.is_ipv4() { "ipv4" } else { "ipv6" }.to_string(),
        },
        Err(_) => {
            let mut domain = trimmed.to_lowercase();
            if domain.ends_with('.') {
                domain.pop();
            }
            NormalizedAddress {
                address: domain,
                kind: "domain".to_string(),
            }
        }
    }
}

fn extract_input_address(url: &str) -> Result<NormalizedAddress, HostAddressRegistryError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| HostAddressRegistryError {
        error_code: code::HOST_ADDRESS_UNRESOLVABLE,
        details: Some(format!("宿主机连接地址格式无效: {url}")),
    })?;
    let hostname = parsed.host_str().unwrap_or_default();
    Ok(normalize_address(hostname))
}

/// Mirrors resolveDomainAddresses: dns.lookup all + verbatim, dedup by
/// normalized address; empty/failed resolution -> HOST_ADDRESS_UNRESOLVABLE.
async fn resolve_domain_addresses(domain: &str) -> Result<Vec<NormalizedAddress>, HostAddressRegistryError> {
    let resolved = tokio::net::lookup_host((domain, 0u16)).await;
    let addrs = match resolved {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(err) => {
            return Err(HostAddressRegistryError {
                error_code: code::HOST_ADDRESS_UNRESOLVABLE,
                details: Some(format!("面板当前无法解析域名 {domain} ({err})")),
            })
        }
    };

    let mut unique: Vec<NormalizedAddress> = Vec::new();
    for addr in addrs {
        let normalized = normalize_address(&addr.ip().to_string());
        if !unique.iter().any(|u| u.address == normalized.address) {
            unique.push(normalized);
        }
    }
    if unique.is_empty() {
        return Err(HostAddressRegistryError {
            error_code: code::HOST_ADDRESS_UNRESOLVABLE,
            details: Some(format!("面板当前未解析到域名 {domain}")),
        });
    }
    Ok(unique)
}

fn build_snapshot(input: NormalizedAddress, resolved: Vec<NormalizedAddress>) -> HostAddressSnapshot {
    let mut aliases: Vec<NormalizedAddress> = Vec::new();
    aliases.push(input.clone());
    for item in &resolved {
        if !aliases.iter().any(|a| a.address == item.address) {
            aliases.push(item.clone());
        }
    }
    HostAddressSnapshot {
        input,
        resolved,
        aliases,
    }
}

/// Mirrors prepareHostAddressSnapshotForWrite (DNS resolve + conflict check).
/// The conflict check reads aliases outside the transaction; callers that need
/// serializable semantics wrap this in the registry lock (see hosts.rs).
pub async fn prepare_host_address_snapshot_for_write(
    pool: &PgPool,
    url: &str,
    exclude_host_id: Option<i32>,
) -> Result<HostAddressSnapshot, HostAddressRegistryError> {
    let input = extract_input_address(url)?;
    let resolved = if input.kind == "domain" {
        resolve_domain_addresses(&input.address).await?
    } else {
        Vec::new()
    };

    let snapshot = build_snapshot(input, resolved);
    let conflict = check_alias_conflicts(pool, &snapshot, exclude_host_id).await?;
    if let Some(detail) = conflict {
        return Err(HostAddressRegistryError {
            error_code: code::HOST_ADDRESS_EXISTS,
            details: Some(detail),
        });
    }
    Ok(snapshot)
}

/// Returns the TS `detail` string when another host already owns one of the
/// snapshot's alias addresses, mirroring getAliasesByAddresses + formatting.
async fn check_alias_conflicts(
    pool: &PgPool,
    snapshot: &HostAddressSnapshot,
    exclude_host_id: Option<i32>,
) -> Result<Option<String>, HostAddressRegistryError> {
    if snapshot.aliases.is_empty() {
        return Ok(None);
    }
    let addresses: Vec<String> = snapshot.aliases.iter().map(|a| a.address.clone()).collect();
    let rows: Vec<(String, i32, String)> = sqlx::query_as(
        "SELECT a.address, h.id, h.name FROM host_address_aliases a \
         JOIN hosts h ON h.id = a.host_id \
         WHERE a.address = ANY($1) AND ($2::int IS NULL OR a.host_id <> $2)",
    )
    .bind(&addresses)
    .bind(exclude_host_id)
    .fetch_all(pool)
    .await
    .map_err(|_| HostAddressRegistryError {
        error_code: code::INTERNAL_ERROR,
        details: None,
    })?;

    if rows.is_empty() {
        return Ok(None);
    }

    // Group by address preserving first-seen order (TS Map semantics).
    let mut order: Vec<String> = Vec::new();
    let mut by_address: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for (address, host_id, host_name) in rows {
        let label = format!("{host_name}(#{host_id})");
        let entry = by_address.entry(address.clone()).or_default();
        if !entry.contains(&label) {
            if !order.contains(&address) {
                order.push(address.clone());
            }
            entry.push(label);
        }
    }
    let detail = order
        .into_iter()
        .map(|address| {
            let hosts = by_address.get(&address).cloned().unwrap_or_default();
            format!("{address} 已被节点 {} 使用", hosts.join(", "))
        })
        .collect::<Vec<_>>()
        .join("；");
    Ok(Some(detail))
}

/// Mirrors persistHostAddressSnapshot. Runs on an existing transaction.
pub async fn persist_in_tx(
    exec: &mut sqlx::PgConnection,
    host_id: i32,
    snapshot: &HostAddressSnapshot,
    trigger: &str,
) -> Result<(), sqlx::Error>
{
    // deleteMany input aliases whose address differs from the snapshot input.
    sqlx::query(
        "DELETE FROM host_address_aliases WHERE host_id = $1 AND source = 'input' AND address <> $2",
    )
    .bind(host_id)
    .bind(&snapshot.input.address)
    .execute(&mut *exec)
    .await?;

    // upsertHostInputAlias.
    sqlx::query(
        "INSERT INTO host_address_aliases (host_id, address, kind, source) \
         VALUES ($1, $2, $3::\"HostAddressKind\", 'input') \
         ON CONFLICT (host_id, address) DO UPDATE SET kind = EXCLUDED.kind, source = 'input'",
    )
    .bind(host_id)
    .bind(&snapshot.input.address)
    .bind(&snapshot.input.kind)
    .execute(&mut *exec)
    .await?;

    // replaceHostResolvedAliases.
    sqlx::query("DELETE FROM host_address_aliases WHERE host_id = $1 AND source = 'resolved'")
        .bind(host_id)
        .execute(&mut *exec)
        .await?;
    for item in &snapshot.resolved {
        sqlx::query(
            "INSERT INTO host_address_aliases (host_id, address, kind, source) \
             VALUES ($1, $2, $3::\"HostAddressKind\", 'resolved') ON CONFLICT DO NOTHING",
        )
        .bind(host_id)
        .bind(&item.address)
        .bind(&item.kind)
        .execute(&mut *exec)
        .await?;
    }

    // createHostAddressResolutionLog (success).
    let resolved_addresses: Vec<String> =
        snapshot.resolved.iter().map(|r| r.address.clone()).collect();
    let alias_addresses: Vec<String> = snapshot.aliases.iter().map(|a| a.address.clone()).collect();
    sqlx::query(
        "INSERT INTO host_address_resolution_logs \
         (host_id, input_address, input_kind, trigger, status, resolved_addresses, error, details) \
         VALUES ($1, $2, $3::\"HostAddressKind\", $4::\"HostAddressCheckTrigger\", \
                 'success'::\"HostAddressCheckStatus\", $5, NULL, $6)",
    )
    .bind(host_id)
    .bind(&snapshot.input.address)
    .bind(&snapshot.input.kind)
    .bind(trigger)
    .bind(json!(resolved_addresses))
    .bind(json!({ "aliasAddresses": alias_addresses }))
    .execute(&mut *exec)
    .await?;

    // syncHostAddressConflicts over existing + snapshot aliases.
    let existing: Vec<String> =
        sqlx::query_as("SELECT address FROM host_address_aliases WHERE host_id = $1")
            .bind(host_id)
            .fetch_all(&mut *exec)
            .await?
            .into_iter()
            .map(|(a,): (String,)| a)
            .collect();
    let mut all_addresses = existing;
    for alias in &snapshot.aliases {
        all_addresses.push(alias.address.clone());
    }
    sync_host_address_conflicts(&mut *exec, &all_addresses).await?;
    Ok(())
}

/// Mirrors recordHostAddressResolutionFailure (failed resolution snapshot).
/// The caller supplies the already-extracted input address.
pub async fn record_host_address_resolution_failure_in_tx(
    exec: &mut sqlx::PgConnection,
    host_id: i32,
    input: &NormalizedAddress,
    trigger: &str,
    error: &HostAddressRegistryError,
) -> Result<(), sqlx::Error>
{
    let existing: Vec<String> =
        sqlx::query_as("SELECT address FROM host_address_aliases WHERE host_id = $1")
            .bind(host_id)
            .fetch_all(&mut *exec)
            .await?
            .into_iter()
            .map(|(a,): (String,)| a)
            .collect();

    sqlx::query(
        "DELETE FROM host_address_aliases WHERE host_id = $1 AND source = 'input' AND address <> $2",
    )
    .bind(host_id)
    .bind(&input.address)
    .execute(&mut *exec)
    .await?;

    sqlx::query(
        "INSERT INTO host_address_aliases (host_id, address, kind, source) \
         VALUES ($1, $2, $3::\"HostAddressKind\", 'input') \
         ON CONFLICT (host_id, address) DO UPDATE SET kind = EXCLUDED.kind, source = 'input'",
    )
    .bind(host_id)
    .bind(&input.address)
    .bind(&input.kind)
    .execute(&mut *exec)
    .await?;

    sqlx::query(
        "INSERT INTO host_address_resolution_logs \
         (host_id, input_address, input_kind, trigger, status, resolved_addresses, error, details) \
         VALUES ($1, $2, $3::\"HostAddressKind\", $4::\"HostAddressCheckTrigger\", \
                 'failed'::\"HostAddressCheckStatus\", $5::jsonb, $6, $7)",
    )
    .bind(host_id)
    .bind(&input.address)
    .bind(&input.kind)
    .bind(trigger)
    .bind(json!(Vec::<String>::new()))
    .bind(error.details.clone().unwrap_or_else(|| error.error_code.to_string()))
    .bind(json!({ "errorCode": error.error_code }))
    .execute(&mut *exec)
    .await?;

    let mut all = existing;
    all.push(input.address.clone());
    sync_host_address_conflicts(&mut *exec, &all).await?;
    Ok(())
}

/// Mirrors logHostAddressResolutionFailure: warn log + logs table row.
pub async fn log_host_address_resolution_failure(
    pool: &PgPool,
    actor_user_id: Option<i32>,
    host_label: &str,
    url: &str,
    trigger: &str,
    error: &HostAddressRegistryError,
) {
    let input = match extract_input_address(url) {
        Ok(v) => v,
        Err(_) => NormalizedAddress {
            address: url.to_string(),
            kind: "domain".to_string(),
        },
    };
    let message = format!(
        "[HostAddress] {trigger} 解析失败: {host_label} -> {}; {}",
        input.address,
        error.details.clone().unwrap_or_else(|| error.error_code.to_string())
    );
    tracing::warn!("{message}");

    let insert = sqlx::query(
        "INSERT INTO logs (user_id, module, action, content, result) \
         VALUES ($1, 'host', 'host.address_resolve', $2, 'warning')",
    )
    .bind(actor_user_id)
    .bind(&message)
    .execute(pool)
    .await;
    if let Err(err) = insert {
        tracing::warn!("log_host_address_resolution_failure log insert failed: {err}");
    }
}

/// Mirrors syncHostAddressConflicts: create/reactivate pairwise conflicts and
/// resolve stale active conflicts for the given addresses.
pub async fn sync_host_address_conflicts(
    exec: &mut sqlx::PgConnection,
    addresses: &[String],
) -> Result<(), sqlx::Error>
{
    if addresses.is_empty() {
        return Ok(());
    }
    let mut unique: Vec<String> = Vec::new();
    for a in addresses {
        if !unique.contains(a) {
            unique.push(a.clone());
        }
    }

    let rows: Vec<(String, i32, String)> = sqlx::query_as(
        "SELECT a.address, a.host_id, h.name FROM host_address_aliases a \
         JOIN hosts h ON h.id = a.host_id \
         WHERE a.address = ANY($1) ORDER BY a.address ASC, a.host_id ASC",
    )
    .bind(&unique)
    .fetch_all(&mut *exec)
    .await?;

    // Group aliases per address, dedupe hosts by id.
    let mut by_address: Vec<(String, Vec<(i32, String)>)> = Vec::new();
    for (address, host_id, host_name) in rows {
        match by_address.iter_mut().find(|(a, _)| *a == address) {
            Some((_, hosts)) => {
                if !hosts.iter().any(|(id, _)| *id == host_id) {
                    hosts.push((host_id, host_name));
                }
            }
            None => by_address.push((address, vec![(host_id, host_name)])),
        }
    }

    for (address, hosts) in by_address {
        if hosts.len() < 2 {
            continue;
        }
        for i in 0..hosts.len() {
            for j in (i + 1)..hosts.len() {
                let (host_a_id, _) = hosts[i];
                let (host_b_id, _) = hosts[j];
                sqlx::query(
                    "INSERT INTO host_address_conflicts (host_a_id, host_b_id, address, status) \
                     VALUES ($1, $2, $3, 'active') \
                     ON CONFLICT (host_a_id, host_b_id, address) DO UPDATE \
                     SET status = 'active', resolved_at = NULL, last_detected_at = now()",
                )
                .bind(host_a_id)
                .bind(host_b_id)
                .bind(&address)
                .execute(&mut *exec)
                .await?;
            }
        }
    }

    // Resolve active conflicts that are no longer backed by two aliases.
    sqlx::query(
        "UPDATE host_address_conflicts c SET status = 'resolved', resolved_at = now() \
         WHERE c.status = 'active' AND c.address = ANY($1) AND NOT EXISTS ( \
           SELECT 1 FROM host_address_aliases aa JOIN host_address_aliases ab \
             ON aa.address = c.address AND ab.address = c.address \
            AND aa.host_id = c.host_a_id AND ab.host_id = c.host_b_id)",
    )
    .bind(&unique)
    .execute(&mut *exec)
    .await?;
    Ok(())
}

/// Serialized registry section: advisory xact lock helper used by the routes.
pub async fn registry_lock_in_tx(
    tx: &mut sqlx::PgConnection,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1::int, $2::bigint)")
        .bind(HOST_ADDRESS_REGISTRY_LOCK_NAMESPACE)
        .bind(HOST_ADDRESS_REGISTRY_LOCK_KEY)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::from_sql)?;
    Ok(())
}
