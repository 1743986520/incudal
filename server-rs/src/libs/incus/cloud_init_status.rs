//! Cloud-init status detection.
//! Port of lib/cloud-init-status.ts. The pure status helpers and the Incus
//! Files-API polling are ported verbatim; the prisma persistence helpers are
//! ported with sqlx against the same `instances` columns.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::libs::incus::incus_client::{IncusClient, IncusError};

pub type CloudInitState = &'static str;

pub const STATE_MANUAL: CloudInitState = "manual";
pub const STATE_DONE: CloudInitState = "done";
pub const STATE_DONE_WITH_ERRORS: CloudInitState = "done_with_errors";
pub const STATE_RUNNING: CloudInitState = "running";
pub const STATE_DISABLED: CloudInitState = "disabled";
pub const STATE_UNSUPPORTED: CloudInitState = "unsupported";
pub const STATE_AGENT_UNAVAILABLE: CloudInitState = "agent_unavailable";
pub const STATE_UNKNOWN: CloudInitState = "unknown";

pub type CloudInitSource = &'static str;

pub const SOURCE_MANUAL: CloudInitSource = "manual";
pub const SOURCE_STATUS_JSON: CloudInitSource = "status_json";
pub const SOURCE_BOOT_FINISHED: CloudInitSource = "boot_finished";
pub const SOURCE_IMAGE: CloudInitSource = "image";
pub const SOURCE_UNKNOWN: CloudInitSource = "unknown";

/// Mirrors `CloudInitStatusResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudInitStatusResponse {
    pub ready: bool,
    pub state: String,
    pub source: String,
    pub manual_override: bool,
    pub message: String,
    /// ISO-8601 timestamp.
    pub detected_at: String,
}

/// Mirrors the instance fields the module reads.
#[derive(Debug, Clone, Default)]
pub struct InstanceCloudInitRecord {
    pub id: i64,
    pub image: String,
    pub cloud_init_state: Option<String>,
    pub cloud_init_source: Option<String>,
    pub cloud_init_last_checked_at: Option<String>,
    pub cloud_init_completed_at: Option<String>,
    pub cloud_init_manual_completed_at: Option<String>,
    pub cloud_init_manual_completed_by: Option<i64>,
}

/// Instance fields needed by `detectCloudInitStatus`.
#[derive(Debug, Clone, Default)]
pub struct CloudInitDetectionTarget {
    pub id: i64,
    pub image: String,
    pub incus_id: String,
}

const STATUS_JSON_PATHS: [&str; 2] = [
    "/run/cloud-init/status.json",
    "/var/lib/cloud/data/status.json",
];

const BOOT_FINISHED_PATH: &str = "/var/lib/cloud/instance/boot-finished";

fn is_ready_state(state: &str) -> bool {
    matches!(
        state,
        STATE_MANUAL | STATE_DONE | STATE_DONE_WITH_ERRORS | STATE_DISABLED | STATE_UNSUPPORTED
    )
}

fn is_cacheable_state(state: &str) -> bool {
    is_ready_state(state)
}

fn iso_now() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    chrono::DateTime::from_timestamp_millis(millis)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).expect("epoch"))
        .to_rfc3339()
}

fn build_response(
    state: CloudInitState,
    source: CloudInitSource,
    message: &str,
    detected_at: &str,
) -> CloudInitStatusResponse {
    CloudInitStatusResponse {
        ready: is_ready_state(state),
        state: state.to_string(),
        source: source.to_string(),
        manual_override: state == STATE_MANUAL,
        message: message.to_string(),
        detected_at: detected_at.to_string(),
    }
}

fn is_cloud_image_alias(image_alias: &str) -> bool {
    image_alias.to_lowercase().contains("/cloud")
}

fn get_nested_value<'a>(source: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = source;
    for segment in path {
        current = current.get(segment)?;
    }
    Some(current)
}

fn get_nested_string<'a>(source: &'a Value, paths: &[&[&str]]) -> Option<String> {
    for path in paths {
        if let Some(value) = get_nested_value(source, path) {
            if let Some(text) = value.as_str() {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

fn has_issues(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
        Value::Array(items) => items.iter().any(has_issues),
        Value::String(text) => !text.trim().is_empty(),
        Value::Object(map) => {
            for (key, nested) in map {
                if key == "errors" || key == "_errors" || key == "recoverable_errors" || key == "recoverableErrors"
                {
                    if has_issues(nested) {
                        return true;
                    }
                    continue;
                }
                if nested.is_object() || nested.is_array() {
                    if has_issues(nested) {
                        return true;
                    }
                }
            }
            false
        }
    }
}

/// Mirrors `parseStatusPayload`.
pub fn parse_status_payload(raw_content: &str) -> Option<(CloudInitState, String)> {
    if raw_content.trim().is_empty() {
        return None;
    }
    let parsed: Value = serde_json::from_str(raw_content).ok()?;

    let raw_status = get_nested_string(
        &parsed,
        &[
            &["extended_status"],
            &["status"],
            &["v1", "extended_status"],
            &["v1", "status"],
            &["v1", "stage"],
            &["stage"],
        ],
    )
    .map(|s| s.to_lowercase())
    .unwrap_or_default();

    let has_errors = has_issues(&parsed);

    if raw_status.contains("disabled") {
        return Some((
            STATE_DISABLED,
            "Cloud-init is disabled for this instance".to_string(),
        ));
    }

    if raw_status.contains("done") || raw_status.contains("finished") || raw_status.contains("final")
    {
        if has_errors
            || raw_status.contains("error")
            || raw_status.contains("degraded")
        {
            return Some((
                STATE_DONE_WITH_ERRORS,
                "Cloud-init completed with warnings".to_string(),
            ));
        }
        return Some((STATE_DONE, "Cloud-init completed".to_string()));
    }

    if raw_status.contains("running")
        || raw_status.contains("init")
        || raw_status.contains("modules")
        || raw_status.contains("not started")
        || raw_status.contains("not run")
    {
        return Some((
            STATE_RUNNING,
            "Cloud-init is still running".to_string(),
        ));
    }

    if raw_status.contains("error") || raw_status.contains("degraded") {
        return Some((
            STATE_RUNNING,
            "Cloud-init reported issues before completion".to_string(),
        ));
    }

    None
}

async fn read_instance_file(
    client: &IncusClient,
    instance_name: &str,
    file_path: &str,
) -> Result<(String, u16), IncusError> {
    let encoded_path = urlencoding::encode(file_path);
    client
        .read_file(&format!(
            "/1.0/instances/{instance_name}/files?path={encoded_path}"
        ))
        .await
}

/// Mirrors `getCachedCloudInitStatus`: returns the persisted status only when
/// the state is cacheable.
pub fn get_cached_cloud_init_status(
    instance: &InstanceCloudInitRecord,
) -> Option<CloudInitStatusResponse> {
    let detected_at = instance
        .cloud_init_last_checked_at
        .clone()
        .or_else(|| instance.cloud_init_manual_completed_at.clone())
        .or_else(|| instance.cloud_init_completed_at.clone())?;

    let state = instance.cloud_init_state.clone();
    let source = instance
        .cloud_init_source
        .clone()
        .unwrap_or_else(|| SOURCE_UNKNOWN.to_string());

    let state: CloudInitState = match state.as_deref() {
        Some(STATE_MANUAL) => STATE_MANUAL,
        Some(STATE_DONE) => STATE_DONE,
        Some(STATE_DONE_WITH_ERRORS) => STATE_DONE_WITH_ERRORS,
        Some(STATE_DISABLED) => STATE_DISABLED,
        Some(STATE_UNSUPPORTED) => STATE_UNSUPPORTED,
        Some(STATE_RUNNING) | Some(STATE_AGENT_UNAVAILABLE) | Some(STATE_UNKNOWN) | None => {
            return None
        }
        _ => return None,
    };
    if !is_cacheable_state(state) {
        return None;
    }

    let message = match state {
        STATE_MANUAL => "Cloud-init marked complete manually",
        STATE_DONE => "Cloud-init completed",
        STATE_DONE_WITH_ERRORS => "Cloud-init completed with warnings",
        STATE_DISABLED => "Cloud-init is disabled for this instance",
        _ => "Image does not appear to use cloud-init",
    };

    Some(build_response(
        state,
        match source.as_str() {
            "manual" => SOURCE_MANUAL,
            "status_json" => SOURCE_STATUS_JSON,
            "boot_finished" => SOURCE_BOOT_FINISHED,
            "image" => SOURCE_IMAGE,
            _ => SOURCE_UNKNOWN,
        },
        message,
        &detected_at,
    ))
}

/// Mirrors `persistCloudInitStatus` (same `instances` columns).
pub async fn persist_cloud_init_status(
    db: &PgPool,
    instance_id: i64,
    result: &CloudInitStatusResponse,
    manual_completed_by: Option<i64>,
) -> Result<(), sqlx::Error> {
    let detected_at = chrono::DateTime::parse_from_rfc3339(&result.detected_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let ready_detected_at = if result.ready {
        Some(detected_at)
    } else {
        None
    };
    let is_manual = result.state == STATE_MANUAL;
    let manual_at = if is_manual { Some(detected_at) } else { None };
    let manual_by = if is_manual { manual_completed_by } else { None };

    sqlx::query(
        "UPDATE instances SET cloud_init_state = $1, cloud_init_source = $2, \
         cloud_init_last_checked_at = $3, cloud_init_completed_at = $4, \
         cloud_init_manual_completed_at = $5, cloud_init_manual_completed_by = $6 \
         WHERE id = $7",
    )
    .bind(&result.state)
    .bind(&result.source)
    .bind(detected_at)
    .bind(ready_detected_at)
    .bind(manual_at)
    .bind(manual_by)
    .bind(instance_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Mirrors `resetInstanceCloudInitState`.
pub async fn reset_instance_cloud_init_state(
    db: &PgPool,
    instance_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE instances SET cloud_init_state = NULL, cloud_init_source = NULL, \
         cloud_init_last_checked_at = NULL, cloud_init_completed_at = NULL, \
         cloud_init_manual_completed_at = NULL, cloud_init_manual_completed_by = NULL \
         WHERE id = $1",
    )
    .bind(instance_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Mirrors `detectCloudInitStatus`: Inspect the guest files through the Incus
/// Files API to classify cloud-init progress.
pub async fn detect_cloud_init_status(
    client: &IncusClient,
    instance: &CloudInitDetectionTarget,
) -> CloudInitStatusResponse {
    let detected_at = iso_now();

    if !is_cloud_image_alias(&instance.image) {
        return build_response(
            STATE_UNSUPPORTED,
            SOURCE_IMAGE,
            "Image does not appear to use cloud-init",
            &detected_at,
        );
    }

    let mut saw_agent_error = false;

    for file_path in STATUS_JSON_PATHS {
        let result = read_instance_file(client, &instance.incus_id, file_path).await;

        match result {
            Ok((content, 200)) => {
                if let Some((state, message)) = parse_status_payload(&content) {
                    return build_response(state, SOURCE_STATUS_JSON, &message, &detected_at);
                }
                break;
            }
            Ok((_, status)) => {
                if status >= 500 || status == 403 {
                    saw_agent_error = true;
                }
            }
            Err(_) => {
                // Read failures behave like non-200 responses (the TS status
                // code check simply misses).
            }
        }
    }

    let boot_finished = read_instance_file(client, &instance.incus_id, BOOT_FINISHED_PATH).await;
    match boot_finished {
        Ok((_, 200)) => {
            return build_response(
                STATE_DONE,
                SOURCE_BOOT_FINISHED,
                "Cloud-init completed",
                &detected_at,
            );
        }
        Ok((_, status)) => {
            if status >= 500 || status == 403 {
                saw_agent_error = true;
            }
        }
        Err(_) => {}
    }

    if saw_agent_error {
        return build_response(
            STATE_AGENT_UNAVAILABLE,
            SOURCE_UNKNOWN,
            "Guest agent is not ready for cloud-init inspection",
            &detected_at,
        );
    }

    // The TS falls through to "running" only when boot-finished returned 404.
    // Because read failures here surface as errors, a confirmed 404 cannot be
    // distinguished from other failures; mirror the TS by treating a clean
    // non-error, non-5xx read of 404 as "still running".
    if let Ok((_, 404)) = boot_finished {
        return build_response(
            STATE_RUNNING,
            SOURCE_BOOT_FINISHED,
            "Cloud-init is still running",
            &detected_at,
        );
    }

    build_response(
        STATE_UNKNOWN,
        SOURCE_UNKNOWN,
        "Unable to determine cloud-init status",
        &detected_at,
    )
}
