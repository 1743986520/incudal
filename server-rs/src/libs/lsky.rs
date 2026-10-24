//! Lsky 图床客户端 — port of server/src/lib/lsky.ts (upload/delete for ticket
//! attachments; config from system_configs ticket_image_lsky_*).

use serde_json::Value;
use sqlx::PgPool;

use crate::state::SharedAppState;

pub struct LskyConfig {
    pub base_url: String,
    pub token: String,
    pub api_version: &'static str,
    pub target_id: Option<String>,
}

fn as_nonempty(value: Option<String>) -> Option<String> {
    let trimmed = value?.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

fn normalize_base_url(baseUrl: &str) -> String {
    let mut s = baseUrl.trim().trim_end_matches('/').to_string();
    if !s.starts_with("http://") && !s.starts_with("https://") {
        s = format!("https://{s}");
    }
    s
}

fn resolve_api_base(base_url: &str, api_version: &str) -> String {
    let normalized = normalize_base_url(base_url);
    let prefix = if api_version == "v2" { "/api/v2" } else { "/api/v1" };
    if normalized.to_lowercase().ends_with(prefix) {
        normalized
    } else {
        format!("{normalized}{prefix}")
    }
}

async fn config(pool: &PgPool) -> Option<LskyConfig> {
    let read = |key: &'static str| {
        sqlx::query_scalar("SELECT value FROM system_configs WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
    };
    let (base_url, token, api_version, target_id) = tokio::join!(
        read("ticket_image_lsky_base_url"),
        read("ticket_image_lsky_token"),
        read("ticket_image_lsky_api_version"),
        read("ticket_image_lsky_target_id")
    );
    let base_url = as_nonempty(base_url.ok().flatten())?;
    let token = as_nonempty(token.ok().flatten())?;
    let api_version = if api_version.ok().flatten().as_deref() == Some("v2") {
        "v2"
    } else {
        "v1"
    };
    Some(LskyConfig {
        base_url: normalize_base_url(&base_url),
        token,
        api_version,
        target_id: as_nonempty(target_id.ok().flatten()),
    })
}

fn pick_string(values: &[&Value]) -> Option<String> {
    values
        .iter()
        .find_map(|v| v.as_str().map(|s| s.trim()).filter(|s| !s.is_empty()))
        .map(|s| s.to_string())
}

fn pick_number(values: &[&Value]) -> Option<i64> {
    values.iter().find_map(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}

fn extract_url_from_html(value: Option<&str>) -> Option<String> {
    let value = value?;
    let start = value.find("src=\"")? + 5;
    let rest = &value[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn join_url(base: &str, path: Option<String>) -> Option<String> {
    let path = path?;
    if path.starts_with("http://") || path.starts_with("https://") {
        Some(path)
    } else {
        Some(format!(
            "{}/{}",
            base.trim_end_matches('/'),
            path.trim_start_matches('/')
        ))
    }
}

pub struct LskyUploadResult {
    pub provider_file_id: Option<String>,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub url: String,
    pub thumbnail_url: Option<String>,
}

fn extract_lsky_error(payload: Option<&Value>, fallback: String) -> String {
    payload
        .and_then(|p| p.get("message"))
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .unwrap_or(fallback)
}

/// uploadTicketImageToLsky (v1/v2, optional storage/strategy id, tolerant URL
/// extraction across both API shapes).
pub async fn upload_ticket_image_to_lsky(
    state: &SharedAppState,
    filename: &str,
    content_type: &str,
    bytes: Vec<u8>,
    size_bytes: i64,
) -> Result<(LskyUploadResult, &'static str), String> {
    let Some(cfg) = config(&state.db).await else {
        return Err("Lsky image bed is not configured".into());
    };

    // multipart form
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(filename.to_string())
        .mime_str(content_type)
        .map_err(|e| e.to_string())?;
    let mut form = reqwest::multipart::Form::new().part("file", part);
    if let Some(target) = &cfg.target_id {
        let key = if cfg.api_version == "v2" { "storage_id" } else { "strategy_id" };
        form = form.text(key, target.clone());
    }

    let upload_url = format!("{}/upload", resolve_api_base(&cfg.base_url, cfg.api_version));
    let response = state
        .http
        .post(&upload_url)
        .timeout(std::time::Duration::from_secs(30))
        .bearer_auth(&cfg.token)
        .header("Accept", "application/json")
        .multipart(form)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let text = response.text().await.map_err(|e| e.to_string())?;
    let payload: Option<Value> = serde_json::from_str(&text).ok();

    if !status.is_success() || matches!(payload.as_ref().and_then(|p| p.get("status")), Some(Value::Bool(false))) {
        return Err(extract_lsky_error(
            payload.as_ref(),
            format!("Lsky upload failed with status {status}"),
        ));
    }

    // data candidates: payload.data (object or array) then payload itself
    let mut candidates: Vec<Value> = Vec::new();
    if let Some(data) = payload.as_ref().and_then(|p| p.get("data")) {
        match data {
            Value::Array(items) => candidates.extend(items.iter().cloned()),
            Value::Object(_) => candidates.push(data.clone()),
            _ => {}
        }
    }
    if let Some(p) = payload.as_ref() {
        candidates.push(p.clone());
    }

    for candidate in &candidates {
        let links = candidate.get("links").cloned().unwrap_or(Value::Null);
        let html = links.get("html").and_then(Value::as_str).map(|s| s.to_string());
        let markdown = links.get("markdown").and_then(Value::as_str).map(|s| s.to_string());
        let url = pick_string(&[
            candidate.get("url").unwrap_or(&Value::Null),
            candidate.get("public_url").unwrap_or(&Value::Null),
            links.get("url").unwrap_or(&Value::Null),
            links.get("raw_url").unwrap_or(&Value::Null),
        ])
        .or_else(|| extract_url_from_html(html.as_deref()))
        .or_else(|| extract_url_from_html(markdown.as_deref()))
        .or_else(|| {
            join_url(
                &cfg.base_url,
                pick_string(&[
                    candidate.get("pathname").unwrap_or(&Value::Null),
                    candidate.get("path").unwrap_or(&Value::Null),
                ]),
            )
        });
        let Some(url) = url else { continue };

        let thumbnail_url = pick_string(&[
            candidate.get("thumbnail_url").unwrap_or(&Value::Null),
            links.get("thumbnail_url").unwrap_or(&Value::Null),
        ])
        .or(Some(url.clone()));

        let provider_file_id = if cfg.api_version == "v2" {
            pick_string(&[
                candidate.get("id").unwrap_or(&Value::Null),
                candidate.get("key").unwrap_or(&Value::Null),
                candidate.get("hash").unwrap_or(&Value::Null),
            ])
        } else {
            pick_string(&[
                candidate.get("key").unwrap_or(&Value::Null),
                candidate.get("id").unwrap_or(&Value::Null),
                candidate.get("hash").unwrap_or(&Value::Null),
            ])
        };

        return Ok((
            LskyUploadResult {
                provider_file_id,
                filename: pick_string(&[
                    candidate.get("name").unwrap_or(&Value::Null),
                    candidate.get("filename").unwrap_or(&Value::Null),
                ])
                .unwrap_or_else(|| filename.to_string()),
                mime_type: pick_string(&[
                    candidate.get("mimetype").unwrap_or(&Value::Null),
                    candidate.get("mime_type").unwrap_or(&Value::Null),
                ])
                .unwrap_or_else(|| content_type.to_string()),
                size_bytes: pick_number(&[
                    candidate.get("size").unwrap_or(&Value::Null),
                    candidate.get("file_size").unwrap_or(&Value::Null),
                ])
                .unwrap_or(size_bytes),
                width: pick_number(&[candidate.get("width").unwrap_or(&Value::Null)]),
                height: pick_number(&[candidate.get("height").unwrap_or(&Value::Null)]),
                url,
                thumbnail_url,
            },
            cfg.api_version,
        ));
    }

    Err("Lsky upload succeeded but no image URL was returned".into())
}

/// deleteTicketImageFromLsky — best-effort; false when unconfigured/no id.
pub async fn delete_ticket_image_from_lsky(
    state: &SharedAppState,
    provider_version: &str,
    provider_file_id: Option<&str>,
) -> bool {
    let Some(file_id) = provider_file_id else { return false };
    let Some(cfg) = config(&state.db).await else { return false };
    let version = if provider_version == "v2" { "v2" } else { "v1" };
    let api_base = resolve_api_base(&cfg.base_url, version);
    let delete_url = if version == "v2" {
        format!("{api_base}/user/photos/{}", urlencoding::encode(file_id))
    } else {
        format!("{api_base}/images/{}", urlencoding::encode(file_id))
    };
    let result = state
        .http
        .delete(&delete_url)
        .timeout(std::time::Duration::from_secs(15))
        .bearer_auth(&cfg.token)
        .header("Accept", "application/json")
        .send()
        .await;
    matches!(result, Ok(r) if r.status().is_success())
}
