//! Search-engine discovery endpoints — port of server/src/routes/site-meta.ts.
//! robots.txt + sitemap.xml + configured verification files / IndexNow key /
//! custom sitemap path. Only public pages are exposed.

use std::sync::Mutex;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;

use crate::state::SharedAppState;

const DEFAULT_SITE_URL: &str = "https://incudal.di0.uk";
const DEFAULT_SITEMAP_PATH: &str = "/sitemap.xml";
const BUILT_IN_HELP_SLUGS: [&str; 9] = [
    "platform-overview",
    "getting-started",
    "instance-management",
    "networking-basics",
    "hosting-tutorial",
    "hosting-publish",
    "hosting-earnings",
    "billing-basics",
    "common-issues",
];

#[derive(Clone)]
struct SeoRuntimeSettings {
    site_url: String,
    sitemap_path: String,
    verification_path: String,
    verification_content: String,
    indexnow_key: String,
}

static SETTINGS_CACHE: Lazy<Mutex<Option<(SeoRuntimeSettings, std::time::Instant)>>> =
    Lazy::new(|| Mutex::new(None));

fn normalize_site_url(value: Option<&str>) -> String {
    let Some(value) = value else { return DEFAULT_SITE_URL.to_string() };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return DEFAULT_SITE_URL.to_string();
    }
    match url::Url::parse(trimmed) {
        Ok(mut url) if url.scheme() == "http" || url.scheme() == "https" => {
            url.set_fragment(None);
            url.set_query(None);
            let mut s = url.to_string();
            while s.ends_with('/') {
                s.pop();
            }
            s
        }
        _ => DEFAULT_SITE_URL.to_string(),
    }
}

fn normalize_path(value: Option<&str>, fallback: &str, allow_empty: bool) -> String {
    let path = value.unwrap_or("").trim();
    if allow_empty && path.is_empty() {
        return String::new();
    }
    let invalid = !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("..")
        || path.contains('?')
        || path.contains('#')
        || path.starts_with("/api/")
        || path.len() > 200;
    if invalid {
        fallback.to_string()
    } else {
        path.to_string()
    }
}

fn normalize_indexnow_key(value: Option<&str>) -> String {
    let key = value.unwrap_or("").trim();
    let valid = (1..=256).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid { key.to_string() } else { String::new() }
}

async fn config(state: &SharedAppState, key: &str) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM system_configs WHERE key = $1")
        .bind(key)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
}

async fn get_seo_runtime_settings(state: &SharedAppState) -> SeoRuntimeSettings {
    if let Some((cached, expires_at)) = SETTINGS_CACHE.lock().unwrap().clone() {
        if std::time::Instant::now() < expires_at {
            return cached;
        }
    }

    let (site_url, sitemap_path, verification_path, verification_content, indexnow_key) = tokio::join!(
        config(state, "seo_site_url"),
        config(state, "seo_sitemap_path"),
        config(state, "seo_verification_path"),
        config(state, "seo_verification_content"),
        config(state, "seo_indexnow_key")
    );

    let value = SeoRuntimeSettings {
        site_url: normalize_site_url(site_url.as_deref()),
        sitemap_path: normalize_path(sitemap_path.as_deref(), DEFAULT_SITEMAP_PATH, false),
        verification_path: normalize_path(verification_path.as_deref(), "", true),
        verification_content: verification_content.unwrap_or_default(),
        indexnow_key: normalize_indexnow_key(indexnow_key.as_deref()),
    };
    *SETTINGS_CACHE.lock().unwrap() =
        Some((value.clone(), std::time::Instant::now() + std::time::Duration::from_secs(15)));
    value
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn format_last_modified(value: Option<&str>) -> Option<String> {
    let value = value?;
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

async fn build_sitemap_body(state: &SharedAppState, site_url: &str) -> String {
    let mut entries: Vec<(String, Option<String>)> = vec![
        (format!("{site_url}/"), None),
        (format!("{site_url}/market"), None),
        (format!("{site_url}/help"), None),
    ];
    for slug in BUILT_IN_HELP_SLUGS {
        entries.push((format!("{site_url}/help/{slug}"), None));
    }

    // 动态帮助文章（数据库故障时保留基础 sitemap）
    match sqlx::query_as::<_, (String, Option<DateTime<Utc>>)>(
        "SELECT slug, updated_at FROM help_articles WHERE published = true ORDER BY id ASC",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(articles) => {
            for (slug, updated_at) in articles {
                entries.push((
                    format!("{site_url}/help/{}", urlencoding::encode(&slug)),
                    updated_at.map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                ));
            }
        }
        Err(err) => {
            tracing::warn!("[SEO] Unable to load dynamic help articles for sitemap: {err}");
        }
    }

    let mut body = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    body.push_str("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
    for (url, last_modified) in entries {
        body.push_str("  <url>\n");
        body.push_str(&format!("    <loc>{}</loc>\n", escape_xml(&url)));
        if let Some(lastmod) = format_last_modified(last_modified.as_deref()) {
            body.push_str(&format!("    <lastmod>{lastmod}</lastmod>\n"));
        }
        body.push_str("  </url>\n");
    }
    body.push_str("</urlset>\n");
    body
}

async fn send_sitemap(state: &SharedAppState, settings: &SeoRuntimeSettings) -> Response {
    let body = build_sitemap_body(state, &settings.site_url).await;
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=900"),
        ],
        body,
    )
        .into_response()
}

/// Port of handleSeoMetaRequest — called from the app-level fallback for
/// non-API paths ending in .html/.txt/.xml before the static/SPA handling.
pub async fn handle_seo_meta_request(
    state: &SharedAppState,
    pathname: &str,
) -> Option<Response> {
    let lower = pathname.to_lowercase();
    if !(lower.ends_with(".html") || lower.ends_with(".txt") || lower.ends_with(".xml")) {
        return None;
    }
    let settings = get_seo_runtime_settings(state).await;
    if !settings.verification_path.is_empty() && pathname == settings.verification_path {
        let content_type = if lower.ends_with(".html") {
            "text/html; charset=utf-8"
        } else {
            "text/plain; charset=utf-8"
        };
        return Some((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            settings.verification_content,
        )
            .into_response());
    }
    if !settings.indexnow_key.is_empty() && pathname == format!("/{}.txt", settings.indexnow_key)
    {
        return Some((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            settings.indexnow_key,
        )
            .into_response());
    }
    if settings.sitemap_path != DEFAULT_SITEMAP_PATH && pathname == settings.sitemap_path {
        return Some(send_sitemap(state, &settings).await);
    }
    None
}

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/robots.txt", get(robots))
        .route("/sitemap.xml", get(sitemap))
}

async fn robots(
    State(state): State<SharedAppState>,
) -> Response {
    let settings = get_seo_runtime_settings(&state).await;
    let sitemap_url = format!("{}{}", settings.site_url, settings.sitemap_path);
    let body = format!(
        "User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /dashboard\nDisallow: /instances\n\
         Disallow: /profile\nDisallow: /wallet\nDisallow: /inbox\nDisallow: /terminal\n\
         Disallow: /tickets\nDisallow: /api/\nDisallow: /login\nDisallow: /register\n\
         Disallow: /forgot-password\n\nSitemap: {sitemap_url}\n"
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        body,
    )
        .into_response()
}

async fn sitemap(State(state): State<SharedAppState>) -> Response {
    let settings = get_seo_runtime_settings(&state).await;
    send_sitemap(&state, &settings).await
}

