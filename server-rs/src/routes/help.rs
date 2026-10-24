//! 帮助文档路由 — port of server/src/routes/help.ts (mounted at /api/help).
//!
//! Endpoint map (TS decorator -> Rust extractor):
//! - GET    /                        public (no extractor)
//! - GET    /pinned                  public
//! - GET    /category-config         public
//! - GET    /categories              public
//! - GET    /article/{slug}          public
//! - PUT    /admin/category-config   authenticateAdmin -> AdminAuth
//! - GET    /admin                   authenticateAdmin -> AdminAuth
//! - GET    /admin/{id}              authenticateAdmin -> AdminAuth
//! - POST   /admin                   authenticateAdmin -> AdminAuth
//! - PATCH  /admin/{id}              authenticateAdmin -> AdminAuth
//! - DELETE /admin/{id}              authenticateAdmin -> AdminAuth

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::auth::AdminAuth;
use crate::error::{code, ApiError};
use crate::response::parse_pagination;
use crate::routes::users::create_log;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/", get(list_articles))
        .route("/pinned", get(pinned_articles))
        .route("/category-config", get(category_config))
        .route("/categories", get(categories))
        .route("/article/{slug}", get(article_by_slug))
        .route("/admin/category-config", put(category_config_update))
        .route("/admin", get(admin_list).post(admin_create))
        .route(
            "/admin/{id}",
            get(admin_get).patch(admin_update).delete(admin_delete),
        )
}

/// 默认分类配置 (routes/help.ts DEFAULT_CATEGORIES)
fn default_categories() -> Value {
    json!([
        { "id": "general", "name": "常规", "color": "#6b7280" },
        { "id": "getting-started", "name": "快速开始", "color": "#22c55e" },
        { "id": "instances", "name": "实例管理", "color": "#3b82f6" },
        { "id": "networking", "name": "网络配置", "color": "#8b5cf6" },
        { "id": "hosting", "name": "托管服务", "color": "#06b6d4" },
        { "id": "billing", "name": "计费相关", "color": "#f59e0b" },
        { "id": "faq", "name": "常见问题", "color": "#ef4444" }
    ])
}

// ===========================================================================
// helpers
// ===========================================================================

/// TS `Date` fields serialize as ISO strings through Fastify's JSON encoder.
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// JS `Number(id)` param semantics: NaN -> 400 INVALID_ID; non-integral /
/// out-of-range values would fail Prisma's Int validation -> 500.
fn js_number_id(raw: &str) -> Result<i32, ApiError> {
    let t = raw.trim();
    let v: f64 = if t.is_empty() {
        0.0
    } else {
        t.parse::<f64>()
            .map_err(|_| ApiError::bad_request(code::INVALID_ID))?
    };
    if v.is_nan() {
        return Err(ApiError::bad_request(code::INVALID_ID));
    }
    if !v.is_finite() || v.fract() != 0.0 || !(i32::MIN as f64..=i32::MAX as f64).contains(&v) {
        return Err(ApiError::internal(format!(
            "Prisma Int argument out of range: {v}"
        )));
    }
    Ok(v as i32)
}

/// Fastify schema validation failure -> 400 { error, code: VALIDATION_ERROR }.
fn validation_error(messages: Vec<String>) -> ApiError {
    let first = messages[0].clone();
    let mut err = ApiError::with_message(code::VALIDATION_ERROR, StatusCode::BAD_REQUEST, first);
    if messages.len() > 1 {
        err = err.with_details(messages.join(", "));
    }
    err
}

// ===========================================================================
// db helpers (port of db/help.ts)
// ===========================================================================

#[derive(Debug, FromRow)]
struct HelpArticleListRow {
    id: i32,
    title: String,
    slug: String,
    category: String,
    sort_order: i32,
    published: bool,
    pinned: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// db/help.ts getHelpArticles: paged list without content.
async fn get_help_articles(
    state: &SharedAppState,
    pagination: crate::response::Pagination,
    published_only: bool,
    category: Option<&str>,
) -> Result<(Vec<HelpArticleListRow>, i64), ApiError> {
    let mut sql = String::from(
        "SELECT id, title, slug, category, sort_order, published, pinned, created_at, updated_at \
         FROM help_articles WHERE 1 = 1",
    );
    let mut count_sql = String::from("SELECT COUNT(*) FROM help_articles WHERE 1 = 1");
    let mut params_count = 0usize;
    if published_only {
        params_count += 1;
        sql.push_str(&format!(" AND published = ${params_count}"));
        count_sql.push_str(&format!(" AND published = ${params_count}"));
    }
    if category.is_some() {
        params_count += 1;
        let idx = format!("${params_count}");
        sql.push_str(&format!(" AND category = {idx}"));
        count_sql.push_str(&format!(" AND category = {idx}"));
    }
    // 置顶文章优先，同 db/help.ts 的默认排序（pinnedOnly 分支只被
    // getPinnedHelpArticles 使用，那里是独立的 SQL）。
    sql.push_str(" ORDER BY pinned DESC, sort_order ASC, created_at DESC");
    params_count += 1;
    let skip_idx = params_count;
    params_count += 1;
    sql.push_str(&format!(" OFFSET ${skip_idx} LIMIT ${params_count}"));

    let mut q = sqlx::query_as::<_, HelpArticleListRow>(&sql);
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    if published_only {
        q = q.bind(true);
        cq = cq.bind(true);
    }
    if let Some(c) = category {
        q = q.bind(c);
        cq = cq.bind(c);
    }
    q = q.bind(pagination.skip).bind(pagination.take);

    let items = q.fetch_all(&state.db).await?;
    let total = cq.fetch_one(&state.db).await?;
    Ok((items, total))
}

/// db/help.ts getPinnedHelpArticles.
async fn get_pinned_help_articles(
    state: &SharedAppState,
    limit: i64,
) -> Result<Vec<Value>, ApiError> {
    let rows: Vec<(i32, String, String, String)> = sqlx::query_as(
        "SELECT id, title, slug, category FROM help_articles \
         WHERE published = TRUE AND pinned = TRUE \
         ORDER BY sort_order ASC, created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, title, slug, category)| {
            json!({ "id": id, "title": title, "slug": slug, "category": category })
        })
        .collect())
}

#[derive(Debug, FromRow)]
struct HelpArticleRow {
    id: i32,
    title: String,
    slug: String,
    content: String,
    category: String,
    sort_order: i32,
    published: bool,
    pinned: bool,
    created_by: Option<i32>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl HelpArticleRow {
    /// db/help.ts getHelpArticleById/getHelpArticleBySlug serialization.
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "title": self.title,
            "slug": self.slug,
            "content": self.content,
            "category": self.category,
            "sort_order": self.sort_order,
            "published": if self.published { 1 } else { 0 },
            "pinned": if self.pinned { 1 } else { 0 },
            "created_by": self.created_by,
            "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
        })
    }
}

async fn get_help_article_by_id(
    state: &SharedAppState,
    id: i32,
) -> Result<Option<HelpArticleRow>, ApiError> {
    let row = sqlx::query_as::<_, HelpArticleRow>(
        "SELECT id, title, slug, content, category, sort_order, published, pinned, created_by, created_at, updated_at \
         FROM help_articles WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

async fn get_help_article_by_slug(
    state: &SharedAppState,
    slug: &str,
) -> Result<Option<HelpArticleRow>, ApiError> {
    // findFirst where slug + published = true.
    let row = sqlx::query_as::<_, HelpArticleRow>(
        "SELECT id, title, slug, content, category, sort_order, published, pinned, created_by, created_at, updated_at \
         FROM help_articles WHERE slug = $1 AND published = TRUE LIMIT 1",
    )
    .bind(slug)
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

async fn create_help_article(
    state: &SharedAppState,
    title: &str,
    slug: &str,
    content: &str,
    category: &str,
    sort_order: i32,
    published: bool,
    pinned: bool,
    created_by: i32,
) -> Result<i32, ApiError> {
    let row: (i32,) = sqlx::query_as(
        "INSERT INTO help_articles (title, slug, content, category, sort_order, published, pinned, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(title)
    .bind(slug)
    .bind(content)
    .bind(category)
    .bind(sort_order)
    .bind(published)
    .bind(pinned)
    .bind(created_by)
    .fetch_one(&state.db)
    .await?;
    Ok(row.0)
}

/// db/help.ts updateHelpArticle: only provided fields are updated; no-op when
/// the update set is empty.
#[allow(clippy::too_many_arguments)]
async fn update_help_article(
    state: &SharedAppState,
    id: i32,
    title: Option<&str>,
    slug: Option<&str>,
    content: Option<&str>,
    category: Option<&str>,
    sort_order: Option<i32>,
    published: Option<bool>,
    pinned: Option<bool>,
) -> Result<(), ApiError> {
    if title.is_none()
        && slug.is_none()
        && content.is_none()
        && category.is_none()
        && sort_order.is_none()
        && published.is_none()
        && pinned.is_none()
    {
        return Ok(());
    }

    // Build the final SQL with positional placeholders in field order.
    let mut sql = String::from("UPDATE help_articles SET ");
    let mut idx = 1usize;
    let mut bind_order: Vec<u8> = Vec::new(); // 0=title 1=slug 2=content 3=category 4=sort 5=published 6=pinned
    let fields: [(bool, u8, &str); 7] = [
        (title.is_some(), 0, "title = "),
        (slug.is_some(), 1, "slug = "),
        (content.is_some(), 2, "content = "),
        (category.is_some(), 3, "category = "),
        (sort_order.is_some(), 4, "sort_order = "),
        (published.is_some(), 5, "published = "),
        (pinned.is_some(), 6, "pinned = "),
    ];
    let mut parts: Vec<String> = Vec::new();
    for (present, tag, name) in fields {
        if present {
            parts.push(format!("{}${idx}", name));
            idx += 1;
            bind_order.push(tag);
        }
    }
    sql.push_str(&parts.join(", "));
    sql.push_str(&format!(" WHERE id = ${idx}"));

    let mut q = sqlx::query(&sql);
    for tag in bind_order {
        q = match tag {
            0 => q.bind(title.unwrap()),
            1 => q.bind(slug.unwrap()),
            2 => q.bind(content.unwrap()),
            3 => q.bind(category.unwrap()),
            4 => q.bind(sort_order.unwrap()),
            5 => q.bind(published.unwrap()),
            _ => q.bind(pinned.unwrap()),
        };
    }
    q.bind(id).execute(&state.db).await?;
    Ok(())
}

async fn delete_help_article(state: &SharedAppState, id: i32) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM help_articles WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// db/help.ts getHelpCategories: groupBy category where published.
async fn get_help_categories(state: &SharedAppState) -> Result<Vec<Value>, ApiError> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT category, COUNT(*) AS count FROM help_articles \
         WHERE published = TRUE GROUP BY category ORDER BY category ASC",
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(category, count)| json!({ "category": category, "count": count }))
        .collect())
}

// ===========================================================================
// GET / — 获取帮助文档列表（公开，只显示已发布）
// ===========================================================================

async fn list_articles(
    State(state): State<SharedAppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let category = params.get("category").filter(|c| !c.is_empty()).map(|s| s.as_str());
    let pagination = parse_pagination(&params, 20, None);

    let (items, total) =
        get_help_articles(&state, pagination, true, category).await?;

    let articles: Vec<Value> = items
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "title": a.title,
                "slug": a.slug,
                "category": a.category,
                "createdAt": iso(a.created_at),
                "updatedAt": iso(a.updated_at),
            })
        })
        .collect();

    Ok(Json(json!({
        "articles": articles,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
        "totalPages": (total + pagination.page_size - 1) / pagination.page_size,
    })))
}

// ===========================================================================
// GET /pinned — 获取置顶的帮助文档（公开，用于首页显示）
// ===========================================================================

async fn pinned_articles(
    State(state): State<SharedAppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    // Math.min(Math.max(parseInt(limit, 10) || 6, 1), 20)
    let limit = match params.get("limit") {
        Some(raw) => match js_parse_int(raw) {
            Some(v) if v != 0 => v,
            _ => 6,
        },
        None => 6,
    };
    let limit = limit.clamp(1, 20);

    let articles = get_pinned_help_articles(&state, limit).await?;
    Ok(Json(json!({ "articles": articles })))
}

/// JS parseInt base-10: optional sign + leading digits, else NaN.
fn js_parse_int(raw: &str) -> Option<i64> {
    let s = raw.trim_start();
    let bytes = s.as_bytes();
    let mut idx = 0usize;
    let mut sign = 1i64;
    if idx < bytes.len() && (bytes[idx] == b'+' || bytes[idx] == b'-') {
        if bytes[idx] == b'-' {
            sign = -1;
        }
        idx += 1;
    }
    let start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == start {
        return None; // NaN
    }
    s[start..idx].parse::<i64>().ok().map(|v| sign * v)
}

// ===========================================================================
// GET /category-config — 获取帮助分类配置（公开）
// ===========================================================================

async fn category_config(State(state): State<SharedAppState>) -> Result<Json<Value>, ApiError> {
    // getSystemConfig('help_categories', false) — no decryption.
    let config_str: Option<(Option<String>,)> =
        sqlx::query_as("SELECT value FROM system_configs WHERE key = 'help_categories'")
            .fetch_optional(&state.db)
            .await?;
    if let Some((Some(config_str),)) = config_str {
        if let Ok(parsed) = serde_json::from_str::<Value>(&config_str) {
            return Ok(Json(json!({ "categories": parsed })));
        }
        // 解析失败，返回默认
    }
    Ok(Json(json!({ "categories": default_categories() })))
}

// ===========================================================================
// GET /categories — 获取帮助分类列表（公开）
// ===========================================================================

async fn categories(State(state): State<SharedAppState>) -> Result<Json<Value>, ApiError> {
    let categories = get_help_categories(&state).await?;
    Ok(Json(json!({ "categories": categories })))
}

// ===========================================================================
// GET /article/{slug} — 通过 slug 获取帮助文档详情（公开）
// ===========================================================================

async fn article_by_slug(
    State(state): State<SharedAppState>,
    Path(slug): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let article = get_help_article_by_slug(&state, &slug)
        .await?
        .ok_or_else(|| ApiError::not_found(code::ARTICLE_NOT_FOUND))?;

    Ok(Json(json!({
        "article": {
            "id": article.id,
            "title": article.title,
            "slug": article.slug,
            "content": article.content,
            "category": article.category,
            "created_at": iso(article.created_at),
            "updated_at": iso(article.updated_at),
        }
    })))
}

// ===========================================================================
// PUT /admin/category-config — 保存帮助分类配置（管理员）
// ===========================================================================

/// Fastify schema: categories is an array of { id: ^[a-z0-9-]+$, name:
/// minLength 1, color: ^#[0-9a-fA-F]{6}$ }.
fn validate_category_config(body: &Value) -> Result<Vec<Value>, ApiError> {
    let obj = match body.as_object() {
        Some(o) => o,
        None => {
            return Err(validation_error(vec!["body must be object".to_string()]));
        }
    };

    let mut messages: Vec<String> = Vec::new();
    let Some(categories_value) = obj.get("categories") else {
        return Err(validation_error(vec!["categories is required".to_string()]));
    };
    let Some(categories) = categories_value.as_array() else {
        return Err(validation_error(vec!["categories must be array".to_string()]));
    };

    for (index, item) in categories.iter().enumerate() {
        let prefix = format!("categories/{index}");
        let Some(item_obj) = item.as_object() else {
            messages.push(format!("{prefix} must be object"));
            continue;
        };
        for field in ["id", "name", "color"] {
            if !item_obj.contains_key(field) {
                messages.push(format!("{field} is required"));
            }
        }
        if let Some(id) = item_obj.get("id") {
            match id.as_str() {
                Some(s) if !s.is_empty() && regex_is_slug(s) => {}
                Some(_) => messages.push(format!("{prefix}/id format is invalid")),
                None => messages.push(format!("{prefix}/id must be string")),
            }
        }
        if let Some(name) = item_obj.get("name") {
            match name.as_str() {
                Some(s) if !s.is_empty() => {}
                Some(_) => messages.push(format!("{prefix}/name is too short")),
                None => messages.push(format!("{prefix}/name must be string")),
            }
        }
        if let Some(color) = item_obj.get("color") {
            match color.as_str() {
                Some(s) if regex_is_hex_color(s) => {}
                Some(_) => messages.push(format!("{prefix}/color format is invalid")),
                None => messages.push(format!("{prefix}/color must be string")),
            }
        }
    }

    if !messages.is_empty() {
        return Err(validation_error(messages));
    }
    Ok(categories.clone())
}

fn regex_is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn regex_is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

async fn category_config_update(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let categories = validate_category_config(&body)?;
    let serialized = json!(categories).to_string();

    // 检查配置是否已存在 (upsert).
    let existing: Option<(i32,)> =
        sqlx::query_as("SELECT id FROM system_configs WHERE key = 'help_categories'")
            .fetch_optional(&state.db)
            .await?;

    if existing.is_some() {
        sqlx::query("UPDATE system_configs SET value = $2 WHERE key = 'help_categories'")
            .bind(&serialized)
            .execute(&state.db)
            .await?;
    } else {
        // 创建新配置
        sqlx::query(
            "INSERT INTO system_configs (key, value, type, label, description) \
             VALUES ('help_categories', $1, 'json', '帮助中心分类配置', '帮助文档的分类配置（ID、名称、颜色）')",
        )
        .bind(&serialized)
        .execute(&state.db)
        .await?;
        // invalidateCachedConfig — the Rust port has no config cache (no-op).
    }

    create_log(
        &state,
        admin.0.id,
        "system",
        "help.category_config",
        &format!("Updated help category config ({} categories)", categories.len()),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Category config saved" })))
}

// ===========================================================================
// GET /admin — 获取所有帮助文档列表（管理员，包括未发布）
// ===========================================================================

async fn admin_list(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let category = params.get("category").filter(|c| !c.is_empty()).map(|s| s.as_str());
    let pagination = parse_pagination(&params, 20, None);

    let (items, total) = get_help_articles(&state, pagination, false, category).await?;

    let articles: Vec<Value> = items
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "title": a.title,
                "slug": a.slug,
                "category": a.category,
                "sort_order": a.sort_order,
                "published": if a.published { 1 } else { 0 },
                "pinned": if a.pinned { 1 } else { 0 },
                "created_at": iso(a.created_at),
                "updated_at": iso(a.updated_at),
            })
        })
        .collect();

    Ok(Json(json!({
        "articles": articles,
        "total": total,
        "page": pagination.page,
        "pageSize": pagination.page_size,
        "totalPages": (total + pagination.page_size - 1) / pagination.page_size,
    })))
}

// ===========================================================================
// GET /admin/{id} — 获取帮助文档详情（管理员）
// ===========================================================================

async fn admin_get(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let article_id = js_number_id(&id)?;

    let article = get_help_article_by_id(&state, article_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::ARTICLE_NOT_FOUND))?;

    Ok(Json(json!({ "article": article.to_json() })))
}

// ===========================================================================
// POST /admin — 创建帮助文档（管理员）
// ===========================================================================

/// Fastify schema for create/update article bodies.
struct ArticleBody {
    title: Option<String>,
    slug: Option<String>,
    content: Option<String>,
    category: Option<String>,
    sort_order: Option<i32>,
    published: Option<bool>,
    pinned: Option<bool>,
}

fn validate_article_body(body: &Value, required: bool) -> Result<ArticleBody, ApiError> {
    let obj = match body.as_object() {
        Some(o) => o,
        None => return Err(validation_error(vec!["body must be object".to_string()])),
    };

    let mut messages: Vec<String> = Vec::new();
    if required {
        for field in ["title", "slug", "content"] {
            if !obj.contains_key(field) {
                messages.push(format!("{field} is required"));
            }
        }
    }

    let mut title = None;
    if let Some(v) = obj.get("title") {
        match v.as_str() {
            Some(s) if !s.is_empty() => title = Some(s.to_string()),
            Some(_) => messages.push("title is too short".to_string()),
            None => messages.push("title must be string".to_string()),
        }
    }
    let mut slug = None;
    if let Some(v) = obj.get("slug") {
        match v.as_str() {
            Some(s) if !s.is_empty() => {
                if regex_is_slug(s) {
                    slug = Some(s.to_string());
                } else {
                    messages.push("slug format is invalid".to_string());
                }
            }
            Some(_) => messages.push("slug is too short".to_string()),
            None => messages.push("slug must be string".to_string()),
        }
    }
    let mut content = None;
    if let Some(v) = obj.get("content") {
        match v.as_str() {
            Some(s) => content = Some(s.to_string()),
            None => messages.push("content must be string".to_string()),
        }
    }
    let mut category = None;
    if let Some(v) = obj.get("category") {
        match v.as_str() {
            Some(s) => category = Some(s.to_string()),
            None => messages.push("category must be string".to_string()),
        }
    }
    let mut sort_order = None;
    if let Some(v) = obj.get("sortOrder") {
        match v.as_i64() {
            Some(n) if n >= i32::MIN as i64 && n <= i32::MAX as i64 => {
                sort_order = Some(n as i32)
            }
            // TS: a float/out-of-range Int fails Prisma validation -> 500.
            Some(_) => return Err(ApiError::internal("Prisma Int argument out of range")),
            None => messages.push("sortOrder must be integer".to_string()),
        }
    }
    let mut published = None;
    if let Some(v) = obj.get("published") {
        match v.as_bool() {
            Some(b) => published = Some(b),
            None => messages.push("published must be boolean".to_string()),
        }
    }
    let mut pinned = None;
    if let Some(v) = obj.get("pinned") {
        match v.as_bool() {
            Some(b) => pinned = Some(b),
            None => messages.push("pinned must be boolean".to_string()),
        }
    }

    if !messages.is_empty() {
        return Err(validation_error(messages));
    }

    Ok(ArticleBody {
        title,
        slug,
        content,
        category,
        sort_order,
        published,
        pinned,
    })
}

async fn admin_create(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let article = validate_article_body(&body, true)?;

    let title = article.title.unwrap_or_default();
    let slug = article.slug.unwrap_or_default();
    let content = article.content.unwrap_or_default();

    // Check slug uniqueness
    if get_help_article_by_slug(&state, &slug).await?.is_some() {
        return Err(ApiError::bad_request(code::SLUG_EXISTS));
    }

    let article_id = create_help_article(
        &state,
        &title,
        &slug,
        &content,
        article.category.as_deref().unwrap_or("general"),
        article.sort_order.unwrap_or(0),
        article.published.unwrap_or(true), // published !== false
        article.pinned.unwrap_or(false),   // pinned === true
        admin.0.id,
    )
    .await?;

    create_log(
        &state,
        admin.0.id,
        "system",
        "help.create",
        &format!("Created help article \"{title}\" (ID: {article_id})"),
        "success",
    )
    .await;

    Ok(Json(json!({
        "message": "Article created",
        "article": { "id": article_id, "title": title, "slug": slug },
    })))
}

// ===========================================================================
// PATCH /admin/{id} — 更新帮助文档（管理员）
// ===========================================================================

async fn admin_update(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let article_id = js_number_id(&id)?;
    let article = validate_article_body(&body, false)?;

    let existing = get_help_article_by_id(&state, article_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::ARTICLE_NOT_FOUND))?;

    // Check slug uniqueness if changed
    if let Some(slug) = article.slug.as_deref() {
        if slug != existing.slug && get_help_article_by_slug(&state, slug).await?.is_some() {
            return Err(ApiError::bad_request(code::SLUG_EXISTS));
        }
    }

    update_help_article(
        &state,
        article_id,
        article.title.as_deref(),
        article.slug.as_deref(),
        article.content.as_deref(),
        article.category.as_deref(),
        article.sort_order,
        article.published,
        article.pinned,
    )
    .await?;

    create_log(
        &state,
        admin.0.id,
        "system",
        "help.update",
        &format!("Updated help article \"{}\" (ID: {article_id})", existing.title),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Article updated" })))
}

// ===========================================================================
// DELETE /admin/{id} — 删除帮助文档（管理员）
// ===========================================================================

async fn admin_delete(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let article_id = js_number_id(&id)?;

    let existing = get_help_article_by_id(&state, article_id)
        .await?
        .ok_or_else(|| ApiError::not_found(code::ARTICLE_NOT_FOUND))?;

    delete_help_article(&state, article_id).await?;

    create_log(
        &state,
        admin.0.id,
        "system",
        "help.delete",
        &format!("Deleted help article \"{}\" (ID: {article_id})", existing.title),
        "success",
    )
    .await;

    Ok(Json(json!({ "message": "Article deleted" })))
}
