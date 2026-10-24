//! 管理员控制面板更新 — port of server/src/routes/system-update.ts
//! (mounted at /api/system-update).
//!
//! Updates never run automatically: the admin checks a source, then explicitly
//! confirms and starts the update (spawned detached, output streamed into a
//! module-level execution record like the TS module globals).
//!
//! Reported deviations:
//! - The two inline TS rate limits (check 20/min, apply 2/10min) are NOT in
//!   rate_limit.rs (file is out of scope) — reported, not ported.
//! - spawn failures surface through the same execution record ('failed') that
//!   the TS 'error' event handler writes.
//! - The two `command`-carrying error bodies ({ error, code, command }) are
//!   built as raw responses because ApiError has no command field.

use std::sync::Mutex;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::auth::AdminAuth;
use crate::error::ApiError;
use crate::routes::users::create_log;
use crate::state::SharedAppState;

pub fn router() -> Router<SharedAppState> {
    Router::new()
        .route("/status", get(update_status))
        .route("/check", post(update_check))
        .route("/apply", post(update_apply))
}

// ===========================================================================
// lib/system-update-security.ts helpers
// ===========================================================================

const DEFAULT_GITHUB_REPOSITORY: &str = "1743986520/incudal";

fn is_repo_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// normalizeGitHubRepository: owner/repo or https://github.com/owner/repo(.git).
fn normalize_github_repository(value: &str) -> Option<String> {
    let candidate = value
        .trim()
        .trim_end_matches('/')
        .trim_end_matches(".git");
    if candidate.split('/').collect::<Vec<_>>().len() == 2
        && candidate.split('/').all(is_repo_segment)
    {
        return Some(candidate.to_string());
    }

    let parsed = reqwest::Url::parse(candidate).ok()?;
    if parsed.scheme() != "https"
        || parsed.host_str().map(|h| h.to_lowercase()) != Some("github.com".to_string())
    {
        return None;
    }
    let parts: Vec<&str> = parsed.path().split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() != 2 || !parts.iter().all(|p| is_repo_segment(p)) {
        return None;
    }
    Some(format!("{}/{}", parts[0], parts[1]))
}

fn get_allowed_repositories() -> Vec<String> {
    let configured: Vec<String> = std::env::var("INCUDAL_UPDATE_ALLOWED_REPOSITORIES")
        .unwrap_or_default()
        .split(',')
        .filter_map(|v| normalize_github_repository(v))
        .collect();
    if configured.is_empty() {
        return vec![DEFAULT_GITHUB_REPOSITORY.to_string()];
    }
    let mut unique: Vec<String> = Vec::new();
    for repo in configured {
        if !unique.contains(&repo) {
            unique.push(repo);
        }
    }
    unique
}

fn is_allowed_repository(repository: &str) -> bool {
    get_allowed_repositories()
        .iter()
        .any(|allowed| allowed.to_lowercase() == repository.to_lowercase())
}

struct PinnedUpdate {
    ref_: String,
    script_sha256: String,
}

fn get_pinned_update() -> Option<PinnedUpdate> {
    let ref_raw = std::env::var("INCUDAL_UPDATE_REF")
        .ok()
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let script = std::env::var("INCUDAL_UPDATE_SCRIPT_SHA256")
        .ok()
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let is_hex = |v: &str, len: usize| v.len() == len && v.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_hex(&ref_raw, 40) || !is_hex(&script, 64) {
        return None;
    }
    Some(PinnedUpdate {
        ref_: ref_raw.to_lowercase(),
        script_sha256: script.to_lowercase(),
    })
}

fn build_manual_command(repository: &str, mode: &str) -> String {
    let Some(pinned) = get_pinned_update() else {
        return "请配置 INCUDAL_UPDATE_REF 和 INCUDAL_UPDATE_SCRIPT_SHA256 后执行受校验的手动更新"
            .to_string();
    };
    let script_url = format!(
        "https://raw.githubusercontent.com/{repository}/{}/scripts/remote-update.sh",
        pinned.ref_
    );
    let temp_path = format!("/tmp/incudal-update-{}.sh", uuid::Uuid::new_v4());
    format!(
        "curl -fsSL '{script_url}' -o '{temp_path}' && printf '%s  %s\\n' '{sha}' '{temp_path}' | sha256sum -c - && sudo /usr/bin/bash '{temp_path}' --source 'https://github.com/{repository}' --ref '{}' --mode '{mode}'; status=$?; rm -f '{temp_path}'; exit $status",
        pinned.ref_,
        sha = pinned.script_sha256,
    )
}

// ===========================================================================
// module state (TS module globals) + execution record
// ===========================================================================

#[derive(Debug, Clone)]
struct UpdateExecution {
    id: String,
    status: String, // running | succeeded | failed
    source_repository: String,
    mode: String,
    started_at: String,
    finished_at: Option<String>,
    exit_code: Option<i32>,
    signal: Option<String>,
    output: String,
    error: Option<String>,
}

impl UpdateExecution {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "status": self.status,
            "sourceRepository": self.source_repository,
            "mode": self.mode,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "exitCode": self.exit_code,
            "signal": self.signal,
            "output": self.output,
            "error": self.error,
        })
    }
}

struct UpdateState {
    active: bool,
    last: Option<UpdateExecution>,
}

static UPDATE_STATE: Mutex<Option<UpdateState>> = Mutex::new(None);

fn with_update_state<T>(f: impl FnOnce(&mut UpdateState) -> T) -> T {
    let mut guard = UPDATE_STATE.lock().expect("update state mutex");
    let state = guard.get_or_insert(UpdateState {
        active: false,
        last: None,
    });
    f(state)
}

const MAX_OUTPUT_CHARS: usize = 16000;

fn current_execution() -> Option<Value> {
    with_update_state(|s| s.last.as_ref().map(|e| e.to_json()))
}

fn append_output(execution: &mut UpdateExecution, chunk: &str) {
    execution.output = format!("{}{chunk}", execution.output);
    if execution.output.len() > MAX_OUTPUT_CHARS {
        // Keep the tail like String.slice(-MAX_OUTPUT_CHARS).
        let mut start = execution.output.len() - MAX_OUTPUT_CHARS;
        while start < execution.output.len() && !execution.output.is_char_boundary(start) {
            start += 1;
        }
        execution.output = execution.output[start..].to_string();
    }
}

// ===========================================================================
// version helpers
// ===========================================================================

fn get_current_version() -> String {
    if let Ok(configured) = std::env::var("INCUDAL_VERSION") {
        let configured = configured.trim();
        if !configured.is_empty() {
            return if configured.starts_with('v') {
                configured.to_string()
            } else {
                format!("v{configured}")
            };
        }
    }
    // 发行包或容器中无法读取 package.json 时返回 unknown，由页面显示人工确认。
    if let Ok(package_json) = std::fs::read_to_string("package.json") {
        if let Ok(value) = serde_json::from_str::<Value>(&package_json) {
            if let Some(version) = value.get("version").and_then(Value::as_str) {
                let version = version.trim();
                if !version.is_empty() {
                    return if version.starts_with('v') {
                        version.to_string()
                    } else {
                        format!("v{version}")
                    };
                }
            }
        }
    }
    "unknown".to_string()
}

/// ^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$
fn normalize_release_version(value: Option<&Value>) -> Option<String> {
    let version = value?.as_str()?.trim();
    let core = version.strip_prefix('v')?;
    let (numeric, pre) = match core.split_once('-') {
        Some((n, p)) => (n, Some(p)),
        None => (core, None),
    };
    let parts: Vec<&str> = numeric.split('.').collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    if let Some(pre) = pre {
        if pre.is_empty()
            || !pre
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return None;
        }
    }
    Some(version.to_string())
}

/// ^v(\d+)\.(\d+)\.(\d+) — PREFIX match, so pre-release suffixes compare by
/// their numeric core only (the TS regex has no end anchor).
fn compare_versions(left: &str, right: &str) -> Option<i64> {
    let parse = |v: &str| -> Option<(i64, i64, i64)> {
        let rest = v.strip_prefix('v')?;
        let mut parts = rest.split('.');
        let take_digits = |s: &str| -> Option<i64> {
            let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                return None;
            }
            digits.parse().ok()
        };
        let major = take_digits(parts.next()?)?;
        let minor = take_digits(parts.next()?)?;
        let patch = take_digits(parts.next()?)?;
        Some((major, minor, patch))
    };
    let (lm, ln, lp) = parse(left)?;
    let (rm, rn, rp) = parse(right)?;
    Some((lm - rm) * 1_000_000i64 + (ln - rn) * 1_000i64 + (lp - rp))
}

fn get_source_urls(repository: &str) -> String {
    format!("https://github.com/{repository}")
}

// ===========================================================================
// GitHub release fetch (15s timeout mirrors the TS AbortSignal)
// ===========================================================================

struct UpdateRelease {
    version: String,
    name: String,
    url: String,
    published_at: Option<String>,
    notes: String,
}

impl UpdateRelease {
    fn to_json(&self) -> Value {
        json!({
            "version": self.version,
            "name": self.name,
            "url": self.url,
            "publishedAt": self.published_at,
            "notes": self.notes,
        })
    }
}

async fn fetch_latest_release(
    state: &SharedAppState,
    repository: &str,
) -> Result<UpdateRelease, String> {
    let url = format!("https://api.github.com/repos/{repository}/releases/latest");
    let mut request = state
        .http
        .get(&url)
        .timeout(std::time::Duration::from_secs(15))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "Incudal-System-Update");
    if let Ok(token) = std::env::var("INCUDAL_AGENT_RELEASE_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
    }
    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GitHub Release 查询失败（HTTP {}）", status.as_u16()));
    }
    let payload: Value = response.json().await.map_err(|e| e.to_string())?;

    let version = normalize_release_version(payload.get("tag_name"))
        .ok_or_else(|| "GitHub Release 未返回有效版本号".to_string())?;
    let notes = payload
        .get("body")
        .and_then(Value::as_str)
        .map(|b| b.chars().take(6000).collect::<String>())
        .unwrap_or_default();
    let name = payload
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or(&version)
        .to_string();
    let url = payload
        .get("html_url")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://github.com/{repository}/releases/tag/{version}"));
    Ok(UpdateRelease {
        version,
        name,
        url,
        published_at: payload
            .get("published_at")
            .and_then(Value::as_str)
            .map(str::to_string),
        notes,
    })
}

// ===========================================================================
// update executor discovery
// ===========================================================================

fn get_install_directory() -> String {
    std::env::var("INCUDAL_INSTALL_DIR")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/opt/incudal".to_string())
}

/// Best-effort uid probe (the TS uses process.getuid()). /proc/self/status is
/// read on Linux; anything else is treated as root so a configured command runs
/// without the sudo prefix (the sudo path fails its existsSync check anyway on
/// non-Linux hosts).
fn current_uid() -> u32 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(first) = rest.split_whitespace().next() {
                    if let Ok(v) = first.parse::<u32>() {
                        return v;
                    }
                }
            }
        }
    }
    0
}

struct UpdateExecutor {
    command: String,
    prefix_args: Vec<String>,
    #[allow(dead_code)]
    label: String,
}

fn get_update_executor() -> Option<UpdateExecutor> {
    let uid = current_uid();
    if let Ok(configured) = std::env::var("INCUDAL_WEB_UPDATE_COMMAND") {
        let configured = configured.trim().to_string();
        if !configured.is_empty() {
            if !configured.starts_with('/')
                || configured.chars().any(|c| c.is_whitespace())
                || !std::path::Path::new(&configured).exists()
            {
                return None;
            }
            if uid == 0 {
                return Some(UpdateExecutor {
                    command: configured.clone(),
                    prefix_args: Vec::new(),
                    label: configured,
                });
            }
            if std::path::Path::new("/usr/bin/sudo").exists() {
                return Some(UpdateExecutor {
                    command: "/usr/bin/sudo".to_string(),
                    prefix_args: vec!["-n".to_string(), configured.clone()],
                    label: format!("sudo {configured}"),
                });
            }
            return None;
        }
    }

    let helper_path = "/usr/local/sbin/incudal-web-update";
    if std::path::Path::new(helper_path).exists() {
        if uid == 0 {
            return Some(UpdateExecutor {
                command: helper_path.to_string(),
                prefix_args: Vec::new(),
                label: helper_path.to_string(),
            });
        }
        if std::path::Path::new("/usr/bin/sudo").exists() {
            return Some(UpdateExecutor {
                command: "/usr/bin/sudo".to_string(),
                prefix_args: vec!["-n".to_string(), helper_path.to_string()],
                label: format!("sudo {helper_path}"),
            });
        }
    }
    None
}

/// The TS replies with `{ error, code, command }`; ApiError cannot carry the
/// extra `command` key, so those two error paths build the body directly.
fn command_error_response(
    status: StatusCode,
    code: &str,
    error: &str,
    command: String,
) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "code": code,
            "command": command,
        })),
    )
        .into_response()
}

// ===========================================================================
// handlers
// ===========================================================================

async fn update_status(
    State(_state): State<SharedAppState>,
    _admin: AdminAuth,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let requested_source = query.get("source").map(|s| s.trim()).unwrap_or("");
    let source_repository = if requested_source.is_empty() {
        None
    } else {
        normalize_github_repository(requested_source)
    };
    let default_repository = get_allowed_repositories()
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_GITHUB_REPOSITORY.to_string());
    Json(json!({
        "currentVersion": get_current_version(),
        "sourceRepository": source_repository.clone().unwrap_or_else(|| default_repository.clone()),
        "sourceUrl": get_source_urls(source_repository.as_deref().unwrap_or(&default_repository)),
        "execution": current_execution(),
        "executorAvailable": get_update_executor().is_some(),
        "installDirectory": get_install_directory(),
    }))
}

#[derive(Deserialize, Default)]
struct CheckBody {
    #[serde(default)]
    source: Option<String>,
}

async fn update_check(
    State(state): State<SharedAppState>,
    _admin: AdminAuth,
    body: Option<Json<CheckBody>>,
) -> Result<Json<Value>, ApiError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let source_repository = match &body.source {
        Some(source) => normalize_github_repository(source),
        None => get_allowed_repositories().first().cloned(),
    };
    let Some(source_repository) = source_repository else {
        return Err(ApiError::with_message(
            "UPDATE_SOURCE_INVALID",
            StatusCode::BAD_REQUEST,
            "仅支持 HTTPS GitHub 仓库地址或 owner/repo",
        ));
    };
    if !is_allowed_repository(&source_repository) {
        return Err(ApiError::with_message(
            "UPDATE_SOURCE_NOT_ALLOWED",
            StatusCode::FORBIDDEN,
            "更新来源不在服务器配置的白名单中",
        ));
    }

    match fetch_latest_release(&state, &source_repository).await {
        Ok(latest) => {
            let current_version = get_current_version();
            let comparison = compare_versions(&latest.version, &current_version);
            Ok(Json(json!({
                "currentVersion": current_version,
                "sourceRepository": source_repository,
                "sourceUrl": get_source_urls(&source_repository),
                "latest": latest.to_json(),
                "updateAvailable": comparison.map(|c| c > 0).unwrap_or(true),
            })))
        }
        Err(message) => Err(ApiError::with_message(
            "UPDATE_CHECK_FAILED",
            StatusCode::BAD_GATEWAY,
            message,
        )),
    }
}

#[derive(Deserialize, Default)]
struct ApplyBody {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    confirm: Option<bool>,
}

async fn update_apply(
    State(state): State<SharedAppState>,
    admin: AdminAuth,
    body: Option<Json<ApplyBody>>,
) -> Result<Response, ApiError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();

    if body.confirm != Some(true) {
        return Err(ApiError::with_message(
            "UPDATE_CONFIRMATION_REQUIRED",
            StatusCode::BAD_REQUEST,
            "必须在页面明确确认后才能更新",
        ));
    }
    if with_update_state(|s| s.active) {
        return Err(ApiError::with_message(
            "UPDATE_IN_PROGRESS",
            StatusCode::CONFLICT,
            "已有更新正在执行",
        ));
    }

    let source_repository = match &body.source {
        Some(source) => normalize_github_repository(source),
        None => get_allowed_repositories().first().cloned(),
    };
    let Some(source_repository) = source_repository else {
        return Err(ApiError::with_message(
            "UPDATE_SOURCE_INVALID",
            StatusCode::BAD_REQUEST,
            "仅支持 HTTPS GitHub 仓库地址或 owner/repo",
        ));
    };
    if !is_allowed_repository(&source_repository) {
        return Err(ApiError::with_message(
            "UPDATE_SOURCE_NOT_ALLOWED",
            StatusCode::FORBIDDEN,
            "更新来源不在服务器配置的白名单中",
        ));
    }
    let mode = body.mode.clone().unwrap_or_else(|| "auto".to_string());
    if !["auto", "docker", "release"].contains(&mode.as_str()) {
        return Err(ApiError::with_message(
            "UPDATE_MODE_INVALID",
            StatusCode::BAD_REQUEST,
            "更新模式必须是 auto、docker 或 release",
        ));
    }
    let Some(pinned) = get_pinned_update() else {
        return Ok(command_error_response(
            StatusCode::CONFLICT,
            "UPDATE_TRUST_CONFIG_REQUIRED",
            "站点更新未配置固定 commit 与脚本 SHA256，请按手工更新提示完成配置",
            build_manual_command(&source_repository, &mode),
        ));
    };

    let Some(executor) = get_update_executor() else {
        return Ok(command_error_response(
            StatusCode::CONFLICT,
            "UPDATE_EXECUTOR_UNAVAILABLE",
            "当前服务没有可用的站点更新执行器，请复制命令到服务器终端执行",
            build_manual_command(&source_repository, &mode),
        ));
    };

    let execution = UpdateExecution {
        id: uuid::Uuid::new_v4().to_string(),
        status: "running".to_string(),
        source_repository: source_repository.clone(),
        mode: mode.clone(),
        started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        finished_at: None,
        exit_code: None,
        signal: None,
        output: String::new(),
        error: None,
    };
    let execution_json = execution.to_json();
    with_update_state(|s| {
        s.active = true;
        s.last = Some(execution);
    });

    let args: Vec<String> = executor
        .prefix_args
        .iter()
        .cloned()
        .chain([
            "--source".to_string(),
            format!("https://github.com/{source_repository}"),
            "--ref".to_string(),
            pinned.ref_.clone(),
            "--script-sha256".to_string(),
            pinned.script_sha256.clone(),
            "--mode".to_string(),
            mode.clone(),
        ])
        .collect();

    let mut command = std::process::Command::new(&executor.command);
    command
        .args(&args)
        .current_dir(std::env::current_dir().unwrap_or_default())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // Mirror `env: { ...process.env, ...overrides }`: rebuild the env map with
    // the overrides applied last, then hand the exact map to the child.
    {
        let mut env_map: std::collections::HashMap<String, String> = std::env::vars().collect();
        env_map.insert(
            "INCUDAL_GITHUB_REPO".to_string(),
            source_repository.clone(),
        );
        env_map.insert(
            "INCUDAL_UPDATE_SOURCE".to_string(),
            format!("https://github.com/{source_repository}"),
        );
        env_map.insert("INCUDAL_UPDATE_REF".to_string(), pinned.ref_.clone());
        env_map.insert(
            "INCUDAL_UPDATE_SCRIPT_SHA256".to_string(),
            pinned.script_sha256.clone(),
        );
        env_map.insert(
            "INCUDAL_INSTALL_DIR".to_string(),
            get_install_directory(),
        );
        command.env_clear().envs(env_map);
    }

    match command.spawn() {
        Ok(mut child) => {
            // The tokio "process" feature is not enabled in this crate, so the
            // detached child is supervised from blocking threads (the TS
            // attaches 'data'/'close' handlers; the observable behavior —
            // output accumulation, finishedAt/exitCode/error updates, and a
            // zombie-free exit — is reproduced here).
            let mut stdout = child.stdout.take();
            let mut stderr = child.stderr.take();
            std::thread::spawn(move || {
                let o_handle = std::thread::spawn(move || {
                    use std::io::Read;
                    if let Some(out) = stdout.as_mut() {
                        let mut buf = [0u8; 4096];
                        loop {
                            match out.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                                    with_update_state(|s| {
                                        if let Some(e) = s.last.as_mut() {
                                            append_output(e, &chunk);
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
                let e_handle = std::thread::spawn(move || {
                    use std::io::Read;
                    if let Some(err_pipe) = stderr.as_mut() {
                        let mut buf = [0u8; 4096];
                        loop {
                            match err_pipe.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                                    with_update_state(|s| {
                                        if let Some(e) = s.last.as_mut() {
                                            append_output(e, &chunk);
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
                let _ = o_handle.join();
                let _ = e_handle.join();
                // 'close' handler.
                let status = child.wait();
                let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                with_update_state(|s| {
                    s.active = false;
                    if let Some(e) = s.last.as_mut() {
                        e.finished_at = Some(now);
                        match &status {
                            Ok(exit) => {
                                e.exit_code = exit.code();
                                e.signal = None;
                                e.status = if exit.success() {
                                    "succeeded".to_string()
                                } else {
                                    "failed".to_string()
                                };
                                if !exit.success() {
                                    e.error = Some(format!(
                                        "更新脚本退出码：{}",
                                        exit.code()
                                            .map(|c| c.to_string())
                                            .unwrap_or_else(|| "unknown".to_string())
                                    ));
                                }
                            }
                            Err(err) => {
                                e.status = "failed".to_string();
                                e.error = Some(err.to_string());
                            }
                        }
                    }
                });
            });
        }
        Err(err) => {
            // TS 'error' event: mark failed and clear the active flag.
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            with_update_state(|s| {
                s.active = false;
                if let Some(e) = s.last.as_mut() {
                    e.status = "failed".to_string();
                    e.error = Some(err.to_string());
                    e.finished_at = Some(now);
                }
            });
        }
    }

    create_log(
        &state,
        admin.0.id,
        "system",
        "system.update_start",
        &format!("Admin started panel update from {source_repository}"),
        "success",
    )
    .await;
    // logAdminAction -> logAuditEvent(module 'admin'): contentParts stay empty
    // (no targetUsername/resourceName/reason), so the log row has empty content.
    create_log(&state, admin.0.id, "admin", "system.update_start", "", "success").await;

    Ok((StatusCode::ACCEPTED, Json(json!({
        "accepted": true,
        "execution": execution_json,
    })))
        .into_response())
}
