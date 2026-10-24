//! Rate limiting mirroring @fastify/rate-limit + config/rate-limit.ts:
//! global 300/min per IP on /api/*, per-route rules matched with `*` wildcards
//! (`*` = one segment), counters in the shared state (Redis or in-memory).
//! The RULES table is a full, order-preserving port of `rateLimitRules` in
//! server/src/config/rate-limit.ts (declaration order = match order: the TS
//! findRateLimitRule returns the FIRST matching rule, so e.g.
//! `DELETE /api/inbox/read` is limited by the earlier `/api/inbox/*` DELETE
//! rule (30/min), not by the later `/api/inbox/read` DELETE rule (10/min)).

use axum::extract::{ConnectInfo, State};
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::state::SharedAppState;

pub const GLOBAL_RATE_LIMIT_MAX: u32 = 300;
pub const GLOBAL_RATE_LIMIT_WINDOW_SECS: u64 = 60;

pub struct RateLimitRule {
    /// Path segments without the leading empty; "*" matches exactly one segment.
    pub segments: &'static [&'static str],
    /// None = any method.
    pub method: Option<&'static str>,
    pub max: u32,
    pub window_secs: u64,
}

macro_rules! rule {
    ($method:expr, [$($seg:expr),+ $(,)?], $max:expr, $window:expr) => {
        RateLimitRule {
            segments: &[$($seg),+],
            method: $method,
            max: $max,
            window_secs: $window,
        }
    };
}

// Full port of server/src/config/rate-limit.ts rateLimitRules (83 entries).
// Order is significant: first match wins, exactly like the TS for-loop.
pub static RULES: &[RateLimitRule] = &[
    // ========== 认证相关 (严格限制) ==========
    rule!(Some("POST"), ["api", "auth", "login"], 5, 60),
    rule!(Some("POST"), ["api", "auth", "register"], 3, 60),
    rule!(Some("POST"), ["api", "auth", "send-verification-code"], 5, 3600),
    rule!(Some("POST"), ["api", "auth", "refresh"], 10, 60),
    rule!(None, ["api", "auth", "2fa", "*"], 10, 60),
    rule!(Some("POST"), ["api", "auth", "forgot-password", "send-code"], 5, 3600),
    rule!(Some("POST"), ["api", "auth", "forgot-password", "reset"], 5, 60),
    // ========== 实例操作 (适中限制) ==========
    rule!(Some("POST"), ["api", "instances"], 5, 60),
    rule!(Some("GET"), ["api", "instances"], 60, 60),
    rule!(Some("GET"), ["api", "instances", "dashboard-summary"], 30, 60),
    rule!(Some("POST"), ["api", "instances", "*", "start"], 10, 60),
    rule!(Some("POST"), ["api", "instances", "*", "stop"], 10, 60),
    rule!(Some("POST"), ["api", "instances", "*", "restart"], 5, 60),
    rule!(Some("POST"), ["api", "instances", "*", "reinstall"], 2, 300),
    // ========== 快照/备份 (严格限制) ==========
    rule!(Some("POST"), ["api", "instances", "*", "snapshots"], 5, 300),
    rule!(Some("GET"), ["api", "instances", "*", "snapshots"], 30, 60),
    rule!(Some("POST"), ["api", "instances", "*", "backups"], 3, 600),
    rule!(Some("GET"), ["api", "instances", "*", "backups"], 30, 60),
    rule!(Some("POST"), ["api", "instances", "*", "backups", "*", "export"], 5, 600),
    rule!(Some("POST"), ["api", "instances", "*", "backups", "export", "*", "download-token"], 10, 600),
    rule!(Some("GET"), ["api", "instances", "*", "backups", "export", "*", "download"], 5, 600),
    // ========== 端口映射 ==========
    rule!(Some("POST"), ["api", "instances", "*", "ports"], 10, 60),
    rule!(Some("GET"), ["api", "instances", "*", "ports"], 60, 60),
    // ========== 反代站点 ==========
    rule!(Some("GET"), ["api", "instances", "*", "sites"], 60, 60),
    rule!(Some("POST"), ["api", "instances", "*", "sites"], 10, 60),
    rule!(Some("DELETE"), ["api", "instances", "*", "sites", "*"], 10, 60),
    rule!(Some("POST"), ["api", "instances", "*", "sites", "*", "refresh"], 5, 60),
    // ========== 用户管理 ==========
    rule!(Some("GET"), ["api", "users"], 30, 60),
    rule!(Some("POST"), ["api", "users"], 10, 600),
    rule!(Some("POST"), ["api", "users", "create", "send-verification-code"], 5, 600),
    rule!(Some("PATCH"), ["api", "users", "*"], 10, 60),
    rule!(Some("POST"), ["api", "users", "*", "change-email", "send-code"], 5, 600),
    // ========== 主机/节点管理 (管理员) ==========
    rule!(Some("GET"), ["api", "hosts"], 60, 60),
    rule!(Some("POST"), ["api", "hosts"], 5, 60),
    rule!(Some("GET"), ["api", "hosts", "caddy-script", "*"], 10, 60),
    rule!(Some("POST"), ["api", "hosts", "*", "instances", "create-for-user"], 10, 60),
    rule!(None, ["api", "node-groups"], 30, 60),
    // ========== 套餐管理 ==========
    rule!(Some("GET"), ["api", "packages"], 60, 60),
    rule!(Some("POST"), ["api", "packages"], 10, 60),
    rule!(Some("GET"), ["api", "packages", "*", "hosts-detail"], 30, 60),
    rule!(Some("PUT"), ["api", "packages", "*", "release-channel"], 10, 60),
    rule!(Some("POST"), ["api", "packages", "*", "release-quota"], 10, 60),
    // ========== SSH 密钥 ==========
    rule!(Some("GET"), ["api", "ssh-keys"], 30, 60),
    rule!(Some("POST"), ["api", "ssh-keys"], 10, 60),
    rule!(Some("POST"), ["api", "ssh-keys", "generate"], 5, 60),
    // ========== 通知 ==========
    rule!(Some("GET"), ["api", "notifications"], 60, 60),
    rule!(Some("POST"), ["api", "notifications", "channels"], 5, 60),
    // ========== 站内信 ==========
    rule!(Some("GET"), ["api", "inbox"], 60, 60),
    rule!(Some("GET"), ["api", "inbox", "unread-count"], 120, 60),
    rule!(Some("POST"), ["api", "inbox", "*", "read"], 60, 60),
    rule!(Some("POST"), ["api", "inbox", "read-all"], 10, 60),
    rule!(Some("DELETE"), ["api", "inbox", "*"], 30, 60),
    rule!(Some("DELETE"), ["api", "inbox", "read"], 10, 60),
    rule!(Some("POST"), ["api", "inbox", "admin", "send", "*"], 20, 60),
    rule!(Some("POST"), ["api", "inbox", "admin", "broadcast"], 5, 60),
    rule!(Some("POST"), ["api", "inbox", "instances", "*", "notify"], 30, 60),
    rule!(Some("POST"), ["api", "inbox", "hosts", "*", "notify"], 5, 60),
    // ========== 镜像 ==========
    rule!(Some("GET"), ["api", "images"], 60, 60),
    rule!(Some("POST"), ["api", "images", "sync"], 2, 300),
    // ========== 日志 ==========
    rule!(Some("GET"), ["api", "logs"], 30, 60),
    // ========== 帮助文档 ==========
    rule!(Some("GET"), ["api", "help"], 60, 60),
    // ========== OAuth ==========
    rule!(None, ["api", "oauth", "*"], 10, 60),
    // ========== 邀请码 ==========
    rule!(Some("POST"), ["api", "auth", "invite"], 10, 60),
    rule!(Some("GET"), ["api", "auth", "invites"], 30, 60),
    rule!(Some("POST"), ["api", "auth", "user", "invite"], 10, 60),
    rule!(Some("GET"), ["api", "auth", "user", "invites"], 30, 60),
    rule!(Some("DELETE"), ["api", "auth", "user", "invites", "*"], 20, 60),
    // ========== 工单系统 ==========
    rule!(Some("POST"), ["api", "tickets"], 5, 60),
    // ========== 自定义初始化命令 ==========
    rule!(Some("GET"), ["api", "init-commands"], 60, 60),
    rule!(Some("GET"), ["api", "init-commands", "available"], 60, 60),
    rule!(Some("GET"), ["api", "init-commands", "distros"], 60, 60),
    rule!(Some("POST"), ["api", "init-commands"], 10, 60),
    rule!(Some("GET"), ["api", "init-commands", "*"], 60, 60),
    rule!(Some("PUT"), ["api", "init-commands", "*"], 20, 60),
    rule!(Some("DELETE"), ["api", "init-commands", "*"], 20, 60),
    rule!(Some("GET"), ["api", "tickets"], 60, 60),
    rule!(Some("GET"), ["api", "tickets", "pending-count"], 120, 60),
    rule!(Some("GET"), ["api", "tickets", "my-hosts"], 60, 60),
    rule!(Some("GET"), ["api", "tickets", "hosts", "*"], 60, 60),
    rule!(Some("GET"), ["api", "tickets", "attachments", "*", "content"], 240, 60),
    rule!(Some("GET"), ["api", "tickets", "*"], 60, 60),
    rule!(Some("GET"), ["api", "tickets", "*", "messages"], 60, 60),
    rule!(Some("POST"), ["api", "tickets", "*", "messages"], 20, 60),
    rule!(Some("PATCH"), ["api", "tickets", "*", "status"], 20, 60),
    rule!(Some("POST"), ["api", "tickets", "*", "close"], 20, 60),
    // Inline config.rateLimit entries from system-update.ts (not in the shared
    // config table upstream).
    rule!(Some("POST"), ["api", "system-update", "check"], 20, 60),
    rule!(Some("POST"), ["api", "system-update", "apply"], 2, 600),
];

/// Mirrors config/rate-limit.ts findRateLimitRule matching:
/// - rule.method is compared exactly (the TS uses `rule.method !== method`;
///   '*' matches any method) — HTTP methods are always uppercase on the wire.
/// - path segments must be equal; `*` matches exactly one NON-EMPTY segment
///   (the TS compiles `*` to `[^/]+`).
fn matches_rule(rule: &RateLimitRule, path: &str, method: &str) -> bool {
    if let Some(m) = rule.method {
        if m != method {
            return false;
        }
    }
    let path = path.trim_matches('/');
    let mut rule_segments = rule.segments.iter().copied();
    let mut path_segments = path.split('/');
    loop {
        match (rule_segments.next(), path_segments.next()) {
            (None, None) => return true,
            (Some("*"), Some(p)) if !p.is_empty() => continue,
            (Some(r), Some(p)) if r == p => continue,
            _ => return false,
        }
    }
}

pub fn find_rule(path: &str, method: &str) -> Option<&'static RateLimitRule> {
    RULES.iter().find(|r| matches_rule(r, path, method))
}

/// Mirrors lib/client-ip.ts applyVerifiedClientIp: trust CF-Connecting-IP /
/// X-Forwarded-For only when the peer is loopback/private (reverse proxy or
/// Cloudflare in front).
pub fn client_ip(parts: &Parts, peer: SocketAddr) -> IpAddr {
    let peer_is_local = is_local_ip(peer.ip());
    if peer_is_local {
        if let Some(cf) = parts
            .headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return cf;
        }
        if let Some(xff) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return xff;
        }
    }
    peer.ip()
}

fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
    }
}

/// Axum middleware applying the global + per-route limits.
pub async fn rate_limit_middleware(
    State(state): State<SharedAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();

    // Only /api/* is limited; health and terminal websockets are whitelisted.
    let limited = path.starts_with("/api/")
        && path != "/api/health"
        && !(path.starts_with("/api/ws/instances/") && path.ends_with("/terminal"));

    if !limited {
        return next.run(req).await;
    }

    let rule = find_rule(&path, &method);
    let max = rule.map(|r| r.max).unwrap_or(GLOBAL_RATE_LIMIT_MAX);
    let window_secs = rule
        .map(|r| r.window_secs)
        .unwrap_or(GLOBAL_RATE_LIMIT_WINDOW_SECS);

    let (parts, body) = req.into_parts();
    let ip = client_ip(&parts, peer);
    let key = match rule {
        Some(r) => format!("{ip}:/{}", r.segments.join("/")),
        None => format!("{ip}"),
    };

    let (count, _window) = state
        .shared
        .increment_window(&format!("rl:{key}"), Duration::from_secs(window_secs))
        .await;

    let req = Request::from_parts(parts, body);

    if count > max as i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let retry_after = window_secs.saturating_sub(now % window_secs).max(1);
        return too_many_response(retry_after);
    }
    next.run(req).await
}

fn too_many_response(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": "Too many requests, please try again later",
            "retryAfter": retry_after.to_string(),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matching() {
        let login = find_rule("/api/auth/login", "POST").unwrap();
        assert_eq!(login.max, 5);
        assert!(find_rule("/api/auth/login", "GET").is_none());
        let instances = find_rule("/api/instances", "GET").unwrap();
        assert_eq!(instances.max, 60);
        let oauth = find_rule("/api/oauth/github", "GET").unwrap();
        assert_eq!(oauth.max, 10);
        // No rule for arbitrary paths -> global limit only.
        assert!(find_rule("/api/friends/42", "GET").is_none());
    }

    #[test]
    fn declaration_order_first_match_wins() {
        // `/api/inbox/*` DELETE (30) is declared BEFORE `/api/inbox/read`
        // DELETE (10), so the wildcard wins for this path — TS for-loop order.
        let inbox_read = find_rule("/api/inbox/read", "DELETE").unwrap();
        assert_eq!(inbox_read.max, 30);
        // Other message deletes hit the wildcard too.
        assert_eq!(find_rule("/api/inbox/123", "DELETE").unwrap().max, 30);
        // read-all POST is matched by the exact rule declared before */read.
        assert_eq!(find_rule("/api/inbox/read-all", "POST").unwrap().max, 10);
        // unread-count beats the plain /api/inbox GET rule.
        assert_eq!(find_rule("/api/inbox/unread-count", "GET").unwrap().max, 120);
    }

    #[test]
    fn multi_segment_wildcards() {
        let export = find_rule("/api/instances/9/backups/55/export", "POST").unwrap();
        assert_eq!(export.max, 5);
        assert_eq!(export.window_secs, 600);
        // download-token vs download: methods disambiguate.
        assert_eq!(
            find_rule("/api/instances/9/backups/export/55/download-token", "POST")
                .unwrap()
                .max,
            10
        );
        assert_eq!(
            find_rule("/api/instances/9/backups/export/55/download", "GET")
                .unwrap()
                .max,
            5
        );
        // Wrong method does not match a method-specific rule.
        assert!(find_rule("/api/instances/9/backups/55/export", "GET").is_none());
        // Deeply nested single-segment wildcards do not span two segments.
        assert!(find_rule("/api/instances/9/backups/55/other", "POST").is_none());
    }

    #[test]
    fn tricky_new_rules() {
        // Method-`*` rule (auth 2fa) matches any method.
        assert_eq!(find_rule("/api/auth/2fa/verify", "POST").unwrap().max, 10);
        assert_eq!(find_rule("/api/auth/2fa/enable", "DELETE").unwrap().max, 10);
        // Reinstall: 2 per 5 minutes.
        let reinstall = find_rule("/api/instances/42/reinstall", "POST").unwrap();
        assert_eq!(reinstall.max, 2);
        assert_eq!(reinstall.window_secs, 300);
        // Static ticket subpaths declared before /api/tickets/*.
        assert_eq!(find_rule("/api/tickets/pending-count", "GET").unwrap().max, 120);
        assert_eq!(find_rule("/api/tickets/my-hosts", "GET").unwrap().max, 60);
        assert_eq!(
            find_rule("/api/tickets/attachments/7/content", "GET").unwrap().max,
            240
        );
        assert_eq!(find_rule("/api/tickets/77", "GET").unwrap().max, 60);
        // init-commands static segments win over the wildcard.
        assert_eq!(find_rule("/api/init-commands/available", "GET").unwrap().max, 60);
        assert_eq!(find_rule("/api/init-commands/42", "PUT").unwrap().max, 20);
        // node-groups matches every method (TS method '*').
        assert!(find_rule("/api/node-groups", "PATCH").is_some());
        // users/change-email wildcard with 4 segments.
        assert_eq!(
            find_rule("/api/users/7/change-email/send-code", "POST").unwrap().max,
            5
        );
    }
}
