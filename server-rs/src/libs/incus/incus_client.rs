//! Incus API client.
//! Port of lib/incus/incus-client.ts (undici Agent + mTLS replaced with
//! reqwest + rustls client certificates).
//!
//! Wire behavior preserved from the TS server:
//! - every request sends `Content-Type: application/json`;
//! - `{ type: "error" }` envelopes raise `IncusError::Api` with the Incus
//!   error string and status;
//! - `{ type: "async", operation }` envelopes wait via
//!   `incus_utils::wait_for_operation` and resolve to the operation metadata;
//! - sync responses resolve to `metadata` when present, otherwise to the
//!   whole envelope (`data.metadata || data`);
//! - non-JSON bodies (e.g. mTLS handshake failures in plain text) raise an
//!   `IncusError::Api` carrying the raw body text and HTTP status;
//! - non-GET requests double-check the ambient execution guard after the
//!   operation completes.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use once_cell::sync::Lazy;
use serde_json::{json, Value};

use crate::libs::incus::incus_execution_guard::{
    get_incus_execution_guard, throw_if_incus_execution_aborted,
};
use crate::libs::incus::incus_tls::{
    build_incus_tls_connect_options, panel_certificate_paths, resolve_incus_target,
    trust_ca_path_from_environment, IncusTlsTrust, PIN_MISMATCH_MESSAGE, TlsConnectOptions,
};
use crate::libs::incus::incus_utils::wait_for_operation;

/// Default request timeout for the async-operation wait (ms), matching the TS
/// `request(..., timeout = 120000)` default.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 120_000;

#[derive(Debug, Clone, thiserror::Error)]
pub enum IncusError {
    /// Mirrors `IncusApiError`: an Incus API or non-JSON HTTP failure.
    #[error("{message}")]
    Api {
        message: String,
        status_code: i64,
        method: String,
        path: String,
    },
    /// Connection/DNS/TLS transport failure.
    #[error("{0}")]
    Transport(String),
    /// The client has not been connected yet (TS: "Incus 客户端未连接").
    #[error("Incus 客户端未连接")]
    NotConnected,
    /// The ambient execution guard was aborted (lease lost).
    #[error("{0}")]
    Aborted(String),
    /// Any other failure (config errors, file IO, pin mismatch, ...).
    #[error("{0}")]
    Other(String),
}

impl IncusError {
    pub fn message(&self) -> &str {
        match self {
            IncusError::Api { message, .. } => message,
            IncusError::Transport(m) => m,
            IncusError::NotConnected => "Incus 客户端未连接",
            IncusError::Aborted(m) => m,
            IncusError::Other(m) => m,
        }
    }

    /// HTTP status carried by API failures, if any.
    pub fn status_code(&self) -> Option<i64> {
        match self {
            IncusError::Api { status_code, .. } => Some(*status_code),
            _ => None,
        }
    }
}

static NOT_FOUND_HINT: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"\b404\b").expect("static regex")
});
static INSTANCE_MISSING_BEFORE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?:instance|container|virtual machine).*(?:not found|does not exist|no such)")
        .expect("static regex")
});
static INSTANCE_MISSING_AFTER: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?:not found|does not exist|no such).*(?:instance|container|virtual machine)")
        .expect("static regex")
});

/// A missing instance is the only safe negative result for cleanup. Network
/// failures and other API errors must remain unknown and must not be treated
/// as proof that the resource was removed.
pub fn is_incus_not_found(error: &IncusError) -> bool {
    if let IncusError::Api { status_code, message, .. } = error {
        if *status_code == 404 {
            return true;
        }
        return NOT_FOUND_HINT.is_match(message)
            || INSTANCE_MISSING_BEFORE.is_match(message)
            || INSTANCE_MISSING_AFTER.is_match(message);
    }
    let message = error.message();
    NOT_FOUND_HINT.is_match(message)
        || INSTANCE_MISSING_BEFORE.is_match(message)
        || INSTANCE_MISSING_AFTER.is_match(message)
}

/// Mirrors `IncusClientOptions` from types/incus.ts.
#[derive(Debug, Clone, Default)]
pub struct IncusClientOptions {
    pub url: String,
    /// Legacy deployment paths — accepted but never used, exactly like the TS
    /// client which always substitutes the server-managed panel pair.
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub ca_path: Option<String>,
    pub server_certificate: Option<String>,
    pub server_fingerprint: Option<String>,
    pub allow_private_network: bool,
}

/// Mirrors `IncusApiResponse` (loose JSON is parsed directly from Value).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IncusApiResponse {
    #[serde(rename = "type")]
    pub response_type: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub status_code: Option<i64>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub err: Option<String>,
}

/// Raw dispatch outcome: HTTP status, body text, and the peer certificate DER
/// when the backend exposes it (used for pinned-fingerprint verification).
pub type DispatchResult = Result<(u16, String, Option<Vec<u8>>), IncusError>;

type BoxedFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = DispatchResult> + Send>,
>;
type DispatcherFn = Arc<
    dyn Fn(String, String, Option<Value>, u64) -> BoxedFuture + Send + Sync,
>;

/// Mirrors the TS `IncusClient`. Cheap to share via `Arc`; `connect()` may be
/// called again to reconnect (the pool relies on that).
pub struct IncusClient {
    original_url: String,
    base_url: RwLock<String>,
    servername: RwLock<Option<String>>,
    connected: AtomicBool,
    allow_private_network: bool,
    cert_path: String,
    key_path: String,
    tls: TlsConnectOptions,
    dispatcher: RwLock<Option<DispatcherFn>>,
    /// Kept for raw streaming requests (backup export / restore upload) that
    /// must not buffer the body as text.
    http_client: RwLock<Option<reqwest::Client>>,
}

impl std::fmt::Debug for IncusClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncusClient")
            .field("original_url", &self.original_url)
            .field("base_url", &self.base_url())
            .field("connected", &self.connected.load(Ordering::Relaxed))
            .finish()
    }
}

fn normalize_url(url: &str) -> String {
    // If it parses as a URL it is already normalized.
    if reqwest::Url::parse(url).is_ok() {
        return url.to_string();
    }
    // Otherwise it is probably a bare IPv6 literal without brackets:
    // https://2a06:de04:10:1250:::8443 -> https://[2a06:de04:10:1250::]:8443
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let scheme = format!("{scheme}://");
    let Some(last_colon) = rest.rfind(':') else {
        return url.to_string();
    };
    let after_last_colon = &rest[last_colon + 1..];
    if !after_last_colon.is_empty()
        && after_last_colon
            .bytes()
            .all(|b| b.is_ascii_digit())
    {
        let addr = &rest[..last_colon];
        if addr.contains(':') {
            return format!("{scheme}[{addr}]:{after_last_colon}");
        }
    }
    url.to_string()
}

impl IncusClient {
    /// Mirrors the TS constructor. Reads the environment trust anchor
    /// (INCUS_CA_PATH) and validates the pinned fingerprint against the CA
    /// certificate before any connection is attempted.
    pub fn new(options: &IncusClientOptions) -> Result<Self, IncusError> {
        let original_url = normalize_url(&options.url);
        // certPath/keyPath on Host are legacy deployment paths and may refer to
        // the host filesystem. The application runs with the managed
        // certificate pair mounted elsewhere, so never use persisted paths for
        // filesystem access.
        let (cert_path, key_path) = panel_certificate_paths();

        let trust = if let Some(server_certificate) = &options.server_certificate {
            IncusTlsTrust {
                ca_pem: Some(server_certificate.clone()),
                fingerprint: options.server_fingerprint.clone(),
            }
        } else if let Some(ca_path) = &options.ca_path {
            IncusTlsTrust {
                ca_pem: Some(read_file_to_string(ca_path)?),
                fingerprint: None,
            }
        } else if let Some(env_ca_path) = trust_ca_path_from_environment()? {
            IncusTlsTrust {
                ca_pem: Some(read_file_to_string(&env_ca_path)?),
                fingerprint: None,
            }
        } else {
            IncusTlsTrust::default()
        };

        let tls = build_incus_tls_connect_options(&trust)?;

        Ok(Self {
            base_url: RwLock::new(original_url.clone()),
            original_url,
            servername: RwLock::new(None),
            connected: AtomicBool::new(false),
            allow_private_network: options.allow_private_network,
            cert_path,
            key_path,
            tls,
            dispatcher: RwLock::new(None),
            http_client: RwLock::new(None),
        })
    }

    /// The connection URL currently in use (pinned to the resolved address
    /// after `connect()`).
    pub fn base_url(&self) -> String {
        self.base_url
            .read()
            .expect("base_url lock poisoned")
            .clone()
    }

    pub fn servername(&self) -> Option<String> {
        self.servername
            .read()
            .expect("servername lock poisoned")
            .clone()
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Mirrors `connect()`: resolve the target, load the managed certificate
    /// pair, build the mTLS HTTP client, then verify with GET /1.0.
    pub async fn connect(&self) -> Result<Value, IncusError> {
        let result = self.connect_inner().await;
        match result {
            Ok(info) => {
                self.connected.store(true, Ordering::Relaxed);
                Ok(info)
            }
            Err(err) => {
                self.connected.store(false, Ordering::Relaxed);
                Err(IncusError::Other(format!(
                    "无法连接到 Incus: {}",
                    err.message()
                )))
            }
        }
    }

    async fn connect_inner(&self) -> Result<Value, IncusError> {
        let target = resolve_incus_target(&self.original_url, self.allow_private_network).await?;

        let cert_pem = read_file_to_string(&self.cert_path)?;
        let key_pem = read_file_to_string(&self.key_path)?;
        let identity = reqwest::Identity::from_pem(
            format!("{cert_pem}\n{key_pem}").as_bytes(),
        )
        .map_err(|e| IncusError::Other(format!("invalid client certificate: {e}")))?;

        let mut builder = reqwest::Client::builder()
            .identity(identity)
            // Mirrors the undici agent timeouts: headersTimeout 120s,
            // bodyTimeout 300s. reqwest has no split header/body timeout, so
            // the per-read timeout covers both.
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(300))
            .tls_info(true);

        if let Some(ca_pem) = &self.tls.ca_pem {
            let ca = reqwest::tls::Certificate::from_pem(ca_pem.as_bytes())
                .map_err(|e| IncusError::Other(format!("invalid CA certificate: {e}")))?;
            builder = builder.add_root_certificate(ca);
        }
        if self.tls.pinned_fingerprint.is_some() {
            // The pinned host certificate usually has a SAN that does not
            // contain the management IP, so standard hostname verification
            // would always fail. Chain validation is replaced by the exact
            // sha256 pin check performed on every response in `request()`
            // (see incus_tls module docs for the TS comparison).
            builder = builder.danger_accept_invalid_certs(true);
        }

        let http = builder
            .build()
            .map_err(|e| IncusError::Other(format!("failed to build HTTP client: {e}")))?;

        *self.base_url.write().expect("base_url lock poisoned") = target.url.clone();
        *self.servername.write().expect("servername lock poisoned") = target.servername;

        // The dispatcher captures the resolved URL; connect() rebuilds it on
        // every (re)connect so a pinned address change is always picked up.
        let http_for_dispatch = http.clone();
        let base_url = target.url;
        let dispatcher: DispatcherFn = Arc::new(
            move |method: String,
                  path: String,
                  body: Option<Value>,
                  _timeout_ms: u64|
                  -> BoxedFuture {
                let http = http_for_dispatch.clone();
                let base_url = base_url.clone();
                Box::pin(async move {
                    let url = format!("{base_url}{path}");
                    let mut request = http.request(parse_method(&method), &url);
                    request = request.header("Content-Type", "application/json");
                    if let Some(body) = &body {
                        request = request.body(body.to_string());
                    }
                    let response = request
                        .send()
                        .await
                        .map_err(|e| IncusError::Transport(format!("{e}")))?;
                    let peer = response
                        .extensions()
                        .get::<reqwest::tls::TlsInfo>()
                        .and_then(|info| info.peer_certificate().map(|d| d.to_vec()));
                    let status = response.status().as_u16();
                    let text = response
                        .text()
                        .await
                        .map_err(|e| IncusError::Transport(format!("{e}")))?;
                    Ok((status, text, peer))
                })
            },
        );
        *self.dispatcher.write().expect("dispatcher lock poisoned") = Some(dispatcher);
        *self.http_client.write().expect("http client lock poisoned") = Some(http);

        self.get_server_info().await
    }

    fn dispatcher(&self) -> Result<DispatcherFn, IncusError> {
        self.dispatcher
            .read()
            .expect("dispatcher lock poisoned")
            .clone()
            .ok_or(IncusError::NotConnected)
    }

    /// Direct dispatch without the envelope handling of `request` (mirrors the
    /// TS direct undici calls). `path` may be a full URL or a path.
    pub(crate) async fn dispatch_raw(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, String, Option<Vec<u8>>), IncusError> {
        let dispatcher = self.dispatcher()?;
        dispatcher(method.to_string(), path.to_string(), body.cloned(), 0).await
    }

    /// Mirrors `request<T>(method, path, body, timeout)`. `timeout_ms` only
    /// bounds the async-operation wait, exactly like the TS signature.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        timeout_ms: u64,
    ) -> Result<Value, IncusError> {
        let guard = get_incus_execution_guard();
        throw_if_incus_execution_aborted()?;
        if method != "GET" {
            if let Some(guard) = &guard {
                guard.assert_active()?;
                throw_if_incus_execution_aborted()?;
            }
        }

        let dispatcher = self.dispatcher()?;
        let method_string = method.to_string();
        let path_string = path.to_string();
        let body_owned = body.cloned();

        let send_fut = {
            let dispatcher = dispatcher.clone();
            let method_string = method_string.clone();
            let path_string = path_string.clone();
            let body_owned = body_owned.clone();
            async move { dispatcher(method_string, path_string, body_owned, timeout_ms).await }
        };

        // TS attaches the guard's AbortSignal to the request; mirror that by
        // racing the in-flight call against the guard abort flag.
        let dispatched = match &guard {
            Some(guard) => {
                let abort_watch = abort_watcher(guard.clone());
                tokio::select! {
                    biased;
                    result = send_fut => result,
                    () = abort_watch => return Err(guard.abort_error()),
                }
            }
            None => send_fut.await,
        };
        let (status, text, peer_der) = dispatched?;

        // Pinned hosts: verify the live peer certificate fingerprint on every
        // response (TS: custom checkServerIdentity during the handshake).
        if let Some(expected) = &self.tls.pinned_fingerprint {
            let matches = peer_der
                .as_deref()
                .map(|der| crate::libs::incus::incus_tls::der_fingerprint(der) == *expected)
                .unwrap_or(false);
            if !matches {
                return Err(IncusError::Api {
                    message: PIN_MISMATCH_MESSAGE.to_string(),
                    status_code: status as i64,
                    method: method_string,
                    path: path_string,
                });
            }
        }

        // Try to parse JSON; non-JSON responses (e.g. mTLS errors) fail.
        let data: Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => {
                // Incus returns plain text for some errors (like mTLS failures)
                let message = if text.is_empty() {
                    format!("HTTP {status}")
                } else {
                    text.clone()
                };
                tracing::error!("[Incus API Error] {method} {path} -> {status}: {message}");
                return Err(IncusError::Api {
                    message,
                    status_code: status as i64,
                    method: method_string,
                    path: path_string,
                });
            }
        };

        let envelope_type = data.get("type").and_then(Value::as_str).unwrap_or_default();
        if envelope_type == "error" {
            let error_message = data
                .get("error")
                .and_then(Value::as_str)
                .or_else(|| data.get("err").and_then(Value::as_str))
                .unwrap_or("Incus API 错误")
                .to_string();
            tracing::error!("[Incus API Error] {} {}: {}", method, path, error_message);
            return Err(IncusError::Api {
                status_code: data
                    .get("status_code")
                    .and_then(Value::as_i64)
                    .unwrap_or(status as i64),
                message: error_message,
                method: method_string,
                path: path_string,
            });
        }

        // Async operations must complete before returning.
        if envelope_type == "async" {
            if let Some(operation) = data.get("operation").and_then(Value::as_str) {
                let result = wait_for_operation(self, operation, timeout_ms).await?;
                throw_if_incus_execution_aborted()?;
                if method != "GET" {
                    if let Some(guard) = &guard {
                        guard.assert_active()?;
                    }
                }
                return Ok(result);
            }
        }

        throw_if_incus_execution_aborted()?;
        if method != "GET" {
            if let Some(guard) = &guard {
                guard.assert_active()?;
            }
        }

        // `data.metadata || data`
        match data.get("metadata") {
            Some(metadata) if !metadata.is_null() => Ok(metadata.clone()),
            _ => Ok(data),
        }
    }

    /// `request` with the TS default timeout.
    pub async fn request_default(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, IncusError> {
        self.request(method, path, body, DEFAULT_REQUEST_TIMEOUT_MS)
            .await
    }

    /// Check whether a file exists via the Files API (no JSON parsing).
    pub async fn check_file_exists(&self, path: &str) -> Result<(bool, u16), IncusError> {
        let result = self.read_file(path).await?;
        Ok((result.1 == 200, result.1))
    }

    /// Read an instance file via the Files API (no JSON parsing).
    /// Returns `(content, status_code)`.
    pub async fn read_file(&self, path: &str) -> Result<(String, u16), IncusError> {
        let dispatcher = self
            .dispatcher()
            .map_err(|_| IncusError::NotConnected)?;
        let url = format!("{}{}", self.base_url(), path);
        let (status, text, _peer) = dispatcher(
            "GET".to_string(),
            url,
            None,
            DEFAULT_REQUEST_TIMEOUT_MS,
        )
        .await?;
        Ok((text, status))
    }

    /// Raw GET used by `wait_for_operation_long` (mirrors the TS direct
    /// undici request that bypasses the envelope handling in `request`).
    pub(crate) async fn request_raw_get(
        &self,
        url: &str,
        guard: Option<&Arc<crate::libs::incus::incus_execution_guard::IncusExecutionGuard>>,
    ) -> DispatchResult {
        let dispatcher = self.dispatcher()?;
        let fut = dispatcher("GET".to_string(), url.to_string(), None, 0);
        match guard {
            Some(guard) => {
                let abort_watch = abort_watcher(guard.clone());
                tokio::select! {
                    biased;
                    result = fut => result,
                    () = abort_watch => Err(guard.abort_error()),
                }
            }
            None => fut.await,
        }
    }

    // ==================== server info ====================

    pub async fn get_server_info(&self) -> Result<Value, IncusError> {
        self.request_default("GET", "/1.0", None).await
    }

    pub async fn get_resources(&self) -> Result<Value, IncusError> {
        self.request_default("GET", "/1.0/resources", None).await
    }

    /// Raw request returning the live `reqwest::Response` (backup export
    /// streaming and restore upload). Mirrors the TS dedicated-Agent calls in
    /// incus-backups.ts / incus-restore.ts.
    pub(crate) async fn raw_request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, IncusError> {
        let http = self
            .http_client
            .read()
            .expect("http client lock poisoned")
            .clone()
            .ok_or(IncusError::NotConnected)?;
        let mut request = http.request(parse_method(method), url);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| IncusError::Transport(format!("{e}")))?;
        Ok(response)
    }

    /// Mirrors `close()`: drops the HTTP connection pool and marks the client
    /// disconnected. It can be revived with another `connect()`.
    pub fn close(&self) {
        *self.dispatcher.write().expect("dispatcher lock poisoned") = None;
        *self.http_client.write().expect("http client lock poisoned") = None;
        self.connected.store(false, Ordering::Relaxed);
    }

    /// Test-only constructor with a scripted dispatcher. The dispatcher
    /// receives `(method, path_or_url, body, timeout_ms)` and returns
    /// `(status, body_text, peer_certificate_der)`.
    #[cfg(test)]
    pub fn for_tests(
        dispatcher: Arc<
            dyn Fn(String, String, Option<Value>, u64) -> DispatchResultFut + Send + Sync,
        >,
    ) -> Self {
        Self {
            original_url: "https://127.0.0.1:8443".to_string(),
            base_url: RwLock::new("https://127.0.0.1:8443".to_string()),
            servername: RwLock::new(None),
            connected: AtomicBool::new(true),
            allow_private_network: true,
            cert_path: String::new(),
            key_path: String::new(),
            tls: TlsConnectOptions::default(),
            dispatcher: RwLock::new(Some(Arc::new(
                move |method: String,
                      path: String,
                      body: Option<Value>,
                      timeout_ms: u64|
                      -> BoxedFuture { dispatcher(method, path, body, timeout_ms) },
            ))),
            http_client: RwLock::new(None),
        }
    }
}

pub type DispatchResultFut = std::pin::Pin<
    Box<dyn std::future::Future<Output = DispatchResult> + Send>,
>;

async fn abort_watcher(guard: Arc<crate::libs::incus::incus_execution_guard::IncusExecutionGuard>) {
    loop {
        if guard.is_aborted() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn parse_method(method: &str) -> reqwest::Method {
    method.parse().unwrap_or(reqwest::Method::GET)
}

fn read_file_to_string(path: &str) -> Result<String, IncusError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| IncusError::Other(format!("cannot read {path}: {e}")))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| IncusError::Other(format!("cannot read {path}: {e}")))?;
    Ok(contents)
}

/// Convenience for callers that want a JSON body from a typed payload.
pub fn json_body<T: serde::Serialize>(body: &T) -> Value {
    serde_json::to_value(body).unwrap_or_else(|_| json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_bare_ipv6_urls() {
        assert_eq!(
            normalize_url("https://2a06:de04:10:1250:::8443"),
            "https://[2a06:de04:10:1250::]:8443"
        );
        assert_eq!(
            normalize_url("https://[2a06:de04:10:1250::]:8443"),
            "https://[2a06:de04:10:1250::]:8443"
        );
        assert_eq!(
            normalize_url("https://host.example:8443"),
            "https://host.example:8443"
        );
    }

    #[test]
    fn not_found_detection_only_trusts_404_or_instance_missing_phrases() {
        let not_found = IncusError::Api {
            message: "Instance not found".to_string(),
            status_code: 404,
            method: "GET".into(),
            path: "/1.0/instances/demo".into(),
        };
        assert!(is_incus_not_found(&not_found));

        let timeout = IncusError::Transport("connect ETIMEDOUT".to_string());
        assert!(!is_incus_not_found(&timeout));

        let phrase_only = IncusError::Other(
            "Failed to fetch instance: does not exist".to_string(),
        );
        assert!(is_incus_not_found(&phrase_only));
    }
}
