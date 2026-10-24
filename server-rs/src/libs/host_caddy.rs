//! Caddy Admin API client.
//! Port of lib/caddy-client.ts. Talks to the per-host Caddy API (:8444,
//! Basic Auth). TLS handling mirrors buildCaddyTlsConnectOptions: self-signed
//! certificates are accepted unless CADDY_API_CA_PATH (custom CA) or
//! CADDY_API_FINGERPRINT (sha256 pin, checked per response like the Incus
//! client) are configured.

use std::time::Duration;

use base64::Engine as _;
use sha2::{Digest, Sha256};

pub struct CaddyClient {
    base_url: String,
    auth_header: String,
    http: reqwest::Client,
    pinned_fingerprint: Option<String>,
}

fn build_site_route_id(domain: &str) -> String {
    let digest = hex::encode(Sha256::digest(domain.to_lowercase().as_bytes()));
    format!("site-{}", &digest[..32])
}

fn build_legacy_site_route_id(domain: &str) -> String {
    format!("site-{}", domain.replace('.', "-"))
}

impl CaddyClient {
    /// Mirrors createCaddyClient. Returns Err only when the configured
    /// fingerprint env var is malformed.
    pub fn new(host: &str, port: i64, username: &str, password: &str) -> Result<Self, String> {
        let ca_path = std::env::var("CADDY_API_CA_PATH")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let fingerprint = std::env::var("CADDY_API_FINGERPRINT")
            .ok()
            .map(|v| v.replace(':', "").trim().to_lowercase())
            .filter(|v| !v.is_empty());
        if let Some(f) = &fingerprint {
            if f.len() != 64 || !f.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(
                    "CADDY_API_FINGERPRINT must be a SHA-256 certificate fingerprint (64 hex characters)"
                        .to_string(),
                );
            }
        }

        let formatted_host = crate::libs::incus::network_address::format_host_for_url(host);
        let base_url = format!("https://{formatted_host}:{port}");
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
        );

        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(ca_path.is_none() && fingerprint.is_none())
            .tls_info(fingerprint.is_some());
        if let Some(ca) = &ca_path {
            let pem = std::fs::read(ca).map_err(|e| format!("read CADDY_API_CA_PATH failed: {e}"))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| format!("parse CADDY_API_CA_PATH failed: {e}"))?;
            builder = builder.add_root_certificate(cert);
        }
        let http = builder.build().map_err(|e| format!("caddy client build failed: {e}"))?;

        Ok(Self {
            base_url,
            auth_header,
            http,
            pinned_fingerprint: fingerprint,
        })
    }

    /// Mirrors the private `request` helper.
    async fn request(&self, method: &str, path: &str, body: Option<&serde_json::Value>) -> Result<serde_json::Value, String> {
        use reqwest::Method;
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| format!("invalid method {method}"))?;
        let url = format!("{}{}", self.base_url, path);
        let mut req = self
            .http
            .request(method, &url)
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json");
        if let Some(body) = body {
            req = req.body(body.to_string());
        }
        let response = req.send().await.map_err(|e| format!("{e}"))?;

        let status = response.status();
        if status.is_client_error() || status.is_server_error() {
            let text = response.text().await.unwrap_or_default();
            return Err(format!("Caddy API error: {} {text}", status.as_u16()));
        }

        if let Some(expected) = &self.pinned_fingerprint {
            let actual = response
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(|info| info.peer_certificate())
                .map(|der| hex::encode(Sha256::digest(&der)));
            match actual {
                Some(a) if a == *expected => {}
                _ => {
                    return Err(
                        "Caddy API certificate does not match CADDY_API_FINGERPRINT".to_string(),
                    )
                }
            }
        }

        let text = response.text().await.unwrap_or_default();
        if text.is_empty() {
            return Ok(serde_json::Value::Object(Default::default()));
        }
        serde_json::from_str(&text).map_err(|e| format!("invalid caddy payload: {e}"))
    }

    /// Mirrors getConfig.
    pub async fn get_config(&self) -> Result<serde_json::Value, String> {
        self.request("GET", "/config/", None).await
    }

    /// Mirrors testConnection.
    pub async fn test_connection(&self) -> bool {
        self.get_config().await.is_ok()
    }

    /// Mirrors addSite: POST route into the `sites` server, falling back to
    /// creating the server (PUT) and finally PATCH-merging the http app.
    pub async fn add_site(
        &self,
        domain: &str,
        target_ip: &str,
        target_port: i64,
        https_enabled: bool,
    ) -> Result<(), String> {
        let route_id = build_site_route_id(domain);
        let mut matcher = serde_json::json!({ "host": [domain] });
        if !https_enabled {
            matcher["protocol"] = serde_json::json!("http");
        }
        let route = serde_json::json!({
            "@id": route_id,
            "match": [matcher],
            "handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{ "dial": format!("{target_ip}:{target_port}") }],
            }],
            "terminal": true,
        });

        let server_name = "sites";
        match self
            .request(
                "POST",
                &format!("/config/apps/http/servers/{server_name}/routes"),
                Some(&route),
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(post_error) => {
                tracing::info!("[Caddy] POST 路由失败: {post_error}");
            }
        }

        let server_config = serde_json::json!({
            "listen": [":80", ":443"],
            "routes": [route],
            "automatic_https": { "disable_redirects": true },
        });

        match self
            .request(
                "PUT",
                &format!("/config/apps/http/servers/{server_name}"),
                Some(&server_config),
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(put_error) => {
                tracing::info!("[Caddy] PUT 服务器失败: {put_error}");
                if !put_error.contains("404") {
                    return Err(put_error);
                }
            }
        }

        let http_app = serde_json::json!({
            "servers": { server_name: server_config },
        });
        self.request("PATCH", "/config/apps/http", Some(&http_app))
            .await
            .map(|_| ())
            .map_err(|e| format!("无法创建站点配置: {e}"))
    }

    /// Mirrors deleteSite: tries the hashed route id then the legacy id.
    pub async fn delete_site(&self, domain: &str) -> Result<(), String> {
        let mut route_ids = vec![build_site_route_id(domain)];
        let legacy = build_legacy_site_route_id(domain);
        if !route_ids.contains(&legacy) {
            route_ids.push(legacy);
        }
        for route_id in route_ids {
            match self.request("DELETE", &format!("/id/{route_id}"), None).await {
                Ok(_) => return Ok(()),
                Err(error) => {
                    if error.contains("404") {
                        continue;
                    }
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Mirrors getSites.
    pub async fn get_sites(&self) -> Vec<String> {
        let Ok(config) = self.get_config().await else {
            return Vec::new();
        };
        let mut domains = Vec::new();
        let Some(servers) = config
            .pointer("/apps/http/servers")
            .and_then(serde_json::Value::as_object)
        else {
            return domains;
        };
        for (_name, server) in servers {
            let Some(routes) = server.get("routes").and_then(serde_json::Value::as_array) else {
                continue;
            };
            for route in routes {
                if let Some(hosts) = route
                    .pointer("/match/0/host")
                    .and_then(serde_json::Value::as_array)
                {
                    for host in hosts {
                        if let Some(h) = host.as_str() {
                            domains.push(h.to_string());
                        }
                    }
                }
            }
        }
        domains
    }
}
