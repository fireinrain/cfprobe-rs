use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;

use reqwest::{
    Client,
    header::{ACCEPT, ACCEPT_ENCODING, HOST, HeaderName, HeaderValue, LOCATION, USER_AGENT},
    redirect,
};

use serde::Serialize;

use crate::{error::CfProbeError, probe::Target};

use super::model::{
    CloudflareHttpSignals, HttpDetection, HttpHeader, HttpProbeStatus, format_http_version,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum HttpScheme {
    Http,
    Https,
}

impl HttpScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",

            Self::Https => "https",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Self::Http => 80,

            Self::Https => 443,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpProbeConfig {
    pub scheme: HttpScheme,

    pub port: u16,

    pub timeout: Duration,

    pub connect_timeout: Duration,

    pub max_body_bytes: u64,

    pub follow_redirects: bool,

    pub max_redirects: usize,

    pub accept_invalid_certs: bool,

    pub accept_invalid_hostnames: bool,

    pub user_agent: String,

    pub max_header_value_bytes: usize,

    /*
     * Maximum number of Target-specific
     * reqwest Clients kept in memory.
     *
     * Each Client contains its own connection pool.
     *
     * When the limit is reached, the cache is
     * rotated conservatively.
     */
    pub max_cached_clients: usize,

    /*
     * Keep idle connections around so repeated
     * probes of the same target can reuse them.
     */
    pub pool_idle_timeout: Duration,

    pub pool_max_idle_per_host: usize,
}

impl Default for HttpProbeConfig {
    fn default() -> Self {
        Self {
            scheme: HttpScheme::Https,

            port: 443,

            timeout: Duration::from_secs(10),

            connect_timeout: Duration::from_secs(5),

            max_body_bytes: 1024 * 1024,

            follow_redirects: false,

            max_redirects: 1,

            accept_invalid_certs: true,

            accept_invalid_hostnames: true,

            user_agent: "cfprobe/0.1".to_string(),

            max_header_value_bytes: 4096,

            max_cached_clients: 64,

            pool_idle_timeout: Duration::from_secs(90),

            pool_max_idle_per_host: 4,
        }
    }
}

#[derive(Debug, Clone, Eq)]
struct HttpClientKey {
    ip: IpAddr,

    hostname: String,

    scheme: HttpScheme,

    port: u16,
}

impl PartialEq for HttpClientKey {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
            && self.hostname == other.hostname
            && self.scheme == other.scheme
            && self.port == other.port
    }
}

impl Hash for HttpClientKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip.hash(state);

        self.hostname.hash(state);

        self.scheme.hash(state);

        self.port.hash(state);
    }
}

#[derive(Clone)]
pub struct HttpProber {
    config: HttpProbeConfig,

    /*
     * Client cache.
     *
     * std::sync::Mutex is sufficient because the
     * critical section is tiny and never awaits.
     */
    clients: Arc<Mutex<HashMap<HttpClientKey, Client>>>,
}

impl HttpProber {
    pub fn new(config: HttpProbeConfig) -> Result<Self, CfProbeError> {
        if config.port == 0 {
            return Err(CfProbeError::InvalidResponse(
                "HTTP port cannot be 0".to_string(),
            ));
        }

        if config.max_body_bytes == 0 {
            return Err(CfProbeError::InvalidResponse(
                "max_body_bytes cannot be 0".to_string(),
            ));
        }

        if config.connect_timeout > config.timeout {
            return Err(CfProbeError::InvalidResponse(
                "connect_timeout cannot be greater than timeout".to_string(),
            ));
        }

        if config.max_cached_clients == 0 {
            return Err(CfProbeError::InvalidResponse(
                "max_cached_clients cannot be 0".to_string(),
            ));
        }

        if config.pool_max_idle_per_host == 0 {
            return Err(CfProbeError::InvalidResponse(
                "pool_max_idle_per_host cannot be 0".to_string(),
            ));
        }

        Ok(Self {
            config,

            clients: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn config(&self) -> &HttpProbeConfig {
        &self.config
    }

    pub fn cached_client_count(&self) -> usize {
        self.clients.lock().map(|cache| cache.len()).unwrap_or(0)
    }

    /// Phase 5 compatibility API。
    ///
    /// 使用 config 中的默认 scheme + port。
    pub async fn probe(&self, ip: IpAddr, hostname: &str) -> Result<HttpDetection, CfProbeError> {
        self.probe_with_target_params(ip, hostname, self.config.scheme, self.config.port)
            .await
    }

    /// Phase 8/9 推荐 API。
    pub async fn probe_target(&self, target: &Target) -> Result<HttpDetection, CfProbeError> {
        target.validate()?;

        self.probe_with_target_params(target.ip, &target.hostname, target.scheme, target.port)
            .await
    }

    pub async fn probe_with_target_params(
        &self,

        ip: IpAddr,

        hostname: &str,

        scheme: HttpScheme,

        port: u16,
    ) -> Result<HttpDetection, CfProbeError> {
        if port == 0 {
            return Err(CfProbeError::InvalidResponse(
                "HTTP port cannot be 0".to_string(),
            ));
        }

        let hostname = normalize_hostname(hostname)?;

        let url = build_url(scheme, &hostname, port);

        /*
         * 获取 Target-specific Client。
         *
         * 如果之前已经探测过完全相同的：
         *
         * IP + Host + Scheme + Port
         *
         * 那么直接复用 Client，
         * 进而复用它内部的 connection pool。
         */
        let client = self.get_or_create_client(&hostname, ip, scheme, port)?;

        let host_header = build_host_header(&hostname, scheme, port);

        let response = client
            .get(&url)
            .header(
                HOST,
                HeaderValue::from_str(&host_header).map_err(|error| {
                    CfProbeError::InvalidResponse(format!("invalid Host header: {error}"))
                })?,
            )
            .header(USER_AGENT, self.config.user_agent.clone())
            .header(ACCEPT, "*/*")
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .await;

        let response = match response {
            Ok(response) => response,

            Err(error) => {
                return Ok(HttpDetection::failed(
                    ip,
                    hostname,
                    port,
                    url,
                    format!("HTTP request failed: {error}"),
                ));
            }
        };

        let status_code = response.status().as_u16();

        let http_version = format_http_version(response.version());

        let final_url = response.url().to_string();

        let headers = collect_headers(response.headers(), self.config.max_header_value_bytes);

        let signals =
            collect_cloudflare_signals(response.headers(), self.config.max_header_value_bytes);

        let content_type = header_string(
            response.headers(),
            "content-type",
            self.config.max_header_value_bytes,
        );

        let content_length = response.content_length();

        let redirect_location = header_string(
            response.headers(),
            LOCATION.as_str(),
            self.config.max_header_value_bytes,
        );

        let (body_bytes_read, body_truncated) =
            read_limited_body(response, self.config.max_body_bytes).await;

        let status = if body_truncated {
            HttpProbeStatus::ResponseBodyLimitReached
        } else {
            HttpProbeStatus::ResponseReceived
        };

        Ok(HttpDetection {
            ip,

            hostname,

            port,

            url,

            final_url: Some(final_url),

            status_code: Some(status_code),

            http_version: Some(http_version),

            status,

            headers,

            signals,

            content_type,

            content_length,

            body_bytes_read,

            body_truncated,

            redirect_location,

            error: None,
        })
    }

    fn get_or_create_client(
        &self,

        hostname: &str,

        ip: IpAddr,

        scheme: HttpScheme,

        port: u16,
    ) -> Result<Client, CfProbeError> {
        let key = HttpClientKey {
            ip,

            hostname: hostname.to_string(),

            scheme,

            port,
        };

        /*
         * First lookup.
         */
        {
            let cache = self.clients.lock().map_err(|_| {
                CfProbeError::InvalidResponse("HTTP client cache mutex poisoned".to_string())
            })?;

            if let Some(client) = cache.get(&key) {
                return Ok(client.clone());
            }
        }

        /*
         * Not cached:
         *
         * construct a new Client.
         */
        let socket_addr = SocketAddr::new(ip, port);

        let client = self.build_client(hostname, socket_addr)?;

        /*
         * Second lookup.
         *
         * Another concurrent task may have created
         * the same Client while we were building ours.
         *
         * Prefer the already cached Client.
         */
        let mut cache = self.clients.lock().map_err(|_| {
            CfProbeError::InvalidResponse("HTTP client cache mutex poisoned".to_string())
        })?;

        if let Some(existing) = cache.get(&key) {
            return Ok(existing.clone());
        }

        /*
         * Bounded cache.
         *
         * We deliberately use coarse eviction:
         *
         * once the cache reaches capacity,
         * clear it completely.
         *
         * This is simpler and avoids retaining an
         * unbounded number of target-specific Client
         * objects.
         *
         * A future phase can replace this with true LRU.
         */
        if cache.len() >= self.config.max_cached_clients {
            cache.clear();
        }

        cache.insert(key, client.clone());

        Ok(client)
    }

    fn build_client(
        &self,

        hostname: &str,

        socket_addr: SocketAddr,
    ) -> Result<Client, CfProbeError> {
        let client = reqwest::Client::builder()
            /*
             * Do NOT inherit HTTP_PROXY /
             * HTTPS_PROXY / ALL_PROXY.
             */
            .no_proxy()
            .user_agent(self.config.user_agent.clone())
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.timeout)
            /*
             * Reuse idle connections inside
             * the Target-specific Client.
             */
            .pool_idle_timeout(self.config.pool_idle_timeout)
            .pool_max_idle_per_host(self.config.pool_max_idle_per_host)
            /*
             * Critical:
             *
             * hostname remains the logical
             * destination / SNI.
             *
             * actual TCP target is socket_addr.
             */
            .resolve(hostname, socket_addr)
            /*
             * HTTP detection does not decide
             * certificate trust.
             *
             * TLS detection is responsible for
             * certificate verification evidence.
             */
            .danger_accept_invalid_certs(self.config.accept_invalid_certs)
            .danger_accept_invalid_hostnames(self.config.accept_invalid_hostnames)
            /*
             * Redirects disabled by default.
             */
            .redirect(if self.config.follow_redirects {
                redirect::Policy::limited(self.config.max_redirects)
            } else {
                redirect::Policy::none()
            })
            .build()
            .map_err(|error| {
                CfProbeError::InvalidResponse(format!("failed to build HTTP client: {error}"))
            })?;

        Ok(client)
    }
}

fn normalize_hostname(hostname: &str) -> Result<String, CfProbeError> {
    let hostname = hostname.trim();

    if hostname.is_empty() {
        return Err(CfProbeError::Dns {
            message: "hostname is empty".to_string(),
        });
    }

    let hostname = hostname.trim_end_matches('.');

    if hostname.is_empty() {
        return Err(CfProbeError::Dns {
            message: "hostname is empty".to_string(),
        });
    }

    hickory_resolver::proto::rr::Name::from_utf8(&format!("{hostname}.")).map_err(|error| {
        CfProbeError::Dns {
            message: format!("invalid hostname `{hostname}`: {error}"),
        }
    })?;

    Ok(hostname.to_ascii_lowercase())
}

fn build_url(scheme: HttpScheme, hostname: &str, port: u16) -> String {
    let default_port = scheme.default_port();

    if port == default_port {
        format!("{}://{}/", scheme.as_str(), hostname,)
    } else {
        format!("{}://{}:{}/", scheme.as_str(), hostname, port,)
    }
}

fn build_host_header(hostname: &str, scheme: HttpScheme, port: u16) -> String {
    if port == scheme.default_port() {
        hostname.to_string()
    } else {
        format!("{}:{}", hostname, port,)
    }
}

fn collect_headers(
    headers: &reqwest::header::HeaderMap,

    max_value_bytes: usize,
) -> Vec<HttpHeader> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let value = value.to_str().ok()?;

            Some(HttpHeader {
                name: name.as_str().to_string(),

                value: truncate_header_value(value, max_value_bytes),
            })
        })
        .collect()
}

fn collect_cloudflare_signals(
    headers: &reqwest::header::HeaderMap,

    max_value_bytes: usize,
) -> CloudflareHttpSignals {
    let server = header_string(headers, "server", max_value_bytes);

    let server_cloudflare = server
        .as_deref()
        .map(|value| value.to_ascii_lowercase().contains("cloudflare"))
        .unwrap_or(false);

    CloudflareHttpSignals {
        cf_ray: header_string(headers, "cf-ray", max_value_bytes),

        cf_cache_status: header_string(headers, "cf-cache-status", max_value_bytes),

        server,

        server_cloudflare,

        cf_connecting_ip: header_string(headers, "cf-connecting-ip", max_value_bytes),

        cf_ip_country: header_string(headers, "cf-ipcountry", max_value_bytes),

        age: header_string(headers, "age", max_value_bytes),

        via: header_string(headers, "via", max_value_bytes),

        cdn_cache_control: header_string(headers, "cdn-cache-control", max_value_bytes),

        cf_mitigated: header_string(headers, "cf-mitigated", max_value_bytes),
    }
}

fn header_string(
    headers: &reqwest::header::HeaderMap,

    name: &str,

    max_value_bytes: usize,
) -> Option<String> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;

    let value = headers.get(name)?.to_str().ok()?;

    Some(truncate_header_value(value, max_value_bytes))
}

fn truncate_header_value(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes.min(value.len());

    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }

    let mut result = value[..end].to_string();

    result.push_str("...[truncated]");

    result
}

async fn read_limited_body(response: reqwest::Response, max_body_bytes: u64) -> (u64, bool) {
    let mut stream = response.bytes_stream();

    let mut total = 0u64;

    while let Some(chunk_result) = stream.next().await {
        let Ok(chunk) = chunk_result else {
            break;
        };

        total = total.saturating_add(chunk.len() as u64);

        if total >= max_body_bytes {
            return (max_body_bytes, true);
        }
    }

    (total.min(max_body_bytes), false)
}
