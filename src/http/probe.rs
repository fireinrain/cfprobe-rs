use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::StreamExt;

use reqwest::{
    Client,
    header::{HOST, HeaderName, HeaderValue, LOCATION},
    redirect,
};

use crate::error::CfProbeError;

use super::model::{
    CloudflareHttpSignals, HttpDetection, HttpHeader, HttpProbeStatus, format_http_version,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl Default for HttpProbeConfig {
    fn default() -> Self {
        Self {
            scheme: HttpScheme::Https,

            port: 443,

            timeout: Duration::from_secs(10),

            connect_timeout: Duration::from_secs(5),

            max_body_bytes: 1024 * 1024,

            /*
             * Detector 默认不自动跟踪跳转。
             *
             * 原因：
             *
             * https://target
             *        ↓
             * Location: http://other-host
             *
             * 一旦自动跟随，就可能把我们的探测
             * 从指定 IP 转移到另外一个目标。
             *
             * Phase 5 只观察 Location。
             */
            follow_redirects: false,

            max_redirects: 1,

            /*
             * HTTP Detector 的职责是观察 HTTP。
             *
             * TLS certificate validity 已经由 Phase 4
             * 单独检测。
             *
             * 所以默认允许 HTTP probe 在证书异常时
             * 仍然拿到 HTTP response。
             */
            accept_invalid_certs: true,

            accept_invalid_hostnames: true,

            user_agent: "cfprobe/0.1".to_string(),

            max_header_value_bytes: 4096,
        }
    }
}

#[derive(Clone)]
pub struct HttpProber {
    config: HttpProbeConfig,
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

        Ok(Self { config })
    }

    pub async fn probe(&self, ip: IpAddr, hostname: &str) -> Result<HttpDetection, CfProbeError> {
        let hostname = normalize_hostname(hostname)?;

        let url = build_url(self.config.scheme, &hostname, self.config.port);

        let client = self.build_client(&hostname, ip)?;

        let host_header = build_host_header(&hostname, self.config.scheme, self.config.port);

        let response = client
            .get(&url)
            .header(
                HOST,
                HeaderValue::from_str(&host_header).map_err(|error| {
                    CfProbeError::InvalidResponse(format!("invalid Host header: {error}"))
                })?,
            )
            .header(reqwest::header::USER_AGENT, self.config.user_agent.clone())
            .header(reqwest::header::ACCEPT, "*/*")
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .send()
            .await;

        let response = match response {
            Ok(response) => response,

            Err(error) => {
                return Ok(HttpDetection::failed(
                    ip,
                    hostname,
                    self.config.port,
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

        /*
         * follow_redirects=false 时，
         * 这个字段是原始响应的 Location。
         *
         * 如果未来打开 redirect，
         * final_url 会反映最终 URL。
         */
        let _ = self.config.follow_redirects;

        let _ = self.config.max_redirects;

        Ok(HttpDetection {
            ip,

            hostname,

            port: self.config.port,

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

    fn build_client(&self, hostname: &str, ip: IpAddr) -> Result<Client, CfProbeError> {
        let socket_addr = SocketAddr::new(ip, self.config.port);

        let client = reqwest::Client::builder()
            /*
             * 非常重要：
             *
             * cfprobe 必须直接探测指定目标。
             *
             * 不应该继承：
             *
             * HTTP_PROXY
             * HTTPS_PROXY
             * ALL_PROXY
             *
             * 否则结果可能来自用户本机的代理。
             */
            .no_proxy()
            .user_agent(self.config.user_agent.clone())
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.timeout)
            /*
             * hostname -> 指定 IP。
             *
             * URL 仍然使用 hostname。
             *
             * 因此 HTTPS：
             *
             * SNI = hostname
             *
             * TCP:
             *
             * ip:port
             */
            .resolve(hostname, socket_addr)
            /*
             * Phase 5 的 HTTP observation path
             * 不负责判断证书是否可信。
             */
            .danger_accept_invalid_certs(self.config.accept_invalid_certs)
            .danger_accept_invalid_hostnames(self.config.accept_invalid_hostnames)
            /*
             * 不自动跳转。
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

            let value = truncate_header_value(value, max_value_bytes);

            Some(HttpHeader {
                name: name.as_str().to_string(),

                value,
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