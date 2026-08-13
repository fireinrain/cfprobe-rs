use std::net::IpAddr;

use reqwest::Version;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HttpProbeStatus {
    ResponseReceived,

    RequestFailed,

    ResponseBodyLimitReached,

    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpHeader {
    pub name: String,

    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CloudflareHttpSignals {
    pub cf_ray: Option<String>,

    pub cf_cache_status: Option<String>,

    pub server: Option<String>,

    pub server_cloudflare: bool,

    pub cf_connecting_ip: Option<String>,

    pub cf_ip_country: Option<String>,

    pub age: Option<String>,

    pub via: Option<String>,

    pub cdn_cache_control: Option<String>,

    pub cf_mitigated: Option<String>,
}

impl CloudflareHttpSignals {
    pub fn score(&self) -> u8 {
        let mut score = 0u8;

        if self.cf_ray.is_some() {
            score = score.saturating_add(40);
        }

        if self.cf_cache_status.is_some() {
            score = score.saturating_add(25);
        }

        if self.server_cloudflare {
            score = score.saturating_add(20);
        }

        if self.cf_connecting_ip.is_some() {
            score = score.saturating_add(5);
        }

        if self.cf_ip_country.is_some() {
            score = score.saturating_add(5);
        }

        if self.cf_mitigated.is_some() {
            score = score.saturating_add(5);
        }

        score.min(100)
    }

    pub fn has_cloudflare_signal(&self) -> bool {
        self.cf_ray.is_some() || self.cf_cache_status.is_some() || self.server_cloudflare
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpDetection {
    pub ip: IpAddr,

    pub hostname: String,

    pub port: u16,

    pub url: String,

    pub final_url: Option<String>,

    pub status_code: Option<u16>,

    pub http_version: Option<String>,

    pub status: HttpProbeStatus,

    pub headers: Vec<HttpHeader>,

    pub signals: CloudflareHttpSignals,

    pub content_type: Option<String>,

    pub content_length: Option<u64>,

    pub body_bytes_read: u64,

    pub body_truncated: bool,

    pub redirect_location: Option<String>,

    pub error: Option<String>,
}

impl HttpDetection {
    pub fn failed(ip: IpAddr, hostname: String, port: u16, url: String, error: String) -> Self {
        Self {
            ip,
            hostname,
            port,
            url,
            final_url: None,
            status_code: None,
            http_version: None,
            status: HttpProbeStatus::RequestFailed,
            headers: Vec::new(),
            signals: CloudflareHttpSignals::default(),
            content_type: None,
            content_length: None,
            body_bytes_read: 0,
            body_truncated: false,
            redirect_location: None,
            error: Some(error),
        }
    }
}

pub(crate) fn format_http_version(version: Version) -> String {
    match version {
        Version::HTTP_09 => "HTTP/0.9".to_string(),

        Version::HTTP_10 => "HTTP/1.0".to_string(),

        Version::HTTP_11 => "HTTP/1.1".to_string(),

        Version::HTTP_2 => "HTTP/2".to_string(),

        Version::HTTP_3 => "HTTP/3".to_string(),

        other => format!("{other:?}"),
    }
}
