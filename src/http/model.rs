use std::net::IpAddr;

use reqwest::Version;
use serde::Serialize;

/// HTTP 探测阶段的执行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HttpProbeStatus {
    /// 成功收到响应头（不一定是 2xx）。
    ResponseReceived,

    /// 请求阶段失败（网络/超时/连接错误等）。
    RequestFailed,

    /// 响应体超过配置上限而被截断（但头已解析）。
    ResponseBodyLimitReached,

    /// 未执行或未知。
    Unknown,
}

/// 单个 HTTP 头：名称 + 值。
#[derive(Debug, Clone, Serialize)]
pub struct HttpHeader {
    /// 头名称（按原样保留大小写）。
    pub name: String,

    /// 头值（UTF-8 化；若原始值含坏字节会被替代）。
    pub value: String,
}

/// 从响应头中提取的 Cloudflare 典型特征字段。
#[derive(Debug, Clone, Default, Serialize)]
pub struct CloudflareHttpSignals {
    /// `CF-RAY` 头（若存在）。
    pub cf_ray: Option<String>,

    /// `CF-Cache-Status` 头。
    pub cf_cache_status: Option<String>,

    /// 原始 `Server` 头值。
    pub server: Option<String>,

    /// `Server` 头是否等于 "cloudflare"。
    pub server_cloudflare: bool,

    /// `CF-Connecting-IP` 头（通常仅 Enterprise 回源出现）。
    pub cf_connecting_ip: Option<String>,

    /// `CF-IPCountry` 头。
    pub cf_ip_country: Option<String>,

    /// `Age` 头（表明缓存命中）。
    pub age: Option<String>,

    /// `Via` 头。
    pub via: Option<String>,

    /// `CDN-Cache-Control` 头。
    pub cdn_cache_control: Option<String>,

    /// `CF-Mitigated` 头。
    pub cf_mitigated: Option<String>,
}

impl CloudflareHttpSignals {
    /// 基于存在的 Cloudflare 独有特征头给出 0~100 的打分。
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

    /// 是否存在任一强 Cloudflare 信号头（`CF-RAY` / `CF-Cache-Status` / `Server: cloudflare`）。
    pub fn has_cloudflare_signal(&self) -> bool {
        self.cf_ray.is_some() || self.cf_cache_status.is_some() || self.server_cloudflare
    }
}

/// HTTP 探测阶段的结果。
#[derive(Debug, Clone, Serialize)]
pub struct HttpDetection {
    /// 直连目标 IP。
    pub ip: IpAddr,

    /// 目标主机名。
    pub hostname: String,

    /// TCP 端口。
    pub port: u16,

    /// 初始请求 URL。
    pub url: String,

    /// 若有重定向，最终落地的 URL（跟随次数上限由配置决定）。
    pub final_url: Option<String>,

    /// HTTP 响应码；若请求阶段失败为 `None`。
    pub status_code: Option<u16>,

    /// 协商出的 HTTP 版本（如 "HTTP/2"）。
    pub http_version: Option<String>,

    /// 本次探测的执行状态。
    pub status: HttpProbeStatus,

    /// 全部响应头（原始顺序）。
    pub headers: Vec<HttpHeader>,

    /// 从 `headers` 中提取的 Cloudflare 专属信号。
    pub signals: CloudflareHttpSignals,

    /// `Content-Type` 头（若存在）。
    pub content_type: Option<String>,

    /// `Content-Length` 头解析为 u64。
    pub content_length: Option<u64>,

    /// 实际读取的响应体字节数（只读了很小的前缀以检测特殊内容）。
    pub body_bytes_read: u64,

    /// 响应体是否超过了限制导致截断。
    pub body_truncated: bool,

    /// `Location` 头值（若存在）。
    pub redirect_location: Option<String>,

    /// 请求阶段失败时的可读错误。
    pub error: Option<String>,
}

impl HttpDetection {
    /// 快速构造一个“请求失败”结果。
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
