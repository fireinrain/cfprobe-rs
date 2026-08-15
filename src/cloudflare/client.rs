use reqwest::Client;
use reqwest::header::{ETAG, HeaderValue, IF_NONE_MATCH};
use serde::Deserialize;

use crate::error::CfProbeError;

const CLOUDFLARE_IPS_API: &str = "https://api.cloudflare.com/client/v4/ips";

#[derive(Debug, Deserialize)]
struct ApiResponse {
    success: bool,

    #[serde(default)]
    errors: Vec<ApiError>,

    result: Option<ApiResult>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: Option<i64>,

    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiResult {
    etag: Option<String>,

    #[serde(default)]
    ipv4_cidrs: Vec<String>,

    #[serde(default)]
    ipv6_cidrs: Vec<String>,
}

/// Cloudflare 官方 IP 段 API 客户端。
///
/// 默认 endpoint: `https://api.cloudflare.com/client/v4/ips`。
#[derive(Clone)]
pub struct CloudflareClient {
    client: Client,

    endpoint: String,
}

impl CloudflareClient {
    /// 使用官方 API endpoint 创建客户端。
    pub fn new(client: Client) -> Self {
        Self {
            client,
            endpoint: CLOUDFLARE_IPS_API.to_string(),
        }
    }

    /// 使用自定义 endpoint（通常用于测试 / 私有镜像）。
    pub fn with_endpoint(client: Client, endpoint: impl Into<String>) -> Self {
        Self {
            client,
            endpoint: endpoint.into(),
        }
    }

    pub async fn fetch_ranges(
        &self,
        etag: Option<&str>,
    ) -> Result<CloudflareFetchResult, CfProbeError> {
        let mut request = self.client.get(&self.endpoint);

        if let Some(etag) = etag {
            let value = HeaderValue::from_str(etag).map_err(|error| {
                CfProbeError::InvalidResponse(format!("invalid cached ETag: {error}"))
            })?;

            request = request.header(IF_NONE_MATCH, value);
        }

        let response = request.send().await?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(CloudflareFetchResult::NotModified);
        }

        let status = response.status();

        if !status.is_success() {
            return Err(CfProbeError::InvalidResponse(format!(
                "Cloudflare returned HTTP status {}",
                status
            )));
        }

        // 有些服务会把 ETag 放在 HTTP header，
        // 我们保留它作为 result.etag 的 fallback。
        let header_etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);

        let response: ApiResponse = response.json().await?;

        if !response.success {
            let message = response
                .errors
                .into_iter()
                .map(|error| match (error.code, error.message) {
                    (Some(code), Some(message)) => {
                        format!("[{code}] {message}")
                    }

                    (_, Some(message)) => message,

                    (Some(code), None) => {
                        format!("error code {code}")
                    }

                    _ => "unknown Cloudflare API error".to_string(),
                })
                .collect::<Vec<_>>()
                .join("; ");

            return Err(CfProbeError::InvalidResponse(message));
        }

        let result = response
            .result
            .ok_or_else(|| CfProbeError::InvalidResponse("missing `result` field".to_string()))?;

        let etag = result.etag.or(header_etag);

        if result.ipv4_cidrs.is_empty() && result.ipv6_cidrs.is_empty() {
            return Err(CfProbeError::InvalidResponse(
                "Cloudflare returned an empty IP range set".to_string(),
            ));
        }

        Ok(CloudflareFetchResult::Updated(CloudflareApiRanges {
            etag,
            ipv4_cidrs: result.ipv4_cidrs,
            ipv6_cidrs: result.ipv6_cidrs,
        }))
    }
}

/// Cloudflare 范围 API 的两种响应情况。
#[derive(Debug, Clone)]
pub enum CloudflareFetchResult {
    /// 服务端返回 304 Not Modified，本地缓存仍然有效。
    NotModified,

    /// 返回了新的范围数据。
    Updated(CloudflareApiRanges),
}

/// 尚未解析的 Cloudflare API 原始响应（CIDR 字符串列表 + ETag）。
#[derive(Debug, Clone)]
pub struct CloudflareApiRanges {
    /// 响应附带的 ETag。
    pub etag: Option<String>,

    /// IPv4 CIDR 字符串列表。
    pub ipv4_cidrs: Vec<String>,

    /// IPv6 CIDR 字符串列表。
    pub ipv6_cidrs: Vec<String>,
}
