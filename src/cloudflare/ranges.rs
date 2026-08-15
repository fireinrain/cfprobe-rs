use ipnet::IpNet;
use std::net::IpAddr;

use crate::error::CfProbeError;

/// 已解析的 Cloudflare 官方 IP/CIDR 范围集合。
///
/// 数据源：`https://api.cloudflare.com/client/v4/ips`
#[derive(Debug, Clone)]
pub struct CloudflareRanges {
    ipv4: Vec<IpNet>,
    ipv6: Vec<IpNet>,

    etag: Option<String>,
}

impl CloudflareRanges {
    /// 从 Cloudflare API 返回的原始字符串列表构造，并执行 CIDR 解析。
    pub fn new(
        ipv4: Vec<String>,
        ipv6: Vec<String>,
        etag: Option<String>,
    ) -> Result<Self, CfProbeError> {
        let ipv4 = parse_ranges(ipv4)?;
        let ipv6 = parse_ranges(ipv6)?;

        Ok(Self { ipv4, ipv6, etag })
    }

    /// 判定给定 IP 是否命中 Cloudflare 官方 CIDR。
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.ipv4.iter().any(|network| network.contains(&ip)),
            IpAddr::V6(_) => self.ipv6.iter().any(|network| network.contains(&ip)),
        }
    }

    /// Cloudflare API 响应附带的 ETag（用于 HTTP 条件请求）。
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    /// 解析后的 IPv4 CIDR 列表。
    pub fn ipv4_ranges(&self) -> &[IpNet] {
        &self.ipv4
    }

    /// 解析后的 IPv6 CIDR 列表。
    pub fn ipv6_ranges(&self) -> &[IpNet] {
        &self.ipv6
    }
}

fn parse_ranges(values: Vec<String>) -> Result<Vec<IpNet>, CfProbeError> {
    values
        .into_iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|error| CfProbeError::InvalidCidr {
                    value,
                    reason: error.to_string(),
                })
        })
        .collect()
}
