use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{CfProbeError, HttpScheme};

/// 一个探测目标：IP 直连地址 + SNI/Host 主机名 + 端口 + scheme。
///
/// TLS 与 HTTP 连接直接使用 `ip` 字段建立（不经过 DNS 解析），
/// `hostname` 用作 TLS SNI、HTTP Host 头以及 DNS 独立探测的查询名。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// 实际建立 TCP 连接所使用的 IP 地址。
    pub ip: IpAddr,

    /// 用作 TLS SNI、HTTP Host 头、DNS 查询名的主机名。
    pub hostname: String,

    /// TCP 端口。
    pub port: u16,

    /// HTTP / HTTPS scheme。
    pub scheme: HttpScheme,
}

impl Target {
    /// 便捷构造：`scheme = HTTPS`，`port = 443`。
    pub fn https(ip: IpAddr, hostname: impl Into<String>) -> Self {
        Self {
            ip,

            hostname: hostname.into(),

            port: 443,

            scheme: HttpScheme::Https,
        }
    }

    /// 便捷构造：`scheme = HTTP`，`port = 80`。
    pub fn http(ip: IpAddr, hostname: impl Into<String>) -> Self {
        Self {
            ip,

            hostname: hostname.into(),

            port: 80,

            scheme: HttpScheme::Http,
        }
    }

    /// 链式覆盖端口号。
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;

        self
    }

    /// 执行基础格式校验（非空端口、合法主机名）。
    ///
    /// 此校验不涉及 SSRF / 私网段等安全策略，后者由 [`TargetPolicy`](crate::TargetPolicy) 负责。
    pub fn validate(&self) -> Result<(), CfProbeError> {
        if self.port == 0 {
            return Err(CfProbeError::InvalidResponse(
                "target port cannot be 0".to_string(),
            ));
        }

        let hostname = self.hostname.trim();

        if hostname.is_empty() {
            return Err(CfProbeError::InvalidResponse(
                "target hostname cannot be empty".to_string(),
            ));
        }

        hickory_resolver::proto::rr::Name::from_utf8(&format!(
            "{}.",
            hostname.trim_end_matches('.'),
        ))
        .map_err(|error| {
            CfProbeError::InvalidResponse(format!("invalid target hostname `{hostname}`: {error}"))
        })?;

        Ok(())
    }
}
