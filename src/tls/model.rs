use std::net::IpAddr;

use serde::Serialize;

/// TLS 握手阶段的宏观执行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TlsDetectionStatus {
    /// 握手完整成功（也可能是放宽校验后成功）。
    HandshakeSucceeded,

    /// TCP 连接建立，但证书链校验未能通过。
    CertificateVerificationFailed,

    /// 握手层面失败（超时、协议不匹配、RST 等）。
    HandshakeFailed,

    /// 未执行或内部错误。
    Unknown,
}

/// 证书链校验结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CertificateVerificationStatus {
    /// 通过内置 trust anchor 验证有效。
    Valid,

    /// 尝试过验证但未通过。
    Invalid,

    /// 因为握手失败或禁用验证而未尝试。
    NotAttempted,

    /// 状态未知。
    Unknown,
}

/// X.509 证书摘要信息（只保留探测所需字段）。
#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    /// DER 编码的 SHA-256 指纹（十六进制小写）。
    pub sha256: String,

    /// Subject DN（RFC 4514 字符串化）。
    pub subject: String,

    /// Issuer DN。
    pub issuer: String,

    /// Serial 号（十六进制）。
    pub serial: String,

    /// NotBefore（UTC RFC3339）。
    pub not_before: String,

    /// NotAfter（UTC RFC3339）。
    pub not_after: String,

    /// SAN 扩展中的 DNS 名称。
    pub dns_names: Vec<String>,

    /// SAN 扩展中的 IP 地址（文本化）。
    pub ip_addresses: Vec<String>,

    /// 是否为 CA 证书。
    pub is_ca: bool,
}

/// TLS 探测结果（IP + SNI + 端口）。
#[derive(Debug, Clone, Serialize)]
pub struct TlsDetection {
    /// 直连的目标 IP。
    pub ip: IpAddr,

    /// 目标主机名。
    pub hostname: String,

    /// TCP 端口。
    pub port: u16,

    /// 发送的 SNI（若为空则未发送）。
    pub sni: Option<String>,

    /// 握手是否成功（`status` 的简写）。
    pub handshake_succeeded: bool,

    /// 握手执行状态。
    pub status: TlsDetectionStatus,

    /// 证书校验结果。
    pub certificate_verification: CertificateVerificationStatus,

    /// 协商出的 TLS 版本（如 "TLS1.3"）。
    pub tls_version: Option<String>,

    /// 协商出的密码套件（IANA 名字）。
    pub cipher_suite: Option<String>,

    /// 协商出的 ALPN 协议（如 "h2"、"http/1.1"）。
    pub alpn: Option<String>,

    /// 服务端返回的完整证书链。
    pub certificates: Vec<CertificateInfo>,

    /// 失败时的可读错误。
    pub error: Option<String>,
}

impl TlsDetection {
    /// 构造一个“握手失败”的结果（快速返回用）。
    pub fn failed(ip: IpAddr, hostname: String, port: u16, error: String) -> Self {
        Self {
            ip,

            hostname,

            port,

            sni: None,

            handshake_succeeded: false,

            status: TlsDetectionStatus::HandshakeFailed,

            certificate_verification: CertificateVerificationStatus::NotAttempted,

            tls_version: None,

            cipher_suite: None,

            alpn: None,

            certificates: Vec::new(),

            error: Some(error),
        }
    }
}
