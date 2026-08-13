use std::net::IpAddr;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TlsDetectionStatus {
    HandshakeSucceeded,

    CertificateVerificationFailed,

    HandshakeFailed,

    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CertificateVerificationStatus {
    Valid,

    Invalid,

    NotAttempted,

    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub sha256: String,

    pub subject: String,

    pub issuer: String,

    pub serial: String,

    pub not_before: String,

    pub not_after: String,

    pub dns_names: Vec<String>,

    pub ip_addresses: Vec<String>,

    pub is_ca: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsDetection {
    pub ip: IpAddr,

    pub hostname: String,

    pub port: u16,

    pub sni: Option<String>,

    pub handshake_succeeded: bool,

    pub status: TlsDetectionStatus,

    pub certificate_verification: CertificateVerificationStatus,

    pub tls_version: Option<String>,

    pub cipher_suite: Option<String>,

    pub alpn: Option<String>,

    pub certificates: Vec<CertificateInfo>,

    pub error: Option<String>,
}

impl TlsDetection {
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
