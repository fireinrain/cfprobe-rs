use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use tokio::{net::TcpStream, time::timeout};

use tokio_rustls::{
    client::{TlsConnector, TlsStream},
    rustls::{self, ClientConfig, RootCertStore},
};

use rustls::pki_types::ServerName;

use webpki_roots::TLS_SERVER_ROOTS;

use x509_parser::{extensions::GeneralName, prelude::*};

use crate::{error::CfProbeError, probe::Target};

use super::{
    model::{CertificateInfo, CertificateVerificationStatus, TlsDetection, TlsDetectionStatus},
    verifier::ObservationVerifier,
};

/// TLS 探测配置。
#[derive(Debug, Clone)]
pub struct TlsProbeConfig {
    /// 单次握手超时。
    pub timeout: Duration,

    /// 默认端口。
    ///
    /// 当调用 `probe` 时使用。
    pub port: u16,

    /// 是否先进行正常的证书链校验握手。
    pub verify_certificate: bool,

    /// 严格模式失败时，是否回退到放宽校验（仅记录证书）。
    pub observation_fallback: bool,

    /// 客户端提供的 ALPN 协议列表。
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl Default for TlsProbeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),

            port: 443,

            verify_certificate: true,

            observation_fallback: true,

            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }
}

/// TLS 握手探测器（可 Clone，内部为 Arc）。
///
/// 在内部预构建了 verified / observation 两种 rustls `ClientConfig`，
/// 避免每次探测重新解析根证书。建议长期存活复用。
#[derive(Clone)]
pub struct TlsProber {
    config: TlsProbeConfig,
    /// 预构建好的 Verified 模式配置，
    /// 避免每次探测重新解析 ~150 个根证书。
    verified_config: Option<Arc<ClientConfig>>,
    /// 预构建好的 Observation 模式配置。
    observation_config: Option<Arc<ClientConfig>>,
}

impl TlsProber {
    /// 根据配置创建 TlsProber；会自动调用 [`crate::init_rustls_crypto`]。
    pub fn new(config: TlsProbeConfig) -> Self {
        crate::init_rustls_crypto();

        let verified_config = if config.verify_certificate {
            match build_client_config(ProbeMode::Verified, &config.alpn_protocols) {
                Ok(cfg) => Some(Arc::new(cfg)),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to pre-build TLS verified config, will fall back at probe time"
                    );
                    None
                }
            }
        } else {
            None
        };

        let observation_config = if config.observation_fallback {
            match build_client_config(ProbeMode::Observation, &config.alpn_protocols) {
                Ok(cfg) => Some(Arc::new(cfg)),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to pre-build TLS observation config, will fall back at probe time"
                    );
                    None
                }
            }
        } else {
            None
        };

        Self {
            config,
            verified_config,
            observation_config,
        }
    }

    /// 获取当前使用的配置引用。
    pub fn config(&self) -> &TlsProbeConfig {
        &self.config
    }

    /// 使用 `TlsProbeConfig::port` 作为默认端口进行 TLS 探测。
    pub async fn probe(&self, ip: IpAddr, hostname: &str) -> Result<TlsDetection, CfProbeError> {
        self.probe_with_port(ip, hostname, self.config.port).await
    }

    /// 对指定 IP + SNI + Port 执行 TLS 探测。
    ///
    /// 行为：
    /// 1. 若 `verify_certificate` 打开，先执行严格校验握手。
    /// 2. 严格失败且 `observation_fallback` 打开，再用忽略校验模式重连，只为提取证书。
    /// 3. 两种模式都失败则返回 `TlsDetectionStatus::HandshakeFailed`。
    pub async fn probe_with_port(
        &self,
        ip: IpAddr,
        hostname: &str,
        port: u16,
    ) -> Result<TlsDetection, CfProbeError> {
        if port == 0 {
            return Err(CfProbeError::InvalidResponse(
                "TLS port cannot be 0".to_string(),
            ));
        }

        let hostname = normalize_hostname(hostname)?;

        /*
         * 第一阶段：
         *
         * 正常验证服务器证书。
         */
        let strict_result = if self.config.verify_certificate {
            self.probe_once(ip, &hostname, port, ProbeMode::Verified)
                .await
        } else {
            None
        };

        /*
         * 如果正常验证模式已经成功，
         * 直接返回，不再做第二次握手。
         */
        if let Some(result) = strict_result {
            if result.handshake_succeeded {
                return Ok(result);
            }

            /*
             * 如果禁止 observation fallback，
             * 那么直接返回 strict 模式结果。
             */
            if !self.config.observation_fallback {
                return Ok(result);
            }
        }

        /*
         * 第二阶段：
         *
         * 如果证书验证失败，但用户允许 observation fallback，
         * 使用 observation verifier 再进行一次 TLS 握手。
         *
         * 这个模式仍然验证 TLS cryptographic handshake，
         * 只是跳过 CA / hostname / expiration 等证书信任判断。
         */
        if self.config.observation_fallback {
            if let Some(result) = self
                .probe_once(ip, &hostname, port, ProbeMode::Observation)
                .await
            {
                return Ok(result);
            }
        }

        /*
         * 理论上 probe_once() 已经会返回失败结果，
         * 这里作为最终保护。
         */
        Ok(TlsDetection::failed(
            ip,
            hostname,
            port,
            "TLS handshake failed".to_string(),
        ))
    }

    /// Phase 8 Facade 使用的 API。
    ///
    /// Target 是整个 cfprobe 的统一目标定义，
    /// 因此这里直接使用 Target 中的 IP / Host / Port。
    pub async fn probe_target(&self, target: &Target) -> Result<TlsDetection, CfProbeError> {
        self.probe_with_port(target.ip, &target.hostname, target.port)
            .await
    }

    async fn probe_once(
        &self,
        ip: IpAddr,
        hostname: &str,
        port: u16,
        mode: ProbeMode,
    ) -> Option<TlsDetection> {
        let addr = SocketAddr::new(ip, port);

        /*
         * -----------------------------------------
         * TCP connect
         * -----------------------------------------
         */
        let stream = match timeout(self.config.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,

            Ok(Err(error)) => {
                return Some(TlsDetection::failed(
                    ip,
                    hostname.to_string(),
                    port,
                    format!("TCP connect failed: {error}"),
                ));
            }

            Err(_) => {
                return Some(TlsDetection::failed(
                    ip,
                    hostname.to_string(),
                    port,
                    "TCP connect timeout".to_string(),
                ));
            }
        };

        /*
         * -----------------------------------------
         * SNI
         * -----------------------------------------
         */
        let server_name = match ServerName::try_from(hostname.to_string()) {
            Ok(name) => name,

            Err(error) => {
                return Some(TlsDetection::failed(
                    ip,
                    hostname.to_string(),
                    port,
                    format!("invalid TLS server name: {error}"),
                ));
            }
        };

        /*
         * -----------------------------------------
         * Rustls ClientConfig
         * -----------------------------------------
         *
         * 99% 场景直接使用预构建的 ClientConfig（一次性根证书解析）。
         * 如果初始化时构建失败，才退回到 probe 时现做。
         */
        let config_clone: Arc<ClientConfig> = match mode {
            ProbeMode::Verified => match self.verified_config.as_ref() {
                Some(cfg) => cfg.clone(),
                None => match build_client_config(mode, &self.config.alpn_protocols) {
                    Ok(cfg) => Arc::new(cfg),
                    Err(error) => {
                        return Some(TlsDetection::failed(
                            ip,
                            hostname.to_string(),
                            port,
                            format!("TLS config failed: {error}"),
                        ));
                    }
                },
            },
            ProbeMode::Observation => match self.observation_config.as_ref() {
                Some(cfg) => cfg.clone(),
                None => match build_client_config(mode, &self.config.alpn_protocols) {
                    Ok(cfg) => Arc::new(cfg),
                    Err(error) => {
                        return Some(TlsDetection::failed(
                            ip,
                            hostname.to_string(),
                            port,
                            format!("TLS config failed: {error}"),
                        ));
                    }
                },
            },
        };

        let connector = TlsConnector::from(config_clone);

        /*
         * -----------------------------------------
         * TLS handshake
         * -----------------------------------------
         */
        let tls_stream =
            match timeout(self.config.timeout, connector.connect(server_name, stream)).await {
                Ok(Ok(stream)) => stream,

                Ok(Err(error)) => {
                    return Some(TlsDetection::failed(
                        ip,
                        hostname.to_string(),
                        port,
                        format!("TLS handshake failed: {error}"),
                    ));
                }

                Err(_) => {
                    return Some(TlsDetection::failed(
                        ip,
                        hostname.to_string(),
                        port,
                        "TLS handshake timeout".to_string(),
                    ));
                }
            };

        /*
         * -----------------------------------------
         * Extract TLS information
         * -----------------------------------------
         */
        Some(build_detection(ip, hostname, port, mode, tls_stream))
    }
}

#[derive(Debug, Clone, Copy)]
enum ProbeMode {
    Verified,

    Observation,
}

fn build_client_config(
    mode: ProbeMode,
    alpn_protocols: &[Vec<u8>],
) -> Result<ClientConfig, rustls::Error> {
    crate::init_rustls_crypto();

    let builder = ClientConfig::builder();

    match mode {
        ProbeMode::Verified => {
            let mut roots = RootCertStore::empty();

            roots.extend(TLS_SERVER_ROOTS.iter().cloned());

            let mut config = builder.with_root_certificates(roots).with_no_client_auth();

            config.alpn_protocols = alpn_protocols.to_vec();

            Ok(config)
        }

        ProbeMode::Observation => {
            let provider = rustls::crypto::CryptoProvider::get_default()
                .ok_or_else(|| rustls::Error::General("no rustls CryptoProvider".to_string()))?;

            let verifier = ObservationVerifier::new(provider.signature_verification_algorithms);

            let mut config = builder
                .dangerous()
                .with_custom_certificate_verifier(verifier.into_arc())
                .with_no_client_auth();

            config.alpn_protocols = alpn_protocols.to_vec();

            Ok(config)
        }
    }
}

fn build_detection(
    ip: IpAddr,
    hostname: &str,
    port: u16,
    mode: ProbeMode,
    stream: TlsStream<TcpStream>,
) -> TlsDetection {
    let (_, connection) = stream.get_ref();

    let tls_version = connection
        .protocol_version()
        .map(|version| format!("{version:?}"));

    let cipher_suite = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()));

    let alpn = connection
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).to_string());

    let certificates = connection
        .peer_certificates()
        .map(parse_certificates)
        .unwrap_or_default();

    let verification = match mode {
        ProbeMode::Verified => CertificateVerificationStatus::Valid,

        ProbeMode::Observation => CertificateVerificationStatus::Unknown,
    };

    let status = match mode {
        ProbeMode::Verified => TlsDetectionStatus::HandshakeSucceeded,

        ProbeMode::Observation => TlsDetectionStatus::CertificateVerificationFailed,
    };

    TlsDetection {
        ip,

        hostname: hostname.to_string(),

        port,

        sni: Some(hostname.to_string()),

        handshake_succeeded: true,

        status,

        certificate_verification: verification,

        tls_version,

        cipher_suite,

        alpn,

        certificates,

        error: None,
    }
}

fn parse_certificates(
    certificates: &[rustls::pki_types::CertificateDer<'static>],
) -> Vec<CertificateInfo> {
    certificates
        .iter()
        .filter_map(|certificate| parse_certificate(certificate.as_ref()))
        .collect()
}

fn parse_certificate(der: &[u8]) -> Option<CertificateInfo> {
    let (_, certificate) = X509Certificate::from_der(der).ok()?;

    let mut dns_names = Vec::new();

    let mut ip_addresses = Vec::new();

    if let Ok(Some(san)) = certificate.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(name) => {
                    dns_names.push(name.to_string());
                }

                GeneralName::IPAddress(bytes) => {
                    if bytes.len() == 4 {
                        let octets: [u8; 4] = match <[u8; 4]>::try_from(bytes.as_ref()) {
                            Ok(value) => value,

                            Err(_) => {
                                continue;
                            }
                        };

                        ip_addresses.push(std::net::Ipv4Addr::from(octets).to_string());
                    } else if bytes.len() == 16 {
                        let octets: [u8; 16] = match <[u8; 16]>::try_from(bytes.as_ref()) {
                            Ok(value) => value,

                            Err(_) => {
                                continue;
                            }
                        };

                        ip_addresses.push(std::net::Ipv6Addr::from(octets).to_string());
                    }
                }

                _ => {}
            }
        }
    }

    let sha256 = Sha256::digest(der);

    Some(CertificateInfo {
        sha256: hex::encode(sha256),

        subject: certificate.subject().to_string(),

        issuer: certificate.issuer().to_string(),

        serial: certificate.raw_serial_as_string(),

        not_before: certificate.validity().not_before.to_string(),

        not_after: certificate.validity().not_after.to_string(),

        dns_names,

        ip_addresses,

        is_ca: certificate.is_ca(),
    })
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
