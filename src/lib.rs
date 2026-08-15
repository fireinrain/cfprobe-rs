//! # cfprobe
//!
//! Cloudflare CDN / 反向代理识别引擎。
//!
//! 通过综合 **IP 段归属、DNS 解析、TLS 握手、HTTP 指纹** 四路证据，
//! 以 **基于规则的证据评分引擎** 判定一个 `IP + Hostname` 是否是
//! Cloudflare 边缘节点上的站点，并给出置信度、详细证据链和各阶段探测结果。
//!
//! ## 快速开始
//!
//! ```rust,no_run
//! use std::net::IpAddr;
//! use cfprobe::{CfProbe, CfProbeConfig, Target};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = CfProbeConfig::cloudflare_web_proxy_v1()?;
//! let probe = CfProbe::new(config).await?;
//!
//! let target = Target::https("104.16.77.250".parse::<IpAddr>()?, "example.com");
//! let result = probe.detect(target).await?;
//!
//! println!("is_cloudflare   : {}", result.is_cloudflare());
//! println!("classification  : {:?}", result.detection.classification);
//! println!("confidence      : {:.2}", result.detection.confidence);
//! # Ok(())
//! # }
//! ```
//!
//! ## 架构概览
//!
//! ```text
//! CfProbe (facade)
//!   ├─ IP/DNS Detector  ─┐
//!   ├─ TLS Prober        ├─→ Evidence Engine → DetectionResult
//!   └─ HTTP Prober       ─┘
//! ```

pub mod cloudflare;
pub mod detector;
pub mod dns;
pub mod error;
pub mod evidence;
pub mod http;
pub mod probe;
pub mod server;
pub mod tls;

use std::sync::OnceLock;

static RUSTLS_CRYPTO_INIT: OnceLock<()> = OnceLock::new();

/// 初始化 rustls 加密提供者（使用 ring backend）。
///
/// 在首次创建 [`CfProbe`] 时会自动调用；如果直接使用底层模块（如 [`TlsProber`]），
/// 请在程序入口手动调用一次。
///
/// 本函数是幂等的，多次调用安全。
pub fn init_rustls_crypto() {
    RUSTLS_CRYPTO_INIT.get_or_init(|| {
        use rustls::crypto::CryptoProvider;

        if CryptoProvider::get_default().is_none() {
            let provider = rustls::crypto::ring::default_provider();
            let _ = CryptoProvider::install_default(provider);
        }
    });
}

pub use cloudflare::{
    CacheConfig, CacheResult, CacheSource, CloudflareApiRanges, CloudflareClient,
    CloudflareFetchResult, CloudflareRangeCache, CloudflareRangeProvider, CloudflareRanges,
};

pub use detector::{CloudflareIpDetection, DetectionKind, detect_cloudflare_ip};

pub use dns::{
    DnsBackend, DnsCache, DnsCacheConfig, DnsDetection, DnsDetectionStatus, DnsDetector, DnsPool,
    DnsResolverEntry, HickoryDnsResolver, ResolverHealth, ResolverObservation,
};

pub use evidence::{
    ClassificationRuleSet, CloudflareWebProxyV1, ConfidenceLevel, ConfidenceRuleSet,
    DetectionClassification, DetectionPolicy, DetectionResult, DnsRuleSet, EvidenceCategory,
    EvidenceDirection, EvidenceEngine, EvidenceInput, EvidenceItem, EvidenceKind, PolicyMetadata,
    RuleSet, ScoreCap,
};

pub use http::{
    CloudflareHttpSignals, HttpDetection, HttpHeader, HttpProbeConfig, HttpProbeStatus, HttpProber,
    HttpScheme,
};

pub use probe::{
    BatchItemResult, BatchItemStatus, BatchResult, BatchScanConfig, CfProbe, CfProbeConfig,
    IpClassification, ProbeResult, ProbeStage, ProbeStageError, Target, TargetPolicy,
};

pub use server::{ServerConfig, ServerMetrics};

pub use tls::{
    CertificateInfo, CertificateVerificationStatus, TlsDetection, TlsDetectionStatus,
    TlsProbeConfig, TlsProber,
};

pub use error::CfProbeError;
