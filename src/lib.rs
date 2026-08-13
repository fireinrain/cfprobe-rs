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
    DnsBackend, DnsCache, DnsCacheConfig, DnsDetection, DnsDetectionStatus, DnsDetector,
    DnsPool, DnsResolverEntry, HickoryDnsResolver, ResolverHealth, ResolverObservation,
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
