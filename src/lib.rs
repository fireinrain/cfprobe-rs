pub mod cloudflare;
pub mod detector;
pub mod dns;
pub mod error;
pub mod evidence;
pub mod http;
pub mod probe;
pub mod server;
pub mod tls;

pub use cloudflare::{
    CacheConfig, CacheResult, CacheSource, CloudflareApiRanges, CloudflareClient,
    CloudflareFetchResult, CloudflareRangeCache, CloudflareRangeProvider, CloudflareRanges,
};

pub use detector::{CloudflareIpDetection, DetectionKind, detect_cloudflare_ip};

pub use dns::{
    DnsBackend, DnsDetection, DnsDetectionStatus, DnsDetector, DnsResolverEntry,
    HickoryDnsResolver, ResolverObservation,
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
    ProbeResult, ProbeStage, ProbeStageError, Target,
};

pub use server::{ServerConfig, ServerMetrics};

pub use tls::{
    CertificateInfo, CertificateVerificationStatus, TlsDetection, TlsDetectionStatus,
    TlsProbeConfig, TlsProber,
};

pub use error::CfProbeError;
