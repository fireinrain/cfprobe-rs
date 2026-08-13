pub mod cloudflare;

pub mod detector;

pub mod dns;

pub mod evidence;

pub mod http;

pub mod tls;

pub mod error;

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
    ConfidenceLevel, DetectionClassification, DetectionResult, EvidenceCategory, EvidenceDirection,
    EvidenceEngine, EvidenceInput, EvidenceItem, EvidenceKind,
};

pub use http::{
    CloudflareHttpSignals, HttpDetection, HttpHeader, HttpProbeConfig, HttpProbeStatus, HttpProber,
    HttpScheme,
};

pub use tls::{
    CertificateInfo, CertificateVerificationStatus, TlsDetection, TlsDetectionStatus,
    TlsProbeConfig, TlsProber,
};

pub use error::CfProbeError;
