pub mod cloudflare;

pub mod detector;

pub mod dns;

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

pub use error::CfProbeError;
