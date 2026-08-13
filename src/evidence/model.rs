use std::net::IpAddr;

use serde::Serialize;
use serde_json::Value;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
)]
pub enum EvidenceCategory {
    Network,
    Dns,
    Tls,
    Http,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
)]
pub enum EvidenceDirection {
    Positive,
    Negative,
    Neutral,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
)]
pub enum EvidenceKind {
    CloudflareIpRange,

    IpOutsideCloudflareRange,

    DnsResolvesToCloudflare,

    DnsResolverConsensus,

    DnsNoCloudflareResolution,

    TlsHandshakeSucceeded,

    TlsCertificateHostnameMatch,

    TlsCertificateHostnameMismatch,

    TlsCertificateVerified,

    TlsCertificateVerificationUnavailable,

    HttpCfRay,

    HttpCfCacheStatus,

    HttpServerCloudflare,

    HttpCfConnectingIp,

    HttpCfIpCountry,

    HttpCfMitigated,

    HttpNoCloudflareSignals,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
)]
pub enum DetectionClassification {
    Cloudflare,

    NotCloudflare,

    Unknown,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
)]
pub enum ConfidenceLevel {
    VeryHigh,

    High,

    Medium,

    Low,

    Insufficient,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
)]
pub struct PolicyMetadata {
    pub id: String,

    pub version: u32,

    pub name: String,

    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceItem {
    pub category:
        EvidenceCategory,

    pub kind:
        EvidenceKind,

    pub direction:
        EvidenceDirection,

    pub score:
        i16,

    pub reason:
        String,

    pub details:
        Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionResult {
    pub ip:
        IpAddr,

    pub hostname:
        Option<String>,

    pub policy:
        PolicyMetadata,

    pub classification:
        DetectionClassification,

    /*
     * This is a heuristic confidence,
     * NOT a statistical probability.
     */
    pub confidence:
        f32,

    pub confidence_level:
        ConfidenceLevel,

    /*
     * Signed aggregate heuristic score.
     */
    pub score:
        i16,

    pub evidence:
        Vec<EvidenceItem>,

    pub positive_evidence_count:
        usize,

    pub negative_evidence_count:
        usize,

    pub summary:
        String,
}