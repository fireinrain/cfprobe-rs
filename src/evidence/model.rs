use std::net::IpAddr;

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EvidenceCategory {
    Network,

    Dns,

    Tls,

    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EvidenceDirection {
    Positive,

    Negative,

    Neutral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DetectionClassification {
    Cloudflare,

    NotCloudflare,

    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ConfidenceLevel {
    VeryHigh,

    High,

    Medium,

    Low,

    Insufficient,
}

impl ConfidenceLevel {
    pub fn from_confidence(confidence: f32, classification: DetectionClassification) -> Self {
        if classification == DetectionClassification::Unknown {
            return Self::Insufficient;
        }

        if confidence >= 0.95 {
            Self::VeryHigh
        } else if confidence >= 0.85 {
            Self::High
        } else if confidence >= 0.70 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceItem {
    pub category: EvidenceCategory,

    pub kind: EvidenceKind,

    pub direction: EvidenceDirection,

    pub score: i16,

    pub reason: String,

    pub details: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionResult {
    pub ip: IpAddr,

    pub hostname: Option<String>,

    pub classification: DetectionClassification,

    pub confidence: f32,

    pub confidence_level: ConfidenceLevel,

    /*
     * Signed aggregate score.
     *
     * This is a heuristic score,
     * NOT a probability.
     */
    pub score: i16,

    pub evidence: Vec<EvidenceItem>,

    pub positive_evidence_count: usize,

    pub negative_evidence_count: usize,

    pub summary: String,
}
