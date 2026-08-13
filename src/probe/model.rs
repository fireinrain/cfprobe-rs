use std::net::IpAddr;

use serde::Serialize;

use crate::{CloudflareIpDetection, DetectionResult, DnsDetection, HttpDetection, TlsDetection};

use super::Target;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProbeStage {
    CloudflareRanges,

    Ip,

    Dns,

    Tls,

    Http,

    Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeStageError {
    pub stage: ProbeStage,

    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub ip: IpAddr,

    pub hostname: String,

    pub port: u16,

    pub target: Target,

    pub ip_detection: Option<CloudflareIpDetection>,

    pub dns: Option<DnsDetection>,

    pub tls: Option<TlsDetection>,

    pub http: Option<HttpDetection>,

    pub detection: DetectionResult,

    pub errors: Vec<ProbeStageError>,
}

impl ProbeResult {
    pub fn is_cloudflare(&self) -> bool {
        self.detection.classification == crate::DetectionClassification::Cloudflare
    }

    pub fn is_unknown(&self) -> bool {
        self.detection.classification == crate::DetectionClassification::Unknown
    }

    pub fn is_not_cloudflare(&self) -> bool {
        self.detection.classification == crate::DetectionClassification::NotCloudflare
    }
}
