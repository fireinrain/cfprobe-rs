use std::net::IpAddr;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DetectionKind {
    CloudflareEdge,
    NotCloudflare,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudflareIpDetection {
    pub ip: IpAddr,
    pub is_cloudflare: bool,
    pub kind: DetectionKind,
}

impl CloudflareIpDetection {
    pub fn cloudflare(ip: IpAddr) -> Self {
        Self {
            ip,
            is_cloudflare: true,
            kind: DetectionKind::CloudflareEdge,
        }
    }

    pub fn not_cloudflare(ip: IpAddr) -> Self {
        Self {
            ip,
            is_cloudflare: false,
            kind: DetectionKind::NotCloudflare,
        }
    }
}
