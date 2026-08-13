use std::net::IpAddr;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DnsAnswer {
    pub resolver: String,

    pub ips: Vec<IpAddr>,

    pub ipv4: Vec<IpAddr>,

    pub ipv6: Vec<IpAddr>,

    pub cname_chain: Vec<String>,

    pub cloudflare_ips: Vec<IpAddr>,

    pub cloudflare_ip_count: usize,

    pub total_ip_count: usize,
}

impl DnsAnswer {
    pub fn has_cloudflare_ip(&self) -> bool {
        self.cloudflare_ip_count > 0
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverObservation {
    pub resolver: String,

    pub success: bool,

    pub ips: Vec<IpAddr>,

    pub cname_chain: Vec<String>,

    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsDetection {
    pub hostname: String,

    pub normalized_hostname: String,

    pub observations: Vec<ResolverObservation>,

    pub union_ips: Vec<IpAddr>,

    pub cloudflare_ips: Vec<IpAddr>,

    pub cloudflare_resolver_count: usize,

    pub successful_resolver_count: usize,

    pub resolver_count: usize,

    pub all_resolvers_agree: bool,

    pub has_cloudflare_ip: bool,

    pub status: DnsDetectionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DnsDetectionStatus {
    CloudflareIp,

    NoCloudflareIp,

    Unknown,
}
