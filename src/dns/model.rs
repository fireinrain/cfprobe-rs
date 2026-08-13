use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ResolverObservation {
    pub resolver: String,

    pub success: bool,

    pub ips: Vec<IpAddr>,

    pub cname_chain: Vec<String>,

    pub duration: Duration,

    pub error: Option<String>,

    pub mx_records: Vec<(u16, String)>,

    pub txt_records: Vec<String>,

    pub ns_records: Vec<String>,
}

impl ResolverObservation {
    pub fn has_cloudflare_ip(&self, ranges: &crate::CloudflareRanges) -> bool {
        self.ips.iter().any(|ip| ranges.contains(*ip))
    }

    pub fn resolved_ip_count(&self) -> usize {
        self.ips.len()
    }
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

    pub total_duration: Duration,

    pub status: DnsDetectionStatus,

    pub mx_records: Vec<(u16, String)>,

    pub txt_records: Vec<String>,

    pub ns_records: Vec<String>,

    pub cname_chain: Vec<String>,
}

impl DnsDetection {
    pub fn has_mx(&self) -> bool {
        !self.mx_records.is_empty()
    }

    pub fn has_txt(&self) -> bool {
        !self.txt_records.is_empty()
    }

    pub fn has_ns(&self) -> bool {
        !self.ns_records.is_empty()
    }

    pub fn has_cname(&self) -> bool {
        !self.cname_chain.is_empty()
    }

    pub fn successful_ratio(&self) -> f32 {
        if self.resolver_count == 0 {
            return 0.0;
        }
        self.successful_resolver_count as f32 / self.resolver_count as f32
    }

    pub fn cloudflare_ratio(&self) -> f32 {
        if self.successful_resolver_count == 0 {
            return 0.0;
        }
        self.cloudflare_resolver_count as f32 / self.successful_resolver_count as f32
    }

    pub fn confidence_ratio(&self) -> f32 {
        if self.resolver_count == 0 {
            return 0.0;
        }
        let success = self.successful_resolver_count as f32 / self.resolver_count as f32;
        let cf = if self.successful_resolver_count == 0 {
            0.0
        } else {
            self.cloudflare_resolver_count as f32 / self.successful_resolver_count as f32
        };
        (success * cf).min(1.0)
    }

    pub fn ips_match_targets(&self, expected_ips: &[IpAddr]) -> bool {
        if expected_ips.is_empty() {
            return false;
        }
        let set: std::collections::HashSet<_> = self.union_ips.iter().copied().collect();
        expected_ips.iter().all(|ip| set.contains(ip))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DnsDetectionStatus {
    CloudflareIp,

    NoCloudflareIp,

    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct ResolverHealth {
    pub success_count: u64,

    pub failure_count: u64,

    pub total_duration: Duration,

    pub last_success: Option<std::time::Instant>,

    pub last_failure: Option<std::time::Instant>,
}

impl ResolverHealth {
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.0;
        }
        self.success_count as f64 / total as f64
    }

    pub fn avg_duration(&self) -> Duration {
        if self.success_count == 0 {
            return Duration::from_secs(0);
        }
        self.total_duration.div_f32(self.success_count as f32)
    }

    pub fn is_healthy(&self) -> bool {
        let total = self.success_count + self.failure_count;
        if total < 3 {
            return true;
        }
        self.success_rate() >= 0.5
    }

    pub fn record_success(&mut self, duration: Duration) {
        self.success_count += 1;
        self.total_duration += duration;
        self.last_success = Some(std::time::Instant::now());
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(std::time::Instant::now());
    }
}