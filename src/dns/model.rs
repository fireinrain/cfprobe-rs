use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

/// 单个 DNS 解析器的一次观测结果（成功或失败）。
#[derive(Debug, Clone, Serialize)]
pub struct ResolverObservation {
    /// 解析器标识（如 "cloudflare"、"google"、"local"）。
    pub resolver: String,

    /// 是否查询成功。
    pub success: bool,

    /// A/AAAA 返回的 IP 列表。
    pub ips: Vec<IpAddr>,

    /// CNAME 链（从目标到最终权威的完整路径）。
    pub cname_chain: Vec<String>,

    /// 查询耗时。
    pub duration: Duration,

    /// 失败时的可读错误。
    pub error: Option<String>,

    /// MX 记录（优先级 + 域名）。
    pub mx_records: Vec<(u16, String)>,

    /// TXT 记录原文。
    pub txt_records: Vec<String>,

    /// NS 记录域名列表。
    pub ns_records: Vec<String>,
}

impl ResolverObservation {
    /// 返回的 IP 中是否有至少一个命中 Cloudflare 官方 CIDR。
    pub fn has_cloudflare_ip(&self, ranges: &crate::CloudflareRanges) -> bool {
        self.ips.iter().any(|ip| ranges.contains(*ip))
    }

    /// 返回的 IP 数量。
    pub fn resolved_ip_count(&self) -> usize {
        self.ips.len()
    }
}

/// 多解析器聚合后的 DNS 探测结果。
///
/// 内部会同时调用本地、Cloudflare、Google 等多个解析器，
/// 然后比较它们对同一主机名的解析答案是否一致。
#[derive(Debug, Clone, Serialize)]
pub struct DnsDetection {
    /// 查询的原始主机名。
    pub hostname: String,

    /// 标准化后的主机名（去尾点、小写）。
    pub normalized_hostname: String,

    /// 每个解析器对应的原始观测记录。
    pub observations: Vec<ResolverObservation>,

    /// 所有解析器返回 IP 的并集（去重）。
    pub union_ips: Vec<IpAddr>,

    /// 命中 Cloudflare 官方 CIDR 的 IP。
    pub cloudflare_ips: Vec<IpAddr>,

    /// 返回了至少一个 Cloudflare IP 的解析器数量。
    pub cloudflare_resolver_count: usize,

    /// 查询成功的解析器数量。
    pub successful_resolver_count: usize,

    /// 总解析器数量（含失败）。
    pub resolver_count: usize,

    /// 全部成功解析器是否返回相同的 IP 集合（按集合比较）。
    pub all_resolvers_agree: bool,

    /// 是否存在任一解析器返回 Cloudflare IP。
    pub has_cloudflare_ip: bool,

    /// 全部解析器累积耗时。
    pub total_duration: Duration,

    /// 三路聚合后的 DNS 分类判定。
    pub status: DnsDetectionStatus,

    /// 聚合后的 MX 记录。
    pub mx_records: Vec<(u16, String)>,

    /// 聚合后的 TXT 记录。
    pub txt_records: Vec<String>,

    /// 聚合后的 NS 记录。
    pub ns_records: Vec<String>,

    /// 聚合后的 CNAME 链。
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

/// DNS 探测阶段的分类结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DnsDetectionStatus {
    /// 至少一部分解析器返回了 Cloudflare IP。
    CloudflareIp,

    /// 成功解析但全部返回非 Cloudflare IP。
    NoCloudflareIp,

    /// 解析全部失败或结果不足以判定。
    Unknown,
}

/// 单个 DNS 解析器的健康度统计（用于 DnsPool 的健康路由）。
#[derive(Debug, Clone, Default)]
pub struct ResolverHealth {
    /// 累计成功次数。
    pub success_count: u64,

    /// 累计失败次数。
    pub failure_count: u64,

    /// 累计成功总耗时（用于计算平均值）。
    pub total_duration: Duration,

    /// 最近一次成功时间。
    pub last_success: Option<std::time::Instant>,

    /// 最近一次失败时间。
    pub last_failure: Option<std::time::Instant>,
}

impl ResolverHealth {
    /// 成功率（0.0 ~ 1.0），样本不足返回 0.0。
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.0;
        }
        self.success_count as f64 / total as f64
    }

    /// 平均成功耗时，样本不足返回 0。
    pub fn avg_duration(&self) -> Duration {
        if self.success_count == 0 {
            return Duration::from_secs(0);
        }
        self.total_duration.div_f32(self.success_count as f32)
    }

    /// 判定解析器是否可继续承担流量（样本 ≥ 3 且成功率 ≥ 50%）。
    pub fn is_healthy(&self) -> bool {
        let total = self.success_count + self.failure_count;
        if total < 3 {
            return true;
        }
        self.success_rate() >= 0.5
    }

    /// 记录一次成功查询。
    pub fn record_success(&mut self, duration: Duration) {
        self.success_count += 1;
        self.total_duration += duration;
        self.last_success = Some(std::time::Instant::now());
    }

    /// 记录一次失败查询。
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(std::time::Instant::now());
    }
}
