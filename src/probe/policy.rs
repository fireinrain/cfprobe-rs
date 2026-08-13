use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::{CfProbeError, DnsDetection, HttpScheme, Target};

/// Target 网络安全策略。
///
/// 默认策略面向：
///
/// “主动探测公网 Web 服务”
///
/// 因此默认拒绝：
///
/// - loopback
/// - RFC1918
/// - link-local
/// - multicast
/// - unspecified
/// - documentation ranges
/// - benchmark ranges
/// - IPv4-mapped IPv6 对应的私有 IPv4
/// - localhost / .local / .internal 等主机名
/// - 非 Cloudflare Web Proxy 支持的端口
#[derive(Debug, Clone)]
pub struct TargetPolicy {
    /// 是否允许私网地址。
    pub allow_private_ips: bool,

    /// 是否允许 loopback。
    pub allow_loopback: bool,

    /// 是否允许 link-local。
    pub allow_link_local: bool,

    /// 是否允许 multicast。
    pub allow_multicast: bool,

    /// 是否允许 unspecified 地址。
    pub allow_unspecified: bool,

    /// 是否允许 documentation / benchmark 地址。
    pub allow_special_use_ips: bool,

    /// 是否允许可能用于本地网络的 hostname。
    pub allow_local_hostnames: bool,

    /// 是否拒绝 DNS 返回私网/特殊用途 IP。
    pub reject_private_dns_answers: bool,

    /// HTTP 允许的端口。
    pub allowed_http_ports: BTreeSet<u16>,

    /// HTTPS 允许的端口。
    pub allowed_https_ports: BTreeSet<u16>,

    /// 最大 hostname 长度。
    pub max_hostname_length: usize,
}

impl TargetPolicy {
    /// Cloudflare Web Proxy V1 默认安全策略。
    pub fn cloudflare_web_proxy_v1() -> Self {
        let http_ports = [80, 8080, 8880, 2052, 2082, 2086, 2095]
            .into_iter()
            .collect();

        let https_ports = [443, 2053, 2083, 2087, 2096, 8443].into_iter().collect();

        Self {
            allow_private_ips: false,

            allow_loopback: false,

            allow_link_local: false,

            allow_multicast: false,

            allow_unspecified: false,

            allow_special_use_ips: false,

            allow_local_hostnames: false,

            reject_private_dns_answers: true,

            allowed_http_ports: http_ports,

            allowed_https_ports: https_ports,

            max_hostname_length: 253,
        }
    }

    /// 创建一个开发/内部网络策略。
    ///
    /// 注意：
    ///
    /// 这个策略不应该用于公网暴露的 HTTP API。
    pub fn development() -> Self {
        Self {
            allow_private_ips: true,

            allow_loopback: true,

            allow_link_local: true,

            allow_multicast: false,

            allow_unspecified: false,

            allow_special_use_ips: true,

            allow_local_hostnames: true,

            reject_private_dns_answers: false,

            allowed_http_ports: (1..=65535).collect(),

            allowed_https_ports: (1..=65535).collect(),

            max_hostname_length: 253,
        }
    }

    pub fn allow_private_ips(mut self, allow: bool) -> Self {
        self.allow_private_ips = allow;

        self
    }

    pub fn allow_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;

        self
    }

    pub fn allow_link_local(mut self, allow: bool) -> Self {
        self.allow_link_local = allow;

        self
    }

    pub fn allow_multicast(mut self, allow: bool) -> Self {
        self.allow_multicast = allow;

        self
    }

    pub fn allow_unspecified(mut self, allow: bool) -> Self {
        self.allow_unspecified = allow;

        self
    }

    pub fn allow_special_use_ips(mut self, allow: bool) -> Self {
        self.allow_special_use_ips = allow;

        self
    }

    pub fn allow_local_hostnames(mut self, allow: bool) -> Self {
        self.allow_local_hostnames = allow;

        self
    }

    pub fn reject_private_dns_answers(mut self, reject: bool) -> Self {
        self.reject_private_dns_answers = reject;

        self
    }

    pub fn allow_http_port(mut self, port: u16) -> Self {
        self.allowed_http_ports.insert(port);

        self
    }

    pub fn allow_https_port(mut self, port: u16) -> Self {
        self.allowed_https_ports.insert(port);

        self
    }

    /// 验证 Target 本身。
    ///
    /// 这个验证必须在任何 DNS/TLS/HTTP 网络操作之前执行。
    pub fn validate_target(&self, target: &Target) -> Result<(), CfProbeError> {
        target.validate()?;

        if target.hostname.len() > self.max_hostname_length {
            return Err(CfProbeError::TargetRejected {
                reason: format!(
                    "hostname exceeds maximum length of {} bytes",
                    self.max_hostname_length,
                ),
            });
        }

        let hostname = normalize_hostname(&target.hostname);

        if !self.allow_local_hostnames && is_local_hostname(&hostname) {
            return Err(CfProbeError::TargetRejected {
                reason: format!("local/internal hostname is not allowed: {hostname}",),
            });
        }

        /*
         * 不允许直接把 IP literal 当成 Host。
         *
         * cfprobe 的目标模型是：
         *
         * IP + hostname
         *
         * 而不是：
         *
         * IP + IP
         */
        if hostname.parse::<IpAddr>().is_ok() {
            return Err(CfProbeError::TargetRejected {
                reason: format!("IP literal is not allowed as hostname: {hostname}",),
            });
        }

        self.validate_ip(target.ip)?;

        self.validate_port(target.scheme, target.port)?;

        Ok(())
    }

    /// 验证目标 IP。
    pub fn validate_ip(&self, ip: IpAddr) -> Result<(), CfProbeError> {
        let classification = classify_ip(ip);

        if classification.loopback && !self.allow_loopback {
            return Err(CfProbeError::TargetRejected {
                reason: format!("loopback IP is not allowed: {ip}",),
            });
        }

        if classification.private && !self.allow_private_ips {
            return Err(CfProbeError::TargetRejected {
                reason: format!("private IP is not allowed: {ip}",),
            });
        }

        if classification.link_local && !self.allow_link_local {
            return Err(CfProbeError::TargetRejected {
                reason: format!("link-local IP is not allowed: {ip}",),
            });
        }

        if classification.multicast && !self.allow_multicast {
            return Err(CfProbeError::TargetRejected {
                reason: format!("multicast IP is not allowed: {ip}",),
            });
        }

        if classification.unspecified && !self.allow_unspecified {
            return Err(CfProbeError::TargetRejected {
                reason: format!("unspecified IP is not allowed: {ip}",),
            });
        }

        if classification.special_use && !self.allow_special_use_ips {
            return Err(CfProbeError::TargetRejected {
                reason: format!("special-use/documentation IP is not allowed: {ip}",),
            });
        }

        Ok(())
    }

    pub fn validate_port(&self, scheme: HttpScheme, port: u16) -> Result<(), CfProbeError> {
        if port == 0 {
            return Err(CfProbeError::TargetRejected {
                reason: "port cannot be 0".to_string(),
            });
        }

        let allowed = match scheme {
            HttpScheme::Http => self.allowed_http_ports.contains(&port),

            HttpScheme::Https => self.allowed_https_ports.contains(&port),
        };

        if !allowed {
            return Err(CfProbeError::TargetRejected {
                reason: format!("{scheme:?} port {port} is not allowed by the target policy",),
            });
        }

        Ok(())
    }

    /// 验证 DNS 结果。
    ///
    /// 这是 SSRF / DNS rebinding 防护的重要部分。
    ///
    /// 例如：
    ///
    /// evil.example
    ///      ↓
    /// 1.2.3.4
    /// 10.0.0.1
    ///
    /// 即使 Target.ip 本身是公网地址，
    /// 我们也不允许继续使用这个 hostname 进行探测。
    pub fn validate_dns(&self, dns: &DnsDetection) -> Result<(), CfProbeError> {
        let hostname = normalize_hostname(&dns.hostname);

        if !self.allow_local_hostnames && is_local_hostname(&hostname) {
            return Err(CfProbeError::TargetRejected {
                reason: format!("DNS target hostname is local/internal: {hostname}",),
            });
        }

        if !self.reject_private_dns_answers {
            return Ok(());
        }

        for ip in &dns.union_ips {
            if is_forbidden_ssrf_ip(*ip) {
                return Err(CfProbeError::TargetRejected {
                    reason: format!(
                        "hostname {} resolved to a private or special-use IP {}",
                        dns.hostname, ip,
                    ),
                });
            }
        }

        /*
         * CNAME 也需要检查。
         *
         * 不能因为最终 A/AAAA 看起来正常，
         * 就允许：
         *
         * example.com
         *   -> internal.local
         */
        for cname in dns
            .observations
            .iter()
            .flat_map(|observation| observation.cname_chain.iter())
        {
            let normalized = normalize_hostname(cname);

            if !self.allow_local_hostnames && is_local_hostname(&normalized) {
                return Err(CfProbeError::TargetRejected {
                    reason: format!("hostname CNAME points to local/internal name: {}", cname,),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IpClassification {
    pub private: bool,

    pub loopback: bool,

    pub link_local: bool,

    pub multicast: bool,

    pub unspecified: bool,

    pub special_use: bool,
}

fn classify_ip(ip: IpAddr) -> IpClassification {
    match ip {
        IpAddr::V4(ip) => classify_ipv4(ip),

        IpAddr::V6(ip) => classify_ipv6(ip),
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> IpClassification {
    let octets = ip.octets();

    let first = octets[0];

    let second = octets[1];

    let third = octets[2];

    let private = ip.is_private() || is_ipv4_cgnat(octets);

    let loopback = ip.is_loopback();

    let link_local = ip.is_link_local();

    let multicast = ip.is_multicast();

    let unspecified = ip.is_unspecified();

    let special_use = is_ipv4_special_use(first, second, third);

    IpClassification {
        private,

        loopback,

        link_local,

        multicast,

        unspecified,

        special_use,
    }
}

fn classify_ipv6(ip: Ipv6Addr) -> IpClassification {
    /*
     * IPv4-mapped IPv6：
     *
     * ::ffff:127.0.0.1
     * ::ffff:10.0.0.1
     *
     * 必须回到 IPv4 规则重新检查。
     */
    if let Some(v4) = ip.to_ipv4() {
        return classify_ipv4(v4);
    }

    let segments = ip.segments();

    let private = ip.is_unique_local();

    let loopback = ip.is_loopback();

    let link_local = ip.is_unicast_link_local();

    let multicast = ip.is_multicast();

    let unspecified = ip.is_unspecified();

    let special_use = is_ipv6_special_use(segments);

    IpClassification {
        private,

        loopback,

        link_local,

        multicast,

        unspecified,

        special_use,
    }
}

fn is_forbidden_ssrf_ip(ip: IpAddr) -> bool {
    let classification = classify_ip(ip);

    classification.private
        || classification.loopback
        || classification.link_local
        || classification.multicast
        || classification.unspecified
        || classification.special_use
}

fn is_ipv4_cgnat(octets: [u8; 4]) -> bool {
    /*
     * 100.64.0.0/10
     */
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_ipv4_special_use(first: u8, second: u8, third: u8) -> bool {
    /*
     * 0.0.0.0/8
     */
    if first == 0 {
        return true;
    }

    /*
     * 127.0.0.0/8
     */
    if first == 127 {
        return true;
    }

    /*
     * 169.254.0.0/16
     */
    if first == 169 && second == 254 {
        return true;
    }

    /*
     * 192.0.0.0/24
     */
    if first == 192 && second == 0 && third == 0 {
        return true;
    }

    /*
     * 192.0.2.0/24
     */
    if first == 192 && second == 0 && third == 2 {
        return true;
    }

    /*
     * 198.18.0.0/15
     */
    if first == 198 && (18..=19).contains(&second) {
        return true;
    }

    /*
     * 198.51.100.0/24
     */
    if first == 198 && second == 51 && third == 100 {
        return true;
    }

    /*
     * 203.0.113.0/24
     */
    if first == 203 && second == 0 && third == 113 {
        return true;
    }

    /*
     * 224.0.0.0/4
     *
     * multicast is also handled independently.
     */
    if (224..=239).contains(&first) {
        return true;
    }

    /*
     * 240.0.0.0/4
     */
    if first >= 240 {
        return true;
    }

    false
}

fn is_ipv6_special_use(segments: [u16; 8]) -> bool {
    /*
     * 2001:db8::/32
     *
     * Documentation.
     */
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }

    /*
     * 2001:0002::/48
     *
     * Benchmarking.
     */
    if segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0x0000 {
        return true;
    }

    /*
     * 100::/64
     *
     * Discard-only prefix.
     */
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return true;
    }

    /*
     * ff00::/8 is covered by is_multicast(),
     * but keep this explicit for clarity.
     */
    if segments[0] & 0xff00 == 0xff00 {
        return true;
    }

    false
}

fn is_local_hostname(hostname: &str) -> bool {
    let hostname = normalize_hostname(hostname);

    if hostname == "localhost" || hostname == "localhost.localdomain" {
        return true;
    }

    const LOCAL_SUFFIXES: &[&str] = &[
        ".local",
        ".localhost",
        ".localdomain",
        ".internal",
        ".intranet",
        ".lan",
        ".home.arpa",
    ];

    LOCAL_SUFFIXES
        .iter()
        .any(|suffix| hostname.ends_with(suffix))
}

fn normalize_hostname(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}
