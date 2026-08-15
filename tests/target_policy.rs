use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use cfprobe::{
    CfProbeConfig, DnsDetection, DnsDetectionStatus, HttpScheme, IpClassification, Target,
    TargetPolicy,
};
use std::sync::Arc;

#[test]
fn public_ip_is_allowed() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target::https("104.16.1.1".parse().unwrap(), "example.com");

    assert!(policy.validate_target(&target,).is_ok());
}

#[test]
fn loopback_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target::http(IpAddr::V4(Ipv4Addr::LOCALHOST), "example.com");

    assert!(policy.validate_target(&target,).is_err());
}

#[test]
fn private_ipv4_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target::http("10.0.0.1".parse().unwrap(), "example.com");

    assert!(policy.validate_target(&target,).is_err());

    let target = Target::http("192.168.1.1".parse().unwrap(), "example.com");

    assert!(policy.validate_target(&target,).is_err());
}

#[test]
fn cgnat_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target::https("100.64.0.1".parse().unwrap(), "example.com");

    assert!(policy.validate_target(&target,).is_err());
}

#[test]
fn ipv4_mapped_ipv6_private_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target::https("::ffff:10.0.0.1".parse::<IpAddr>().unwrap(), "example.com");

    assert!(policy.validate_target(&target,).is_err());
}

#[test]
fn ipv6_unique_local_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target::https("fd00::1".parse::<IpAddr>().unwrap(), "example.com");

    assert!(policy.validate_target(&target,).is_err());
}

#[test]
fn ipv6_link_local_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target::https("fe80::1".parse::<IpAddr>().unwrap(), "example.com");

    assert!(policy.validate_target(&target,).is_err());
}

#[test]
fn multicast_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let ipv4_target = Target::https("224.0.0.1".parse().unwrap(), "example.com");

    assert!(policy.validate_target(&ipv4_target,).is_err());

    let ipv6_target = Target::https("ff02::1".parse::<IpAddr>().unwrap(), "example.com");

    assert!(policy.validate_target(&ipv6_target,).is_err());
}

#[test]
fn documentation_ip_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target::https("192.0.2.1".parse().unwrap(), "example.com");

    assert!(policy.validate_target(&target,).is_err());

    let target = Target::https("2001:db8::1".parse::<IpAddr>().unwrap(), "example.com");

    assert!(policy.validate_target(&target,).is_err());
}

#[test]
fn local_hostname_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    for hostname in [
        "localhost",
        "api.local",
        "service.internal",
        "foo.intranet",
        "router.lan",
        "foo.home.arpa",
    ] {
        let target = Target::https("104.16.1.1".parse().unwrap(), hostname);

        assert!(
            policy.validate_target(&target,).is_err(),
            "hostname should be rejected: {hostname}",
        );
    }
}

#[test]
fn ip_literal_hostname_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target::https("104.16.1.1".parse().unwrap(), "8.8.8.8");

    assert!(policy.validate_target(&target,).is_err());
}

#[test]
fn unsupported_port_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let target = Target {
        ip: "104.16.1.1".parse().unwrap(),

        hostname: "example.com".to_string(),

        port: 22,

        scheme: HttpScheme::Https,
    };

    assert!(policy.validate_target(&target,).is_err());
}

#[test]
fn cloudflare_supported_https_ports_are_allowed() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    for port in [443, 2053, 2083, 2087, 2096, 8443] {
        let target = Target {
            ip: "104.16.1.1".parse().unwrap(),

            hostname: "example.com".to_string(),

            port,

            scheme: HttpScheme::Https,
        };

        assert!(
            policy.validate_target(&target,).is_ok(),
            "HTTPS port should be allowed: {port}",
        );
    }
}

#[test]
fn cloudflare_supported_http_ports_are_allowed() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    for port in [80, 8080, 8880, 2052, 2082, 2086, 2095] {
        let target = Target {
            ip: "104.16.1.1".parse().unwrap(),

            hostname: "example.com".to_string(),

            port,

            scheme: HttpScheme::Http,
        };

        assert!(
            policy.validate_target(&target,).is_ok(),
            "HTTP port should be allowed: {port}",
        );
    }
}

#[test]
fn dns_private_answer_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let dns = DnsDetection {
        hostname: "evil.example".to_string(),

        normalized_hostname: "evil.example.".to_string(),

        observations: Vec::new(),

        union_ips: vec!["1.2.3.4".parse().unwrap(), "10.0.0.1".parse().unwrap()],

        cloudflare_ips: Vec::new(),

        cloudflare_resolver_count: 0,

        successful_resolver_count: 2,

        resolver_count: 2,

        all_resolvers_agree: false,

        has_cloudflare_ip: false,

        total_duration: Duration::from_millis(0),

        status: DnsDetectionStatus::NoCloudflareIp,

        mx_records: Vec::new(),

        txt_records: Vec::new(),

        ns_records: Vec::new(),

        cname_chain: Vec::new(),
    };

    assert!(policy.validate_dns(&dns,).is_err());
}

#[test]
fn dns_rebinding_like_resolution_is_rejected() {
    let policy = TargetPolicy::cloudflare_web_proxy_v1();

    let dns = DnsDetection {
        hostname: "evil.example".to_string(),

        normalized_hostname: "evil.example.".to_string(),

        observations: Vec::new(),

        union_ips: vec!["104.16.1.1".parse().unwrap(), "127.0.0.1".parse().unwrap()],

        cloudflare_ips: vec!["104.16.1.1".parse().unwrap()],

        cloudflare_resolver_count: 1,

        successful_resolver_count: 2,

        resolver_count: 2,

        all_resolvers_agree: false,

        has_cloudflare_ip: true,

        total_duration: Duration::from_millis(0),

        status: DnsDetectionStatus::CloudflareIp,

        mx_records: Vec::new(),

        txt_records: Vec::new(),

        ns_records: Vec::new(),

        cname_chain: Vec::new(),
    };

    assert!(policy.validate_dns(&dns,).is_err());
}

#[test]
fn development_policy_allows_private_targets() {
    let policy = TargetPolicy::development();

    let target = Target::http("127.0.0.1".parse().unwrap(), "localhost");

    assert!(policy.validate_target(&target,).is_ok());
}

#[test]
fn policy_can_be_injected_into_probe_config() {
    let policy = Arc::new(TargetPolicy::development());

    let config = CfProbeConfig::cloudflare_web_proxy_v1()
        .unwrap()
        .with_target_policy_arc(policy);

    assert!(config.target_policy.allow_private_ips);

    assert!(config.target_policy.allow_loopback);
}

#[test]
fn exported_ip_classification_type_is_available() {
    let ip = "192.168.1.1".parse::<IpAddr>().unwrap();

    let _classification: IpClassification = cfprobe::TargetPolicy::cloudflare_web_proxy_v1()
        .validate_ip(ip)
        .err()
        .map(|_| IpClassification {
            private: true,
            loopback: false,
            link_local: false,
            multicast: false,
            unspecified: false,
            special_use: false,
        })
        .unwrap();
}
