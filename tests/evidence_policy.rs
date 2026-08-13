use std::{net::IpAddr, sync::Arc, time::Duration};

use cfprobe::{
    CloudflareHttpSignals, CloudflareIpDetection, CloudflareWebProxyV1, DetectionClassification,
    DnsDetection, DnsDetectionStatus, EvidenceEngine, EvidenceInput, EvidenceKind, HttpDetection,
    HttpProbeStatus,
};

fn cf_ip_detection() -> CloudflareIpDetection {
    let ip: IpAddr = "104.16.1.1".parse().unwrap();

    CloudflareIpDetection {
        ip,

        is_cloudflare: true,

        kind: cfprobe::DetectionKind::CloudflareEdge,
    }
}

fn http_with_cf_ray(ip: IpAddr) -> HttpDetection {
    let mut signals = CloudflareHttpSignals::default();

    signals.cf_ray = Some("abc123-SJC".to_string());

    HttpDetection {
        ip,

        hostname: "example.com".to_string(),

        port: 443,

        url: "https://example.com/".to_string(),

        final_url: Some("https://example.com/".to_string()),

        status_code: Some(200),

        http_version: Some("HTTP/2".to_string()),

        status: HttpProbeStatus::ResponseReceived,

        headers: Vec::new(),

        signals,

        content_type: None,

        content_length: None,

        body_bytes_read: 0,

        body_truncated: false,

        redirect_location: None,

        error: None,
    }
}

fn dns_result(
    ip: IpAddr,

    cf_count: usize,

    success_count: usize,

    resolver_count: usize,
) -> DnsDetection {
    DnsDetection {
        hostname: "example.com".to_string(),

        normalized_hostname: "example.com.".to_string(),

        observations: Vec::new(),

        union_ips: vec![ip],

        cloudflare_ips: if cf_count > 0 { vec![ip] } else { Vec::new() },

        cloudflare_resolver_count: cf_count,

        successful_resolver_count: success_count,

        resolver_count,

        all_resolvers_agree: cf_count == success_count,

        has_cloudflare_ip: cf_count > 0,

        total_duration: Duration::from_millis(0),

        status: if cf_count > 0 {
            DnsDetectionStatus::CloudflareIp
        } else {
            DnsDetectionStatus::NoCloudflareIp
        },

        mx_records: Vec::new(),

        txt_records: Vec::new(),

        ns_records: Vec::new(),

        cname_chain: Vec::new(),
    }
}

#[test]
fn default_policy_has_expected_identity() {
    let policy = CloudflareWebProxyV1::default();

    assert_eq!(policy.metadata().id, "cloudflare-web-proxy");

    assert_eq!(policy.metadata().version, 1);

    assert_eq!(policy.metadata().name, "Cloudflare Web Proxy V1");
}

#[test]
fn policy_contains_expected_weights() {
    let mut policy = CloudflareWebProxyV1::default();

    let rules = policy.rules_mut();

    assert_eq!(rules.weight(EvidenceKind::CloudflareIpRange), 80);

    assert_eq!(rules.weight(EvidenceKind::HttpCfRay), 35);

    assert_eq!(rules.weight(EvidenceKind::DnsResolvesToCloudflare), 25);

    assert_eq!(rules.weight(EvidenceKind::IpOutsideCloudflareRange), -100);
}

#[tokio::test]
async fn changing_http_ray_weight_changes_score() {
    let ip_detection = cf_ip_detection();

    let ip = ip_detection.ip;

    let http = http_with_cf_ray(ip);

    let mut policy = CloudflareWebProxyV1::default();

    policy
        .rules_mut()
        .weights
        .insert(EvidenceKind::HttpCfRay, 0);

    policy
        .rules_mut()
        .weights
        .insert(EvidenceKind::CloudflareIpRange, 20);

    let engine = EvidenceEngine::new(Arc::new(policy));

    let result = engine.evaluate(EvidenceInput::with_host(
        ip,
        "example.com",
        Some(&ip_detection),
        None,
        None,
        Some(&http),
    ));

    /*
     * IP itself is still Cloudflare,
     * but because this is a host query and
     * HTTP is our only host-specific signal,
     * removing its weight should prevent
     * the policy from reaching the positive threshold.
     */
    assert_eq!(result.classification, DetectionClassification::Unknown,);
}

#[tokio::test]
async fn dns_quorum_is_policy_controlled() {
    let ip_detection = cf_ip_detection();

    let ip = ip_detection.ip;

    /*
     * 2 / 3 resolvers see Cloudflare.
     */
    let dns = dns_result(ip, 2, 3, 3);

    /*
     * Policy A:
     *
     * Require 100% Cloudflare agreement.
     */
    let mut strict_policy = CloudflareWebProxyV1::default();

    strict_policy.rules_mut().dns.min_cloudflare_ratio = 1.0;

    let strict_engine = EvidenceEngine::new(Arc::new(strict_policy));

    let strict_result = strict_engine.evaluate(EvidenceInput::with_host(
        ip,
        "example.com",
        Some(&ip_detection),
        Some(&dns),
        None,
        None,
    ));

    assert_eq!(
        strict_result.classification,
        DetectionClassification::Unknown
    );

    /*
     * Policy B:
     *
     * Require only 50%.
     */
    let mut relaxed_policy = CloudflareWebProxyV1::default();

    relaxed_policy.rules_mut().dns.min_cloudflare_ratio = 0.50;

    let relaxed_engine = EvidenceEngine::new(Arc::new(relaxed_policy));

    let relaxed_result = relaxed_engine.evaluate(EvidenceInput::with_host(
        ip,
        "example.com",
        Some(&ip_detection),
        Some(&dns),
        None,
        None,
    ));

    assert_eq!(
        relaxed_result.classification,
        DetectionClassification::Cloudflare
    );
}

#[tokio::test]
async fn http_group_cap_is_policy_controlled() {
    let ip_detection = cf_ip_detection();

    let ip = ip_detection.ip;

    let mut http = http_with_cf_ray(ip);

    http.signals.cf_cache_status = Some("HIT".to_string());

    http.signals.server = Some("cloudflare".to_string());

    http.signals.server_cloudflare = true;

    let mut policy = CloudflareWebProxyV1::default();

    /*
     * Completely disable HTTP
     * contribution.
     */
    policy.rules_mut().category_caps.insert(
        cfprobe::EvidenceCategory::Http,
        cfprobe::ScoreCap::new(0, 0),
    );

    policy
        .rules_mut()
        .weights
        .insert(EvidenceKind::CloudflareIpRange, 20);

    let engine = EvidenceEngine::new(Arc::new(policy));

    let result = engine.evaluate(EvidenceInput::with_host(
        ip,
        "example.com",
        Some(&ip_detection),
        None,
        None,
        Some(&http),
    ));

    /*
     * The host query now has no host-specific
     * effective score.
     */
    assert_eq!(result.classification, DetectionClassification::Unknown,);
}