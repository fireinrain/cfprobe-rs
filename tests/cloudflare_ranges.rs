use std::net::{IpAddr, Ipv4Addr};

use cfprobe::{CloudflareRanges, DetectionKind, detect_cloudflare_ip};

#[test]
fn detect_cloudflare_ipv4() {
    let ranges = CloudflareRanges::new(
        vec!["104.16.0.0/13".to_string()],
        vec![],
        Some("test-etag".to_string()),
    )
    .unwrap();

    let ip = IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1));

    let result = detect_cloudflare_ip(&ranges, ip);

    assert!(result.is_cloudflare);
    assert_eq!(result.kind, DetectionKind::CloudflareEdge);
}

#[test]
fn detect_non_cloudflare_ipv4() {
    let ranges = CloudflareRanges::new(vec!["104.16.0.0/13".to_string()], vec![], None).unwrap();

    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    let result = detect_cloudflare_ip(&ranges, ip);

    assert!(!result.is_cloudflare);
    assert_eq!(result.kind, DetectionKind::NotCloudflare);
}

#[test]
fn detect_cloudflare_ipv6() {
    let ranges = CloudflareRanges::new(vec![], vec!["2400:cb00::/32".to_string()], None).unwrap();

    let ip = IpAddr::V6("2400:cb00:1234::1".parse().unwrap());

    let result = detect_cloudflare_ip(&ranges, ip);

    assert!(result.is_cloudflare);
}

#[test]
fn reject_invalid_cidr() {
    let result = CloudflareRanges::new(vec!["invalid".to_string()], vec![], None);

    assert!(result.is_err());
}
