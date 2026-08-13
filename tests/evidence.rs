use std::net::{IpAddr, Ipv4Addr};

use cfprobe::{
    CertificateVerificationStatus, CloudflareHttpSignals, CloudflareIpDetection,
    DetectionClassification, DnsDetection, DnsDetectionStatus, EvidenceEngine, EvidenceInput,
    HttpDetection, HttpProbeStatus, TlsDetection, TlsDetectionStatus,
};

fn cloudflare_ip_detection(ip: IpAddr) -> CloudflareIpDetection {
    CloudflareIpDetection {
        ip,
        is_cloudflare: true,
        kind: cfprobe::DetectionKind::CloudflareEdge,
    }
}

fn non_cloudflare_ip_detection(ip: IpAddr) -> CloudflareIpDetection {
    CloudflareIpDetection {
        ip,
        is_cloudflare: false,
        kind: cfprobe::DetectionKind::NotCloudflare,
    }
}

fn base_http(ip: IpAddr) -> HttpDetection {
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
        signals: CloudflareHttpSignals::default(),
        content_type: Some("text/html".to_string()),
        content_length: Some(10),
        body_bytes_read: 10,
        body_truncated: false,
        redirect_location: None,
        error: None,
    }
}

fn base_tls(ip: IpAddr) -> TlsDetection {
    TlsDetection {
        ip,
        hostname: "example.com".to_string(),
        port: 443,
        sni: Some("example.com".to_string()),
        handshake_succeeded: true,
        status: TlsDetectionStatus::HandshakeSucceeded,
        certificate_verification: CertificateVerificationStatus::Valid,
        tls_version: Some("TLSv1_3".to_string()),
        cipher_suite: Some("TLS13_AES_256_GCM_SHA384".to_string()),
        alpn: Some("h2".to_string()),
        certificates: vec![cfprobe::CertificateInfo {
            sha256: "test".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "Test CA".to_string(),
            serial: "01".to_string(),
            not_before: "2026-01-01".to_string(),
            not_after: "2027-01-01".to_string(),
            dns_names: vec!["example.com".to_string()],
            ip_addresses: Vec::new(),
            is_ca: false,
        }],
        error: None,
    }
}

#[tokio::test]
async fn ip_only_cloudflare_is_positive() {
    let ip = IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1));

    let detection = cloudflare_ip_detection(ip);

    let result = EvidenceEngine::evaluate(EvidenceInput::ip_only(ip, &detection));

    assert_eq!(result.classification, DetectionClassification::Cloudflare,);

    assert!(result.confidence >= 0.85);

    assert!(result.score > 0);
}

#[tokio::test]
async fn host_requires_host_specific_evidence() {
    let ip = IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1));

    let detection = cloudflare_ip_detection(ip);

    let result = EvidenceEngine::evaluate(EvidenceInput::with_host(
        ip,
        "example.com",
        Some(&detection),
        None,
        None,
        None,
    ));

    /*
     * IP being a Cloudflare edge IP alone
     * is not enough to prove that this specific
     * hostname is using Cloudflare.
     */
    assert_eq!(result.classification, DetectionClassification::Unknown,);
}

#[tokio::test]
async fn strong_combined_evidence_is_cloudflare() {
    let ip = IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1));

    let ip_detection = cloudflare_ip_detection(ip);

    let dns = DnsDetection {
        hostname: "example.com".to_string(),
        normalized_hostname: "example.com.".to_string(),
        observations: Vec::new(),
        union_ips: vec![ip],
        cloudflare_ips: vec![ip],
        cloudflare_resolver_count: 3,
        successful_resolver_count: 3,
        resolver_count: 3,
        all_resolvers_agree: true,
        has_cloudflare_ip: true,
        status: DnsDetectionStatus::CloudflareIp,
    };

    let tls = base_tls(ip);

    let mut http = base_http(ip);

    http.signals.cf_ray = Some("abc123-SJC".to_string());

    http.signals.cf_cache_status = Some("HIT".to_string());

    http.signals.server = Some("cloudflare".to_string());

    http.signals.server_cloudflare = true;

    let result = EvidenceEngine::evaluate(EvidenceInput::with_host(
        ip,
        "example.com",
        Some(&ip_detection),
        Some(&dns),
        Some(&tls),
        Some(&http),
    ));

    assert_eq!(result.classification, DetectionClassification::Cloudflare,);

    assert!(result.confidence >= 0.90);

    assert!(result.positive_evidence_count >= 5);
}

#[tokio::test]
async fn outside_cloudflare_ip_is_negative() {
    let ip = "8.8.8.8".parse().unwrap();

    let detection = non_cloudflare_ip_detection(ip);

    let result = EvidenceEngine::evaluate(EvidenceInput::ip_only(ip, &detection));

    assert_eq!(
        result.classification,
        DetectionClassification::NotCloudflare,
    );

    assert!(result.confidence >= 0.95);

    assert!(result.score < 0);
}

#[tokio::test]
async fn spoofed_http_headers_do_not_override_non_cloudflare_ip() {
    let ip = "8.8.8.8".parse().unwrap();

    let ip_detection = non_cloudflare_ip_detection(ip);

    let mut http = base_http(ip);

    http.signals.cf_ray = Some("fake-ray".to_string());

    http.signals.cf_cache_status = Some("HIT".to_string());

    http.signals.server = Some("cloudflare".to_string());

    http.signals.server_cloudflare = true;

    let result = EvidenceEngine::evaluate(EvidenceInput::with_host(
        ip,
        "example.com",
        Some(&ip_detection),
        None,
        None,
        Some(&http),
    ));

    assert_eq!(
        result.classification,
        DetectionClassification::NotCloudflare,
    );

    assert!(result.score < 0);
}

#[tokio::test]
async fn dns_failure_is_not_negative() {
    let ip = "104.16.1.1".parse().unwrap();

    let ip_detection = cloudflare_ip_detection(ip);

    let dns = DnsDetection {
        hostname: "example.com".to_string(),
        normalized_hostname: "example.com.".to_string(),
        observations: Vec::new(),
        union_ips: Vec::new(),
        cloudflare_ips: Vec::new(),
        cloudflare_resolver_count: 0,
        successful_resolver_count: 0,
        resolver_count: 3,
        all_resolvers_agree: false,
        has_cloudflare_ip: false,
        status: DnsDetectionStatus::Unknown,
    };

    let result = EvidenceEngine::evaluate(EvidenceInput::with_host(
        ip,
        "example.com",
        Some(&ip_detection),
        Some(&dns),
        None,
        None,
    ));

    /*
     * IP alone is not enough for a hostname query.
     *
     * DNS failure must NOT turn into
     * "NotCloudflare".
     */
    assert_eq!(result.classification, DetectionClassification::Unknown,);

    assert!(result.score >= 0);
}

#[tokio::test]
async fn certificate_wildcard_is_recognized() {
    let ip = "104.16.1.1".parse().unwrap();

    let detection = cloudflare_ip_detection(ip);

    let mut tls = base_tls(ip);

    tls.certificates[0].dns_names = vec!["*.example.com".to_string()];

    tls.hostname = "api.example.com".to_string();

    let result = EvidenceEngine::evaluate(EvidenceInput::with_host(
        ip,
        "api.example.com",
        Some(&detection),
        None,
        Some(&tls),
        None,
    ));

    assert_eq!(result.classification, DetectionClassification::Cloudflare,);
}

#[tokio::test]
async fn http_correlated_headers_are_capped() {
    let ip = "104.16.1.1".parse().unwrap();

    let detection = cloudflare_ip_detection(ip);

    let mut http = base_http(ip);

    http.signals.cf_ray = Some("ray".to_string());

    http.signals.cf_cache_status = Some("HIT".to_string());

    http.signals.server = Some("cloudflare".to_string());

    http.signals.server_cloudflare = true;

    http.signals.cf_connecting_ip = Some("1.2.3.4".to_string());

    http.signals.cf_ip_country = Some("US".to_string());

    http.signals.cf_mitigated = Some("challenge".to_string());

    let result = EvidenceEngine::evaluate(EvidenceInput::with_host(
        ip,
        "example.com",
        Some(&detection),
        None,
        None,
        Some(&http),
    ));

    /*
     * The HTTP evidence must not explode
     * because several correlated headers exist.
     *
     * The maximum final score is still bounded
     * by the overall evidence model.
     */
    assert!(result.score <= 100);

    assert_eq!(result.classification, DetectionClassification::Cloudflare,);
}




