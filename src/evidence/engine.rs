use std::net::IpAddr;

use serde_json::json;

use crate::{
    CertificateVerificationStatus, CloudflareIpDetection, DnsDetection, DnsDetectionStatus,
    HttpDetection, TlsDetection,
};

use super::model::{
    ConfidenceLevel, DetectionClassification, DetectionResult, EvidenceCategory, EvidenceDirection,
    EvidenceItem, EvidenceKind,
};

const NETWORK_MAX_SCORE: i16 = 80;

const DNS_MAX_SCORE: i16 = 35;

const TLS_MAX_SCORE: i16 = 20;

const HTTP_MAX_SCORE: i16 = 45;

const CLOUD_FLARE_THRESHOLD: i16 = 65;

const NOT_CLOUD_FLARE_THRESHOLD: i16 = -50;

/**
 * 评分模型

当前基础分：

Network
    Cloudflare IP      +80
    Outside CF         -100

DNS
    Cloudflare DNS     +25
    Resolver consensus +0~10

TLS
    Handshake            +5
    Cert SAN match      +10
    Cert verified        +5
    Cert mismatch        -5

HTTP
    CF-Ray              +35
    CF-Cache-Status       +5
    Server: cloudflare    +5
    CF-Connecting-IP      +1
    CF-IPCountry           +1
    CF-Mitigated           +2

然后：

Network max = +80 / -100
DNS max     = +35
TLS max     = +20
HTTP max    = +45

最后：

[-100, +100]
 * 
 * 
 * 
 */
pub struct EvidenceInput<'a> {
    pub ip: IpAddr,

    pub hostname: Option<&'a str>,

    pub ip_detection: Option<&'a CloudflareIpDetection>,

    pub dns: Option<&'a DnsDetection>,

    pub tls: Option<&'a TlsDetection>,

    pub http: Option<&'a HttpDetection>,
}

impl<'a> EvidenceInput<'a> {
    pub fn ip_only(ip: IpAddr, ip_detection: &'a CloudflareIpDetection) -> Self {
        Self {
            ip,

            hostname: None,

            ip_detection: Some(ip_detection),

            dns: None,

            tls: None,

            http: None,
        }
    }

    pub fn with_host(
        ip: IpAddr,
        hostname: &'a str,
        ip_detection: Option<&'a CloudflareIpDetection>,
        dns: Option<&'a DnsDetection>,
        tls: Option<&'a TlsDetection>,
        http: Option<&'a HttpDetection>,
    ) -> Self {
        Self {
            ip,

            hostname: Some(hostname),

            ip_detection,

            dns,

            tls,

            http,
        }
    }
}

pub struct EvidenceEngine;

impl EvidenceEngine {
    pub fn evaluate(input: EvidenceInput<'_>) -> DetectionResult {
        let mut evidence = Vec::new();

        validate_consistency(&input);

        collect_ip_evidence(&input, &mut evidence);

        collect_dns_evidence(&input, &mut evidence);

        collect_tls_evidence(&input, &mut evidence);

        collect_http_evidence(&input, &mut evidence);

        let positive_evidence_count = evidence
            .iter()
            .filter(|item| item.direction == EvidenceDirection::Positive)
            .count();

        let negative_evidence_count = evidence
            .iter()
            .filter(|item| item.direction == EvidenceDirection::Negative)
            .count();

        let score = calculate_aggregate_score(&evidence);

        let classification = classify(&input, score, &evidence);

        let confidence = calculate_confidence(&classification, score, &evidence);

        let confidence_level = ConfidenceLevel::from_confidence(confidence, classification);

        let summary = build_summary(&classification, confidence, score, &evidence);

        DetectionResult {
            ip: input.ip,

            hostname: input.hostname.map(ToOwned::to_owned),

            classification,

            confidence,

            confidence_level,

            score,

            evidence,

            positive_evidence_count,

            negative_evidence_count,

            summary,
        }
    }
}

fn validate_consistency(input: &EvidenceInput<'_>) {
    if let Some(detection) = input.ip_detection {
        debug_assert_eq!(detection.ip, input.ip,);
    }

    if let Some(tls) = input.tls {
        debug_assert_eq!(tls.ip, input.ip,);

        if let Some(hostname) = input.hostname {
            debug_assert!(same_hostname(&tls.hostname, hostname,));
        }
    }

    if let Some(http) = input.http {
        debug_assert_eq!(http.ip, input.ip,);

        if let Some(hostname) = input.hostname {
            debug_assert!(same_hostname(&http.hostname, hostname,));
        }
    }

    if let Some(dns) = input.dns {
        if let Some(hostname) = input.hostname {
            debug_assert!(same_hostname(&dns.hostname, hostname,));
        }
    }
}

fn collect_ip_evidence(input: &EvidenceInput<'_>, evidence: &mut Vec<EvidenceItem>) {
    let Some(detection) = input.ip_detection else {
        return;
    };

    if detection.is_cloudflare {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Network,

            kind: EvidenceKind::CloudflareIpRange,

            direction: EvidenceDirection::Positive,

            score: NETWORK_MAX_SCORE,

            reason: format!(
                "target IP {} belongs to a Cloudflare published IP range",
                input.ip,
            ),

            details: json!({
                "ip": input.ip,
                "is_cloudflare": true,
            }),
        });
    } else {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Network,

            kind: EvidenceKind::IpOutsideCloudflareRange,

            direction: EvidenceDirection::Negative,

            /*
             * A normal Cloudflare CDN edge IP
             * should be inside Cloudflare's published
             * network ranges.
             */
            score: -100,

            reason: format!(
                "target IP {} is outside the published Cloudflare IP ranges",
                input.ip,
            ),

            details: json!({
                "ip": input.ip,
                "is_cloudflare": false,
            }),
        });
    }
}

fn collect_dns_evidence(input: &EvidenceInput<'_>, evidence: &mut Vec<EvidenceItem>) {
    let Some(dns) = input.dns else {
        return;
    };

    match dns.status {
        DnsDetectionStatus::CloudflareIp => {
            let resolver_ratio = if dns.resolver_count == 0 {
                0.0
            } else {
                dns.cloudflare_resolver_count as f32 / dns.resolver_count as f32
            };

            let base_score: i16 = 25;

            let consensus_bonus: i16 = if resolver_ratio >= 1.0 {
                10
            } else if resolver_ratio >= 0.67 {
                5
            } else {
                0
            };

            evidence.push(EvidenceItem {
                category: EvidenceCategory::Dns,

                kind: EvidenceKind::DnsResolvesToCloudflare,

                direction: EvidenceDirection::Positive,

                score: (base_score + consensus_bonus).min(DNS_MAX_SCORE),

                reason: format!(
                    "DNS resolved {} to Cloudflare IP addresses; {} of {} resolvers agreed",
                    dns.hostname, dns.cloudflare_resolver_count, dns.resolver_count,
                ),

                details: json!({
                    "cloudflare_ips":
                        dns.cloudflare_ips,

                    "cloudflare_resolver_count":
                        dns.cloudflare_resolver_count,

                    "successful_resolver_count":
                        dns.successful_resolver_count,

                    "resolver_count":
                        dns.resolver_count,

                    "all_resolvers_agree":
                        dns.all_resolvers_agree,
                }),
            });

            if dns.all_resolvers_agree && dns.resolver_count > 1 {
                evidence.push(EvidenceItem {
                    category: EvidenceCategory::Dns,

                    kind: EvidenceKind::DnsResolverConsensus,

                    direction: EvidenceDirection::Positive,

                    /*
                     * This is intentionally informational.
                     *
                     * The main DNS evidence already contains
                     * the consensus bonus. We do NOT add another
                     * score here, otherwise resolver agreement
                     * would be double-counted.
                     */
                    score: 0,

                    reason: "all successful DNS resolvers agreed on the Cloudflare result"
                        .to_string(),

                    details: json!({
                        "resolver_count":
                            dns.resolver_count,
                    }),
                });
            }
        }

        DnsDetectionStatus::NoCloudflareIp => {
            evidence.push(EvidenceItem {
                category: EvidenceCategory::Dns,

                kind: EvidenceKind::DnsNoCloudflareResolution,

                direction: EvidenceDirection::Negative,

                score: -10,

                reason: format!(
                    "DNS did not resolve {} to Cloudflare IP ranges",
                    dns.hostname,
                ),

                details: json!({
                    "union_ips":
                        dns.union_ips,

                    "successful_resolver_count":
                        dns.successful_resolver_count,

                    "resolver_count":
                        dns.resolver_count,
                }),
            });
        }

        DnsDetectionStatus::Unknown => {
            /*
             * DNS failure is NOT negative evidence.
             */
        }
    }
}

fn collect_tls_evidence(input: &EvidenceInput<'_>, evidence: &mut Vec<EvidenceItem>) {
    let Some(tls) = input.tls else {
        return;
    };

    if !tls.handshake_succeeded {
        return;
    }

    evidence.push(EvidenceItem {
        category: EvidenceCategory::Tls,

        kind: EvidenceKind::TlsHandshakeSucceeded,

        direction: EvidenceDirection::Positive,

        /*
         * TLS success only proves that the target
         * is speaking TLS. It is supporting evidence,
         * not Cloudflare-specific evidence.
         */
        score: 5,

        reason: format!(
            "TLS handshake succeeded for {} with SNI {}",
            tls.ip,
            tls.sni.as_deref().unwrap_or("<none>"),
        ),

        details: json!({
            "tls_version":
                tls.tls_version,

            "cipher_suite":
                tls.cipher_suite,

            "alpn":
                tls.alpn,

            "sni":
                tls.sni,
        }),
    });

    let Some(hostname) = input.hostname else {
        return;
    };

    let certificate_match = tls.certificates.iter().any(|certificate| {
        certificate
            .dns_names
            .iter()
            .any(|name| dns_name_matches(hostname, name))
    });

    if certificate_match {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Tls,

            kind: EvidenceKind::TlsCertificateHostnameMatch,

            direction: EvidenceDirection::Positive,

            score: 10,

            reason: format!("TLS certificate SAN matches hostname {}", hostname,),

            details: json!({
                "hostname":
                    hostname,

                "matched":
                    true,
            }),
        });
    } else if !tls.certificates.is_empty() {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Tls,

            kind: EvidenceKind::TlsCertificateHostnameMismatch,

            direction: EvidenceDirection::Negative,

            score: -5,

            reason: format!(
                "TLS handshake succeeded but no certificate SAN matched hostname {}",
                hostname,
            ),

            details: json!({
                "hostname":
                    hostname,

                "matched":
                    false,
            }),
        });
    }

    match tls.certificate_verification {
        CertificateVerificationStatus::Valid => {
            evidence.push(EvidenceItem {
                category: EvidenceCategory::Tls,

                kind: EvidenceKind::TlsCertificateVerified,

                direction: EvidenceDirection::Positive,

                score: 5,

                reason: "TLS certificate verification succeeded".to_string(),

                details: json!({
                    "verified":
                        true,
                }),
            });
        }

        CertificateVerificationStatus::Invalid => {
            evidence.push(EvidenceItem {
                category: EvidenceCategory::Tls,

                kind: EvidenceKind::TlsCertificateHostnameMismatch,

                direction: EvidenceDirection::Negative,

                score: -3,

                reason: "TLS certificate verification failed".to_string(),

                details: json!({
                    "verified":
                        false,
                }),
            });
        }

        CertificateVerificationStatus::NotAttempted | CertificateVerificationStatus::Unknown => {
            evidence.push(EvidenceItem {
                category: EvidenceCategory::Tls,

                kind: EvidenceKind::TlsCertificateVerificationUnavailable,

                direction: EvidenceDirection::Neutral,

                score: 0,

                reason: "TLS certificate trust verification was not available".to_string(),

                details: json!({
                    "verified":
                        false,
                }),
            });
        }
    }
}

fn collect_http_evidence(input: &EvidenceInput<'_>, evidence: &mut Vec<EvidenceItem>) {
    let Some(http) = input.http else {
        return;
    };

    if http.status_code.is_none() {
        return;
    }

    let signals = &http.signals;

    let mut score: i16 = 0;

    if signals.cf_ray.is_some() {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Http,

            kind: EvidenceKind::HttpCfRay,

            direction: EvidenceDirection::Positive,

            score: 35,

            reason: "HTTP response contains CF-Ray".to_string(),

            details: json!({
                "cf_ray":
                    signals.cf_ray,
            }),
        });

        score += 35;
    }

    if signals.cf_cache_status.is_some() {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Http,

            kind: EvidenceKind::HttpCfCacheStatus,

            direction: EvidenceDirection::Positive,

            score: 5,

            reason: "HTTP response contains CF-Cache-Status".to_string(),

            details: json!({
                "cf_cache_status":
                    signals.cf_cache_status,
            }),
        });

        score += 5;
    }

    if signals.server_cloudflare {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Http,

            kind: EvidenceKind::HttpServerCloudflare,

            direction: EvidenceDirection::Positive,

            /*
             * Server header alone is weak and easy to spoof.
             */
            score: 5,

            reason: "HTTP Server header contains `cloudflare`".to_string(),

            details: json!({
                "server":
                    signals.server,
            }),
        });

        score += 5;
    }

    if signals.cf_connecting_ip.is_some() {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Http,

            kind: EvidenceKind::HttpCfConnectingIp,

            direction: EvidenceDirection::Positive,

            score: 1,

            reason: "HTTP response contains CF-Connecting-IP".to_string(),

            details: json!({
                "cf_connecting_ip":
                    signals.cf_connecting_ip,
            }),
        });

        score += 1;
    }

    if signals.cf_ip_country.is_some() {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Http,

            kind: EvidenceKind::HttpCfIpCountry,

            direction: EvidenceDirection::Positive,

            score: 1,

            reason: "HTTP response contains CF-IPCountry".to_string(),

            details: json!({
                "cf_ipcountry":
                    signals.cf_ip_country,
            }),
        });

        score += 1;
    }

    if signals.cf_mitigated.is_some() {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Http,

            kind: EvidenceKind::HttpCfMitigated,

            direction: EvidenceDirection::Positive,

            score: 2,

            reason: "HTTP response contains CF-Mitigated".to_string(),

            details: json!({
                "cf_mitigated":
                    signals.cf_mitigated,
            }),
        });

        score += 2;
    }

    /*
     * HTTP headers are strongly correlated.
     *
     * Never allow a single HTTP response to contribute
     * more than HTTP_MAX_SCORE.
     */
    let actual_score = score.min(HTTP_MAX_SCORE);

    /*
     * If HTTP produced no Cloudflare-specific signal,
     * do not add negative evidence.
     *
     * Absence of a header is not proof of absence.
     */
    if actual_score == 0 {
        evidence.push(EvidenceItem {
            category: EvidenceCategory::Http,

            kind: EvidenceKind::HttpNoCloudflareSignals,

            direction: EvidenceDirection::Neutral,

            score: 0,

            reason: "HTTP response contained no Cloudflare-specific headers".to_string(),

            details: json!({
                "status_code":
                    http.status_code,

                "http_version":
                    http.http_version,
            }),
        });
    }

    /*
     * The individual evidence items already carry their own
     * score for auditability. The group cap is applied later
     * by calculate_aggregate_score().
     */
}

fn calculate_aggregate_score(evidence: &[EvidenceItem]) -> i16 {
    let mut network = 0i16;

    let mut dns = 0i16;

    let mut tls = 0i16;

    let mut http = 0i16;

    for item in evidence {
        match item.category {
            EvidenceCategory::Network => {
                network += item.score;
            }

            EvidenceCategory::Dns => {
                dns += item.score;
            }

            EvidenceCategory::Tls => {
                tls += item.score;
            }

            EvidenceCategory::Http => {
                http += item.score;
            }
        }
    }

    /*
     * Network negative evidence can be stronger than
     * the positive cap because being outside Cloudflare's
     * published network is a strong contradiction.
     */
    network = network.clamp(-100, NETWORK_MAX_SCORE);

    dns = dns.clamp(-DNS_MAX_SCORE, DNS_MAX_SCORE);

    tls = tls.clamp(-TLS_MAX_SCORE, TLS_MAX_SCORE);

    http = http.clamp(0, HTTP_MAX_SCORE);

    (network + dns + tls + http).clamp(-100, 100)
}

fn classify(
    input: &EvidenceInput<'_>,

    score: i16,

    evidence: &[EvidenceItem],
) -> DetectionClassification {
    /*
     * If we have a concrete IP-range negative,
     * treat the target as non-Cloudflare.
     *
     * This is specifically for the normal Cloudflare
     * CDN edge use case.
     */
    if let Some(detection) = input.ip_detection {
        if !detection.is_cloudflare {
            return DetectionClassification::NotCloudflare;
        }
    }

    let has_hostname = input.hostname.is_some();

    /*
     * IP-only query:
     *
     * If the caller explicitly asks "is this IP a
     * Cloudflare IP?", the IP range evidence is enough.
     */
    if !has_hostname {
        if score >= CLOUD_FLARE_THRESHOLD {
            return DetectionClassification::Cloudflare;
        }

        if score <= NOT_CLOUD_FLARE_THRESHOLD {
            return DetectionClassification::NotCloudflare;
        }

        return DetectionClassification::Unknown;
    }

    /*
     * Host-based query:
     *
     * IP range alone does not prove that this specific
     * hostname is using Cloudflare.
     *
     * Require at least one host-specific positive signal.
     */
    let host_specific_positive = evidence.iter().any(|item| {
        item.direction == EvidenceDirection::Positive
            && matches!(
                item.kind,
                EvidenceKind::DnsResolvesToCloudflare
                    | EvidenceKind::TlsCertificateHostnameMatch
                    | EvidenceKind::HttpCfRay
                    | EvidenceKind::HttpCfCacheStatus
                    | EvidenceKind::HttpServerCloudflare
                    | EvidenceKind::HttpCfConnectingIp
                    | EvidenceKind::HttpCfMitigated
            )
    });

    if score >= CLOUD_FLARE_THRESHOLD && host_specific_positive {
        return DetectionClassification::Cloudflare;
    }

    if score <= NOT_CLOUD_FLARE_THRESHOLD {
        return DetectionClassification::NotCloudflare;
    }

    DetectionClassification::Unknown
}

fn calculate_confidence(
    classification: &DetectionClassification,

    score: i16,

    evidence: &[EvidenceItem],
) -> f32 {
    match classification {
        DetectionClassification::Cloudflare => {
            /*
             * Scores are mapped to a human-readable confidence
             * range. This is NOT a statistical probability.
             */
            let normalized = score.max(0).min(100) as f32;

            let confidence = 0.50 + normalized / 200.0;

            confidence.min(0.99)
        }

        DetectionClassification::NotCloudflare => {
            let negative = score.min(0).abs() as f32;

            if evidence
                .iter()
                .any(|item| item.kind == EvidenceKind::IpOutsideCloudflareRange)
            {
                return 0.99;
            }

            (0.50 + negative / 200.0).min(0.99)
        }

        DetectionClassification::Unknown => 0.0,
    }
}

fn build_summary(
    classification: &DetectionClassification,

    confidence: f32,

    score: i16,

    evidence: &[EvidenceItem],
) -> String {
    let positive = evidence
        .iter()
        .filter(|item| item.direction == EvidenceDirection::Positive)
        .map(|item| item.reason.clone())
        .take(3)
        .collect::<Vec<_>>();

    let negative = evidence
        .iter()
        .filter(|item| item.direction == EvidenceDirection::Negative)
        .map(|item| item.reason.clone())
        .take(2)
        .collect::<Vec<_>>();

    match classification {
        DetectionClassification::Cloudflare => {
            format!(
                "Cloudflare evidence is strong (score={}, confidence={:.2}); positive signals: {}",
                score,
                confidence,
                positive.join("; "),
            )
        }

        DetectionClassification::NotCloudflare => {
            format!(
                "Cloudflare evidence is insufficient or contradicted (score={}, confidence={:.2}); negative signals: {}",
                score,
                confidence,
                negative.join("; "),
            )
        }

        DetectionClassification::Unknown => {
            if positive.is_empty() && negative.is_empty() {
                format!(
                    "insufficient evidence to classify the target (score={})",
                    score,
                )
            } else {
                format!(
                    "evidence is inconclusive (score={}); positive: {}; negative: {}",
                    score,
                    positive.join("; "),
                    negative.join("; "),
                )
            }
        }
    }
}

fn same_hostname(left: &str, right: &str) -> bool {
    normalize_hostname(left) == normalize_hostname(right)
}

fn normalize_hostname(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn dns_name_matches(hostname: &str, pattern: &str) -> bool {
    let hostname = normalize_hostname(hostname);

    let pattern = normalize_hostname(pattern);

    if hostname == pattern {
        return true;
    }

    /*
     * Only support the normal single-label wildcard:
     *
     * *.example.com
     *
     * It matches:
     *
     * api.example.com
     *
     * But not:
     *
     * foo.api.example.com
     */
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let expected_suffix = format!(".{}", suffix,);

        if !hostname.ends_with(&expected_suffix) {
            return false;
        }

        let prefix_len = hostname.len() - expected_suffix.len();

        if prefix_len == 0 {
            return false;
        }

        let prefix = &hostname[..prefix_len];

        return !prefix.contains('.');
    }

    false
}
