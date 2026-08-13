use std::net::IpAddr;

use serde_json::json;

use crate::{
    CertificateVerificationStatus,
    CloudflareIpDetection,
    DnsDetection,
    DnsDetectionStatus,
    HttpDetection,
    TlsDetection,
};

use super::{
    model::{
        ConfidenceLevel,
        DetectionClassification,
        DetectionResult,
        EvidenceCategory,
        EvidenceDirection,
        EvidenceItem,
        EvidenceKind,
    },

    policy::{
        DetectionPolicy,
    },
};

pub struct EvidenceInput<'a> {
    pub ip:
        IpAddr,

    pub hostname:
        Option<&'a str>,

    pub ip_detection:
        Option<
            &'a CloudflareIpDetection,
        >,

    pub dns:
        Option<&'a DnsDetection>,

    pub tls:
        Option<&'a TlsDetection>,

    pub http:
        Option<&'a HttpDetection>,
}

impl<'a> EvidenceInput<'a> {
    pub fn ip_only(
        ip: IpAddr,
        ip_detection:
            &'a CloudflareIpDetection,
    ) -> Self {
        Self {
            ip,

            hostname:
                None,

            ip_detection:
                Some(
                    ip_detection
                ),

            dns:
                None,

            tls:
                None,

            http:
                None,
        }
    }

    pub fn with_host(
        ip: IpAddr,

        hostname: &'a str,

        ip_detection:
            Option<
                &'a CloudflareIpDetection
            >,

        dns:
            Option<
                &'a DnsDetection
            >,

        tls:
            Option<
                &'a TlsDetection
            >,

        http:
            Option<
                &'a HttpDetection
            >,
    ) -> Self {
        Self {
            ip,

            hostname:
                Some(hostname),

            ip_detection,

            dns,

            tls,

            http,
        }
    }
}

pub struct EvidenceEngine<P>
where
    P: DetectionPolicy,
{
    policy: P,
}

impl<P> EvidenceEngine<P>
where
    P: DetectionPolicy,
{
    pub fn new(
        policy: P,
    ) -> Self {
        Self {
            policy,
        }
    }

    pub fn policy(
        &self,
    ) -> &P {
        &self.policy
    }

    pub fn evaluate(
        &self,
        input:
            EvidenceInput<'_>,
    ) -> DetectionResult {
        validate_consistency(
            &input,
        );

        let mut evidence =
            Vec::new();

        collect_ip_evidence(
            self.policy.rules(),
            &input,
            &mut evidence,
        );

        collect_dns_evidence(
            self.policy.rules(),
            &input,
            &mut evidence,
        );

        collect_tls_evidence(
            self.policy.rules(),
            &input,
            &mut evidence,
        );

        collect_http_evidence(
            self.policy.rules(),
            &input,
            &mut evidence,
        );

        let positive_evidence_count =
            evidence
                .iter()
                .filter(
                    |item| {
                        item.direction
                            == EvidenceDirection::
                                Positive
                    },
                )
                .count();

        let negative_evidence_count =
            evidence
                .iter()
                .filter(
                    |item| {
                        item.direction
                            == EvidenceDirection::
                                Negative
                    },
                )
                .count();

        let score =
            calculate_aggregate_score(
                self.policy.rules(),
                &evidence,
            );

        let classification =
            classify(
                self.policy.rules(),
                &input,
                score,
                &evidence,
            );

        let confidence =
            calculate_confidence(
                self.policy.rules(),
                &classification,
                score,
                &evidence,
            );

        let confidence_level =
            confidence_level(
                self.policy.rules(),
                confidence,
                &classification,
            );

        let summary =
            build_summary(
                &classification,
                confidence,
                score,
                &evidence,
            );

        DetectionResult {
            ip:
                input.ip,

            hostname:
                input.hostname
                    .map(
                        ToOwned::to_owned
                    ),

            policy:
                self.policy
                    .metadata()
                    .clone(),

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

fn validate_consistency(
    input:
        &EvidenceInput<'_>,
) {
    if let Some(
        detection,
    ) = input.ip_detection
    {
        debug_assert_eq!(
            detection.ip,
            input.ip,
        );
    }

    if let Some(
        tls,
    ) = input.tls
    {
        debug_assert_eq!(
            tls.ip,
            input.ip,
        );

        if let Some(
            hostname,
        ) = input.hostname
        {
            debug_assert!(
                same_hostname(
                    &tls.hostname,
                    hostname,
                ),
            );
        }
    }

    if let Some(
        http,
    ) = input.http
    {
        debug_assert_eq!(
            http.ip,
            input.ip,
        );

        if let Some(
            hostname,
        ) = input.hostname
        {
            debug_assert!(
                same_hostname(
                    &http.hostname,
                    hostname,
                ),
            );
        }
    }

    if let Some(
        dns,
    ) = input.dns
    {
        if let Some(
            hostname,
        ) = input.hostname
        {
            debug_assert!(
                same_hostname(
                    &dns.hostname,
                    hostname,
                ),
            );
        }
    }
}

fn collect_ip_evidence(
    rules:
        &super::policy::RuleSet,

    input:
        &EvidenceInput<'_>,

    evidence:
        &mut Vec<EvidenceItem>,
) {
    let Some(
        detection,
    ) = input.ip_detection
    else {
        return;
    };

    let kind =
        if detection.is_cloudflare {
            EvidenceKind::
                CloudflareIpRange
        } else {
            EvidenceKind::
                IpOutsideCloudflareRange
        };

    let score =
        rules.weight(kind);

    let (
        direction,
        reason,
    ) =
        if detection.is_cloudflare {
            (
                EvidenceDirection::
                    Positive,

                format!(
                    "target IP {} belongs to a Cloudflare published IP range",
                    input.ip,
                ),
            )
        } else {
            (
                EvidenceDirection::
                    Negative,

                format!(
                    "target IP {} is outside the published Cloudflare IP ranges",
                    input.ip,
                ),
            )
        };

    evidence.push(
        EvidenceItem {
            category:
                EvidenceCategory::
                    Network,

            kind,

            direction,

            score,

            reason,

            details:
                json!({
                    "ip":
                        input.ip,

                    "is_cloudflare":
                        detection.is_cloudflare,
                }),
        },
    );
}

fn collect_dns_evidence(
    rules:
        &super::policy::RuleSet,

    input:
        &EvidenceInput<'_>,

    evidence:
        &mut Vec<EvidenceItem>,
) {
    let Some(
        dns,
    ) = input.dns
    else {
        return;
    };

    let resolver_count =
        dns.resolver_count;

    if resolver_count == 0 {
        return;
    }

    let successful_ratio =
        dns.successful_resolver_count
            as f32
            / resolver_count
                as f32;

    /*
     * This is policy-controlled.
     *
     * Example:
     *
     * 3 resolvers
     * 2 successful
     * min_successful_ratio = 0.5
     *
     * => sufficient
     */
    if successful_ratio
        < rules
            .dns
            .min_successful_ratio
    {
        /*
         * Not enough successful resolvers:
         *
         * Unknown, not negative.
         */
        return;
    }

    let cloudflare_ratio =
        if dns.successful_resolver_count
            == 0
        {
            0.0
        } else {
            dns.cloudflare_resolver_count
                as f32
                / dns.successful_resolver_count
                    as f32
        };

    if dns.cloudflare_resolver_count
        > 0
        && cloudflare_ratio
            >= rules
                .dns
                .min_cloudflare_ratio
    {
        let kind =
            EvidenceKind::
                DnsResolvesToCloudflare;

        let mut score =
            rules.weight(kind);

        /*
         * Consensus is an independent bonus
         * only if every successful resolver agrees.
         *
         * But the policy controls its value.
         */
        let all_successful_agree =
            dns.cloudflare_resolver_count
                == dns.successful_resolver_count;

        if all_successful_agree
            && dns.successful_resolver_count
                > 1
        {
            let consensus_kind =
                EvidenceKind::
                    DnsResolverConsensus;

            let consensus_score =
                rules.weight(
                    consensus_kind,
                );

            score +=
                consensus_score;

            evidence.push(
                EvidenceItem {
                    category:
                        EvidenceCategory::
                            Dns,

                    kind:
                        consensus_kind,

                    direction:
                        EvidenceDirection::
                            Positive,

                    score:
                        consensus_score,

                    reason:
                        format!(
                            "all {} successful DNS resolvers agreed on the Cloudflare result",
                            dns.successful_resolver_count,
                        ),

                    details:
                        json!({
                            "successful_resolver_count":
                                dns.successful_resolver_count,
                        }),
                },
            );
        }

        evidence.push(
            EvidenceItem {
                category:
                    EvidenceCategory::
                        Dns,

                kind,

                direction:
                    EvidenceDirection::
                        Positive,

                score,

                reason:
                    format!(
                        "DNS resolved {} to Cloudflare IP addresses; {} of {} successful resolvers agreed",
                        dns.hostname,
                        dns.cloudflare_resolver_count,
                        dns.successful_resolver_count,
                    ),

                details:
                    json!({
                        "cloudflare_ips":
                            dns.cloudflare_ips,

                        "cloudflare_resolver_count":
                            dns.cloudflare_resolver_count,

                        "successful_resolver_count":
                            dns.successful_resolver_count,

                        "resolver_count":
                            dns.resolver_count,

                        "cloudflare_ratio":
                            cloudflare_ratio,
                    }),
            },
        );

        return;
    }

    /*
     * Only produce negative evidence if:
     *
     * - enough resolvers succeeded
     * - ZERO resolvers saw Cloudflare
     * - policy enables this
     */
    if dns.cloudflare_resolver_count
        == 0
        && rules
            .dns
            .negative_when_no_cloudflare
    {
        let kind =
            EvidenceKind::
                DnsNoCloudflareResolution;

        evidence.push(
            EvidenceItem {
                category:
                    EvidenceCategory::
                        Dns,

                kind,

                direction:
                    EvidenceDirection::
                        Negative,

                score:
                    rules.weight(kind),

                reason:
                    format!(
                        "DNS did not resolve {} to Cloudflare IP ranges",
                        dns.hostname,
                    ),

                details:
                    json!({
                        "union_ips":
                            dns.union_ips,

                        "successful_resolver_count":
                            dns.successful_resolver_count,

                        "resolver_count":
                            dns.resolver_count,
                    }),
            },
        );
    }
}

fn collect_tls_evidence(
    rules:
        &super::policy::RuleSet,

    input:
        &EvidenceInput<'_>,

    evidence:
        &mut Vec<EvidenceItem>,
) {
    let Some(
        tls,
    ) = input.tls
    else {
        return;
    };

    if !tls.handshake_succeeded {
        return;
    }

    let kind =
        EvidenceKind::
            TlsHandshakeSucceeded;

    evidence.push(
        EvidenceItem {
            category:
                EvidenceCategory::
                    Tls,

            kind,

            direction:
                EvidenceDirection::
                    Positive,

            score:
                rules.weight(kind),

            reason:
                format!(
                    "TLS handshake succeeded for {} with SNI {}",
                    tls.ip,
                    tls.sni
                        .as_deref()
                        .unwrap_or(
                            "<none>"
                        ),
                ),

            details:
                json!({
                    "tls_version":
                        tls.tls_version,

                    "cipher_suite":
                        tls.cipher_suite,

                    "alpn":
                        tls.alpn,

                    "sni":
                        tls.sni,
                }),
        },
    );

    let Some(
        hostname,
    ) = input.hostname
    else {
        return;
    };

    let certificate_match =
        tls.certificates
            .iter()
            .any(
                |certificate| {
                    certificate
                        .dns_names
                        .iter()
                        .any(
                            |name| {
                                dns_name_matches(
                                    hostname,
                                    name,
                                )
                            },
                        )
                },
            );

    if certificate_match {
        let kind =
            EvidenceKind::
                TlsCertificateHostnameMatch;

        evidence.push(
            EvidenceItem {
                category:
                    EvidenceCategory::
                        Tls,

                kind,

                direction:
                    EvidenceDirection::
                        Positive,

                score:
                    rules.weight(kind),

                reason:
                    format!(
                        "TLS certificate SAN matches hostname {}",
                        hostname,
                    ),

                details:
                    json!({
                        "hostname":
                            hostname,

                        "matched":
                            true,
                    }),
            },
        );
    } else if !tls.certificates.is_empty() {
        let kind =
            EvidenceKind::
                TlsCertificateHostnameMismatch;

        evidence.push(
            EvidenceItem {
                category:
                    EvidenceCategory::
                        Tls,

                kind,

                direction:
                    EvidenceDirection::
                        Negative,

                score:
                    rules.weight(kind),

                reason:
                    format!(
                        "TLS certificate SAN does not match hostname {}",
                        hostname,
                    ),

                details:
                    json!({
                        "hostname":
                            hostname,

                        "matched":
                            false,
                    }),
            },
        );
    }

    match tls.certificate_verification {
        CertificateVerificationStatus::
            Valid =>
        {
            let kind =
                EvidenceKind::
                    TlsCertificateVerified;

            evidence.push(
                EvidenceItem {
                    category:
                        EvidenceCategory::
                            Tls,

                    kind,

                    direction:
                        EvidenceDirection::
                            Positive,

                    score:
                        rules.weight(kind),

                    reason:
                        "TLS certificate verification succeeded"
                            .to_string(),

                    details:
                        json!({
                            "verified":
                                true,
                        }),
                },
            );
        }

        CertificateVerificationStatus::
            Invalid =>
        {
            /*
             * We currently do not have a separate
             * TLS Invalid kind. The certificate mismatch
             * kind is used by the existing Phase 6 model.
             */
            let kind =
                EvidenceKind::
                    TlsCertificateHostnameMismatch;

            evidence.push(
                EvidenceItem {
                    category:
                        EvidenceCategory::
                            Tls,

                    kind,

                    direction:
                        EvidenceDirection::
                            Negative,

                    score:
                        rules.weight(kind),

                    reason:
                        "TLS certificate verification failed"
                            .to_string(),

                    details:
                        json!({
                            "verified":
                                false,
                        }),
                },
            );
        }

        CertificateVerificationStatus::
            NotAttempted
        | CertificateVerificationStatus::
            Unknown =>
        {
            let kind =
                EvidenceKind::
                    TlsCertificateVerificationUnavailable;

            evidence.push(
                EvidenceItem {
                    category:
                        EvidenceCategory::
                            Tls,

                    kind,

                    direction:
                        EvidenceDirection::
                            Neutral,

                    score:
                        rules.weight(kind),

                    reason:
                        "TLS certificate trust verification was not available"
                            .to_string(),

                    details:
                        json!({
                            "verified":
                                false,
                        }),
                },
            );
        }
    }
}

fn collect_http_evidence(
    rules:
        &super::policy::RuleSet,

    input:
        &EvidenceInput<'_>,

    evidence:
        &mut Vec<EvidenceItem>,
) {
    let Some(
        http,
    ) = input.http
    else {
        return;
    };

    if http.status_code.is_none() {
        return;
    }

    let signals =
        &http.signals;

    let candidates = [
        (
            EvidenceKind::HttpCfRay,
            signals.cf_ray.is_some(),
            "HTTP response contains CF-Ray",
        ),

        (
            EvidenceKind::
                HttpCfCacheStatus,
            signals
                .cf_cache_status
                .is_some(),
            "HTTP response contains CF-Cache-Status",
        ),

        (
            EvidenceKind::
                HttpServerCloudflare,
            signals.server_cloudflare,
            "HTTP Server header contains `cloudflare`",
        ),

        (
            EvidenceKind::
                HttpCfConnectingIp,
            signals
                .cf_connecting_ip
                .is_some(),
            "HTTP response contains CF-Connecting-IP",
        ),

        (
            EvidenceKind::
                HttpCfIpCountry,
            signals
                .cf_ip_country
                .is_some(),
            "HTTP response contains CF-IPCountry",
        ),

        (
            EvidenceKind::
                HttpCfMitigated,
            signals
                .cf_mitigated
                .is_some(),
            "HTTP response contains CF-Mitigated",
        ),
    ];

    let mut group_score =
        0i16;

    for (
        kind,
        present,
        reason,
    ) in candidates
    {
        if !present {
            continue;
        }

        let score =
            rules.weight(kind);

        group_score += score;

        evidence.push(
            EvidenceItem {
                category:
                    EvidenceCategory::
                        Http,

                kind,

                direction:
                    EvidenceDirection::
                        Positive,

                score,

                reason:
                    reason.to_string(),

                details:
                    http_signal_details(
                        http,
                        kind,
                    ),
            },
        );
    }

    let cap =
        rules.category_cap(
            EvidenceCategory::Http,
        );

    let capped =
        cap.clamp(
            group_score,
        );

    /*
     * EvidenceItem scores remain the
     * individual rule scores for auditability.
     *
     * Aggregate score applies category cap later.
     */
    if capped == 0 {
        let kind =
            EvidenceKind::
                HttpNoCloudflareSignals;

        evidence.push(
            EvidenceItem {
                category:
                    EvidenceCategory::
                        Http,

                kind,

                direction:
                    EvidenceDirection::
                        Neutral,

                score:
                    rules.weight(kind),

                reason:
                    "HTTP response contained no Cloudflare-specific headers"
                        .to_string(),

                details:
                    json!({
                        "status_code":
                            http.status_code,

                        "http_version":
                            http.http_version,
                    }),
            },
        );
    }
}

fn http_signal_details(
    http:
        &HttpDetection,

    kind:
        EvidenceKind,
) -> serde_json::Value {
    match kind {
        EvidenceKind::HttpCfRay => {
            json!({
                "cf_ray":
                    http.signals.cf_ray,
            })
        }

        EvidenceKind::
            HttpCfCacheStatus =>
        {
            json!({
                "cf_cache_status":
                    http
                        .signals
                        .cf_cache_status,
            })
        }

        EvidenceKind::
            HttpServerCloudflare =>
        {
            json!({
                "server":
                    http.signals.server,
            })
        }

        EvidenceKind::
            HttpCfConnectingIp =>
        {
            json!({
                "cf_connecting_ip":
                    http
                        .signals
                        .cf_connecting_ip,
            })
        }

        EvidenceKind::
            HttpCfIpCountry =>
        {
            json!({
                "cf_ipcountry":
                    http
                        .signals
                        .cf_ip_country,
            })
        }

        EvidenceKind::
            HttpCfMitigated =>
        {
            json!({
                "cf_mitigated":
                    http
                        .signals
                        .cf_mitigated,
            })
        }

        _ => {
            json!({})
        }
    }
}

fn calculate_aggregate_score(
    rules:
        &super::policy::RuleSet,

    evidence:
        &[EvidenceItem],
) -> i16 {
    let categories = [
        EvidenceCategory::
            Network,

        EvidenceCategory::
            Dns,

        EvidenceCategory::
            Tls,

        EvidenceCategory::
            Http,
    ];

    let mut total =
        0i16;

    for category
        in categories
    {
        let category_score =
            evidence
                .iter()
                .filter(
                    |item| {
                        item.category
                            == category
                    },
                )
                .map(
                    |item| item.score
                )
                .sum::<i16>();

        let cap =
            rules.category_cap(
                category,
            );

        total +=
            cap.clamp(
                category_score,
            );
    }

    rules.overall_cap
        .clamp(total)
}

fn classify(
    rules:
        &super::policy::RuleSet,

    input:
        &EvidenceInput<'_>,

    score:
        i16,

    evidence:
        &[EvidenceItem],
) -> DetectionClassification {
    /*
     * A known IP outside the provider's
     * published ranges is a hard contradiction.
     */
    if let Some(
        detection,
    ) = input.ip_detection
    {
        if !detection.is_cloudflare {
            return DetectionClassification::
                NotCloudflare;
        }
    }

    let has_hostname =
        input.hostname.is_some();

    /*
     * IP-only detection.
     */
    if !has_hostname {
        if !rules
            .classification
            .allow_ip_only_classification
        {
            return DetectionClassification::
                Unknown;
        }

        if score
            >= rules
                .classification
                .cloudflare_threshold
        {
            return DetectionClassification::
                Cloudflare;
        }

        if score
            <= rules
                .classification
                .not_cloudflare_threshold
        {
            return DetectionClassification::
                NotCloudflare;
        }

        return DetectionClassification::
            Unknown;
    }

    /*
     * Host-specific detection.
     */
    let host_specific_positive =
        evidence
            .iter()
            .any(
                |item| {
                    item.direction
                        == EvidenceDirection::
                            Positive
                        && rules
                            .classification
                            .host_specific_positive_kinds
                            .contains(
                                &item.kind,
                            )
                },
            );

    if rules
        .classification
        .require_host_specific_positive
        && !host_specific_positive
    {
        /*
         * We cannot prove this specific hostname
         * is being served through the provider.
         */
        if score
            <= rules
                .classification
                .not_cloudflare_threshold
        {
            return DetectionClassification::
                NotCloudflare;
        }

        return DetectionClassification::
            Unknown;
    }

    if score
        >= rules
            .classification
            .cloudflare_threshold
    {
        return DetectionClassification::
            Cloudflare;
    }

    if score
        <= rules
            .classification
            .not_cloudflare_threshold
    {
        return DetectionClassification::
            NotCloudflare;
    }

    DetectionClassification::
        Unknown
}

fn calculate_confidence(
    rules:
        &super::policy::RuleSet,

    classification:
        &DetectionClassification,

    score:
        i16,

    evidence:
        &[EvidenceItem],
) -> f32 {
    match classification {
        DetectionClassification::
            Cloudflare =>
        {
            let normalized =
                score
                    .max(0)
                    .min(100)
                    as f32;

            (
                rules
                    .confidence
                    .positive_base
                    + normalized
                        / rules
                            .confidence
                            .positive_divisor
            )
            .min(
                rules
                    .confidence
                    .max_confidence,
            )
        }

        DetectionClassification::
            NotCloudflare =>
        {
            let has_hard_negative =
                evidence
                    .iter()
                    .any(
                        |item| {
                            item.kind
                                == EvidenceKind::
                                    IpOutsideCloudflareRange
                        },
                    );

            if has_hard_negative {
                return rules
                    .confidence
                    .max_confidence;
            }

            let negative =
                score
                    .min(0)
                    .abs()
                    as f32;

            (
                rules
                    .confidence
                    .negative_base
                    + negative
                        / rules
                            .confidence
                            .negative_divisor
            )
            .min(
                rules
                    .confidence
                    .max_confidence,
            )
        }

        DetectionClassification::
            Unknown =>
        {
            0.0
        }
    }
}

fn confidence_level(
    rules:
        &super::policy::RuleSet,

    confidence:
        f32,

    classification:
        &DetectionClassification,
) -> ConfidenceLevel {
    if *classification
        == DetectionClassification::
            Unknown
    {
        return ConfidenceLevel::
            Insufficient;
    }

    if confidence
        >= rules
            .confidence
            .very_high_threshold
    {
        ConfidenceLevel::
            VeryHigh
    } else if confidence
        >= rules
            .confidence
            .high_threshold
    {
        ConfidenceLevel::
            High
    } else if confidence
        >= rules
            .confidence
            .medium_threshold
    {
        ConfidenceLevel::
            Medium
    } else {
        ConfidenceLevel::
            Low
    }
}

fn build_summary(
    classification:
        &DetectionClassification,

    confidence:
        f32,

    score:
        i16,

    evidence:
        &[EvidenceItem],
) -> String {
    let positive =
        evidence
            .iter()
            .filter(
                |item| {
                    item.direction
                        == EvidenceDirection::
                            Positive
                },
            )
            .map(
                |item| {
                    item.reason
                        .clone()
                },
            )
            .take(3)
            .collect::<Vec<_>>();

    let negative =
        evidence
            .iter()
            .filter(
                |item| {
                    item.direction
                        == EvidenceDirection::
                            Negative
                },
            )
            .map(
                |item| {
                    item.reason
                        .clone()
                },
            )
            .take(2)
            .collect::<Vec<_>>();

    match classification {
        DetectionClassification::
            Cloudflare =>
        {
            format!(
                "Cloudflare evidence is strong (score={}, confidence={:.2}); positive signals: {}",
                score,
                confidence,
                positive.join("; "),
            )
        }

        DetectionClassification::
            NotCloudflare =>
        {
            format!(
                "Cloudflare evidence is insufficient or contradicted (score={}, confidence={:.2}); negative signals: {}",
                score,
                confidence,
                negative.join("; "),
            )
        }

        DetectionClassification::
            Unknown =>
        {
            if positive.is_empty()
                && negative.is_empty()
            {
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

fn same_hostname(
    left:
        &str,

    right:
        &str,
) -> bool {
    normalize_hostname(left)
        == normalize_hostname(right)
}

fn normalize_hostname(
    hostname:
        &str,
) -> String {
    hostname
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn dns_name_matches(
    hostname:
        &str,

    pattern:
        &str,
) -> bool {
    let hostname =
        normalize_hostname(
            hostname,
        );

    let pattern =
        normalize_hostname(
            pattern,
        );

    if hostname == pattern {
        return true;
    }

    /*
     * Standard single-label wildcard:
     *
     * *.example.com
     *
     * matches:
     * api.example.com
     *
     * but not:
     * foo.api.example.com
     */
    if let Some(
        suffix,
    ) = pattern.strip_prefix("*.")
    {
        let expected_suffix =
            format!(
                ".{}",
                suffix,
            );

        if !hostname
            .ends_with(
                &expected_suffix,
            )
        {
            return false;
        }

        let prefix_len =
            hostname.len()
                - expected_suffix.len();

        if prefix_len == 0 {
            return false;
        }

        let prefix =
            &hostname[
                ..prefix_len
            ];

        return !prefix.contains('.');
    }

    false
}