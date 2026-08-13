use std::collections::{
    BTreeMap,
    BTreeSet,
};

use serde::Serialize;

use super::model::{
    DetectionClassification,
    EvidenceCategory,
    EvidenceKind,
    PolicyMetadata,
};

/**
 * 评分模型 v1.0 default

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

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
)]
pub struct ScoreCap {
    pub min: i16,

    pub max: i16,
}

impl ScoreCap {
    pub const fn new(
        min: i16,
        max: i16,
    ) -> Self {
        Self {
            min,
            max,
        }
    }

    pub fn clamp(
        &self,
        value: i16,
    ) -> i16 {
        value.clamp(
            self.min,
            self.max,
        )
    }
}

#[derive(
    Debug,
    Clone,
    Serialize,
)]
pub struct DnsRuleSet {
    /*
     * Minimum ratio of successful resolvers.
     *
     * Example:
     *
     * resolver_count = 3
     * successful = 2
     * ratio = 0.67
     */
    pub min_successful_ratio:
        f32,

    /*
     * Minimum ratio of successful resolvers that
     * must resolve to Cloudflare in order to generate
     * positive DNS evidence.
     */
    pub min_cloudflare_ratio:
        f32,

    /*
     * Whether a DNS result with zero Cloudflare
     * resolvers should produce negative evidence.
     */
    pub negative_when_no_cloudflare:
        bool,
}

impl Default for DnsRuleSet {
    fn default() -> Self {
        Self {
            min_successful_ratio:
                0.50,

            min_cloudflare_ratio:
                0.50,

            negative_when_no_cloudflare:
                true,
        }
    }
}

#[derive(
    Debug,
    Clone,
    Serialize,
)]
pub struct ClassificationRuleSet {
    /*
     * Score required for a positive classification.
     */
    pub cloudflare_threshold:
        i16,

    /*
     * Score at or below which a target can be
     * classified as NotCloudflare.
     */
    pub not_cloudflare_threshold:
        i16,

    /*
     * For hostname-based detection, require at least
     * one hostname-specific positive signal.
     *
     * This prevents:
     *
     * IP = Cloudflare
     * Host = unrelated.example
     *
     * from being classified as Cloudflare.
     */
    pub require_host_specific_positive:
        bool,

    /*
     * Kinds that count as host-specific positive evidence.
     */
    pub host_specific_positive_kinds:
        BTreeSet<EvidenceKind>,

    /*
     * Whether IP-only queries can be classified solely
     * from the provider IP range.
     */
    pub allow_ip_only_classification:
        bool,
}

impl Default for ClassificationRuleSet {
    fn default() -> Self {
        let mut kinds =
            BTreeSet::new();

        kinds.insert(
            EvidenceKind::
                DnsResolvesToCloudflare,
        );

        kinds.insert(
            EvidenceKind::
                TlsCertificateHostnameMatch,
        );

        kinds.insert(
            EvidenceKind::HttpCfRay,
        );

        kinds.insert(
            EvidenceKind::
                HttpCfCacheStatus,
        );

        kinds.insert(
            EvidenceKind::
                HttpServerCloudflare,
        );

        kinds.insert(
            EvidenceKind::
                HttpCfConnectingIp,
        );

        kinds.insert(
            EvidenceKind::
                HttpCfMitigated,
        );

        Self {
            cloudflare_threshold:
                65,

            not_cloudflare_threshold:
                -50,

            require_host_specific_positive:
                true,

            host_specific_positive_kinds:
                kinds,

            allow_ip_only_classification:
                true,
        }
    }
}

#[derive(
    Debug,
    Clone,
    Serialize,
)]
pub struct ConfidenceRuleSet {
    /*
     * Used for positive classification:
     *
     * confidence =
     *   positive_base + score / positive_divisor
     */
    pub positive_base:
        f32,

    pub positive_divisor:
        f32,

    /*
     * Used for negative classification when there
     * is no absolute negative signal.
     */
    pub negative_base:
        f32,

    pub negative_divisor:
        f32,

    pub max_confidence:
        f32,

    pub very_high_threshold:
        f32,

    pub high_threshold:
        f32,

    pub medium_threshold:
        f32,
}

impl Default for ConfidenceRuleSet {
    fn default() -> Self {
        Self {
            positive_base:
                0.50,

            positive_divisor:
                200.0,

            negative_base:
                0.50,

            negative_divisor:
                200.0,

            max_confidence:
                0.99,

            very_high_threshold:
                0.95,

            high_threshold:
                0.85,

            medium_threshold:
                0.70,
        }
    }
}

#[derive(
    Debug,
    Clone,
    Serialize,
)]
pub struct RuleSet {
    /*
     * Individual evidence weights.
     *
     * EvidenceEngine NEVER hard-codes these values.
     */
    pub weights:
        BTreeMap<
            EvidenceKind,
            i16,
        >,

    /*
     * Maximum contribution of each evidence category.
     */
    pub category_caps:
        BTreeMap<
            EvidenceCategory,
            ScoreCap,
        >,

    pub dns:
        DnsRuleSet,

    pub classification:
        ClassificationRuleSet,

    pub confidence:
        ConfidenceRuleSet,

    /*
     * Absolute overall score boundary.
     */
    pub overall_cap:
        ScoreCap,
}

impl RuleSet {
    pub fn weight(
        &self,
        kind:
            EvidenceKind,
    ) -> i16 {
        self.weights
            .get(&kind)
            .copied()
            .unwrap_or(0)
    }

    pub fn category_cap(
        &self,
        category:
            EvidenceCategory,
    ) -> ScoreCap {
        self.category_caps
            .get(&category)
            .copied()
            .unwrap_or(
                ScoreCap::new(
                    -100,
                    100,
                ),
            )
    }

    pub fn cloudflare_web_proxy_v1()
        -> Self
    {
        let mut weights =
            BTreeMap::new();

        /*
         * Network
         */
        weights.insert(
            EvidenceKind::
                CloudflareIpRange,
            80,
        );

        weights.insert(
            EvidenceKind::
                IpOutsideCloudflareRange,
            -100,
        );

        /*
         * DNS
         */
        weights.insert(
            EvidenceKind::
                DnsResolvesToCloudflare,
            25,
        );

        weights.insert(
            EvidenceKind::
                DnsResolverConsensus,
            10,
        );

        weights.insert(
            EvidenceKind::
                DnsNoCloudflareResolution,
            -10,
        );

        /*
         * TLS
         */
        weights.insert(
            EvidenceKind::
                TlsHandshakeSucceeded,
            5,
        );

        weights.insert(
            EvidenceKind::
                TlsCertificateHostnameMatch,
            10,
        );

        weights.insert(
            EvidenceKind::
                TlsCertificateHostnameMismatch,
            -5,
        );

        weights.insert(
            EvidenceKind::
                TlsCertificateVerified,
            5,
        );

        weights.insert(
            EvidenceKind::
                TlsCertificateVerificationUnavailable,
            0,
        );

        /*
         * HTTP
         */
        weights.insert(
            EvidenceKind::HttpCfRay,
            35,
        );

        weights.insert(
            EvidenceKind::
                HttpCfCacheStatus,
            5,
        );

        weights.insert(
            EvidenceKind::
                HttpServerCloudflare,
            5,
        );

        weights.insert(
            EvidenceKind::
                HttpCfConnectingIp,
            1,
        );

        weights.insert(
            EvidenceKind::
                HttpCfIpCountry,
            1,
        );

        weights.insert(
            EvidenceKind::
                HttpCfMitigated,
            2,
        );

        weights.insert(
            EvidenceKind::
                HttpNoCloudflareSignals,
            0,
        );

        let mut caps =
            BTreeMap::new();

        caps.insert(
            EvidenceCategory::
                Network,
            ScoreCap::new(
                -100,
                80,
            ),
        );

        caps.insert(
            EvidenceCategory::
                Dns,
            ScoreCap::new(
                -35,
                35,
            ),
        );

        caps.insert(
            EvidenceCategory::
                Tls,
            ScoreCap::new(
                -20,
                20,
            ),
        );

        /*
         * HTTP evidence is strongly correlated.
         *
         * CF-Ray + CF-Cache-Status +
         * Server: cloudflare
         *
         * must not become unlimited evidence.
         */
        caps.insert(
            EvidenceCategory::
                Http,
            ScoreCap::new(
                0,
                45,
            ),
        );

        Self {
            weights,

            category_caps:
                caps,

            dns:
                DnsRuleSet {
                    min_successful_ratio:
                        0.50,

                    min_cloudflare_ratio:
                        0.50,

                    negative_when_no_cloudflare:
                        true,
                },

            classification:
                ClassificationRuleSet::
                    default(),

            confidence:
                ConfidenceRuleSet::
                    default(),

            overall_cap:
                ScoreCap::new(
                    -100,
                    100,
                ),
        }
    }
}

pub trait DetectionPolicy:
    Send + Sync
{
    fn metadata(
        &self,
    ) -> &PolicyMetadata;

    fn rules(
        &self,
    ) -> &RuleSet;

    fn positive_classification(
        &self,
    ) -> DetectionClassification {
        DetectionClassification::
            Cloudflare
    }

    fn negative_classification(
        &self,
    ) -> DetectionClassification {
        DetectionClassification::
            NotCloudflare
    }
}

#[derive(
    Debug,
    Clone,
)]
pub struct CloudflareWebProxyV1 {
    metadata:
        PolicyMetadata,

    rules:
        RuleSet,
}

impl Default
    for CloudflareWebProxyV1
{
    fn default() -> Self {
        Self {
            metadata:
                PolicyMetadata {
                    id:
                        "cloudflare-web-proxy"
                            .to_string(),

                    version:
                        1,

                    name:
                        "Cloudflare Web Proxy V1"
                            .to_string(),

                    description:
                        "Evidence policy for identifying web traffic served through Cloudflare's published edge network"
                            .to_string(),
                },

            rules:
                RuleSet::
                    cloudflare_web_proxy_v1(),
        }
    }
}

impl DetectionPolicy
    for CloudflareWebProxyV1
{
    fn metadata(
        &self,
    ) -> &PolicyMetadata {
        &self.metadata
    }

    fn rules(
        &self,
    ) -> &RuleSet {
        &self.rules
    }
}

impl CloudflareWebProxyV1 {
    pub fn rules_mut(
        &mut self,
    ) -> &mut RuleSet {
        &mut self.rules
    }

    pub fn metadata(
        &self,
    ) -> &PolicyMetadata {
        &self.metadata
    }
}