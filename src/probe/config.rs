use std::sync::Arc;

use crate::{
    CfProbeError, DetectionPolicy, DnsResolverEntry, HickoryDnsResolver, HttpProbeConfig,
    TargetPolicy, TlsProbeConfig,
};

pub struct CfProbeConfig {
    pub policy: Arc<dyn DetectionPolicy>,

    pub target_policy: Arc<TargetPolicy>,

    pub dns_resolvers: Vec<DnsResolverEntry>,

    pub tls: TlsProbeConfig,

    pub http: HttpProbeConfig,

    /*
     * Cloudflare IP ranges are foundational
     * for CloudflareWebProxyV1.
     *
     * If unavailable, final classification is forced
     * to Unknown.
     */
    pub require_cloudflare_ranges: bool,
}

impl CfProbeConfig {
    pub fn new(policy: Arc<dyn DetectionPolicy>, dns_resolvers: Vec<DnsResolverEntry>) -> Self {
        Self {
            policy,

            target_policy: Arc::new(TargetPolicy::cloudflare_web_proxy_v1()),

            dns_resolvers,

            tls: TlsProbeConfig::default(),

            http: HttpProbeConfig::default(),

            require_cloudflare_ranges: true,
        }
    }

    pub fn cloudflare_web_proxy_v1() -> Result<Self, CfProbeError> {
        let resolver = HickoryDnsResolver::system()?;

        let policy = crate::CloudflareWebProxyV1::default();

        let target_policy = TargetPolicy::cloudflare_web_proxy_v1();

        Ok(Self {
            policy: Arc::new(policy),

            target_policy: Arc::new(target_policy),

            dns_resolvers: vec![DnsResolverEntry {
                name: "system".to_string(),

                resolver: Arc::new(resolver),
            }],

            tls: TlsProbeConfig::default(),

            http: HttpProbeConfig::default(),

            require_cloudflare_ranges: true,
        })
    }

    pub fn with_target_policy(mut self, policy: TargetPolicy) -> Self {
        self.target_policy = Arc::new(policy);

        self
    }

    pub fn with_target_policy_arc(mut self, policy: Arc<TargetPolicy>) -> Self {
        self.target_policy = policy;

        self
    }

    pub fn with_tls_config(mut self, config: TlsProbeConfig) -> Self {
        self.tls = config;

        self
    }

    pub fn with_http_config(mut self, config: HttpProbeConfig) -> Self {
        self.http = config;

        self
    }

    pub fn require_cloudflare_ranges(mut self, required: bool) -> Self {
        self.require_cloudflare_ranges = required;

        self
    }
}
