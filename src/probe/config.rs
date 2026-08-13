use std::sync::Arc;

use crate::{
    CfProbeError, DetectionPolicy, DnsResolverEntry, HickoryDnsResolver, HttpProbeConfig,
    TlsProbeConfig,
};

pub struct CfProbeConfig {
    pub policy: Arc<dyn DetectionPolicy>,

    pub dns_resolvers: Vec<DnsResolverEntry>,

    pub tls: TlsProbeConfig,

    pub http: HttpProbeConfig,

    /*
     * If Cloudflare IP range data cannot be loaded,
     * the detector will still execute TLS/HTTP where
     * possible, but the final classification becomes
     * Unknown when this flag is true.
     *
     * This is the safer commercial default.
     */
    pub require_cloudflare_ranges: bool,
}

impl CfProbeConfig {
    pub fn new(policy: Arc<dyn DetectionPolicy>, dns_resolvers: Vec<DnsResolverEntry>) -> Self {
        Self {
            policy,

            dns_resolvers,

            tls: TlsProbeConfig::default(),

            http: HttpProbeConfig::default(),

            require_cloudflare_ranges: true,
        }
    }

    pub fn cloudflare_web_proxy_v1() -> Result<Self, CfProbeError> {
        let resolver = HickoryDnsResolver::system()?;

        let policy = crate::CloudflareWebProxyV1::default();

        Ok(Self {
            policy: Arc::new(policy),

            dns_resolvers: vec![DnsResolverEntry {
                name: "system".to_string(),

                resolver: Arc::new(resolver),
            }],

            tls: TlsProbeConfig::default(),

            http: HttpProbeConfig::default(),

            require_cloudflare_ranges: true,
        })
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
