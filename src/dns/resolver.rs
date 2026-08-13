use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;

use hickory_resolver::{
    Resolver,
    config::{CLOUDFLARE, GOOGLE, QUAD9, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
    proto::rr::{RData, RecordType},
};

use crate::error::CfProbeError;

use super::backend::DnsBackend;

#[derive(Clone)]
pub struct HickoryDnsResolver {
    resolver: Resolver<TokioRuntimeProvider>,

    name: String,
}

impl HickoryDnsResolver {
    pub fn system() -> Result<Self, CfProbeError> {
        let mut opts = ResolverOpts::default();

        opts.timeout = Duration::from_secs(5);

        opts.attempts = 2;

        let resolver = Resolver::builder_tokio()
            .map_err(|error| CfProbeError::Dns {
                message: error.to_string(),
            })?
            .with_options(opts)
            .build()
            .map_err(|error| CfProbeError::Dns {
                message: error.to_string(),
            })?;

        Ok(Self {
            resolver,
            name: "system".to_string(),
        })
    }

    pub fn with_config(
        config: ResolverConfig,
        name: impl Into<String>,
    ) -> Result<Self, CfProbeError> {
        let mut opts = ResolverOpts::default();

        opts.timeout = Duration::from_secs(5);

        opts.attempts = 2;

        let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|error| CfProbeError::Dns {
                message: error.to_string(),
            })?;

        Ok(Self {
            resolver,
            name: name.into(),
        })
    }

    pub fn google() -> Result<Self, CfProbeError> {
        Self::with_config(ResolverConfig::udp_and_tcp(&GOOGLE), "google")
    }

    pub fn cloudflare() -> Result<Self, CfProbeError> {
        Self::with_config(ResolverConfig::udp_and_tcp(&CLOUDFLARE), "cloudflare")
    }

    pub fn quad9() -> Result<Self, CfProbeError> {
        Self::with_config(ResolverConfig::udp_and_tcp(&QUAD9), "quad9")
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[async_trait]
impl DnsBackend for HickoryDnsResolver {
    async fn lookup_ip(&self, fqdn: &str) -> Result<Vec<IpAddr>, CfProbeError> {
        let lookup = self
            .resolver
            .lookup_ip(fqdn)
            .await
            .map_err(|error| CfProbeError::Dns {
                message: format!("{}: {}", self.name, error,),
            })?;

        Ok(lookup.iter().collect())
    }

    async fn lookup_cname(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError> {
        let lookup = self
            .resolver
            .lookup(fqdn, RecordType::CNAME)
            .await
            .map_err(|error| CfProbeError::Dns {
                message: format!("{}: {}", self.name, error,),
            })?;

        let mut result = Vec::new();

        for record in lookup.answers() {
            if let RData::CNAME(cname) = &record.data {
                result.push(cname.0.to_ascii());
            }
        }

        Ok(result)
    }
}
