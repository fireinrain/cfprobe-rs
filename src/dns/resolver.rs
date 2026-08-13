use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use hickory_resolver::{
    Resolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
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
        Self::system_with_timeouts(Duration::from_secs(5), 2)
    }

    pub fn system_with_timeouts(
        timeout: Duration,
        attempts: usize,
    ) -> Result<Self, CfProbeError> {
        crate::init_rustls_crypto();

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = attempts;

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
        Self::with_config_and_timeouts(config, name, Duration::from_secs(5), 2)
    }

    pub fn with_config_and_timeouts(
        config: ResolverConfig,
        name: impl Into<String>,
        timeout: Duration,
        attempts: usize,
    ) -> Result<Self, CfProbeError> {
        crate::init_rustls_crypto();

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = attempts;

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

    fn make_config(ips: &[IpAddr]) -> ResolverConfig {
        let name_servers: Vec<NameServerConfig> = ips
            .iter()
            .map(|ip| NameServerConfig::udp_and_tcp(*ip))
            .collect();

        ResolverConfig::from_parts(None, Vec::new(), name_servers)
    }

    pub fn google() -> Result<Self, CfProbeError> {
        Self::with_config(
            Self::make_config(&[
                IpAddr::from([8, 8, 8, 8]),
                IpAddr::from([8, 8, 4, 4]),
            ]),
            "google",
        )
    }

    pub fn cloudflare() -> Result<Self, CfProbeError> {
        Self::with_config(
            Self::make_config(&[
                IpAddr::from([1, 1, 1, 1]),
                IpAddr::from([1, 0, 0, 1]),
            ]),
            "cloudflare",
        )
    }

    pub fn quad9() -> Result<Self, CfProbeError> {
        Self::with_config(
            Self::make_config(&[
                IpAddr::from([9, 9, 9, 9]),
                IpAddr::from([149, 112, 112, 112]),
            ]),
            "quad9",
        )
    }

    pub fn doh(
        url: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, CfProbeError> {
        Self::doh_with_timeouts(url, name, Duration::from_secs(5), 2)
    }

    pub fn doh_with_timeouts(
        url: impl Into<String>,
        name: impl Into<String>,
        timeout: Duration,
        attempts: usize,
    ) -> Result<Self, CfProbeError> {
        crate::init_rustls_crypto();

        let url_str = url.into();

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = attempts;

        let host_part = url_str
            .trim_start_matches("https://")
            .trim_start_matches("http://");

        let (host, path) = match host_part.find('/') {
            Some(idx) => (&host_part[..idx], &host_part[idx..]),
            None => (host_part, "/dns-query"),
        };

        let host_ip: IpAddr = host
            .parse()
            .map_err(|_| CfProbeError::Dns {
                message: format!("DoH host is not an IP address: {host}"),
            })?;

        let server_name: Arc<str> = Arc::from(host.to_string());
        let path: Option<Arc<str>> = Some(Arc::from(path.to_string()));

        let name_server = NameServerConfig::https(host_ip, server_name, path);

        let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);

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

    fn reverse_arpa(ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa.",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            IpAddr::V6(v6) => {
                let mut nibbles = [0u8; 32];
                let segments = v6.segments();
                let mut i = 0;
                for seg in segments {
                    nibbles[i] = (seg >> 12) as u8;
                    nibbles[i + 1] = (seg >> 8) as u8 & 0xf;
                    nibbles[i + 2] = (seg >> 4) as u8 & 0xf;
                    nibbles[i + 3] = (seg & 0xf) as u8;
                    i += 4;
                }
                let mut reversed = String::with_capacity(64);
                for (idx, n) in nibbles.iter().enumerate() {
                    if idx > 0 {
                        reversed.push('.');
                    }
                    reversed.push_str(&format!("{:x}", n));
                }
                reversed.push_str(".ip6.arpa.");
                reversed
            }
        }
    }
}

#[async_trait]
impl DnsBackend for HickoryDnsResolver {
    fn name(&self) -> &str {
        &self.name
    }

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

    async fn lookup_mx(&self, fqdn: &str) -> Result<Vec<(u16, String)>, CfProbeError> {
        let lookup = self
            .resolver
            .lookup(fqdn, RecordType::MX)
            .await
            .map_err(|error| CfProbeError::Dns {
                message: format!("{}: {}", self.name, error,),
            })?;

        let mut result = Vec::new();

        for record in lookup.answers() {
            if let RData::MX(mx) = &record.data {
                result.push((mx.preference, mx.exchange.to_ascii()));
            }
        }

        Ok(result)
    }

    async fn lookup_txt(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError> {
        let lookup = self
            .resolver
            .lookup(fqdn, RecordType::TXT)
            .await
            .map_err(|error| CfProbeError::Dns {
                message: format!("{}: {}", self.name, error,),
            })?;

        let mut result = Vec::new();

        for record in lookup.answers() {
            if let RData::TXT(txt) = &record.data {
                let data = txt
                    .txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b))
                    .collect::<Vec<_>>()
                    .join("");
                result.push(data);
            }
        }

        Ok(result)
    }

    async fn lookup_ns(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError> {
        let lookup = self
            .resolver
            .lookup(fqdn, RecordType::NS)
            .await
            .map_err(|error| CfProbeError::Dns {
                message: format!("{}: {}", self.name, error,),
            })?;

        let mut result = Vec::new();

        for record in lookup.answers() {
            if let RData::NS(ns) = &record.data {
                result.push(ns.0.to_ascii());
            }
        }

        Ok(result)
    }

    async fn lookup_ptr(&self, ip: IpAddr) -> Result<Vec<String>, CfProbeError> {
        let arpa = Self::reverse_arpa(ip);

        let lookup = self
            .resolver
            .lookup(&arpa, RecordType::PTR)
            .await
            .map_err(|error| CfProbeError::Dns {
                message: format!("{}: {}", self.name, error,),
            })?;

        let mut result = Vec::new();

        for record in lookup.answers() {
            if let RData::PTR(ptr) = &record.data {
                result.push(ptr.0.to_ascii());
            }
        }

        Ok(result)
    }
}