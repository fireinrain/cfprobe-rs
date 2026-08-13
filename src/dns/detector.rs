use std::collections::{BTreeSet, HashSet};

use std::sync::Arc;

use futures::future::join_all;

use crate::{cloudflare::CloudflareRanges, error::CfProbeError};

use super::{
    backend::DnsBackend,
    model::{DnsDetection, DnsDetectionStatus, ResolverObservation},
};

const MAX_CNAME_DEPTH: usize = 16;

pub struct DnsResolverEntry {
    pub name: String,

    pub resolver: Arc<dyn DnsBackend>,
}

pub struct DnsDetector {
    resolvers: Vec<DnsResolverEntry>,

    min_successful_resolvers: usize,
}

impl DnsDetector {
    pub fn new(resolvers: Vec<DnsResolverEntry>) -> Self {
        let min_successful_resolvers = if resolvers.len() <= 1 {
            1
        } else {
            resolvers.len() / 2 + 1
        };

        Self {
            resolvers,

            min_successful_resolvers,
        }
    }

    pub fn with_min_successful_resolvers(mut self, value: usize) -> Self {
        self.min_successful_resolvers = value.max(1);

        self
    }

    pub async fn detect(
        &self,
        hostname: &str,
        cloudflare_ranges: &CloudflareRanges,
    ) -> Result<DnsDetection, CfProbeError> {
        let normalized = normalize_hostname(hostname)?;

        if self.resolvers.is_empty() {
            return Err(CfProbeError::Dns {
                message: "no DNS resolvers configured".to_string(),
            });
        }

        let tasks = self.resolvers.iter().map(|entry| {
            let resolver = entry.resolver.clone();

            let name = entry.name.clone();

            let hostname = normalized.clone();

            async move { resolve_one(&name, resolver, &hostname).await }
        });

        let results = join_all(tasks).await;

        let mut observations = Vec::with_capacity(results.len());

        let mut union_ips = BTreeSet::new();

        let mut cloudflare_ips = BTreeSet::new();

        let mut successful_resolver_count = 0usize;

        let mut cloudflare_resolver_count = 0usize;

        for observation in results {
            if observation.success {
                successful_resolver_count += 1;

                let has_cloudflare = observation
                    .ips
                    .iter()
                    .any(|ip| cloudflare_ranges.contains(*ip));

                if has_cloudflare {
                    cloudflare_resolver_count += 1;
                }

                for ip in &observation.ips {
                    union_ips.insert(*ip);

                    if cloudflare_ranges.contains(*ip) {
                        cloudflare_ips.insert(*ip);
                    }
                }
            }

            observations.push(observation);
        }

        let all_resolvers_agree = successful_resolver_count > 0
            && (cloudflare_resolver_count == successful_resolver_count
                || cloudflare_resolver_count == 0);

        //let all_resolvers_agree = successful_resolver_count == self.resolvers.len();

        let has_cloudflare_ip = cloudflare_resolver_count >= self.min_successful_resolvers
            && !cloudflare_ips.is_empty();

        let status = if successful_resolver_count < self.min_successful_resolvers {
            DnsDetectionStatus::Unknown
        } else if has_cloudflare_ip {
            DnsDetectionStatus::CloudflareIp
        } else {
            DnsDetectionStatus::NoCloudflareIp
        };

        Ok(DnsDetection {
            hostname: hostname.to_string(),

            normalized_hostname: normalized,

            observations,

            union_ips: union_ips.into_iter().collect(),

            cloudflare_ips: cloudflare_ips.into_iter().collect(),

            cloudflare_resolver_count,

            successful_resolver_count,

            resolver_count: self.resolvers.len(),

            all_resolvers_agree,

            has_cloudflare_ip,

            status,
        })
    }
}

async fn resolve_one(
    name: &str,
    resolver: Arc<dyn DnsBackend>,
    hostname: &str,
) -> ResolverObservation {
    let ips = match resolver.lookup_ip(hostname).await {
        Ok(ips) => ips,

        Err(error) => {
            return ResolverObservation {
                resolver: name.to_string(),

                success: false,

                ips: Vec::new(),

                cname_chain: Vec::new(),

                error: Some(error.to_string()),
            };
        }
    };

    let cname_chain = match resolve_cname_chain(resolver.as_ref(), hostname).await {
        Ok(chain) => chain,

        Err(error) => {
            return ResolverObservation {
                resolver: name.to_string(),

                success: false,

                ips,

                cname_chain: Vec::new(),

                error: Some(error.to_string()),
            };
        }
    };

    ResolverObservation {
        resolver: name.to_string(),

        success: true,

        ips,

        cname_chain,

        error: None,
    }
}

async fn resolve_cname_chain(
    resolver: &dyn DnsBackend,
    hostname: &str,
) -> Result<Vec<String>, CfProbeError> {
    let mut chain = Vec::new();

    let mut current = hostname.to_string();

    let mut visited = HashSet::new();

    for _ in 0..MAX_CNAME_DEPTH {
        if !visited.insert(current.clone()) {
            return Err(CfProbeError::Dns {
                message: format!("CNAME loop detected at {current}",),
            });
        }

        let cnames = resolver.lookup_cname(&current).await?;

        let Some(next) = cnames.first() else {
            break;
        };

        let next = if next.ends_with('.') {
            next.to_ascii_lowercase()
        } else {
            format!("{}.", next.to_ascii_lowercase(),)
        };

        chain.push(next.clone());

        current = next;
    }

    if chain.len() >= MAX_CNAME_DEPTH {
        return Err(CfProbeError::Dns {
            message: format!("CNAME chain exceeds maximum depth {}", MAX_CNAME_DEPTH,),
        });
    }

    Ok(chain)
}

fn normalize_hostname(hostname: &str) -> Result<String, CfProbeError> {
    let hostname = hostname.trim();

    if hostname.is_empty() {
        return Err(CfProbeError::Dns {
            message: "hostname is empty".to_string(),
        });
    }

    let fqdn = if hostname.ends_with('.') {
        hostname.to_string()
    } else {
        format!("{hostname}.")
    };

    hickory_resolver::proto::rr::Name::from_utf8(&fqdn).map_err(|error| CfProbeError::Dns {
        message: format!("invalid hostname `{hostname}`: {error}",),
    })?;

    Ok(fqdn.to_ascii_lowercase())
}
