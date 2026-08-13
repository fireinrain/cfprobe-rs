use std::net::IpAddr;

use async_trait::async_trait;

use crate::error::CfProbeError;

#[async_trait]
pub trait DnsBackend: Send + Sync {
    /// Resolve A + AAAA records.
    async fn lookup_ip(&self, fqdn: &str) -> Result<Vec<IpAddr>, CfProbeError>;

    /// Resolve direct CNAME records.
    async fn lookup_cname(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError>;
}
