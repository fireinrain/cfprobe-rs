use std::net::IpAddr;

use async_trait::async_trait;

use crate::error::CfProbeError;

#[async_trait]
pub trait DnsBackend: Send + Sync {
    fn name(&self) -> &str;

    async fn lookup_ip(&self, fqdn: &str) -> Result<Vec<IpAddr>, CfProbeError>;

    async fn lookup_cname(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError>;

    async fn lookup_mx(&self, fqdn: &str) -> Result<Vec<(u16, String)>, CfProbeError>;

    async fn lookup_txt(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError>;

    async fn lookup_ns(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError>;

    async fn lookup_ptr(&self, ip: IpAddr) -> Result<Vec<String>, CfProbeError>;
}
