use ipnet::IpNet;
use std::net::IpAddr;

use crate::error::CfProbeError;

#[derive(Debug, Clone)]
pub struct CloudflareRanges {
    ipv4: Vec<IpNet>,
    ipv6: Vec<IpNet>,

    etag: Option<String>,
}

impl CloudflareRanges {
    pub fn new(
        ipv4: Vec<String>,
        ipv6: Vec<String>,
        etag: Option<String>,
    ) -> Result<Self, CfProbeError> {
        let ipv4 = parse_ranges(ipv4)?;
        let ipv6 = parse_ranges(ipv6)?;

        Ok(Self { ipv4, ipv6, etag })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.ipv4.iter().any(|network| network.contains(&ip)),
            IpAddr::V6(_) => self.ipv6.iter().any(|network| network.contains(&ip)),
        }
    }

    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    pub fn ipv4_ranges(&self) -> &[IpNet] {
        &self.ipv4
    }

    pub fn ipv6_ranges(&self) -> &[IpNet] {
        &self.ipv6
    }
}

fn parse_ranges(values: Vec<String>) -> Result<Vec<IpNet>, CfProbeError> {
    values
        .into_iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|error| CfProbeError::InvalidCidr {
                    value,
                    reason: error.to_string(),
                })
        })
        .collect()
}
