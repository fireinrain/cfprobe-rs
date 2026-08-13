use std::net::IpAddr;

use serde::Serialize;

use crate::{CfProbeError, HttpScheme};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Target {
    pub ip: IpAddr,

    pub hostname: String,

    pub port: u16,

    pub scheme: HttpScheme,
}

impl Target {
    pub fn https(ip: IpAddr, hostname: impl Into<String>) -> Self {
        Self {
            ip,

            hostname: hostname.into(),

            port: 443,

            scheme: HttpScheme::Https,
        }
    }

    pub fn http(ip: IpAddr, hostname: impl Into<String>) -> Self {
        Self {
            ip,

            hostname: hostname.into(),

            port: 80,

            scheme: HttpScheme::Http,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;

        self
    }

    pub fn validate(&self) -> Result<(), CfProbeError> {
        if self.port == 0 {
            return Err(CfProbeError::InvalidResponse(
                "target port cannot be 0".to_string(),
            ));
        }

        let hostname = self.hostname.trim();

        if hostname.is_empty() {
            return Err(CfProbeError::InvalidResponse(
                "target hostname cannot be empty".to_string(),
            ));
        }

        hickory_resolver::proto::rr::Name::from_utf8(&format!(
            "{}.",
            hostname.trim_end_matches('.')
        ))
        .map_err(|error| {
            CfProbeError::InvalidResponse(format!("invalid target hostname `{hostname}`: {error}"))
        })?;

        Ok(())
    }
}
