use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CfProbeError {
    Http(reqwest::Error),

    Io(std::io::Error),

    Dns { message: String },

    Json(serde_json::Error),

    InvalidResponse(String),

    InvalidCidr { value: String, reason: String },

    CacheCorrupted { path: PathBuf, reason: String },

    CacheLockTimeout,

    CacheDirectoryUnavailable,

    SystemClock(std::time::SystemTimeError),
}

impl fmt::Display for CfProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(err) => {
                write!(f, "HTTP request failed: {err}")
            }

            Self::Io(err) => {
                write!(f, "I/O error: {err}")
            }

            Self::Dns { message } => {
                write!(f, "DNS resolution failed: {message}")
            }

            Self::Json(err) => {
                write!(f, "JSON error: {err}")
            }

            Self::InvalidResponse(message) => {
                write!(f, "Invalid Cloudflare API response: {message}")
            }

            Self::InvalidCidr { value, reason } => {
                write!(f, "Invalid CIDR `{value}`: {reason}")
            }

            Self::CacheCorrupted { path, reason } => {
                write!(f, "Cache file `{}` is corrupted: {reason}", path.display())
            }

            Self::CacheLockTimeout => {
                write!(f, "Timed out waiting for Cloudflare cache lock")
            }

            Self::CacheDirectoryUnavailable => {
                write!(f, "Unable to determine a platform cache directory")
            }

            Self::SystemClock(err) => {
                write!(f, "System clock error: {err}")
            }
        }
    }
}

impl std::error::Error for CfProbeError {}

impl From<reqwest::Error> for CfProbeError {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(value)
    }
}

impl From<std::io::Error> for CfProbeError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for CfProbeError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<std::time::SystemTimeError> for CfProbeError {
    fn from(value: std::time::SystemTimeError) -> Self {
        Self::SystemClock(value)
    }
}
