use std::fmt;
use std::path::PathBuf;

/// cfprobe 全局错误枚举。
///
/// 错误分为几类：
/// - 网络 / IO 类（`Http`、`Io`、`Dns`）
/// - 安全策略违规（`TargetRejected`）
/// - 取消（`Cancelled`，贯穿全流水线）
/// - 数据 / 缓存类（`InvalidCidr`、`CacheCorrupted`、`CacheLockTimeout`…）
#[derive(Debug)]
pub enum CfProbeError {
    /// HTTP 请求错误（来自 reqwest）。
    Http(reqwest::Error),

    /// 文件系统 / 底层 IO 错误。
    Io(std::io::Error),

    /// JSON 序列化 / 反序列化错误。
    Json(serde_json::Error),

    /// DNS 解析失败（含解析器超时、网络错误等）。
    Dns { message: String },

    /// 目标被安全策略拒绝（SSRF、私网 IP、非法端口等）。
    TargetRejected { reason: String },

    /// 由 `CancellationToken` 触发的取消。
    Cancelled,

    /// 远端返回内容不符合预期格式。
    InvalidResponse(String),

    /// Cloudflare API 返回了无效的 CIDR 字符串。
    InvalidCidr { value: String, reason: String },

    /// 本地缓存文件损坏（JSON 解析失败等）。
    CacheCorrupted { path: PathBuf, reason: String },

    /// 获取跨进程缓存文件锁超时（通常意味着其他进程卡住）。
    CacheLockTimeout,

    /// 无法确定平台级缓存目录（`directories` crate 返回 None）。
    CacheDirectoryUnavailable,

    /// 系统时钟错误（UNIX_EPOCH 回退等）。
    SystemClock(std::time::SystemTimeError),
}

impl fmt::Display for CfProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(error) => {
                write!(f, "HTTP request failed: {error}",)
            }

            Self::Io(error) => {
                write!(f, "I/O error: {error}",)
            }

            Self::Json(error) => {
                write!(f, "JSON error: {error}",)
            }

            Self::Dns { message } => {
                write!(f, "DNS resolution failed: {message}",)
            }

            Self::TargetRejected { reason } => {
                write!(f, "Target rejected by security policy: {reason}",)
            }

            Self::Cancelled => {
                write!(f, "Probe cancelled",)
            }

            Self::InvalidResponse(message) => {
                write!(f, "Invalid response: {message}",)
            }

            Self::InvalidCidr { value, reason } => {
                write!(f, "Invalid CIDR `{value}`: {reason}",)
            }

            Self::CacheCorrupted { path, reason } => {
                write!(f, "Cache file `{}` is corrupted: {reason}", path.display(),)
            }

            Self::CacheLockTimeout => {
                write!(f, "Timed out waiting for Cloudflare cache lock",)
            }

            Self::CacheDirectoryUnavailable => {
                write!(f, "Unable to determine a platform cache directory",)
            }

            Self::SystemClock(error) => {
                write!(f, "System clock error: {error}",)
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
