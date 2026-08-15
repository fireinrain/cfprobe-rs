use std::net::IpAddr;

use serde::Serialize;

use crate::{CloudflareIpDetection, DetectionResult, DnsDetection, HttpDetection, TlsDetection};

use super::Target;

/// 探测流水线中的各个阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProbeStage {
    /// 加载 Cloudflare 官方 IP/CIDR 段。
    CloudflareRanges,

    /// 本地 CIDR 匹配判定 IP 是否归属 Cloudflare。
    Ip,

    /// DNS 解析（多解析器并发 + CNAME 链遍历）。
    Dns,

    /// TLS 握手与证书解析。
    Tls,

    /// HTTP 请求与 Cloudflare 头指纹抽取。
    Http,

    /// 证据汇总打分与最终分类。
    Evidence,
}

/// 某个阶段发生的非致命错误（已被降级为错误列表项，不中断其他阶段）。
#[derive(Debug, Clone, Serialize)]
pub struct ProbeStageError {
    /// 出错的阶段。
    pub stage: ProbeStage,

    /// 可读错误信息。
    pub message: String,
}

/// 单目标探测的完整结果：包含各阶段的原始输出、证据聚合结果、错误列表。
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    /// 直连目标 IP（与 `target.ip` 相同，便于直接访问）。
    pub ip: IpAddr,

    /// 目标主机名（与 `target.hostname` 相同）。
    pub hostname: String,

    /// 目标端口（与 `target.port` 相同）。
    pub port: u16,

    /// 原始目标定义。
    pub target: Target,

    /// IP 段归属判定结果；若 Cloudflare 范围加载失败则为 `None`。
    pub ip_detection: Option<CloudflareIpDetection>,

    /// DNS 探测结果；未执行或全部失败为 `None`。
    pub dns: Option<DnsDetection>,

    /// TLS 探测结果；未执行或失败为 `None`。
    pub tls: Option<TlsDetection>,

    /// HTTP 探测结果；未执行或失败为 `None`。
    pub http: Option<HttpDetection>,

    /// 证据引擎输出：分类、置信度、分数、证据列表。
    pub detection: DetectionResult,

    /// 各阶段的非致命错误（致命错误会直接通过 `Result::Err` 返回）。
    pub errors: Vec<ProbeStageError>,
}

impl ProbeResult {
    /// 快捷方法：最终分类是否为 `Cloudflare`。
    pub fn is_cloudflare(&self) -> bool {
        self.detection.classification == crate::DetectionClassification::Cloudflare
    }

    /// 快捷方法：最终分类是否为 `Unknown`。
    pub fn is_unknown(&self) -> bool {
        self.detection.classification == crate::DetectionClassification::Unknown
    }

    /// 快捷方法：最终分类是否为 `NotCloudflare`。
    pub fn is_not_cloudflare(&self) -> bool {
        self.detection.classification == crate::DetectionClassification::NotCloudflare
    }
}
