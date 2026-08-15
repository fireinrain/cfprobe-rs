use std::net::IpAddr;

use serde::Serialize;
use serde_json::Value;

/// 证据所属的大类（对应流水线阶段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum EvidenceCategory {
    /// IP 归属 / 网络层。
    Network,
    /// DNS 解析相关。
    Dns,
    /// TLS 握手 / 证书相关。
    Tls,
    /// HTTP 头指纹相关。
    Http,
}

/// 证据的判定方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EvidenceDirection {
    /// 支持"该站点在 Cloudflare 上"的证据。
    Positive,
    /// 反对"该站点在 Cloudflare 上"的证据。
    Negative,
    /// 信息性证据，不直接影响分数。
    Neutral,
}

/// 具体的证据种类（枚举对应 22 条规则位）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum EvidenceKind {
    /// IP 命中 Cloudflare 官方 CIDR。
    CloudflareIpRange,

    /// IP 不在 Cloudflare 官方 CIDR 内。
    IpOutsideCloudflareRange,

    /// 部分 DNS 解析结果指向 Cloudflare IP。
    DnsResolvesToCloudflare,

    /// 多解析器共识：多数解析器返回 Cloudflare IP。
    DnsResolverConsensus,

    /// 全部解析器都未返回 Cloudflare IP。
    DnsNoCloudflareResolution,

    /// CNAME 链末端指向 Cloudflare 托管域。
    DnsCnameToCloudflare,

    /// 存在 CNAME 链（信息性）。
    DnsCnameChain,

    /// TLS 握手成功完成。
    TlsHandshakeSucceeded,

    /// 证书 SAN 匹配目标主机名。
    TlsCertificateHostnameMatch,

    /// 证书 SAN 与目标主机名不匹配。
    TlsCertificateHostnameMismatch,

    /// 证书链验证通过（受信任 CA + 有效期）。
    TlsCertificateVerified,

    /// 无法验证证书（缺少根证书等）。
    TlsCertificateVerificationUnavailable,

    /// HTTP 响应存在 `CF-Ray` 头（Cloudflare 强信号）。
    HttpCfRay,

    /// HTTP 响应存在 `CF-Cache-Status` 头。
    HttpCfCacheStatus,

    /// HTTP `Server` 头为 `cloudflare`。
    HttpServerCloudflare,

    /// HTTP 响应存在 `CF-Connecting-IP` 头。
    HttpCfConnectingIp,

    /// HTTP 响应存在 `CF-IPCountry` 头。
    HttpCfIpCountry,

    /// HTTP 响应存在 `CF-Mitigated` 头。
    HttpCfMitigated,

    /// HTTP 响应未检测到任何 Cloudflare 典型头。
    HttpNoCloudflareSignals,
}

/// 证据引擎给出的最终分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DetectionClassification {
    /// 综合证据判定目标在 Cloudflare 边缘节点上。
    Cloudflare,

    /// 综合证据判定目标不在 Cloudflare 上。
    NotCloudflare,

    /// 证据不足或关键前置数据缺失，无法判定。
    Unknown,
}

/// 置信度等级（由置信度分 + 阈值映射得到）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ConfidenceLevel {
    /// 极高置信度（强证据多路一致）。
    VeryHigh,
    /// 高置信度。
    High,
    /// 中等置信度。
    Medium,
    /// 低置信度。
    Low,
    /// 证据不足以支撑可信判定。
    Insufficient,
}

/// 评分策略的元数据（便于在结果中追溯所用规则集版本）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyMetadata {
    /// 稳定策略 ID，例如 `cloudflare-web-proxy-v1`。
    pub id: String,

    /// 规则版本号（单调递增）。
    pub version: u32,

    /// 可读名称。
    pub name: String,

    /// 可读描述。
    pub description: String,
}

/// 一条独立证据。
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceItem {
    /// 证据所属大类。
    pub category: EvidenceCategory,

    /// 证据的具体种类。
    pub kind: EvidenceKind,

    /// 证据方向（支持 / 反对 / 中性）。
    pub direction: EvidenceDirection,

    /// 本条证据的加权分数（正值加分，负值减分）。
    pub score: i16,

    /// 人可读的一句话理由。
    pub reason: String,

    /// 结构化细节（`serde_json::Value`，随 `kind` 变化 schema）。
    pub details: Value,
}

/// 证据引擎最终输出。
#[derive(Debug, Clone, Serialize)]
pub struct DetectionResult {
    /// 目标 IP。
    pub ip: IpAddr,

    /// 目标主机名（仅在提供时存在）。
    pub hostname: Option<String>,

    /// 所用策略的元数据。
    pub policy: PolicyMetadata,

    /// 最终分类。
    pub classification: DetectionClassification,

    /// 启发式置信度（0.0 – 1.0），注意**不是统计概率**。
    pub confidence: f32,

    /// 置信度等级。
    pub confidence_level: ConfidenceLevel,

    /// 加权后聚合总分（有符号整数）。
    pub score: i16,

    /// 全部证据条目（按 category / direction 排序）。
    pub evidence: Vec<EvidenceItem>,

    /// 正向证据数量。
    pub positive_evidence_count: usize,

    /// 负向证据数量。
    pub negative_evidence_count: usize,

    /// 人可读摘要（综合证据数量 + 强信号，拼出的一句话说明）。
    pub summary: String,
}
