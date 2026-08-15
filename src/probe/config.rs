use std::sync::Arc;
use std::time::Duration;

use crate::{
    CfProbeError, DetectionPolicy, DnsCache, DnsCacheConfig, DnsResolverEntry, HickoryDnsResolver,
    HttpProbeConfig, TargetPolicy, TlsProbeConfig,
};

/// [`CfProbe`] 的构建配置。
///
/// 使用 [`cloudflare_web_proxy_v1`](Self::cloudflare_web_proxy_v1) 获取一组预调优的默认值，
/// 再通过链式 `with_*` 方法覆盖特定字段。
pub struct CfProbeConfig {
    /// 证据分类策略，决定最终的打分与分类规则。
    pub policy: Arc<dyn DetectionPolicy>,

    /// 目标安全策略，用于 SSRF / 私网段 / 端口白名单等校验。
    pub target_policy: Arc<TargetPolicy>,

    /// DNS 解析器池，多解析器之间并发执行并做共识聚合。
    pub dns_resolvers: Vec<DnsResolverEntry>,

    /// 可选的 DNS 内存缓存（含容量上限与 TTL 淘汰）。
    pub dns_cache: Option<Arc<DnsCache>>,

    /// TLS 探测参数（超时、证书验证行为等）。
    pub tls: TlsProbeConfig,

    /// HTTP 探测参数（超时、最大 body 字节等）。
    pub http: HttpProbeConfig,

    /// 拉取 Cloudflare 官方 IP 段的 HTTP 请求超时。
    pub cloudflare_http_timeout: Duration,

    /// 若为 `true`，当 Cloudflare IP 段不可用时最终分类强制置为 `Unknown`。
    ///
    /// 该选项仅影响最终兜底行为，各证据阶段照常执行。
    pub require_cloudflare_ranges: bool,
}

impl CfProbeConfig {
    /// 使用指定策略和 DNS 解析器列表创建一个基础配置。
    ///
    /// 其他字段采用默认值：默认 `TargetPolicy`、无 DNS 缓存、
    /// 默认 TLS/HTTP 配置、10s Cloudflare HTTP 超时、`require_cloudflare_ranges = true`。
    pub fn new(policy: Arc<dyn DetectionPolicy>, dns_resolvers: Vec<DnsResolverEntry>) -> Self {
        Self {
            policy,

            target_policy: Arc::new(TargetPolicy::cloudflare_web_proxy_v1()),

            dns_resolvers,

            dns_cache: None,

            tls: TlsProbeConfig::default(),

            http: HttpProbeConfig::default(),

            cloudflare_http_timeout: Duration::from_secs(10),

            require_cloudflare_ranges: true,
        }
    }

    /// 创建一套针对 Cloudflare Web 反代场景的预调优配置。
    ///
    /// - 使用系统 DNS 解析器（`/etc/resolv.conf` 或等价机制）
    /// - 内置 `CloudflareWebProxyV1` 评分策略
    /// - 启用严格 SSRF 防护与 Cloudflare 官方端口白名单
    /// - 默认无 DNS 缓存
    pub fn cloudflare_web_proxy_v1() -> Result<Self, CfProbeError> {
        let resolver = HickoryDnsResolver::system()?;

        let policy = crate::CloudflareWebProxyV1::default();

        let target_policy = TargetPolicy::cloudflare_web_proxy_v1();

        Ok(Self {
            policy: Arc::new(policy),

            target_policy: Arc::new(target_policy),

            dns_resolvers: vec![DnsResolverEntry::new("system", Arc::new(resolver))],

            dns_cache: None,

            tls: TlsProbeConfig::default(),

            http: HttpProbeConfig::default(),

            cloudflare_http_timeout: Duration::from_secs(10),

            require_cloudflare_ranges: true,
        })
    }

    /// 覆盖目标安全策略。
    pub fn with_target_policy(mut self, policy: TargetPolicy) -> Self {
        self.target_policy = Arc::new(policy);

        self
    }

    /// 使用已有的 `Arc<TargetPolicy>` 覆盖目标安全策略。
    pub fn with_target_policy_arc(mut self, policy: Arc<TargetPolicy>) -> Self {
        self.target_policy = policy;

        self
    }

    /// 覆盖 TLS 探测配置。
    pub fn with_tls_config(mut self, config: TlsProbeConfig) -> Self {
        self.tls = config;

        self
    }

    /// 覆盖 HTTP 探测配置。
    pub fn with_http_config(mut self, config: HttpProbeConfig) -> Self {
        self.http = config;

        self
    }

    /// 设置拉取 Cloudflare 官方 IP 段的 HTTP 超时。
    pub fn with_cloudflare_http_timeout(mut self, timeout: Duration) -> Self {
        self.cloudflare_http_timeout = timeout;

        self
    }

    /// 设置当 Cloudflare IP 段不可用时，是否强制最终分类为 `Unknown`。
    pub fn require_cloudflare_ranges(mut self, required: bool) -> Self {
        self.require_cloudflare_ranges = required;

        self
    }

    /// 启用 DNS 内存缓存。
    pub fn with_dns_cache(mut self, cache: DnsCache) -> Self {
        self.dns_cache = Some(Arc::new(cache));
        self
    }

    /// 通过 [`DnsCacheConfig`] 启用并配置 DNS 内存缓存。
    pub fn with_dns_cache_config(mut self, config: DnsCacheConfig) -> Self {
        self.dns_cache = Some(Arc::new(DnsCache::new(config)));
        self
    }
}
