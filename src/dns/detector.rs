use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{RwLock, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::CloudflareRanges;
use crate::error::CfProbeError;

use super::backend::DnsBackend;
use super::model::{DnsDetection, DnsDetectionStatus, ResolverHealth, ResolverObservation};
use super::pool::DnsCache;

/// DnsDetector 使用的解析器条目（名称 + 实现）。
#[derive(Clone)]
pub struct DnsResolverEntry {
    /// 解析器标识名（local / cloudflare / google 等）。
    pub name: String,
    /// 实际执行 DNS 查询的后端。
    pub backend: Arc<dyn DnsBackend>,
}

impl DnsResolverEntry {
    /// 构造一个解析器条目。
    pub fn new(name: impl Into<String>, backend: Arc<dyn DnsBackend>) -> Self {
        Self {
            name: name.into(),
            backend,
        }
    }
}

/// 多解析器 DNS 探测器。
///
/// 功能：
/// - 并行调用多个 DNS 后端
/// - 失败后端自动熔断（ban 一段时间）
/// - 支持可选的答案缓存
/// - 健康度统计，用于后续路由策略
pub struct DnsDetector {
    resolvers: Vec<DnsResolverEntry>,
    max_concurrency: usize,
    cache: Option<Arc<DnsCache>>,
    health: Arc<RwLock<HashMap<String, ResolverHealth>>>,
    banned_until: Arc<RwLock<HashMap<String, Instant>>>,
    cname_max_depth: usize,
    ban_duration: Duration,
}

impl DnsDetector {
    /// 用一组解析器构造 DnsDetector。
    pub fn new(resolvers: Vec<DnsResolverEntry>) -> Self {
        Self {
            resolvers,
            max_concurrency: 8,
            cache: None,
            health: Arc::new(RwLock::new(HashMap::new())),
            banned_until: Arc::new(RwLock::new(HashMap::new())),
            cname_max_depth: 5,
            ban_duration: Duration::from_secs(30),
        }
    }

    /// 设置失败解析器的熔断时长。
    pub fn with_ban_duration(mut self, duration: Duration) -> Self {
        self.ban_duration = duration;
        self
    }

    /// 从 `DnsPool` 复制后端 + 缓存，构造 DnsDetector。
    pub fn from_pool(pool: &crate::dns::pool::DnsPool) -> Self {
        let entries: Vec<DnsResolverEntry> = pool
            .backends()
            .iter()
            .map(|(name, backend)| DnsResolverEntry {
                name: name.clone(),
                backend: Arc::clone(backend),
            })
            .collect();

        let mut detector = Self::new(entries);
        detector = detector.with_cache(Arc::new(pool.cache().clone()));
        detector
    }

    /// 设置多解析器并行查询的并发上限。
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.max_concurrency = n;
        self
    }

    /// 附加 DNS 答案缓存。
    pub fn with_cache(mut self, cache: Arc<DnsCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_cname_max_depth(mut self, depth: usize) -> Self {
        self.cname_max_depth = depth;
        self
    }

    pub fn resolver_count(&self) -> usize {
        self.resolvers.len()
    }

    pub fn resolvers(&self) -> &[DnsResolverEntry] {
        &self.resolvers
    }

    pub async fn resolver_health(&self) -> HashMap<String, ResolverHealth> {
        self.health.read().await.clone()
    }

    pub async fn unhealthy_resolver_names(&self) -> Vec<String> {
        let health = self.health.read().await;
        let banned = self.banned_until.read().await;
        let now = Instant::now();

        health
            .iter()
            .filter(|(_, h)| !h.is_healthy())
            .map(|(name, _)| name.clone())
            .chain(
                banned
                    .iter()
                    .filter(|(_, until)| **until > now)
                    .map(|(name, _)| name.clone()),
            )
            .collect()
    }

    pub async fn ban_resolver(&self, name: &str) {
        let mut banned = self.banned_until.write().await;
        banned.insert(name.to_string(), Instant::now() + self.ban_duration);
    }

    pub async fn unban_resolver(&self, name: &str) {
        let mut banned = self.banned_until.write().await;
        banned.remove(name);
    }

    pub async fn banned_resolver_names(&self) -> Vec<String> {
        let banned = self.banned_until.read().await;
        let now = Instant::now();
        banned
            .iter()
            .filter(|(_, until)| **until > now)
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub fn is_cloudflare_cname(cname: &str) -> bool {
        let cname_lower = cname.to_ascii_lowercase();
        let cf_domains = [
            "cloudflare.net",
            "cloudflare.com",
            "cfargoson.com",
            "cfargoson.link",
            "cflare.co",
        ];
        cf_domains
            .iter()
            .any(|d| cname_lower.ends_with(d) || cname_lower.contains(d))
    }

    fn normalize_hostname(hostname: &str) -> String {
        let trimmed = hostname.trim().trim_end_matches('.').to_string();
        if trimmed.is_empty() {
            return hostname.to_string();
        }
        trimmed
    }

    fn fqdn(hostname: &str) -> String {
        let trimmed = hostname.trim().trim_end_matches('.').to_string();
        format!("{trimmed}.")
    }

    pub fn validate_hostname(hostname: &str) -> Result<(), CfProbeError> {
        let trimmed = hostname.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(CfProbeError::InvalidResponse(
                "hostname cannot be empty".to_string(),
            ));
        }
        if trimmed.len() > 253 {
            return Err(CfProbeError::InvalidResponse(format!(
                "hostname too long: {} chars (max 253)",
                trimmed.len()
            )));
        }
        for label in trimmed.split('.') {
            if label.is_empty() {
                return Err(CfProbeError::InvalidResponse(format!(
                    "empty label in hostname: {}",
                    hostname
                )));
            }
            if label.len() > 63 {
                return Err(CfProbeError::InvalidResponse(format!(
                    "label too long: {} chars (max 63)",
                    label.len()
                )));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(CfProbeError::InvalidResponse(format!(
                    "label starts or ends with hyphen: {}",
                    label
                )));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(CfProbeError::InvalidResponse(format!(
                    "label contains invalid characters: {}",
                    label
                )));
            }
        }
        Ok(())
    }

    pub async fn detect(
        &self,
        hostname: &str,
        cf_ranges: &CloudflareRanges,
    ) -> Result<DnsDetection, CfProbeError> {
        self.detect_with_cancel(hostname, cf_ranges, CancellationToken::new())
            .await
    }

    pub async fn detect_with_cancel(
        &self,
        hostname: &str,
        cf_ranges: &CloudflareRanges,
        cancellation: CancellationToken,
    ) -> Result<DnsDetection, CfProbeError> {
        let total_start = Instant::now();

        let normalized = Self::normalize_hostname(hostname);
        let fqdn = Self::fqdn(hostname);

        let semaphore = Arc::new(Semaphore::new(self.max_concurrency));

        let mut futures = FuturesUnordered::new();

        let unhealthy: HashSet<String> =
            self.unhealthy_resolver_names().await.into_iter().collect();

        for resolver_entry in &self.resolvers {
            if cancellation.is_cancelled() {
                break;
            }

            if unhealthy.contains(&resolver_entry.name) {
                continue;
            }

            let resolver = resolver_entry.clone();
            let fqdn = fqdn.clone();
            let semaphore = Arc::clone(&semaphore);
            let cache = self.cache.clone();
            let cname_max_depth = self.cname_max_depth;
            let cancellation = cancellation.clone();

            futures.push(tokio::spawn(async move {
                let _permit = semaphore
                    .acquire()
                    .await
                    .expect("semaphore should not be closed");
                Self::resolve_one_cached(resolver, &fqdn, cache, cname_max_depth, cancellation)
                    .await
            }));
        }

        let mut observations: Vec<ResolverObservation> = Vec::new();
        let mut all_mx: Vec<(u16, String)> = Vec::new();
        let mut all_txt: Vec<String> = Vec::new();
        let mut all_ns: Vec<String> = Vec::new();
        let mut all_cname_chain: Vec<String> = Vec::new();
        let mut mx_seen = HashSet::new();
        let mut txt_seen = HashSet::new();
        let mut ns_seen = HashSet::new();
        let mut cname_seen = HashSet::new();

        while let Some(result) = futures.next().await {
            if cancellation.is_cancelled() {
                break;
            }

            match result {
                Ok(observation) => {
                    Self::record_health_with_ban(
                        self.health.clone(),
                        self.banned_until.clone(),
                        &observation,
                        self.ban_duration,
                    )
                    .await;

                    for mx in &observation.mx_records {
                        if mx_seen.insert(mx.clone()) {
                            all_mx.push(mx.clone());
                        }
                    }
                    for txt in &observation.txt_records {
                        if txt_seen.insert(txt.clone()) {
                            all_txt.push(txt.clone());
                        }
                    }
                    for ns in &observation.ns_records {
                        if ns_seen.insert(ns.clone()) {
                            all_ns.push(ns.clone());
                        }
                    }
                    for cname in &observation.cname_chain {
                        if cname_seen.insert(cname.clone()) {
                            all_cname_chain.push(cname.clone());
                        }
                    }

                    observations.push(observation);
                }
                Err(_) => continue,
            }
        }

        let total_duration = total_start.elapsed();

        Ok(self.aggregate(
            &normalized,
            &fqdn,
            observations,
            total_duration,
            cf_ranges,
            all_mx,
            all_txt,
            all_ns,
            all_cname_chain,
        ))
    }

    pub async fn detect_ptr(&self, ip: IpAddr) -> Result<Vec<String>, CfProbeError> {
        self.detect_ptr_with_cancel(ip, CancellationToken::new())
            .await
    }

    pub async fn detect_ptr_with_cancel(
        &self,
        ip: IpAddr,
        cancellation: CancellationToken,
    ) -> Result<Vec<String>, CfProbeError> {
        let key = ip.to_string();

        if let Some(ref cache) = self.cache {
            if let Some(cached) = cache.get_ptr(&key).await {
                return Ok(cached);
            }
        }

        /*
         * 对多个 resolver 的 PTR 查询并发执行。
         * 典型配置中会有 2~4 个 resolver，
         * 串行耗时 ≈ sum(time_i)，改为并发后 ≈ max(time_i)。
         */
        let mut futures = Vec::with_capacity(self.resolvers.len());
        for resolver_entry in &self.resolvers {
            let backend = resolver_entry.backend.clone();
            futures.push(async move { backend.lookup_ptr(ip).await });
        }

        use futures::StreamExt;
        let mut stream = futures::stream::iter(futures).buffer_unordered(self.resolvers.len());

        let mut results: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        while let Some(result) = stream.next().await {
            if cancellation.is_cancelled() {
                break;
            }
            match result {
                Ok(ptr_list) => {
                    for ptr in ptr_list {
                        if seen.insert(ptr.clone()) {
                            results.push(ptr);
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        if !results.is_empty() {
            if let Some(ref cache) = self.cache {
                cache.set_ptr(&key, results.clone()).await;
            }
        }

        Ok(results)
    }

    pub async fn detect_batch(
        &self,
        hostnames: &[String],
        cf_ranges: &CloudflareRanges,
    ) -> Vec<(String, Result<DnsDetection, CfProbeError>)> {
        self.detect_batch_with_cancel(hostnames, cf_ranges, CancellationToken::new())
            .await
    }

    pub async fn detect_batch_with_cancel(
        &self,
        hostnames: &[String],
        cf_ranges: &CloudflareRanges,
        cancellation: CancellationToken,
    ) -> Vec<(String, Result<DnsDetection, CfProbeError>)> {
        let mut results = Vec::with_capacity(hostnames.len());

        for hostname in hostnames {
            if cancellation.is_cancelled() {
                break;
            }

            let result = self
                .detect_with_cancel(hostname, cf_ranges, cancellation.clone())
                .await;

            results.push((hostname.clone(), result));
        }

        results
    }

    async fn resolve_one_cached(
        entry: DnsResolverEntry,
        fqdn: &str,
        cache: Option<Arc<DnsCache>>,
        cname_max_depth: usize,
        cancellation: CancellationToken,
    ) -> ResolverObservation {
        let resolver_name = entry.name.clone();
        let backend = entry.backend.clone();
        let start = Instant::now();

        let mut ips: Vec<IpAddr> = Vec::new();
        let mut success = true;
        let mut error: Option<String> = None;

        if cancellation.is_cancelled() {
            return ResolverObservation {
                resolver: resolver_name,
                success: false,
                ips: Vec::new(),
                cname_chain: Vec::new(),
                duration: start.elapsed(),
                error: Some("cancelled".to_string()),
                mx_records: Vec::new(),
                txt_records: Vec::new(),
                ns_records: Vec::new(),
            };
        }

        let fqdn_owned = fqdn.to_string();
        let cache_clone = cache.clone();
        let backend_clone = backend.clone();

        /*
         * CNAME 分支：
         *   1) cache lookup / backend CNAME query
         *   2) walk_cname_chain (可能多轮 CNAME lookup，串行)
         *   3) 用 final_fqdn 发起 IP 查询 (依赖 CNAME 结果)
         *
         * 但 MX/TXT/NS 三件事完全不依赖 CNAME，可以和整个 CNAME+IP 流水线同时跑。
         *
         * 因此：
         *  Task A: (CNAME → walk chain → IP)   (总 = 2~3 RTT)
         *  Task B: MX   (1 RTT)  ┐
         *  Task C: TXT  (1 RTT)  ├─ 这三者独立并发
         *  Task D: NS   (1 RTT)  ┘
         *              ↓
         *  总时间 = max(Task A, max(B,C,D))
         *         = max(3 RTT, 1 RTT) = 3 RTT
         *  之前:    = 1 RTT (CNAME) + walk + 1 RTT (IP) + 1 (MX) + 1 (TXT) + 1 (NS)
         *         ≈ 5 RTT
         */

        let cname_ip_task = async move {
            let cname_result = if let Some(ref cache) = cache_clone {
                if let Some(cached) = cache.get_cname(&fqdn_owned).await {
                    Ok(cached)
                } else {
                    let result = backend_clone.lookup_cname(&fqdn_owned).await;
                    if let Ok(ref cnames) = result {
                        cache.set_cname(&fqdn_owned, cnames.clone()).await;
                    }
                    result
                }
            } else {
                backend_clone.lookup_cname(&fqdn_owned).await
            };

            let mut walked_chain: Vec<String> = Vec::new();
            let mut final_fqdn = fqdn_owned.clone();

            if let Ok(cnames) = &cname_result {
                walked_chain =
                    Self::walk_cname_chain(&backend_clone, &fqdn_owned, cnames, cname_max_depth)
                        .await;
                if let Some(last) = walked_chain.last() {
                    final_fqdn = format!("{}.", last.trim_end_matches('.'));
                }
            }

            let ip_lookup_target = if walked_chain.is_empty() {
                fqdn_owned.clone()
            } else {
                final_fqdn.clone()
            };

            let ip_result = if let Some(ref cache) = cache_clone {
                if let Some(cached) = cache.get_ip(&ip_lookup_target).await {
                    Ok(cached)
                } else {
                    let result = backend_clone.lookup_ip(&ip_lookup_target).await;
                    if let Ok(ref ips) = result {
                        cache.set_ip(&ip_lookup_target, ips.clone()).await;
                    }
                    result
                }
            } else {
                backend_clone.lookup_ip(&ip_lookup_target).await
            };

            (cname_result, walked_chain, ip_result)
        };

        let backend2 = backend.clone();
        let cache2 = cache.clone();
        let fqdn_mx = fqdn.to_string();
        let mx_task = async move {
            if let Some(ref cache) = cache2 {
                if let Some(cached) = cache.get_mx(&fqdn_mx).await {
                    return Ok(cached);
                }
                let result = backend2.lookup_mx(&fqdn_mx).await;
                if let Ok(ref mx) = result {
                    cache.set_mx(&fqdn_mx, mx.clone()).await;
                }
                result
            } else {
                backend2.lookup_mx(&fqdn_mx).await
            }
        };

        let backend3 = backend.clone();
        let cache3 = cache.clone();
        let fqdn_txt = fqdn.to_string();
        let txt_task = async move {
            if let Some(ref cache) = cache3 {
                if let Some(cached) = cache.get_txt(&fqdn_txt).await {
                    return Ok(cached);
                }
                let result = backend3.lookup_txt(&fqdn_txt).await;
                if let Ok(ref txt) = result {
                    cache.set_txt(&fqdn_txt, txt.clone()).await;
                }
                result
            } else {
                backend3.lookup_txt(&fqdn_txt).await
            }
        };

        let backend4 = backend.clone();
        let cache4 = cache;
        let fqdn_ns = fqdn.to_string();
        let ns_task = async move {
            if let Some(ref cache) = cache4 {
                if let Some(cached) = cache.get_ns(&fqdn_ns).await {
                    return Ok(cached);
                }
                let result = backend4.lookup_ns(&fqdn_ns).await;
                if let Ok(ref ns) = result {
                    cache.set_ns(&fqdn_ns, ns.clone()).await;
                }
                result
            } else {
                backend4.lookup_ns(&fqdn_ns).await
            }
        };

        let ((cname_result, walked_chain, ip_result), mx_result, txt_result, ns_result) =
            tokio::join!(cname_ip_task, mx_task, txt_task, ns_task);

        let duration = start.elapsed();

        match &ip_result {
            Ok(list) => {
                ips = list.iter().copied().collect();
            }
            Err(err) => {
                success = false;
                error = Some(err.to_string());
            }
        }

        // cname_result 本身的错误不置 success=false，
        // 保持与原代码语义一致。
        let _ = cname_result;

        let cname_chain = walked_chain;

        let filtered_ips = Self::filter_private_ips(&ips);

        let mx_records = mx_result.unwrap_or_default();
        let txt_records = txt_result.unwrap_or_default();
        let ns_records = ns_result.unwrap_or_default();

        ResolverObservation {
            resolver: resolver_name,
            success,
            ips: filtered_ips,
            cname_chain,
            duration,
            error,
            mx_records,
            txt_records,
            ns_records,
        }
    }

    async fn walk_cname_chain(
        backend: &Arc<dyn DnsBackend>,
        _original_fqdn: &str,
        initial_cnames: &[String],
        max_depth: usize,
    ) -> Vec<String> {
        if initial_cnames.is_empty() || max_depth == 0 {
            return initial_cnames.to_vec();
        }

        let mut chain: Vec<String> = initial_cnames.to_vec();
        let mut visited: HashSet<String> = HashSet::new();

        for cname in initial_cnames {
            visited.insert(cname.clone());
        }

        let mut current = initial_cnames.last().cloned();
        let depth_limit = max_depth.saturating_sub(initial_cnames.len());

        for _ in 0..depth_limit {
            let Some(target) = current.clone() else {
                break;
            };

            let fqdn = if target.ends_with('.') {
                target.clone()
            } else {
                format!("{}.", target)
            };

            match backend.lookup_cname(&fqdn).await {
                Ok(more) => {
                    if more.is_empty() {
                        break;
                    }
                    let mut progressed = false;
                    for next in more {
                        if !visited.contains(&next) {
                            visited.insert(next.clone());
                            chain.push(next.clone());
                            current = Some(next);
                            progressed = true;
                        }
                    }
                    if !progressed {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        chain
    }

    async fn record_health_with_ban(
        health: Arc<RwLock<HashMap<String, ResolverHealth>>>,
        banned: Arc<RwLock<HashMap<String, Instant>>>,
        observation: &ResolverObservation,
        ban_duration: Duration,
    ) {
        let mut map = health.write().await;
        let h = map.entry(observation.resolver.clone()).or_default();

        if observation.success {
            h.record_success(observation.duration);
        } else {
            h.record_failure();
            if h.failure_count >= 3 && !h.is_healthy() {
                drop(map);
                let mut banned_map = banned.write().await;
                banned_map.insert(observation.resolver.clone(), Instant::now() + ban_duration);
            }
        }
    }

    fn aggregate(
        &self,
        normalized: &str,
        _fqdn: &str,
        observations: Vec<ResolverObservation>,
        total_duration: std::time::Duration,
        cf_ranges: &CloudflareRanges,
        all_mx: Vec<(u16, String)>,
        all_txt: Vec<String>,
        all_ns: Vec<String>,
        all_cname_chain: Vec<String>,
    ) -> DnsDetection {
        let successful = observations
            .iter()
            .filter(|o| o.success && !o.ips.is_empty())
            .count();

        let mut union_ips: Vec<IpAddr> = observations
            .iter()
            .flat_map(|o| o.ips.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        union_ips.sort();

        let mut cloudflare_ips: Vec<IpAddr> = union_ips
            .iter()
            .copied()
            .filter(|ip| cf_ranges.contains(*ip))
            .collect();

        cloudflare_ips.sort();

        let cloudflare_resolver_count = observations
            .iter()
            .filter(|o| o.success && o.ips.iter().any(|ip| cf_ranges.contains(*ip)))
            .count();

        let has_cloudflare_ip = !cloudflare_ips.is_empty();

        let all_resolvers_agree = observations.iter().filter(|o| o.success).count() <= 1
            || observations.iter().filter(|o| o.success).all(|o| {
                o.ips.len() == cloudflare_ips.len()
                    && o.ips.iter().all(|ip| cf_ranges.contains(*ip))
            });

        let status = if has_cloudflare_ip {
            DnsDetectionStatus::CloudflareIp
        } else if !union_ips.is_empty() {
            DnsDetectionStatus::NoCloudflareIp
        } else {
            DnsDetectionStatus::Unknown
        };

        DnsDetection {
            hostname: normalized.to_string(),
            normalized_hostname: normalized.to_string(),
            observations,
            union_ips,
            cloudflare_ips,
            cloudflare_resolver_count,
            successful_resolver_count: successful,
            resolver_count: self.resolvers.len(),
            all_resolvers_agree,
            has_cloudflare_ip,
            total_duration,
            status,
            mx_records: all_mx,
            txt_records: all_txt,
            ns_records: all_ns,
            cname_chain: all_cname_chain,
        }
    }

    fn filter_private_ips(ips: &[IpAddr]) -> Vec<IpAddr> {
        ips.iter()
            .filter(|ip| match ip {
                IpAddr::V4(v4) => {
                    !v4.is_private()
                        && !v4.is_loopback()
                        && !v4.is_link_local()
                        && !v4.is_broadcast()
                        && !v4.is_multicast()
                        && !v4.is_unspecified()
                        && !Self::is_cgnat(v4)
                }
                IpAddr::V6(v6) => {
                    !v6.is_loopback()
                        && !v6.is_multicast()
                        && !v6.is_unspecified()
                        && !Self::is_ula(v6)
                        && !Self::is_link_local_v6(v6)
                }
            })
            .copied()
            .collect()
    }

    fn is_cgnat(ip: &std::net::Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127
    }

    fn is_ula(ip: &std::net::Ipv6Addr) -> bool {
        ip.segments()[0] & 0xfe00 == 0xfc00
    }

    fn is_link_local_v6(ip: &std::net::Ipv6Addr) -> bool {
        ip.segments()[0] & 0xffc0 == 0xfe80
    }
}
