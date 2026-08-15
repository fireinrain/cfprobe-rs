use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use tokio::sync::RwLock;

use crate::error::CfProbeError;

use super::backend::DnsBackend;

#[derive(Debug, Clone)]
pub struct DnsCacheConfig {
    pub ttl: Duration,
    pub max_entries: usize,
    pub eviction_interval: Option<Duration>,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(300),
            max_entries: 10_000,
            eviction_interval: None,
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry<T: Clone> {
    value: T,
    expires_at: Instant,
}

impl<T: Clone> CacheEntry<T> {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

#[derive(Debug, Clone)]
pub struct DnsCache {
    ttl: Duration,
    max_entries: usize,
    ip_cache: Arc<RwLock<HashMap<String, CacheEntry<Vec<IpAddr>>>>>,
    cname_cache: Arc<RwLock<HashMap<String, CacheEntry<Vec<String>>>>>,
    mx_cache: Arc<RwLock<HashMap<String, CacheEntry<Vec<(u16, String)>>>>>,
    txt_cache: Arc<RwLock<HashMap<String, CacheEntry<Vec<String>>>>>,
    ns_cache: Arc<RwLock<HashMap<String, CacheEntry<Vec<String>>>>>,
    ptr_cache: Arc<RwLock<HashMap<String, CacheEntry<Vec<String>>>>>,
}

impl DnsCache {
    pub fn new(config: DnsCacheConfig) -> Self {
        Self {
            ttl: config.ttl,
            max_entries: config.max_entries,
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
            cname_cache: Arc::new(RwLock::new(HashMap::new())),
            mx_cache: Arc::new(RwLock::new(HashMap::new())),
            txt_cache: Arc::new(RwLock::new(HashMap::new())),
            ns_cache: Arc::new(RwLock::new(HashMap::new())),
            ptr_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self::new(DnsCacheConfig {
            ttl,
            max_entries: 10_000,
            eviction_interval: None,
        })
    }

    fn make_entry<T: Clone>(&self, value: T) -> CacheEntry<T> {
        CacheEntry {
            value,
            expires_at: Instant::now() + self.ttl,
        }
    }

    pub async fn get_ip(&self, key: &str) -> Option<Vec<IpAddr>> {
        let cache = self.ip_cache.read().await;
        if let Some(entry) = cache.get(key) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    pub async fn set_ip(&self, key: &str, value: Vec<IpAddr>) {
        let mut cache = self.ip_cache.write().await;
        if cache.len() >= self.max_entries {
            self.evict_expired(&mut cache);
            if cache.len() >= self.max_entries {
                return;
            }
        }
        cache.insert(key.to_string(), self.make_entry(value));
    }

    pub async fn get_cname(&self, key: &str) -> Option<Vec<String>> {
        let cache = self.cname_cache.read().await;
        if let Some(entry) = cache.get(key) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    pub async fn set_cname(&self, key: &str, value: Vec<String>) {
        let mut cache = self.cname_cache.write().await;
        if cache.len() >= self.max_entries {
            self.evict_expired(&mut cache);
            if cache.len() >= self.max_entries {
                return;
            }
        }
        cache.insert(key.to_string(), self.make_entry(value));
    }

    pub async fn get_mx(&self, key: &str) -> Option<Vec<(u16, String)>> {
        let cache = self.mx_cache.read().await;
        if let Some(entry) = cache.get(key) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    pub async fn set_mx(&self, key: &str, value: Vec<(u16, String)>) {
        let mut cache = self.mx_cache.write().await;
        if cache.len() >= self.max_entries {
            self.evict_expired(&mut cache);
            if cache.len() >= self.max_entries {
                return;
            }
        }
        cache.insert(key.to_string(), self.make_entry(value));
    }

    pub async fn get_txt(&self, key: &str) -> Option<Vec<String>> {
        let cache = self.txt_cache.read().await;
        if let Some(entry) = cache.get(key) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    pub async fn set_txt(&self, key: &str, value: Vec<String>) {
        let mut cache = self.txt_cache.write().await;
        if cache.len() >= self.max_entries {
            self.evict_expired(&mut cache);
            if cache.len() >= self.max_entries {
                return;
            }
        }
        cache.insert(key.to_string(), self.make_entry(value));
    }

    pub async fn get_ns(&self, key: &str) -> Option<Vec<String>> {
        let cache = self.ns_cache.read().await;
        if let Some(entry) = cache.get(key) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    pub async fn set_ns(&self, key: &str, value: Vec<String>) {
        let mut cache = self.ns_cache.write().await;
        if cache.len() >= self.max_entries {
            self.evict_expired(&mut cache);
            if cache.len() >= self.max_entries {
                return;
            }
        }
        cache.insert(key.to_string(), self.make_entry(value));
    }

    pub async fn get_ptr(&self, key: &str) -> Option<Vec<String>> {
        let cache = self.ptr_cache.read().await;
        if let Some(entry) = cache.get(key) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    pub async fn set_ptr(&self, key: &str, value: Vec<String>) {
        let mut cache = self.ptr_cache.write().await;
        if cache.len() >= self.max_entries {
            self.evict_expired(&mut cache);
            if cache.len() >= self.max_entries {
                return;
            }
        }
        cache.insert(key.to_string(), self.make_entry(value));
    }

    pub async fn clear(&self) {
        self.ip_cache.write().await.clear();
        self.cname_cache.write().await.clear();
        self.mx_cache.write().await.clear();
        self.txt_cache.write().await.clear();
        self.ns_cache.write().await.clear();
        self.ptr_cache.write().await.clear();
    }

    pub async fn len(&self) -> usize {
        let ip = self.ip_cache.read().await.len();
        let cname = self.cname_cache.read().await.len();
        let mx = self.mx_cache.read().await.len();
        let txt = self.txt_cache.read().await.len();
        let ns = self.ns_cache.read().await.len();
        let ptr = self.ptr_cache.read().await.len();
        ip + cname + mx + txt + ns + ptr
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    pub async fn evict_all_expired(&self) {
        let mut ip = self.ip_cache.write().await;
        self.evict_expired(&mut ip);
        drop(ip);

        let mut cname = self.cname_cache.write().await;
        self.evict_expired(&mut cname);
        drop(cname);

        let mut mx = self.mx_cache.write().await;
        self.evict_expired(&mut mx);
        drop(mx);

        let mut txt = self.txt_cache.write().await;
        self.evict_expired(&mut txt);
        drop(txt);

        let mut ns = self.ns_cache.write().await;
        self.evict_expired(&mut ns);
        drop(ns);

        let mut ptr = self.ptr_cache.write().await;
        self.evict_expired(&mut ptr);
    }

    fn evict_expired<T: Clone>(&self, cache: &mut HashMap<String, CacheEntry<T>>) {
        cache.retain(|_, entry| !entry.is_expired());
    }
}

/// DNS 后端池：组合多个解析后端（本地系统、DoT、DoH）+ 共享答案缓存。
///
/// 可直接通过 `DnsDetector::from_pool(&pool)` 创建检测器。
#[derive(Clone)]
pub struct DnsPool {
    backends: Vec<(String, Arc<dyn DnsBackend>)>,
    cache: DnsCache,
}

impl DnsPool {
    /// 创建一个空的 DnsPool（之后用 `add_*` 注册后端）。
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
            cache: DnsCache::new(DnsCacheConfig::default()),
        }
    }

    pub fn with_cache(mut self, cache: DnsCache) -> Self {
        self.cache = cache;
        self
    }

    pub fn add_backend<B: DnsBackend + 'static>(
        mut self,
        name: impl Into<String>,
        backend: B,
    ) -> Self {
        self.backends.push((name.into(), Arc::new(backend)));
        self
    }

    pub fn add_backend_arc(
        mut self,
        name: impl Into<String>,
        backend: Arc<dyn DnsBackend>,
    ) -> Self {
        self.backends.push((name.into(), backend));
        self
    }

    pub fn backends(&self) -> &[(String, Arc<dyn DnsBackend>)] {
        &self.backends
    }

    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    /*
     * 核心 helper：对所有 backends 并发执行某个查询，
     * 用 HashSet 合并去重，返回结果列表。
     *
     * 把 N 个 backends 的 sum(time_i) 变为 max(time_i)。
     */
    async fn query_backends_concurrent<T, F, Fut>(&self, f: F) -> Vec<T>
    where
        T: Clone + Eq + std::hash::Hash,
        F: Fn(Arc<dyn DnsBackend>) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<Vec<T>, CfProbeError>> + Send,
    {
        let n = self.backends.len();
        if n == 0 {
            return Vec::new();
        }

        let mut futures = Vec::with_capacity(n);
        for (_name, backend) in &self.backends {
            futures.push(f(backend.clone()));
        }

        let mut stream = futures::stream::iter(futures).buffer_unordered(n);
        let mut results: Vec<T> = Vec::new();
        let mut seen = HashSet::new();

        while let Some(result) = stream.next().await {
            if let Ok(items) = result {
                for item in items {
                    if seen.insert(item.clone()) {
                        results.push(item);
                    }
                }
            }
        }
        results
    }

    pub async fn lookup_ip(&self, fqdn: &str) -> Result<Vec<IpAddr>, CfProbeError> {
        if let Some(cached) = self.cache.get_ip(fqdn).await {
            return Ok(cached);
        }

        let cache_key = fqdn.to_string();
        let results = self
            .query_backends_concurrent({
                let fqdn_for_closure = cache_key.clone();
                move |backend| {
                    let q = fqdn_for_closure.clone();
                    async move { backend.lookup_ip(&q).await }
                }
            })
            .await;

        if !results.is_empty() {
            self.cache.set_ip(&cache_key, results.clone()).await;
        }

        Ok(results)
    }

    pub async fn lookup_cname(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError> {
        if let Some(cached) = self.cache.get_cname(fqdn).await {
            return Ok(cached);
        }

        let cache_key = fqdn.to_string();
        let results = self
            .query_backends_concurrent({
                let fqdn_for_closure = cache_key.clone();
                move |backend| {
                    let q = fqdn_for_closure.clone();
                    async move { backend.lookup_cname(&q).await }
                }
            })
            .await;

        if !results.is_empty() {
            self.cache.set_cname(&cache_key, results.clone()).await;
        }

        Ok(results)
    }

    pub async fn lookup_mx(&self, fqdn: &str) -> Result<Vec<(u16, String)>, CfProbeError> {
        if let Some(cached) = self.cache.get_mx(fqdn).await {
            return Ok(cached);
        }

        let cache_key = fqdn.to_string();
        let results = self
            .query_backends_concurrent({
                let fqdn_for_closure = cache_key.clone();
                move |backend| {
                    let q = fqdn_for_closure.clone();
                    async move { backend.lookup_mx(&q).await }
                }
            })
            .await;

        if !results.is_empty() {
            self.cache.set_mx(&cache_key, results.clone()).await;
        }

        Ok(results)
    }

    pub async fn lookup_txt(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError> {
        if let Some(cached) = self.cache.get_txt(fqdn).await {
            return Ok(cached);
        }

        let cache_key = fqdn.to_string();
        let results = self
            .query_backends_concurrent({
                let fqdn_for_closure = cache_key.clone();
                move |backend| {
                    let q = fqdn_for_closure.clone();
                    async move { backend.lookup_txt(&q).await }
                }
            })
            .await;

        if !results.is_empty() {
            self.cache.set_txt(&cache_key, results.clone()).await;
        }

        Ok(results)
    }

    pub async fn lookup_ns(&self, fqdn: &str) -> Result<Vec<String>, CfProbeError> {
        if let Some(cached) = self.cache.get_ns(fqdn).await {
            return Ok(cached);
        }

        let cache_key = fqdn.to_string();
        let results = self
            .query_backends_concurrent({
                let fqdn_for_closure = cache_key.clone();
                move |backend| {
                    let q = fqdn_for_closure.clone();
                    async move { backend.lookup_ns(&q).await }
                }
            })
            .await;

        if !results.is_empty() {
            self.cache.set_ns(&cache_key, results.clone()).await;
        }

        Ok(results)
    }

    pub async fn lookup_ptr(&self, ip: IpAddr) -> Result<Vec<String>, CfProbeError> {
        let key = ip.to_string();
        if let Some(cached) = self.cache.get_ptr(&key).await {
            return Ok(cached);
        }

        let results = self
            .query_backends_concurrent(move |backend| async move { backend.lookup_ptr(ip).await })
            .await;

        if !results.is_empty() {
            self.cache.set_ptr(&key, results.clone()).await;
        }

        Ok(results)
    }

    pub async fn resolve_all(
        &self,
        fqdn: &str,
    ) -> Result<
        (
            Vec<IpAddr>,
            Vec<String>,
            Vec<(u16, String)>,
            Vec<String>,
            Vec<String>,
        ),
        CfProbeError,
    > {
        let (ip_res, cname_res, mx_res, txt_res, ns_res) = tokio::join!(
            self.lookup_ip(fqdn),
            self.lookup_cname(fqdn),
            self.lookup_mx(fqdn),
            self.lookup_txt(fqdn),
            self.lookup_ns(fqdn),
        );

        Ok((ip_res?, cname_res?, mx_res?, txt_res?, ns_res?))
    }

    pub async fn resolve_all_with_ptr(
        &self,
        fqdn: &str,
    ) -> Result<
        (
            Vec<IpAddr>,
            Vec<String>,
            Vec<(u16, String)>,
            Vec<String>,
            Vec<String>,
            Vec<String>,
        ),
        CfProbeError,
    > {
        let (ips, cnames, mx, txt, ns) = self.resolve_all(fqdn).await?;

        let mut ptr_results: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for ip in &ips {
            match self.lookup_ptr(*ip).await {
                Ok(ptr_list) => {
                    for ptr in ptr_list {
                        if seen.insert(ptr.clone()) {
                            ptr_results.push(ptr);
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok((ips, cnames, mx, txt, ns, ptr_results))
    }

    pub async fn health_check(&self) -> Vec<(String, bool)> {
        let n = self.backends.len();
        let mut futures = Vec::with_capacity(n);
        for (name, backend) in &self.backends {
            let name = name.clone();
            futures.push(async move {
                let ok = backend.lookup_ip("cloudflare.com.").await.is_ok();
                (name, ok)
            });
        }
        let mut stream = futures::stream::iter(futures).buffer_unordered(n);
        let mut results = Vec::with_capacity(n);
        while let Some(r) = stream.next().await {
            results.push(r);
        }
        results
    }
}

impl Default for DnsPool {
    fn default() -> Self {
        Self::new()
    }
}
