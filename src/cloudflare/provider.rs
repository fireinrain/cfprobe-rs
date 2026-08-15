use std::net::IpAddr;
use std::sync::Arc;

use crate::cloudflare::{CloudflareClient, CloudflareRanges};

use crate::cloudflare::cache::{CacheConfig, CacheResult, CloudflareRangeCache};

use crate::detector::{CloudflareIpDetection, detect_cloudflare_ip};

use crate::error::CfProbeError;

/// Cloudflare 范围供应器（简化 facade，直接使用 [`CloudflareRangeCache`]）。
#[derive(Clone)]
pub struct CloudflareRangeProvider {
    cache: CloudflareRangeCache,
}

impl CloudflareRangeProvider {
    /// 由 CloudflareClient 构造；缓存文件位于 `directories::ProjectDirs::cache_dir`。
    pub fn new(client: CloudflareClient) -> Result<Self, CfProbeError> {
        Ok(Self {
            cache: CloudflareRangeCache::new(client)?,
        })
    }

    pub fn with_cache_dir(
        client: CloudflareClient,
        cache_dir: impl AsRef<std::path::Path>,
    ) -> Result<Self, CfProbeError> {
        Ok(Self {
            cache: CloudflareRangeCache::with_cache_dir(client, cache_dir)?,
        })
    }

    pub fn with_config(self, config: CacheConfig) -> Self {
        Self {
            cache: self.cache.with_config(config),
        }
    }

    pub async fn get(&self) -> Result<CacheResult, CfProbeError> {
        self.cache.get().await
    }

    pub async fn load(&self) -> Result<Arc<CloudflareRanges>, CfProbeError> {
        Ok(self.cache.get().await?.ranges)
    }

    pub async fn contains(&self, ip: IpAddr) -> Result<CloudflareIpDetection, CfProbeError> {
        let result = self.cache.get().await?;

        Ok(detect_cloudflare_ip(&result.ranges, ip))
    }
}
