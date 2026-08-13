use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atomic_write_file::AtomicWriteFile;
use directories::ProjectDirs;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::cloudflare::{CloudflareClient, CloudflareRanges};
use crate::error::CfProbeError;

const CACHE_SCHEMA_VERSION: u32 = 2;

const CACHE_FILE_NAME: &str = "cloudflare-ip-ranges.json";

const LOCK_FILE_NAME: &str = "cloudflare-ip-ranges.lock";

#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// 多久认为缓存是 fresh。
    pub refresh_interval: Duration,

    /// 网络失败时最多允许使用多久以前的数据。
    pub stale_if_error: Duration,

    /// 等待其他进程刷新缓存的最长时间。
    pub lock_timeout: Duration,

    /// 轮询文件锁的间隔。
    pub lock_retry_interval: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_secs(24 * 60 * 60),

            stale_if_error: Duration::from_secs(7 * 24 * 60 * 60),

            lock_timeout: Duration::from_secs(30),

            lock_retry_interval: Duration::from_millis(100),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSource {
    Memory,
    Disk,
    Network,
    NotModified,
    StaleFallback,
}

#[derive(Debug, Clone)]
pub struct CacheResult {
    pub ranges: Arc<CloudflareRanges>,

    pub source: CacheSource,

    pub fetched_at: SystemTime,

    pub etag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheFile {
    schema_version: u32,

    fetched_at_unix_ms: i64,

    etag: Option<String>,

    ipv4_cidrs: Vec<String>,

    ipv6_cidrs: Vec<String>,
}

impl CacheFile {
    fn age(&self) -> Option<Duration> {
        let millis: u64 = self.fetched_at_unix_ms.try_into().ok()?;

        let fetched_at = UNIX_EPOCH.checked_add(Duration::from_millis(millis))?;

        SystemTime::now().duration_since(fetched_at).ok()
    }

    fn fetched_at(&self) -> Option<SystemTime> {
        let millis: u64 = self.fetched_at_unix_ms.try_into().ok()?;

        UNIX_EPOCH.checked_add(Duration::from_millis(millis))
    }
}

#[derive(Clone)]
pub struct CloudflareRangeCache {
    client: CloudflareClient,

    cache_file: PathBuf,

    lock_file: PathBuf,

    config: CacheConfig,

    memory: Arc<RwLock<Option<Arc<MemoryEntry>>>>,

    refresh_lock: Arc<Mutex<()>>,
}

#[derive(Debug)]
struct MemoryEntry {
    ranges: Arc<CloudflareRanges>,

    fetched_at: SystemTime,

    etag: Option<String>,
}

impl CloudflareRangeCache {
    pub fn new(client: CloudflareClient) -> Result<Self, CfProbeError> {
        let project_dirs = ProjectDirs::from("com", "cfprobe", "cfprobe")
            .ok_or(CfProbeError::CacheDirectoryUnavailable)?;

        let cache_dir = project_dirs.cache_dir();

        Self::with_cache_dir(client, cache_dir)
    }

    pub fn with_cache_dir(
        client: CloudflareClient,
        cache_dir: impl AsRef<Path>,
    ) -> Result<Self, CfProbeError> {
        let cache_dir = cache_dir.as_ref();

        let cache_file = cache_dir.join(CACHE_FILE_NAME);

        let lock_file = cache_dir.join(LOCK_FILE_NAME);

        Ok(Self {
            client,

            cache_file,

            lock_file,

            config: CacheConfig::default(),

            memory: Arc::new(RwLock::new(None)),

            refresh_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn with_config(mut self, config: CacheConfig) -> Self {
        self.config = config;

        self
    }

    pub fn cache_file(&self) -> &Path {
        &self.cache_file
    }

    pub async fn get(&self) -> Result<CacheResult, CfProbeError> {
        // -------------------------------------------------
        // 1. Memory cache
        // -------------------------------------------------

        if let Some(entry) = self.memory_read_fresh().await {
            return Ok(CacheResult {
                ranges: entry.ranges.clone(),

                source: CacheSource::Memory,

                fetched_at: entry.fetched_at,

                etag: entry.etag.clone(),
            });
        }

        // -------------------------------------------------
        // 2. Process-local refresh lock
        // -------------------------------------------------

        let _refresh_guard = self.refresh_lock.lock().await;

        // 双重检查。
        //
        // 在我们等待 Mutex 的时候，
        // 另一个 task 可能已经完成刷新。
        if let Some(entry) = self.memory_read_fresh().await {
            return Ok(CacheResult {
                ranges: entry.ranges.clone(),

                source: CacheSource::Memory,

                fetched_at: entry.fetched_at,

                etag: entry.etag.clone(),
            });
        }

        // -------------------------------------------------
        // 3. Disk cache
        // -------------------------------------------------
        //
        // 只读取一次磁盘缓存，后续阶段（#4 二次检查 / #5 stale fallback）
        // 直接复用这个值，避免重复 read + JSON 反序列化。
        let mut disk_cache = self.read_disk_cache().await?;

        if let Some(cache) = disk_cache.as_ref() {
            if self.is_fresh(cache) {
                let result = self.install_memory(cache.clone(), CacheSource::Disk).await?;
                return Ok(result);
            }
        }

        // -------------------------------------------------
        // 4. Cross-process file lock
        // -------------------------------------------------

        let lock = self.acquire_process_lock().await?;

        // 非常重要：
        //
        // 进程 A 获取 Mutex 后，
        // 进程 B 可能已经在我们之前更新了 cache。
        //
        // 所以获取 file lock 后必须再次检查 disk。
        disk_cache = self.read_disk_cache().await?;
        if let Some(cache) = disk_cache.as_ref() {
            if self.is_fresh(cache) {
                let result = self.install_memory(cache.clone(), CacheSource::Disk).await?;
                drop(lock);
                return Ok(result);
            }
        }

        // -------------------------------------------------
        // 5. Stale cache
        // -------------------------------------------------
        //
        // 直接复用阶段 #4 结束时最后一次读到的 disk_cache，
        // 避免第三次 syscall + JSON 解析。

        let stale_result = match disk_cache {
            Some(cache) if self.is_stale_usable(&cache) => Some(cache),
            _ => None,
        };

        // -------------------------------------------------
        // 6. Conditional HTTP request
        // -------------------------------------------------

        let etag = stale_result
            .as_ref()
            .and_then(|cache| cache.etag.as_deref());

        let fetch_result = self.client.fetch_ranges(etag).await;

        match fetch_result {
            Ok(crate::cloudflare::client::CloudflareFetchResult::NotModified) => {
                let stale = stale_result.ok_or_else(|| {
                    CfProbeError::InvalidResponse(
                        "Cloudflare returned 304 but local cache is unavailable".to_string(),
                    )
                })?;

                let now = current_unix_timestamp_ms()?;

                let updated_cache = CacheFile {
                    schema_version: CACHE_SCHEMA_VERSION,

                    fetched_at_unix_ms: now,

                    etag: stale.etag.clone(),

                    ipv4_cidrs: stale.ipv4_cidrs.clone(),

                    ipv6_cidrs: stale.ipv6_cidrs.clone(),
                };

                // 即使 304，也更新 fetched_at。
                //
                // 否则如果 API 长期都是 304，
                // 本地缓存仍会因为旧 timestamp 被
                // 判断为 stale。
                let _ = self.write_disk_cache(&updated_cache).await;

                let result = self
                    .install_memory_from_cache(&updated_cache, CacheSource::NotModified)
                    .await?;

                drop(lock);

                Ok(result)
            }

            Ok(crate::cloudflare::client::CloudflareFetchResult::Updated(remote)) => {
                let now = current_unix_timestamp_ms()?;

                let cache = CacheFile {
                    schema_version: CACHE_SCHEMA_VERSION,

                    fetched_at_unix_ms: now,

                    etag: remote.etag.clone(),

                    ipv4_cidrs: remote.ipv4_cidrs.clone(),

                    ipv6_cidrs: remote.ipv6_cidrs.clone(),
                };

                // 远程数据已经成功拿到。
                //
                // 即使磁盘写入失败，
                // 也应该继续使用内存中的新数据，
                // 而不是让整个检测失败。
                let ranges = Arc::new(CloudflareRanges::new(
                    remote.ipv4_cidrs.clone(),
                    remote.ipv6_cidrs.clone(),
                    remote.etag.clone(),
                )?);

                let memory = MemoryEntry {
                    ranges: ranges.clone(),

                    fetched_at: UNIX_EPOCH
                        .checked_add(Duration::from_secs(now.try_into().map_err(|_| {
                            CfProbeError::InvalidResponse("timestamp overflow".to_string())
                        })?))
                        .ok_or_else(|| {
                            CfProbeError::InvalidResponse("invalid timestamp".to_string())
                        })?,

                    etag: remote.etag.clone(),
                };

                {
                    let mut guard = self.memory.write().await;

                    *guard = Some(Arc::new(memory));
                }

                let _ = self.write_disk_cache(&cache).await;

                drop(lock);

                Ok(CacheResult {
                    ranges,

                    source: CacheSource::Network,

                    fetched_at: SystemTime::now(),

                    etag: remote.etag,
                })
            }

            Err(error) => {
                // 网络失败，但是 stale cache 仍然可用。
                if let Some(cache) = stale_result {
                    let result = self
                        .install_memory_from_cache(&cache, CacheSource::StaleFallback)
                        .await?;

                    drop(lock);

                    return Ok(result);
                }

                drop(lock);

                Err(error)
            }
        }
    }

    async fn memory_read_fresh(&self) -> Option<Arc<MemoryEntry>> {
        let guard = self.memory.read().await;

        let entry = guard.as_ref()?;

        let age = entry.fetched_at.elapsed().ok()?;

        if age <= self.config.refresh_interval {
            Some(entry.clone())
        } else {
            None
        }
    }

    fn is_fresh(&self, cache: &CacheFile) -> bool {
        cache
            .age()
            .map(|age| age <= self.config.refresh_interval)
            .unwrap_or(false)
    }

    fn is_stale_usable(&self, cache: &CacheFile) -> bool {
        cache
            .age()
            .map(|age| age <= self.config.stale_if_error)
            .unwrap_or(false)
    }

    async fn install_memory(
        &self,
        cache: CacheFile,
        source: CacheSource,
    ) -> Result<CacheResult, CfProbeError> {
        self.install_memory_from_cache(&cache, source).await
    }

    async fn install_memory_from_cache(
        &self,
        cache: &CacheFile,
        source: CacheSource,
    ) -> Result<CacheResult, CfProbeError> {
        if cache.schema_version != CACHE_SCHEMA_VERSION {
            return Err(CfProbeError::CacheCorrupted {
                path: self.cache_file.clone(),

                reason: format!("unsupported schema version {}", cache.schema_version),
            });
        }

        let ranges = Arc::new(CloudflareRanges::new(
            cache.ipv4_cidrs.clone(),
            cache.ipv6_cidrs.clone(),
            cache.etag.clone(),
        )?);

        let fetched_at = cache
            .fetched_at()
            .ok_or_else(|| CfProbeError::CacheCorrupted {
                path: self.cache_file.clone(),

                reason: "invalid timestamp".to_string(),
            })?;

        let entry = MemoryEntry {
            ranges: ranges.clone(),

            fetched_at,

            etag: cache.etag.clone(),
        };

        {
            let mut guard = self.memory.write().await;

            *guard = Some(Arc::new(entry));
        }

        Ok(CacheResult {
            ranges,

            source,

            fetched_at,

            etag: cache.etag.clone(),
        })
    }

    async fn read_disk_cache(&self) -> Result<Option<CacheFile>, CfProbeError> {
        let bytes = match tokio::fs::read(&self.cache_file).await {
            Ok(bytes) => bytes,

            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }

            Err(error) => {
                return Err(error.into());
            }
        };

        let cache: CacheFile = match serde_json::from_slice(&bytes) {
            Ok(cache) => cache,

            Err(_) => {
                self.invalidate_disk_cache().await;

                return Ok(None);
            }
        };

        if cache.schema_version != CACHE_SCHEMA_VERSION {
            self.invalidate_disk_cache().await;

            return Ok(None);
        }

        if cache.ipv4_cidrs.is_empty() && cache.ipv6_cidrs.is_empty() {
            self.invalidate_disk_cache().await;

            return Ok(None);
        }

        if CloudflareRanges::new(
            cache.ipv4_cidrs.clone(),
            cache.ipv6_cidrs.clone(),
            cache.etag.clone(),
        )
        .is_err()
        {
            self.invalidate_disk_cache().await;

            return Ok(None);
        }

        Ok(Some(cache))
    }

    async fn invalidate_disk_cache(&self) {
        let _ = tokio::fs::remove_file(&self.cache_file).await;
    }

    async fn write_disk_cache(&self, cache: &CacheFile) -> Result<(), CfProbeError> {
        let parent = self
            .cache_file
            .parent()
            .ok_or(CfProbeError::CacheDirectoryUnavailable)?;

        tokio::fs::create_dir_all(parent).await?;

        let content = serde_json::to_vec_pretty(cache)?;

        let cache_file = self.cache_file.clone();

        tokio::task::spawn_blocking(move || -> Result<(), CfProbeError> {
            let mut file = AtomicWriteFile::open(&cache_file).map_err(CfProbeError::Io)?;

            use std::io::Write;

            file.write_all(&content).map_err(CfProbeError::Io)?;

            file.sync_all().map_err(CfProbeError::Io)?;

            file.commit().map_err(CfProbeError::Io)?;

            Ok(())
        })
        .await
        .map_err(|error| {
            CfProbeError::InvalidResponse(format!("cache writer task failed: {error}"))
        })??;

        Ok(())
    }

    async fn acquire_process_lock(&self) -> Result<std::fs::File, CfProbeError> {
        let parent = self
            .lock_file
            .parent()
            .ok_or(CfProbeError::CacheDirectoryUnavailable)?
            .to_path_buf();

        tokio::fs::create_dir_all(&parent).await?;

        let deadline = tokio::time::Instant::now() + self.config.lock_timeout;

        loop {
            let lock_path = self.lock_file.clone();

            let attempt =
                tokio::task::spawn_blocking(move || -> Result<std::fs::File, std::io::Error> {
                    use std::fs::OpenOptions;

                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open(lock_path)?;

                    match file.try_lock_exclusive() {
                        Ok(()) => Ok(file),

                        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::WouldBlock,
                                "cache lock is busy",
                            ))
                        }

                        Err(error) => Err(error),
                    }
                })
                .await
                .map_err(|error| {
                    CfProbeError::InvalidResponse(format!("cache lock task failed: {error}"))
                })?;

            match attempt {
                Ok(file) => {
                    return Ok(file);
                }

                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(CfProbeError::CacheLockTimeout);
                    }

                    tokio::time::sleep(self.config.lock_retry_interval).await;
                }

                Err(error) => {
                    return Err(error.into());
                }
            }
        }
    }
}

fn current_unix_timestamp_ms() -> Result<i64, CfProbeError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)?;

    let millis = duration.as_millis();

    i64::try_from(millis)
        .map_err(|_| CfProbeError::InvalidResponse("timestamp overflow".to_string()))
}