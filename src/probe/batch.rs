use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{Stream, StreamExt, stream};

use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::{CfProbeError, DetectionClassification};

use super::{CfProbe, ProbeResult, Target};

/// 批量扫描配置。
#[derive(Debug, Clone)]
pub struct BatchScanConfig {
    /// 同时执行多少个 Target。
    ///
    /// 注意：
    ///
    /// 一个 Target 内部还会并发执行：
    ///
    /// DNS
    /// TLS
    /// HTTP
    ///
    /// 所以这里控制的是 Target 级并发。
    pub concurrency: usize,

    /// 单个 Target 的总超时时间。
    ///
    /// 它是最外层 timeout。
    pub target_timeout: Duration,

    /// 每秒最多启动多少个 Target。
    ///
    /// None = 不限制启动速率。
    pub requests_per_second: Option<u32>,

    /// 可选的批次大小上限。
    ///
    /// None = 不限制。
    pub max_targets: Option<usize>,
}

impl Default for BatchScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 32,

            target_timeout: Duration::from_secs(30),

            requests_per_second: None,

            max_targets: None,
        }
    }
}

impl BatchScanConfig {
    pub fn validate(&self) -> Result<(), CfProbeError> {
        if self.concurrency == 0 {
            return Err(CfProbeError::InvalidResponse(
                "batch concurrency cannot be 0".to_string(),
            ));
        }

        if self.target_timeout.is_zero() {
            return Err(CfProbeError::InvalidResponse(
                "target timeout cannot be zero".to_string(),
            ));
        }

        if let Some(rps) = self.requests_per_second {
            if rps == 0 {
                return Err(CfProbeError::InvalidResponse(
                    "requests_per_second cannot be 0".to_string(),
                ));
            }
        }

        if let Some(max_targets) = self.max_targets {
            if max_targets == 0 {
                return Err(CfProbeError::InvalidResponse(
                    "max_targets cannot be 0".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;

        self
    }

    pub fn with_target_timeout(mut self, timeout: Duration) -> Self {
        self.target_timeout = timeout;

        self
    }

    pub fn with_requests_per_second(mut self, rps: Option<u32>) -> Self {
        self.requests_per_second = rps;

        self
    }

    pub fn with_max_targets(mut self, max_targets: Option<usize>) -> Self {
        self.max_targets = max_targets;

        self
    }
}

/// 单个批量任务的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchItemStatus {
    Completed,

    Failed,

    TimedOut,
}

/// 单个 Target 的批量结果。
#[derive(Debug, Clone)]
pub struct BatchItemResult {
    /// 输入数组中的原始位置。
    pub index: usize,

    pub target: Target,

    pub status: BatchItemStatus,

    /// Completed 时通常存在。
    pub result: Option<ProbeResult>,

    pub error: Option<String>,

    /// 单个 Target 实际耗时。
    pub elapsed: Duration,
}

impl BatchItemResult {
    pub fn is_completed(&self) -> bool {
        self.status == BatchItemStatus::Completed
    }

    pub fn is_failed(&self) -> bool {
        self.status == BatchItemStatus::Failed
    }

    pub fn is_timed_out(&self) -> bool {
        self.status == BatchItemStatus::TimedOut
    }

    pub fn classification(&self) -> Option<DetectionClassification> {
        self.result
            .as_ref()
            .map(|result| result.detection.classification)
    }
}

/// 整个批量任务结果。
#[derive(Debug, Clone)]
pub struct BatchResult {
    pub total: usize,

    pub completed: usize,

    pub failed: usize,

    pub timed_out: usize,

    pub cloudflare: usize,

    pub not_cloudflare: usize,

    pub unknown: usize,

    pub elapsed: Duration,

    /// scan() 会按照原始输入顺序返回。
    pub items: Vec<BatchItemResult>,
}

impl BatchResult {
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }

        self.completed as f64 / self.total as f64
    }

    pub fn cloudflare_rate(&self) -> f64 {
        if self.completed == 0 {
            return 0.0;
        }

        self.cloudflare as f64 / self.completed as f64
    }
}

/// 简单的全局启动速率控制器。
///
/// 它控制的是：
///
/// “开始一个新 Target”
///
/// 而不是：
///
/// “整个 Target 内的每一个网络请求”。
#[derive(Debug)]
struct StartRateLimiter {
    interval: Option<Duration>,

    next_start: Mutex<Instant>,
}

impl StartRateLimiter {
    fn new(requests_per_second: Option<u32>) -> Self {
        let interval = requests_per_second.map(|rps| Duration::from_secs_f64(1.0 / rps as f64));

        Self {
            interval,

            next_start: Mutex::new(Instant::now()),
        }
    }

    async fn wait(&self) {
        let Some(interval) = self.interval else {
            return;
        };

        /*
         * 故意在 Mutex 中串行控制启动时刻。
         *
         * 这样即使多个 Target 同时准备开始，
         * 也不会瞬间全部启动。
         */
        let mut next_start = self.next_start.lock().await;

        let now = Instant::now();

        if *next_start > now {
            tokio::time::sleep(*next_start - now).await;
        }

        *next_start = Instant::now() + interval;
    }
}

impl CfProbe {
    /// 批量扫描。
    ///
    /// 返回结果按照输入 targets 的原始顺序排列。
    pub async fn scan(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
    ) -> Result<BatchResult, CfProbeError> {
        config.validate()?;

        if let Some(max_targets) = config.max_targets {
            if targets.len() > max_targets {
                return Err(CfProbeError::InvalidResponse(format!(
                    "batch contains {} targets, exceeding max_targets {}",
                    targets.len(),
                    max_targets,
                )));
            }
        }

        let total = targets.len();

        let started = Instant::now();

        let mut stream = self.scan_unordered(targets, config)?;

        let mut items = Vec::with_capacity(total);

        while let Some(item) = stream.next().await {
            items.push(item);
        }

        /*
         * buffer_unordered() 按完成顺序返回。
         *
         * scan() 对外提供稳定的输入顺序，
         * 所以这里重新排序。
         */
        items.sort_by_key(|item| item.index);

        let elapsed = started.elapsed();

        Ok(build_batch_result(items, elapsed))
    }

    /// 流式批量扫描。
    ///
    /// 结果按照 Target 完成顺序返回。
    ///
    /// 例如：
    ///
    /// Target A 需要 1s
    /// Target B 需要 100ms
    ///
    /// 那么 B 会先返回。
    ///
    /// 当 Stream 被 Drop 时，
    /// 未完成的 futures 也会被取消。
    pub fn scan_unordered(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
    ) -> Result<impl Stream<Item = BatchItemResult> + 'static, CfProbeError> {
        config.validate()?;

        if let Some(max_targets) = config.max_targets {
            if targets.len() > max_targets {
                return Err(CfProbeError::InvalidResponse(format!(
                    "batch contains {} targets, exceeding max_targets {}",
                    targets.len(),
                    max_targets,
                )));
            }
        }

        let concurrency = config.concurrency;

        let target_timeout = config.target_timeout;

        let limiter = Arc::new(StartRateLimiter::new(config.requests_per_second));

        let probe = self.clone();

        let stream = stream::iter(targets.into_iter().enumerate())
            .map(move |(index, target)| {
                let probe = probe.clone();

                let limiter = limiter.clone();

                async move { execute_one(probe, index, target, target_timeout, limiter).await }
            })
            .buffer_unordered(concurrency);

        Ok(stream)
    }
}

async fn execute_one(
    probe: CfProbe,

    index: usize,

    target: Target,

    target_timeout: Duration,

    limiter: Arc<StartRateLimiter>,
) -> BatchItemResult {
    let started = Instant::now();

    /*
     * Validate before waiting for the rate limiter.
     *
     * 一个明显非法的 Target 不应该占用
     * rate limit slot。
     */
    if let Err(error) = target.validate() {
        return BatchItemResult {
            index,

            target,

            status: BatchItemStatus::Failed,

            result: None,

            error: Some(error.to_string()),

            elapsed: started.elapsed(),
        };
    }

    /*
     * Global start-rate limiting.
     */
    limiter.wait().await;

    /*
     * Target-level timeout。
     *
     * 注意底层 DNS / TLS / HTTP 自己也有 timeout，
     * 这里是整个 Target 的最后一道保险。
     */
    let result = timeout(target_timeout, probe.detect(target.clone())).await;

    let elapsed = started.elapsed();

    match result {
        Ok(Ok(result)) => BatchItemResult {
            index,

            target,

            status: BatchItemStatus::Completed,

            result: Some(result),

            error: None,

            elapsed,
        },

        Ok(Err(error)) => BatchItemResult {
            index,

            target,

            status: BatchItemStatus::Failed,

            result: None,

            error: Some(error.to_string()),

            elapsed,
        },

        Err(_) => BatchItemResult {
            index,

            target,

            status: BatchItemStatus::TimedOut,

            result: None,

            error: Some(format!("target probe timed out after {:?}", target_timeout,)),

            elapsed,
        },
    }
}

fn build_batch_result(items: Vec<BatchItemResult>, elapsed: Duration) -> BatchResult {
    let total = items.len();

    let completed = items
        .iter()
        .filter(|item| item.status == BatchItemStatus::Completed)
        .count();

    let failed = items
        .iter()
        .filter(|item| item.status == BatchItemStatus::Failed)
        .count();

    let timed_out = items
        .iter()
        .filter(|item| item.status == BatchItemStatus::TimedOut)
        .count();

    let cloudflare = items
        .iter()
        .filter(|item| item.classification() == Some(DetectionClassification::Cloudflare))
        .count();

    let not_cloudflare = items
        .iter()
        .filter(|item| item.classification() == Some(DetectionClassification::NotCloudflare))
        .count();

    let unknown = items
        .iter()
        .filter(|item| item.classification() == Some(DetectionClassification::Unknown))
        .count();

    BatchResult {
        total,

        completed,

        failed,

        timed_out,

        cloudflare,

        not_cloudflare,

        unknown,

        elapsed,

        items,
    }
}
