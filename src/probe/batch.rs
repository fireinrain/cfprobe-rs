use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{Stream, StreamExt, stream};

use serde::Serialize;

use tokio::sync::Mutex;
use tokio::time::timeout;

use tokio_util::sync::CancellationToken;

use crate::{CfProbeError, DetectionClassification};

use super::{CfProbe, ProbeResult, Target};

/// 批量扫描配置。
#[derive(Debug, Clone)]
pub struct BatchScanConfig {
    /// 同时执行的 Target 数量。
    ///
    /// 注意：
    ///
    /// 每个 Target 内部还会并发进行：
    ///
    /// DNS
    /// TLS
    /// HTTP
    ///
    /// 所以这个值应该根据机器资源谨慎设置。
    pub concurrency: usize,

    /// 单个 Target 的总超时时间。
    pub target_timeout: Duration,

    /// 每秒最多启动多少个新的 Target。
    ///
    /// None 表示不限制启动速率。
    pub requests_per_second: Option<u32>,

    /// 本次 Batch 允许的最大 Target 数量。
    ///
    /// None 表示不限制。
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

/// 单个 Target 的执行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BatchItemStatus {
    Completed,

    Failed,

    TimedOut,

    Cancelled,
}

/// 单个 Target 的结果。
#[derive(Debug, Clone, Serialize)]
pub struct BatchItemResult {
    /// 原始输入中的位置。
    pub index: usize,

    pub target: Target,

    pub status: BatchItemStatus,

    pub result: Option<ProbeResult>,

    pub error: Option<String>,

    /// 从这个 Target 开始执行到结束的时间。
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

    pub fn is_cancelled(&self) -> bool {
        self.status == BatchItemStatus::Cancelled
    }

    pub fn classification(&self) -> Option<DetectionClassification> {
        self.result
            .as_ref()
            .map(|result| result.detection.classification)
    }
}

/// 整个 Batch 的最终结果。
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    pub total: usize,

    pub completed: usize,

    pub failed: usize,

    pub timed_out: usize,

    pub cancelled: usize,

    pub cloudflare: usize,

    pub not_cloudflare: usize,

    pub unknown: usize,

    pub elapsed: Duration,

    /// scan() 会按照原始输入顺序排列。
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

/// Target 启动速率限制器。
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

    /// 等待一个 Target 的启动配额。
    ///
    /// 返回：
    ///
    /// true  = 可以启动
    /// false = 已经取消
    async fn wait(&self, cancellation: &CancellationToken) -> bool {
        let Some(interval) = self.interval else {
            return !cancellation.is_cancelled();
        };

        /*
         * 重要：不能在持锁期间 sleep！
         *
         * 之前：guard = lock().await; sleep(wait); *guard = ...
         *       → 所有并发任务串行在锁上等待前一个任务 sleep 完。
         * 现在：
         *   1) 快速持锁：计算 wait 到什么时候 (deadline)，并预约 next_start。
         *   2) 释放锁后再真正 sleep，让其他 task 能立刻进入步骤 1 预约自己的槽位。
         */
        let deadline = {
            let mut next_start = self.next_start.lock().await;
            let now = Instant::now();
            let start_at = if *next_start > now { *next_start } else { now };
            let deadline = start_at;
            *next_start = start_at + interval;
            deadline
        };

        let now = Instant::now();
        if deadline > now {
            let wait = deadline - now;
            tokio::select! {
                _ = cancellation.cancelled() => {
                    return false;
                }
                _ = tokio::time::sleep(wait) => {}
            }
        }

        !cancellation.is_cancelled()
    }
}

impl CfProbe {
    /// 普通批量扫描。
    ///
    /// 内部使用一个新的 CancellationToken。
    pub async fn scan(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
    ) -> Result<BatchResult, CfProbeError> {
        self.scan_with_cancel(targets, config, CancellationToken::new())
            .await
    }

    /// 带 CancellationToken 的批量扫描。
    ///
    /// 与 scan_unordered() 不同：
    ///
    /// 这个方法会等待 stream 完整消费，因此如果
    /// CancellationToken 被取消，当前已经进入执行的
    /// Target 会返回 Cancelled，尚未执行的 Target
    /// 也会很快被 execute_one() 消费并标记为 Cancelled。
    pub async fn scan_with_cancel(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
        cancellation: CancellationToken,
    ) -> Result<BatchResult, CfProbeError> {
        config.validate()?;

        validate_batch_size(targets.len(), config.max_targets)?;

        let total = targets.len();

        let started = Instant::now();

        let mut stream = self.scan_unordered_with_cancel(targets, config, cancellation)?;

        let mut items = Vec::with_capacity(total);

        while let Some(item) = stream.next().await {
            items.push(item);
        }

        /*
         * buffer_unordered() 是无序完成的。
         *
         * scan() 对外保证稳定输入顺序。
         */
        items.sort_by_key(|item| item.index);

        Ok(build_batch_result(items, started.elapsed()))
    }

    /// 无序流式 Batch。
    ///
    /// Target 按完成顺序返回。
    ///
    /// 调用者主动 drop Stream 后，尚未产生的结果
    /// 不会返回，这是 Stream API 的正常语义。
    pub fn scan_unordered(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
    ) -> Result<impl Stream<Item = BatchItemResult> + 'static, CfProbeError> {
        self.scan_unordered_with_cancel(targets, config, CancellationToken::new())
    }

    /// 带 CancellationToken 的无序流式 Batch。
    pub fn scan_unordered_with_cancel(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
        cancellation: CancellationToken,
    ) -> Result<impl Stream<Item = BatchItemResult> + 'static, CfProbeError> {
        config.validate()?;

        validate_batch_size(targets.len(), config.max_targets)?;

        let limiter = Arc::new(StartRateLimiter::new(config.requests_per_second));

        let probe = self.clone();

        let concurrency = config.concurrency;

        let target_timeout = config.target_timeout;

        let stream = stream::iter(targets.into_iter().enumerate())
            .map(move |(index, target)| {
                let probe = probe.clone();

                let limiter = limiter.clone();

                let cancellation = cancellation.clone();

                async move {
                    execute_one(probe, index, target, target_timeout, limiter, cancellation).await
                }
            })
            .buffer_unordered(concurrency);

        Ok(stream)
    }
}

/// 检查 Batch 大小。
fn validate_batch_size(actual: usize, max_targets: Option<usize>) -> Result<(), CfProbeError> {
    let Some(max_targets) = max_targets else {
        return Ok(());
    };

    if actual > max_targets {
        return Err(CfProbeError::InvalidResponse(format!(
            "batch contains {} targets, exceeding max_targets {}",
            actual, max_targets,
        )));
    }

    Ok(())
}

/// 执行单个 Target。
async fn execute_one(
    probe: CfProbe,

    index: usize,

    target: Target,

    target_timeout: Duration,

    limiter: Arc<StartRateLimiter>,

    cancellation: CancellationToken,
) -> BatchItemResult {
    let started = Instant::now();

    /*
     * 这里只做 Target 自身的结构校验：
     *
     * - hostname 非空
     * - hostname 合法
     * - port != 0
     *
     * 真正的 TargetPolicy / SSRF 校验
     * 仍然由 CfProbe::detect_with_cancel()
     * 统一执行。
     *
     * 因此不存在 CLI / Batch / API
     * 绕过 TargetPolicy 的问题。
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
     * Cancellation 优先级高于 RPS。
     */
    let can_start = limiter.wait(&cancellation).await;

    if !can_start {
        return BatchItemResult {
            index,

            target,

            status: BatchItemStatus::Cancelled,

            result: None,

            error: Some("batch was cancelled".to_string()),

            elapsed: started.elapsed(),
        };
    }

    /*
     * 外层 Target timeout。
     *
     * 这是整个：
     *
     * TargetPolicy
     * DNS
     * TLS
     * HTTP
     * Evidence
     *
     * 的最终保险。
     */
    let result = timeout(
        target_timeout,
        probe.detect_with_cancel(target.clone(), cancellation.clone()),
    )
    .await;

    let elapsed = started.elapsed();

    match result {
        /*
         * Target 完整完成。
         */
        Ok(Ok(result)) => BatchItemResult {
            index,

            target,

            status: BatchItemStatus::Completed,

            result: Some(result),

            error: None,

            elapsed,
        },

        /*
         * CfProbe 主动响应 cancellation。
         */
        Ok(Err(CfProbeError::Cancelled)) => BatchItemResult {
            index,

            target,

            status: BatchItemStatus::Cancelled,

            result: None,

            error: Some("batch was cancelled".to_string()),

            elapsed,
        },

        /*
         * 其他 Probe Error。
         */
        Ok(Err(error)) => BatchItemResult {
            index,

            target,

            status: BatchItemStatus::Failed,

            result: None,

            error: Some(error.to_string()),

            elapsed,
        },

        /*
         * 外层 Target timeout。
         *
         * 不等同于 Cancelled。
         */
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

/// 将单个 item 集合转换成 BatchResult。
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

    let cancelled = items
        .iter()
        .filter(|item| item.status == BatchItemStatus::Cancelled)
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

        cancelled,

        cloudflare,

        not_cloudflare,

        unknown,

        elapsed,

        items,
    }
}