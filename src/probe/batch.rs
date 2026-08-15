use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{Stream, StreamExt, stream};

use serde::Serialize;

use tokio::sync::Mutex;
use tokio::time::timeout;

use tokio_util::sync::CancellationToken;

use crate::{CfProbeError, DetectionClassification};

use super::{CfProbe, ProbeResult, Target};

/// 批量扫描配置：并发度、单目标超时、RPS 限流、容量上限。
///
/// # Default
///
/// ```text
/// concurrency           = 32
/// target_timeout        = 30s
/// requests_per_second   = 无限制
/// max_targets           = 无限制
/// ```
#[derive(Debug, Clone)]
pub struct BatchScanConfig {
    /// 同时执行的 Target 数量。
    ///
    /// 每个 Target 内部还会并发进行 DNS / TLS / HTTP 三路探测，
    /// 因此实际"飞"中的连接数约为 `concurrency × (1 + 解析器数 + 1 + 1)`，
    /// 请按出口带宽与 fd 上限谨慎设置。
    pub concurrency: usize,

    /// 单个 Target 的总超时（包含所有阶段）。超过后该目标置为 `TimedOut`，不影响其他目标。
    pub target_timeout: Duration,

    /// 每秒最多启动多少个新 Target。`None` 表示不限制启动速率。
    ///
    /// 用于公网批量扫描时控制对端压力。实现为"预约式 sleep + 解锁再等待"，
    /// 不会因持锁 sleep 导致所有任务串行。
    pub requests_per_second: Option<u32>,

    /// 本次 Batch 允许的最大 Target 数量。`None` 表示不限制。
    ///
    /// 用于防止误输入超大文件把内存打爆。
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
    /// 校验配置合法性（并发度非零、超时非零等）。
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

    /// 链式设置并发度。
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;

        self
    }

    /// 链式设置单目标总超时。
    pub fn with_target_timeout(mut self, timeout: Duration) -> Self {
        self.target_timeout = timeout;

        self
    }

    /// 链式设置 RPS 启动限流（`None` 为不限）。
    pub fn with_requests_per_second(mut self, rps: Option<u32>) -> Self {
        self.requests_per_second = rps;

        self
    }

    /// 链式设置本次 Batch 的最大目标数上限（`None` 为不限）。
    pub fn with_max_targets(mut self, max_targets: Option<usize>) -> Self {
        self.max_targets = max_targets;

        self
    }
}

/// 批量扫描中单项目的执行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BatchItemStatus {
    /// 探测成功完成。
    Completed,

    /// 探测执行中发生错误（非超时 / 非取消）。
    Failed,

    /// 单目标执行超过 `BatchScanConfig.target_timeout`。
    TimedOut,

    /// 由 `CancellationToken` 主动取消。
    Cancelled,
}

/// 批量扫描中单个目标的结果。
#[derive(Debug, Clone, Serialize)]
pub struct BatchItemResult {
    /// 目标在原始输入切片中的下标（用于恢复输入顺序）。
    pub index: usize,

    /// 原始目标定义。
    pub target: Target,

    /// 执行状态。
    pub status: BatchItemStatus,

    /// 仅当 `status == Completed` 时有值。
    pub result: Option<ProbeResult>,

    /// 失败 / 超时 / 取消时的可读错误信息。
    pub error: Option<String>,

    /// 本目标从启动到完成的真实耗时。
    pub elapsed: Duration,
}

impl BatchItemResult {
    /// `status == Completed` 的快捷判断。
    pub fn is_completed(&self) -> bool {
        self.status == BatchItemStatus::Completed
    }

    /// `status == Failed` 的快捷判断。
    pub fn is_failed(&self) -> bool {
        self.status == BatchItemStatus::Failed
    }

    /// `status == TimedOut` 的快捷判断。
    pub fn is_timed_out(&self) -> bool {
        self.status == BatchItemStatus::TimedOut
    }

    /// `status == Cancelled` 的快捷判断。
    pub fn is_cancelled(&self) -> bool {
        self.status == BatchItemStatus::Cancelled
    }

    /// 快捷取出最终分类（仅 `Completed` 时有值）。
    pub fn classification(&self) -> Option<DetectionClassification> {
        self.result
            .as_ref()
            .map(|result| result.detection.classification)
    }
}

/// 整个批量扫描的汇总结果。
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    /// 总目标数。
    pub total: usize,

    /// 探测成功完成的数量。
    pub completed: usize,

    /// 探测失败的数量（不含超时 / 取消）。
    pub failed: usize,

    /// 单目标超时数量。
    pub timed_out: usize,

    /// 被取消的数量。
    pub cancelled: usize,

    /// Completed 中判定为 Cloudflare 的数量。
    pub cloudflare: usize,

    /// Completed 中判定为 NotCloudflare 的数量。
    pub not_cloudflare: usize,

    /// Completed 中判定为 Unknown 的数量。
    pub unknown: usize,

    /// 整个 batch 从启动到收集完毕的耗时。
    pub elapsed: Duration,

    /// 所有单项结果；[`scan()`](CfProbe::scan) 保证按输入顺序排列，
    /// 而 `scan_unordered()` 返回的 Stream 是完成顺序。
    pub items: Vec<BatchItemResult>,
}

impl BatchResult {
    /// 成功率：`completed / total`。
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }

        self.completed as f64 / self.total as f64
    }

    /// 已完成目标中 Cloudflare 所占比例：`cloudflare / completed`。
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
    /// 等待全部目标完成，按**输入顺序**返回汇总结果。
    ///
    /// 内部创建独立的 `CancellationToken`；如需外部取消请用
    /// [`scan_with_cancel`](Self::scan_with_cancel)。
    pub async fn scan(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
    ) -> Result<BatchResult, CfProbeError> {
        self.scan_with_cancel(targets, config, CancellationToken::new())
            .await
    }

    /// 可取消版本的 [`scan()`](Self::scan)。
    ///
    /// `CancellationToken` 被触发时，尚未启动的目标会立即置为 `Cancelled`，
    /// 已在执行中的目标会在各阶段检查点尽快退出并返回 `Cancelled`。
    /// 返回结果中 `items` 仍按输入顺序排序。
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

    /// 以 Stream 形式按**完成顺序**返回单项结果（不等待全部完成）。
    ///
    /// 适合边扫描边落盘或驱动进度 UI。内部自动新建 `CancellationToken`，
    /// 若需外部取消请使用 [`scan_unordered_with_cancel`](Self::scan_unordered_with_cancel)。
    ///
    /// 注意：调用者 drop Stream 后未消费的结果不会再产生，这是 Stream 的常规语义。
    pub fn scan_unordered(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
    ) -> Result<impl Stream<Item = BatchItemResult> + 'static, CfProbeError> {
        self.scan_unordered_with_cancel(targets, config, CancellationToken::new())
    }

    /// 可取消版本的 [`scan_unordered()`](Self::scan_unordered)。
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
