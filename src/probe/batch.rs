use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{Stream, StreamExt, stream};

use tokio::sync::Mutex;
use tokio::time::timeout;

use tokio_util::sync::CancellationToken;

use serde::Serialize;

use crate::{CfProbeError, DetectionClassification};

use super::{CfProbe, ProbeResult, Target};

#[derive(Debug, Clone)]
pub struct BatchScanConfig {
    pub concurrency: usize,

    pub target_timeout: Duration,

    pub requests_per_second: Option<u32>,

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BatchItemStatus {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchItemResult {
    pub index: usize,

    pub target: Target,

    pub status: BatchItemStatus,

    pub result: Option<ProbeResult>,

    pub error: Option<String>,

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

        let mut next_start = self.next_start.lock().await;

        let now = Instant::now();

        if *next_start > now {
            tokio::time::sleep(*next_start - now).await;
        }

        *next_start = Instant::now() + interval;
    }
}

impl CfProbe {
    pub async fn scan(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
    ) -> Result<BatchResult, CfProbeError> {
        self.scan_with_cancel(targets, config, CancellationToken::new())
            .await
    }

    pub async fn scan_with_cancel(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
        cancellation: CancellationToken,
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

        let mut stream = self.scan_unordered_with_cancel(targets, config, cancellation)?;

        let mut items = Vec::with_capacity(total);

        while let Some(item) = stream.next().await {
            items.push(item);
        }

        items.sort_by_key(|item| item.index);

        Ok(build_batch_result(items, started.elapsed()))
    }

    pub fn scan_unordered(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
    ) -> Result<impl Stream<Item = BatchItemResult> + 'static, CfProbeError> {
        self.scan_unordered_with_cancel(targets, config, CancellationToken::new())
    }

    pub fn scan_unordered_with_cancel(
        &self,
        targets: Vec<Target>,
        config: BatchScanConfig,
        cancellation: CancellationToken,
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

async fn execute_one(
    probe: CfProbe,

    index: usize,

    target: Target,

    target_timeout: Duration,

    limiter: Arc<StartRateLimiter>,

    cancellation: CancellationToken,
) -> BatchItemResult {
    let started = Instant::now();

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

    tokio::select! {
        _ = cancellation.cancelled() => {
            return BatchItemResult {
                index,
                target,
                status:
                    BatchItemStatus::Cancelled,
                result: None,
                error:
                    Some(
                        "batch was cancelled"
                            .to_string(),
                    ),
                elapsed:
                    started.elapsed(),
            };
        }

        _ = limiter.wait() => {}
    }

    let result = tokio::select! {
        _ = cancellation.cancelled() => {
            return BatchItemResult {
                index,
                target,
                status:
                    BatchItemStatus::
                        Cancelled,
                result: None,
                error:
                    Some(
                        "batch was cancelled"
                            .to_string(),
                    ),
                elapsed:
                    started.elapsed(),
            };
        }

        result =
            timeout(
                target_timeout,
                probe.detect(
                    target.clone(),
                ),
            ) => {
            result
        }
    };

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
