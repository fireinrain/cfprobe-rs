use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};

use serde::{Deserialize, Serialize};

use tokio_util::sync::CancellationToken;

use tracing::{error, info};

use uuid::Uuid;

use crate::{
    BatchResult, BatchScanConfig, CfProbe, CfProbeError, DetectionClassification, ProbeResult,
    Target,
};

/// HTTP API 服务配置。
///
/// # Default
///
/// - listen = `127.0.0.1:8080`
/// - api_key = `None`（但绑定到 `0.0.0.0` 时必须显式设置）
/// - max_body_bytes = 1 MiB
/// - max_batch_targets = 1000
/// - default_concurrency = 32
/// - default_target_timeout_ms = 30000
/// - default_requests_per_second = 无限制
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// 监听地址。
    pub listen: SocketAddr,

    /// Bearer API Key。如果绑定的是通配地址则必填（防误暴露）。
    pub api_key: Option<String>,

    /// 单请求最大 body 字节数。
    pub max_body_bytes: usize,

    /// `/scan` 接口单请求最大目标数。
    pub max_batch_targets: usize,

    /// 默认并发度（请求未显式指定时使用）。
    pub default_concurrency: usize,

    /// 默认单目标超时（毫秒）。
    pub default_target_timeout_ms: u64,

    /// 默认 RPS 限流，`None` 为不限。
    pub default_requests_per_second: Option<u32>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),

            api_key: None,

            max_body_bytes: 1024 * 1024,

            max_batch_targets: 1000,

            default_concurrency: 32,

            default_target_timeout_ms: 30_000,

            default_requests_per_second: None,
        }
    }
}

impl ServerConfig {
    /// 校验配置：非零参数、通配地址必须设置 API Key 等。
    pub fn validate(&self) -> Result<(), String> {
        if self.max_body_bytes == 0 {
            return Err("max_body_bytes cannot be 0".to_string());
        }

        if self.max_batch_targets == 0 {
            return Err("max_batch_targets cannot be 0".to_string());
        }

        if self.default_concurrency == 0 {
            return Err("default_concurrency cannot be 0".to_string());
        }

        if self.default_target_timeout_ms == 0 {
            return Err("default_target_timeout_ms cannot be 0".to_string());
        }

        if let Some(rps) = self.default_requests_per_second {
            if rps == 0 {
                return Err("default_requests_per_second cannot be 0".to_string());
            }
        }

        let wildcard = match self.listen.ip() {
            IpAddr::V4(ip) => ip.is_unspecified(),

            IpAddr::V6(ip) => ip.is_unspecified(),
        };

        /*
         * 防止用户直接启动：
         *
         * 0.0.0.0:8080
         *
         * 却没有任何 API 认证。
         */
        if wildcard && self.api_key.is_none() {
            return Err("an API key is required when binding to a wildcard address".to_string());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServerMetrics {
    requests_total: Arc<AtomicU64>,

    requests_failed: Arc<AtomicU64>,

    probe_requests_total: Arc<AtomicU64>,

    scan_requests_total: Arc<AtomicU64>,

    targets_total: Arc<AtomicU64>,

    targets_completed: Arc<AtomicU64>,

    targets_failed: Arc<AtomicU64>,

    targets_timed_out: Arc<AtomicU64>,

    targets_cancelled: Arc<AtomicU64>,

    cloudflare_total: Arc<AtomicU64>,

    not_cloudflare_total: Arc<AtomicU64>,

    unknown_total: Arc<AtomicU64>,

    in_flight: Arc<AtomicU64>,
}

impl ServerMetrics {
    fn on_request_start(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    fn on_request_end(&self) {
        /*
         * 理论上不会出现 underflow。
         *
         * 使用 fetch_update 更严格也可以，
         * 但当前请求生命周期是成对的。
         */
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    fn on_request_failed(&self) {
        self.requests_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn on_probe(&self, result: &ProbeResult) {
        self.probe_requests_total.fetch_add(1, Ordering::Relaxed);

        self.targets_total.fetch_add(1, Ordering::Relaxed);

        self.record_classification(result.detection.classification);
    }

    fn on_batch(&self, result: &BatchResult) {
        self.scan_requests_total.fetch_add(1, Ordering::Relaxed);

        self.targets_total
            .fetch_add(result.total as u64, Ordering::Relaxed);

        self.targets_completed
            .fetch_add(result.completed as u64, Ordering::Relaxed);

        self.targets_failed
            .fetch_add(result.failed as u64, Ordering::Relaxed);

        self.targets_timed_out
            .fetch_add(result.timed_out as u64, Ordering::Relaxed);

        self.targets_cancelled
            .fetch_add(result.cancelled as u64, Ordering::Relaxed);

        self.cloudflare_total
            .fetch_add(result.cloudflare as u64, Ordering::Relaxed);

        self.not_cloudflare_total
            .fetch_add(result.not_cloudflare as u64, Ordering::Relaxed);

        self.unknown_total
            .fetch_add(result.unknown as u64, Ordering::Relaxed);
    }

    fn record_classification(&self, classification: DetectionClassification) {
        match classification {
            DetectionClassification::Cloudflare => {
                self.cloudflare_total.fetch_add(1, Ordering::Relaxed);
            }

            DetectionClassification::NotCloudflare => {
                self.not_cloudflare_total.fetch_add(1, Ordering::Relaxed);
            }

            DetectionClassification::Unknown => {
                self.unknown_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn render_prometheus(&self) -> String {
        let requests_total = self.requests_total.load(Ordering::Relaxed);

        let requests_failed = self.requests_failed.load(Ordering::Relaxed);

        let probe_requests_total = self.probe_requests_total.load(Ordering::Relaxed);

        let scan_requests_total = self.scan_requests_total.load(Ordering::Relaxed);

        let targets_total = self.targets_total.load(Ordering::Relaxed);

        let targets_completed = self.targets_completed.load(Ordering::Relaxed);

        let targets_failed = self.targets_failed.load(Ordering::Relaxed);

        let targets_timed_out = self.targets_timed_out.load(Ordering::Relaxed);

        let targets_cancelled = self.targets_cancelled.load(Ordering::Relaxed);

        let cloudflare_total = self.cloudflare_total.load(Ordering::Relaxed);

        let not_cloudflare_total = self.not_cloudflare_total.load(Ordering::Relaxed);

        let unknown_total = self.unknown_total.load(Ordering::Relaxed);

        let in_flight = self.in_flight.load(Ordering::Relaxed);

        format!(
            "\
# TYPE cfprobe_requests_total counter
cfprobe_requests_total {requests_total}

# TYPE cfprobe_requests_failed_total counter
cfprobe_requests_failed_total {requests_failed}

# TYPE cfprobe_probe_requests_total counter
cfprobe_probe_requests_total {probe_requests_total}

# TYPE cfprobe_scan_requests_total counter
cfprobe_scan_requests_total {scan_requests_total}

# TYPE cfprobe_targets_total counter
cfprobe_targets_total {targets_total}

# TYPE cfprobe_targets_completed_total counter
cfprobe_targets_completed_total {targets_completed}

# TYPE cfprobe_targets_failed_total counter
cfprobe_targets_failed_total {targets_failed}

# TYPE cfprobe_targets_timed_out_total counter
cfprobe_targets_timed_out_total {targets_timed_out}

# TYPE cfprobe_targets_cancelled_total counter
cfprobe_targets_cancelled_total {targets_cancelled}

# TYPE cfprobe_cloudflare_total counter
cfprobe_cloudflare_total {cloudflare_total}

# TYPE cfprobe_not_cloudflare_total counter
cfprobe_not_cloudflare_total {not_cloudflare_total}

# TYPE cfprobe_unknown_total counter
cfprobe_unknown_total {unknown_total}

# TYPE cfprobe_requests_in_flight gauge
cfprobe_requests_in_flight {in_flight}
",
        )
    }
}

#[derive(Clone)]
struct AppState {
    probe: Arc<CfProbe>,

    metrics: ServerMetrics,

    api_key: Option<Arc<str>>,

    shutdown: CancellationToken,

    ready: Arc<AtomicBool>,

    config: ServerConfig,
}

#[derive(Debug, Deserialize)]
struct ProbeRequest {
    target: Target,
}

#[derive(Debug, Deserialize)]
struct ScanRequest {
    targets: Vec<Target>,

    concurrency: Option<usize>,

    target_timeout_ms: Option<u64>,

    requests_per_second: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,

    message: String,

    request_id: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct VersionResponse {
    name: &'static str,

    version: &'static str,
}

pub async fn serve(probe: CfProbe, config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    config
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;

    let address = config.listen;

    let shutdown = CancellationToken::new();

    let state = AppState {
        probe: Arc::new(probe),

        metrics: ServerMetrics::default(),

        api_key: config.api_key.as_deref().map(Arc::<str>::from),

        shutdown: shutdown.clone(),

        ready: Arc::new(AtomicBool::new(true)),

        config: config.clone(),
    };

    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/version", get(version));

    let protected = Router::new()
        .route("/metrics", get(metrics))
        .route("/v1/probe", post(probe_handler))
        .route("/v1/scan", post(scan_handler))
        .with_state(state.clone());

    let app = public
        .merge(protected)
        .layer(middleware::from_fn(request_id_middleware))
        .layer(DefaultBodyLimit::max(config.max_body_bytes))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(address).await?;

    info!(
        listen = %address,
        "cfprobe HTTP server started",
    );

    tokio::select! {
        result =
            axum::serve(
                listener,
                app,
            ) => {
                result?;
            }

        _ =
            shutdown_signal(
                shutdown.clone(),
            ) => {
                /*
                 * shutdown_signal() 已经调用：
                 *
                 * shutdown.cancel()
                 *
                 * 所以所有 child token 都会收到取消。
                 */
                info!(
                    "cfprobe HTTP server shutting down",
                );

                state.ready.store(
                    false,
                    Ordering::Relaxed,
                );
            }
    }

    Ok(())
}

async fn request_id_middleware(
    mut request: axum::extract::Request,

    next: axum::middleware::Next,
) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok().map(str::to_owned))
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    request.extensions_mut().insert(request_id.clone());

    let started = Instant::now();

    let method = request.method().clone();

    let uri = request.uri().clone();

    let mut response = next.run(request).await;

    let elapsed = started.elapsed();

    tracing::info!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        status = %response.status(),
        elapsed_ms =
            elapsed.as_millis() as u64,
        "http request",
    );

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    response
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    if state.ready.load(Ordering::Relaxed) {
        (StatusCode::OK, Json(HealthResponse { status: "ready" }))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "not_ready",
            }),
        )
    }
}

async fn version() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(VersionResponse {
            name: "cfprobe",

            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let request_id = get_request_id(&headers);

    if let Err(response) = authorize(&state, &headers, &request_id) {
        return response;
    }

    let body = state.metrics.render_prometheus();

    let mut response = Response::new(body.into());

    *response.status_mut() = StatusCode::OK;

    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    response
}

async fn probe_handler(
    State(state): State<AppState>,

    headers: HeaderMap,

    Json(request): Json<ProbeRequest>,
) -> Response {
    let request_id = get_request_id(&headers);

    if let Err(response) = authorize(&state, &headers, &request_id) {
        return response;
    }

    state.metrics.on_request_start();

    let guard = RequestMetricsGuard {
        metrics: state.metrics.clone(),
    };

    /*
     * Child token：
     *
     * Root cancellation
     *        ↓
     * Server token
     *        ↓
     * Request token
     */
    let request_cancel = state.shutdown.child_token();

    let result = tokio::select! {
        _ =
            request_cancel
                .cancelled()
        => {
            Err(
                CfProbeError::Cancelled,
            )
        }

        result =
            state
                .probe
                .detect_with_cancel(
                    request.target,
                    request_cancel.clone(),
                )
        => {
            result
        }
    };

    /*
     * 先把 Result 转换成 Response，
     * 再结束 metrics guard。
     *
     * 不再出现：
     *
     * match result { ... }
     * result
     *
     * 这种 moved-value 错误。
     */
    let response = match result {
        Ok(result) => {
            state.metrics.on_probe(&result);

            json_response(StatusCode::OK, &result, request_id)
        }

        Err(CfProbeError::TargetRejected { reason }) => {
            state.metrics.on_request_failed();

            json_error(StatusCode::FORBIDDEN, "target_rejected", reason, request_id)
        }

        Err(CfProbeError::Cancelled) => {
            state.metrics.on_request_failed();

            json_error(
                StatusCode::REQUEST_TIMEOUT,
                "cancelled",
                "probe was cancelled".to_string(),
                request_id,
            )
        }

        Err(error) => {
            state.metrics.on_request_failed();

            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "probe_failed",
                error.to_string(),
                request_id,
            )
        }
    };

    drop(guard);

    response
}

async fn scan_handler(
    State(state): State<AppState>,

    headers: HeaderMap,

    Json(request): Json<ScanRequest>,
) -> Response {
    let request_id = get_request_id(&headers);

    if let Err(response) = authorize(&state, &headers, &request_id) {
        return response;
    }

    state.metrics.on_request_start();

    let guard = RequestMetricsGuard {
        metrics: state.metrics.clone(),
    };

    /*
     * 每个 HTTP 请求拥有自己的 child token。
     */
    let request_cancel = state.shutdown.child_token();

    if request.targets.is_empty() {
        state.metrics.on_request_failed();

        drop(guard);

        return json_error(
            StatusCode::BAD_REQUEST,
            "empty_targets",
            "targets cannot be empty".to_string(),
            request_id,
        );
    }

    if request.targets.len() > state.config.max_batch_targets {
        state.metrics.on_request_failed();

        drop(guard);

        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_many_targets",
            format!(
                "maximum targets per request is {}",
                state.config.max_batch_targets,
            ),
            request_id,
        );
    }

    /*
     * 这里进行结构级验证。
     *
     * TargetPolicy / SSRF 验证仍然由
     * CfProbe::detect_with_cancel()
     * 统一执行。
     */
    for target in &request.targets {
        if let Err(error) = target.validate() {
            state.metrics.on_request_failed();

            drop(guard);

            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                error.to_string(),
                request_id,
            );
        }
    }

    let concurrency = request
        .concurrency
        .unwrap_or(state.config.default_concurrency);

    let timeout = request
        .target_timeout_ms
        .unwrap_or(state.config.default_target_timeout_ms);

    let batch_config = BatchScanConfig::default()
        .with_concurrency(concurrency)
        .with_target_timeout(std::time::Duration::from_millis(timeout))
        .with_requests_per_second(
            request
                .requests_per_second
                .or(state.config.default_requests_per_second),
        )
        .with_max_targets(Some(state.config.max_batch_targets));

    let result = tokio::select! {
        _ =
            request_cancel
                .cancelled()
        => {
            Err(
                CfProbeError::Cancelled,
            )
        }

        result =
            state
                .probe
                .scan_with_cancel(
                    request.targets,
                    batch_config,
                    request_cancel.clone(),
                )
        => {
            result
        }
    };

    let response = match result {
        Ok(result) => {
            state.metrics.on_batch(&result);

            json_response(StatusCode::OK, &result, request_id)
        }

        Err(CfProbeError::Cancelled) => {
            state.metrics.on_request_failed();

            json_error(
                StatusCode::REQUEST_TIMEOUT,
                "cancelled",
                "scan was cancelled".to_string(),
                request_id,
            )
        }

        Err(CfProbeError::TargetRejected { reason }) => {
            state.metrics.on_request_failed();

            json_error(StatusCode::FORBIDDEN, "target_rejected", reason, request_id)
        }

        Err(error) => {
            state.metrics.on_request_failed();

            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan_failed",
                error.to_string(),
                request_id,
            )
        }
    };

    drop(guard);

    response
}

fn authorize(state: &AppState, headers: &HeaderMap, request_id: &str) -> Result<(), Response> {
    let Some(expected) = state.api_key.as_deref() else {
        return Ok(());
    };

    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()))
        .unwrap_or(false)
        || headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .map(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);

    if authorized {
        Ok(())
    } else {
        Err(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "valid API credentials are required".to_string(),
            request_id.to_string(),
        ))
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0u8;

    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }

    difference == 0
}

fn get_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

fn json_response<T>(status: StatusCode, value: &T, request_id: String) -> Response
where
    T: Serialize,
{
    let mut response = (status, Json(value)).into_response();

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    response
}

fn json_error(
    status: StatusCode,

    code: &'static str,

    message: String,

    request_id: String,
) -> Response {
    json_response(
        status,
        &ErrorResponse {
            error: ErrorBody {
                code,

                message,

                request_id: request_id.clone(),
            },
        },
        request_id,
    )
}

struct RequestMetricsGuard {
    metrics: ServerMetrics,
}

impl Drop for RequestMetricsGuard {
    fn drop(&mut self) {
        self.metrics.on_request_end();
    }
}

async fn shutdown_signal(token: CancellationToken) {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(
                %error,
                "failed to install Ctrl-C handler",
            );
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }

            Err(error) => {
                error!(
                    %error,
                    "failed to install SIGTERM handler",
                );
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ =
            ctrl_c => {}

        _ =
            terminate => {}

        _ =
            token.cancelled() => {}
    }

    /*
     * 这里才真正取消 Root token。
     *
     * 所有 child_token() 都会收到取消。
     */
    token.cancel();
}
