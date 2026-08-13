use std::sync::Arc;

use tokio::join;

use tokio_util::sync::CancellationToken;

use crate::{
    CfProbeError, CloudflareRangeProvider, DetectionClassification, DnsDetector, EvidenceEngine,
    EvidenceInput, HttpProber, TlsProber, detect_cloudflare_ip,
};

use super::{CfProbeConfig, ProbeResult, ProbeStage, ProbeStageError, Target};

#[derive(Clone)]
pub struct CfProbe {
    ranges: Arc<CloudflareRangeProvider>,

    dns: Arc<DnsDetector>,

    tls: Arc<TlsProber>,

    http: Arc<HttpProber>,

    evidence: Arc<EvidenceEngine>,

    target_policy: Arc<crate::TargetPolicy>,

    require_cloudflare_ranges: bool,
}

impl CfProbe {
    pub async fn new(config: CfProbeConfig) -> Result<Self, CfProbeError> {
        crate::init_rustls_crypto();

        let cloudflare_http = reqwest::Client::builder()
            .user_agent("cfprobe/0.1")
            .timeout(config.cloudflare_http_timeout)
            .no_proxy()
            .build()
            .map_err(CfProbeError::Http)?;

        let range_client = crate::CloudflareClient::new(cloudflare_http);

        let ranges = CloudflareRangeProvider::new(range_client)?;

        let dns = if let Some(cache) = config.dns_cache {
            DnsDetector::new(config.dns_resolvers).with_cache(cache)
        } else {
            DnsDetector::new(config.dns_resolvers)
        };

        let tls = TlsProber::new(config.tls);

        let http = HttpProber::new(config.http)?;

        let evidence = EvidenceEngine::new(config.policy);

        Ok(Self {
            ranges: Arc::new(ranges),

            dns: Arc::new(dns),

            tls: Arc::new(tls),

            http: Arc::new(http),

            evidence: Arc::new(evidence),

            target_policy: config.target_policy,

            require_cloudflare_ranges: config.require_cloudflare_ranges,
        })
    }

    /// 普通单目标检测。
    ///
    /// 内部自动创建一个 CancellationToken。
    pub async fn detect(&self, target: Target) -> Result<ProbeResult, CfProbeError> {
        self.detect_with_cancel(target, CancellationToken::new())
            .await
    }

    /// 可取消的单目标检测。
    ///
    /// Server / Batch / 上层任务都应该优先调用这个 API。
    pub async fn detect_with_cancel(
        &self,
        target: Target,
        cancellation: CancellationToken,
    ) -> Result<ProbeResult, CfProbeError> {
        /*
         * -----------------------------------------
         * 0. Cancellation
         * -----------------------------------------
         */
        if cancellation.is_cancelled() {
            return Err(CfProbeError::Cancelled);
        }

        /*
         * -----------------------------------------
         * 1. Static Target Policy
         * -----------------------------------------
         *
         * 必须在任何 DNS/TLS/HTTP 操作之前执行。
         */
        self.target_policy.validate_target(&target)?;

        if cancellation.is_cancelled() {
            return Err(CfProbeError::Cancelled);
        }

        let mut errors = Vec::new();

        /*
         * -----------------------------------------
         * Phase A: Cloudflare ranges.load()
         * -----------------------------------------
         *
         * 必须先完成，因为：
         *   - ip_detection 需要它
         *   - dns.detect() 参数签名里就要它
         */
        let ranges = match cancellation.run_until_cancelled(self.ranges.load()).await {
            Some(Ok(ranges)) => Some(ranges),

            Some(Err(error)) => {
                errors.push(ProbeStageError {
                    stage: ProbeStage::CloudflareRanges,

                    message: error.to_string(),
                });

                None
            }

            None => {
                return Err(CfProbeError::Cancelled);
            }
        };

        if cancellation.is_cancelled() {
            return Err(CfProbeError::Cancelled);
        }

        let ip_detection = ranges
            .as_ref()
            .map(|ranges| detect_cloudflare_ip(ranges, target.ip));

        /*
         * -----------------------------------------
         * Phase B: DNS + TLS + HTTP 三者并发
         * -----------------------------------------
         *
         * 关键性能优化：
         * TLS/HTTP 连接使用的是用户给定的 target.ip（不是 DNS 解析出的 IP），
         * 因此完全不需要等 DNS SSRF 校验完成才建立连接。
         * 三件事同时跑，总时间 = max(DNS, TLS, HTTP)，而不是相加。
         */
        let dns_future = async {
            if let Some(ranges) = ranges.as_ref() {
                match cancellation
                    .run_until_cancelled(self.dns.detect(&target.hostname, ranges))
                    .await
                {
                    Some(Ok(result)) => {
                        match self.target_policy.validate_dns(&result) {
                            Ok(()) => Some(Ok(Some(result))),
                            // SSRF / policy 违规直接作为致命错误传回，外层 ? 中止
                            Err(policy_error) => Some(Err(policy_error)),
                        }
                    }
                    Some(Err(error)) => Some(Err(CfProbeError::Dns {
                        message: error.to_string(),
                    })),
                    None => None,
                }
            } else {
                Some(Ok(None))
            }
        };

        let tls_future = async {
            cancellation
                .run_until_cancelled(self.tls.probe_with_port(
                    target.ip,
                    &target.hostname,
                    target.port,
                ))
                .await
        };

        let http_future = async {
            cancellation
                .run_until_cancelled(self.http.probe_with_target_params(
                    target.ip,
                    &target.hostname,
                    target.scheme,
                    target.port,
                ))
                .await
        };

        let (dns_result, tls_result, http_result) = join!(dns_future, tls_future, http_future);

        /* ---- unpack dns ---- */
        let dns = match dns_result {
            Some(Ok(Some(result))) => Some(result),
            Some(Ok(None)) => None,
            // Dns 自身错误（超时、解析失败）→ 记日志，继续其它阶段
            Some(Err(CfProbeError::Dns { message })) => {
                errors.push(ProbeStageError {
                    stage: ProbeStage::Dns,
                    message,
                });
                None
            }
            // SSRF / TargetPolicy 违规 / 其他致命错误 → 立即中止
            Some(Err(fatal)) => return Err(fatal),
            None => return Err(CfProbeError::Cancelled),
        };

        /* ---- unpack tls ---- */
        let tls = match tls_result {
            Some(Ok(result)) => Some(result),
            Some(Err(error)) => {
                errors.push(ProbeStageError {
                    stage: ProbeStage::Tls,
                    message: error.to_string(),
                });
                None
            }
            None => return Err(CfProbeError::Cancelled),
        };

        /* ---- unpack http ---- */
        let http = match http_result {
            Some(Ok(result)) => Some(result),
            Some(Err(error)) => {
                errors.push(ProbeStageError {
                    stage: ProbeStage::Http,
                    message: error.to_string(),
                });
                None
            }
            None => return Err(CfProbeError::Cancelled),
        };

        if cancellation.is_cancelled() {
            return Err(CfProbeError::Cancelled);
        }

        /*
         * -----------------------------------------
         * 6. Evidence
         * -----------------------------------------
         */
        let mut detection = self.evidence.evaluate(EvidenceInput::with_host(
            target.ip,
            &target.hostname,
            ip_detection.as_ref(),
            dns.as_ref(),
            tls.as_ref(),
            http.as_ref(),
        ));

        /*
         * -----------------------------------------
         * 7. Cloudflare range is foundational.
         * -----------------------------------------
         */
        if ranges.is_none() && self.require_cloudflare_ranges {
            detection.classification = DetectionClassification::Unknown;
            detection.confidence = 0.0;
            detection.confidence_level = crate::ConfidenceLevel::Insufficient;
            detection.summary =
                "Cloudflare IP range data was unavailable; final classification was forced to Unknown"
                    .to_string();
            errors.push(ProbeStageError {
                stage: ProbeStage::Evidence,
                message: "foundational Cloudflare IP range data unavailable".to_string(),
            });
        }

        if cancellation.is_cancelled() {
            return Err(CfProbeError::Cancelled);
        }

        Ok(ProbeResult {
            ip: target.ip,
            hostname: target.hostname.clone(),
            port: target.port,
            target,
            ip_detection,
            dns,
            tls,
            http,
            detection,
            errors,
        })
    }
}