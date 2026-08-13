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
        let cloudflare_http = reqwest::Client::builder()
            .user_agent("cfprobe/0.1")
            .timeout(std::time::Duration::from_secs(10))
            .no_proxy()
            .build()
            .map_err(CfProbeError::Http)?;

        let range_client = crate::CloudflareClient::new(cloudflare_http);

        let ranges = CloudflareRangeProvider::new(range_client)?;

        let dns = DnsDetector::new(config.dns_resolvers);

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
         * 2. Cloudflare ranges
         * -----------------------------------------
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

        /*
         * -----------------------------------------
         * 3. IP detection
         * -----------------------------------------
         */
        let ip_detection = ranges
            .as_ref()
            .map(|ranges| detect_cloudflare_ip(ranges, target.ip));

        /*
         * -----------------------------------------
         * 4. DNS
         * -----------------------------------------
         *
         * DNS must happen BEFORE TLS / HTTP.
         *
         * Why?
         *
         * Because DNS result is also part of SSRF
         * / DNS rebinding policy validation.
         */
        let dns = if let Some(ranges) = ranges.as_ref() {
            match cancellation
                .run_until_cancelled(self.dns.detect(&target.hostname, ranges))
                .await
            {
                Some(Ok(result)) => {
                    self.target_policy.validate_dns(&result)?;

                    Some(result)
                }

                Some(Err(error)) => {
                    errors.push(ProbeStageError {
                        stage: ProbeStage::Dns,

                        message: error.to_string(),
                    });

                    None
                }

                None => {
                    return Err(CfProbeError::Cancelled);
                }
            }
        } else {
            None
        };

        if cancellation.is_cancelled() {
            return Err(CfProbeError::Cancelled);
        }

        /*
         * -----------------------------------------
         * 5. TLS + HTTP
         * -----------------------------------------
         *
         * DNS policy validation已经完成，
         * 现在才开始主动网络连接。
         *
         * 两个任务并发执行。
         */
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

        let (tls_result, http_result) = join!(tls_future, http_future,);

        let tls = match tls_result {
            Some(Ok(result)) => Some(result),

            Some(Err(error)) => {
                errors.push(ProbeStageError {
                    stage: ProbeStage::Tls,

                    message: error.to_string(),
                });

                None
            }

            None => {
                return Err(CfProbeError::Cancelled);
            }
        };

        let http = match http_result {
            Some(Ok(result)) => Some(result),

            Some(Err(error)) => {
                errors.push(ProbeStageError {
                    stage: ProbeStage::Http,

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
