use std::sync::Arc;

use crate::{
    CfProbeError, CloudflareRangeProvider, DnsDetector, EvidenceEngine, EvidenceInput, HttpProber,
    TlsProber, detect_cloudflare_ip,
};

use super::{CfProbeConfig, ProbeResult, ProbeStage, ProbeStageError, Target};

#[derive(Clone)]
pub struct CfProbe {
    ranges: Arc<CloudflareRangeProvider>,

    dns: Arc<DnsDetector>,

    tls: Arc<TlsProber>,

    http: Arc<HttpProber>,

    evidence: Arc<EvidenceEngine>,

    require_cloudflare_ranges: bool,
}

impl CfProbe {
    pub async fn new(config: CfProbeConfig) -> Result<Self, CfProbeError> {
        /*
         * One HTTP client / provider for the entire
         * lifetime of CfProbe.
         *
         * CloudflareRangeProvider itself owns the
         * memory + disk cache.
         */
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

            require_cloudflare_ranges: config.require_cloudflare_ranges,
        })
    }

    pub async fn detect(&self, target: Target) -> Result<ProbeResult, CfProbeError> {
        target.validate()?;

        let mut errors = Vec::new();

        /*
         * -----------------------------------------
         * 1. Load Cloudflare ranges
         * -----------------------------------------
         */
        let ranges = match self.ranges.load().await {
            Ok(ranges) => Some(ranges),

            Err(error) => {
                errors.push(ProbeStageError {
                    stage: ProbeStage::CloudflareRanges,

                    message: error.to_string(),
                });

                None
            }
        };

        /*
         * -----------------------------------------
         * 2. IP detection
         * -----------------------------------------
         */
        let ip_detection = ranges
            .as_ref()
            .map(|ranges| detect_cloudflare_ip(ranges, target.ip));

        /*
         * -----------------------------------------
         * 3. DNS + TLS + HTTP
         *
         * They are independent once the target
         * has been validated.
         *
         * Run them concurrently.
         * -----------------------------------------
         */

        let dns_future = async {
            let Some(ranges) = ranges.as_ref() else {
                return None;
            };

            match self.dns.detect(&target.hostname, ranges).await {
                Ok(result) => Some(result),

                Err(error) => {
                    errors.push(ProbeStageError {
                        stage: ProbeStage::Dns,

                        message: error.to_string(),
                    });

                    None
                }
            }
        };

        let tls_future = self.tls.probe(target.ip, &target.hostname);

        let http_future = self.http.probe(target.ip, &target.hostname);

        let (dns_result, tls_result, http_result) =
            tokio::join!(dns_future, tls_future, http_future,);

        /*
         * TLS/HTTP detector failures are normally
         * represented by their own result types.
         *
         * Keep those results even if their internal
         * status is failed, because they are valuable
         * diagnostic information.
         */
        let tls = match tls_result {
            Ok(result) => Some(result),

            Err(error) => {
                errors.push(ProbeStageError {
                    stage: ProbeStage::Tls,

                    message: error.to_string(),
                });

                None
            }
        };

        let http = match http_result {
            Ok(result) => Some(result),

            Err(error) => {
                errors.push(ProbeStageError {
                    stage: ProbeStage::Http,

                    message: error.to_string(),
                });

                None
            }
        };

        /*
         * DNS future above already produced a partial
         * result or an error.
         */
        let dns = dns_result;

        /*
         * -----------------------------------------
         * 4. Evidence Engine
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
         * 5. Safety rule:
         *
         * Cloudflare IP range data is foundational
         * for CloudflareWebProxyV1.
         *
         * If it cannot be loaded and the config says
         * it is required, force the final result to
         * Unknown instead of allowing a CF-Ray header
         * alone to create a strong classification.
         * -----------------------------------------
         */
        if ranges.is_none() && self.require_cloudflare_ranges {
            detection.classification = crate::DetectionClassification::Unknown;

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
