use std::net::IpAddr;
use std::sync::Arc;

use cfprobe::{
    CfProbe, CfProbeConfig, CloudflareWebProxyV1, DetectionClassification, DetectionPolicy,
    HttpProbeConfig, HttpScheme, Target, TlsProbeConfig,
};

#[test]
fn https_target_uses_443() {
    let target = Target::https("104.16.1.1".parse::<IpAddr>().unwrap(), "example.com");

    assert_eq!(target.port, 443);

    assert_eq!(target.scheme, HttpScheme::Https);

    assert!(target.validate().is_ok());
}

#[test]
fn http_target_uses_80() {
    let target = Target::http("104.16.1.1".parse::<IpAddr>().unwrap(), "example.com");

    assert_eq!(target.port, 80);

    assert_eq!(target.scheme, HttpScheme::Http);
}

#[test]
fn target_can_override_port() {
    let target =
        Target::https("104.16.1.1".parse::<IpAddr>().unwrap(), "example.com").with_port(8443);

    assert_eq!(target.port, 8443);
}

#[test]
fn invalid_target_is_rejected() {
    let target = Target::https("104.16.1.1".parse::<IpAddr>().unwrap(), "");

    assert!(target.validate().is_err());
}

#[test]
fn config_accepts_custom_policy() {
    let policy: Arc<dyn DetectionPolicy> = Arc::new(CloudflareWebProxyV1::default());

    let config = CfProbeConfig::new(policy, Vec::new())
        .with_tls_config(TlsProbeConfig::default())
        .with_http_config(HttpProbeConfig::default());

    assert!(config.require_cloudflare_ranges);
}

#[tokio::test]
async fn test_probe_one_way() -> Result<(), Box<dyn std::error::Error>> {
    let probe = CfProbe::new(CfProbeConfig::cloudflare_web_proxy_v1()?).await?;

    let result = probe
        .detect(Target::https("104.16.1.1".parse()?, "example.com"))
        .await?;

    match result.detection.classification {
        DetectionClassification::Cloudflare => {
            println!("Cloudflare");
        }

        DetectionClassification::NotCloudflare => {
            println!("Not Cloudflare");
        }

        DetectionClassification::Unknown => {
            println!("Unknown");
        }
    }

    Ok(())
}
