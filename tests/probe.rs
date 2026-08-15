use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use cfprobe::{
    CfProbe, CfProbeConfig, CloudflareWebProxyV1, DetectionClassification, DetectionPolicy,
    DnsResolverEntry, HickoryDnsResolver, HttpProbeConfig, HttpScheme, Target, TlsProbeConfig,
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
// #[ignore = "slow integration test; requires real internet access to Cloudflare IP ranges + DNS"]
async fn test_probe_one_way() -> Result<(), Box<dyn std::error::Error>> {
    let mut tls = TlsProbeConfig::default();
    tls.timeout = Duration::from_secs(2);

    let mut http = HttpProbeConfig::default();
    http.connect_timeout = Duration::from_millis(800);
    http.timeout = Duration::from_secs(2);

    let resolver = HickoryDnsResolver::system_with_timeouts(Duration::from_secs(2), 1)?;

    let config = CfProbeConfig::new(
        Arc::new(CloudflareWebProxyV1::default()),
        vec![DnsResolverEntry::new("system", Arc::new(resolver))],
    )
    .with_cloudflare_http_timeout(Duration::from_secs(3))
    .with_tls_config(tls)
    .with_http_config(http);

    let probe = CfProbe::new(config).await?;

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
