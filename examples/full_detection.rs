use std::net::IpAddr;
use std::sync::Arc;

use cfprobe::{
    CloudflareClient, CloudflareRangeProvider, CloudflareWebProxyV1, DnsDetector, DnsResolverEntry,
    EvidenceEngine, EvidenceInput, HickoryDnsResolver, HttpProbeConfig, HttpProber, HttpScheme,
    TlsProbeConfig, TlsProber,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --------------------------------------------------
    // 1. Target
    // --------------------------------------------------

    let ip: IpAddr = "104.16.77.250".parse()?;

    let hostname = "example.com";

    println!("Target: {} + {}", ip, hostname);

    // --------------------------------------------------
    // 2. Cloudflare IP Range Provider
    // --------------------------------------------------

    let http_client = reqwest::Client::builder()
        .user_agent("cfprobe-example/0.1")
        .build()?;

    let cloudflare_client = CloudflareClient::new(http_client);

    let range_provider = CloudflareRangeProvider::new(cloudflare_client)?;

    let cloudflare_ip_detection = range_provider.contains(ip).await?;

    println!();
    println!("[IP] {:?}", cloudflare_ip_detection);

    // --------------------------------------------------
    // 3. DNS
    // --------------------------------------------------

    let dns_resolver = HickoryDnsResolver::system()?;

    let dns_detector = DnsDetector::new(vec![DnsResolverEntry {
        name: "system".to_string(),

        resolver: Arc::new(dns_resolver),
    }]);

    let cloudflare_ranges = range_provider.load().await?;

    let dns_detection = dns_detector.detect(hostname, &cloudflare_ranges).await?;

    println!();
    println!("[DNS] {:?}", dns_detection);

    // --------------------------------------------------
    // 4. TLS
    // --------------------------------------------------

    let tls_config = TlsProbeConfig {
        port: 443,

        ..TlsProbeConfig::default()
    };

    let tls_prober = TlsProber::new(tls_config);

    let tls_detection = tls_prober.probe(ip, hostname).await?;

    println!();
    println!("[TLS] {:?}", tls_detection);

    // --------------------------------------------------
    // 5. HTTP
    // --------------------------------------------------

    let http_config = HttpProbeConfig {
        scheme: HttpScheme::Https,

        port: 443,

        ..HttpProbeConfig::default()
    };

    let http_prober = HttpProber::new(http_config)?;

    let http_detection = http_prober.probe(ip, hostname).await?;

    println!();
    println!("[HTTP] {:?}", http_detection);

    // --------------------------------------------------
    // 6. Evidence Engine
    // --------------------------------------------------
    let engine = EvidenceEngine::new(Arc::new(CloudflareWebProxyV1::default()));

    let result = engine.evaluate(EvidenceInput::with_host(
        ip,
        hostname,
        Some(&cloudflare_ip_detection),
        Some(&dns_detection),
        Some(&tls_detection),
        Some(&http_detection),
    ));

    // --------------------------------------------------
    // 7. Final result
    // --------------------------------------------------

    println!();
    println!("========================================");
    println!("FINAL RESULT");
    println!("========================================");

    println!("Classification : {:?}", result.classification);

    println!("Confidence     : {:.2}", result.confidence);

    println!("ConfidenceLevel: {:?}", result.confidence_level);

    println!("Score          : {}", result.score);

    println!("Positive       : {}", result.positive_evidence_count);

    println!("Negative       : {}", result.negative_evidence_count);

    println!();

    println!("Summary:");

    println!("{}", result.summary);

    println!();

    println!("Evidence:");

    for item in &result.evidence {
        println!(
            "- [{:?}] {:?} score={} {}",
            item.category, item.kind, item.score, item.reason
        );
    }

    println!();

    println!("JSON:");

    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}
