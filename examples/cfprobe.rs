use std::net::IpAddr;

use cfprobe::{CfProbe, CfProbeConfig, Target};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /*
     * ------------------------------------------------
     * 1. Create a long-lived detector
     * ------------------------------------------------
     *
     * DNS resolver / Cloudflare cache / HTTP client /
     * TLS config are initialized only once.
     */
    let config = CfProbeConfig::cloudflare_web_proxy_v1()?;

    let probe = CfProbe::new(config).await?;

    /*
     * ------------------------------------------------
     * 2. Target
     * ------------------------------------------------
     */
    let target = Target::https("104.16.77.250".parse::<IpAddr>()?, "example.com");

    /*
     * ------------------------------------------------
     * 3. Detect
     * ------------------------------------------------
     */
    let result = probe.detect(target).await?;

    /*
     * ------------------------------------------------
     * 4. Simple result
     * ------------------------------------------------
     */
    println!("Cloudflare: {}", result.is_cloudflare());

    println!("Classification: {:?}", result.detection.classification);

    println!("Confidence: {:.2}", result.detection.confidence);

    println!("Score: {}", result.detection.score);

    /*
     * ------------------------------------------------
     * 5. Stage results
     * ------------------------------------------------
     */
    println!();
    println!("IP: {:?}", result.ip_detection);

    println!("DNS: {:?}", result.dns);

    println!("TLS: {:?}", result.tls);

    println!("HTTP: {:?}", result.http);

    /*
     * ------------------------------------------------
     * 6. Errors
     * ------------------------------------------------
     */
    if !result.errors.is_empty() {
        println!();
        println!("Stage errors:");

        for error in &result.errors {
            println!("- {:?}: {}", error.stage, error.message);
        }
    }

    /*
     * ------------------------------------------------
     * 7. Full JSON
     * ------------------------------------------------
     */
    println!();
    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}
