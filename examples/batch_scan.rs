use std::net::IpAddr;

use futures::StreamExt;

use cfprobe::{BatchScanConfig, CfProbe, CfProbeConfig, Target};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /*
     * -----------------------------------------
     * 1. Create one long-lived CfProbe.
     * -----------------------------------------
     */
    let config = CfProbeConfig::cloudflare_web_proxy_v1()?;

    let probe = CfProbe::new(config).await?;

    /*
     * -----------------------------------------
     * 2. Build targets.
     * -----------------------------------------
     */
    let targets = vec![
        Target::https("104.16.77.250".parse::<IpAddr>()?, "example.com"),
        Target::https("104.16.76.250".parse::<IpAddr>()?, "example.org"),
    ];

    /*
     * -----------------------------------------
     * 3. Batch config.
     * -----------------------------------------
     *
     * 最多 8 个 Target 同时运行。
     *
     * 每秒最多启动 5 个 Target。
     *
     * 每个 Target 最多运行 20 秒。
     */
    let config = BatchScanConfig::default()
        .with_concurrency(8)
        .with_target_timeout(std::time::Duration::from_secs(20))
        .with_requests_per_second(Some(5));

    /*
     * -----------------------------------------
     * 4. Stream mode
     * -----------------------------------------
     *
     * 按完成顺序返回。
     */
    let mut stream = probe.scan_unordered(targets, config)?;

    while let Some(item) = stream.next().await {
        println!(
            "[{}] {:?} {:?}",
            item.index,
            item.status,
            item.classification(),
        );

        if let Some(error) = item.error {
            eprintln!("error: {}", error,);
        }

        if let Some(result) = item.result {
            println!("  score      = {}", result.detection.score,);

            println!("  confidence = {:.2}", result.detection.confidence,);
        }
    }

    Ok(())
}
