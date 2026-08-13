use std::net::IpAddr;

use cfprobe::{CacheSource, CloudflareClient, CloudflareRangeProvider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http = reqwest::Client::builder()
        .user_agent("cfprobe/0.1")
        .build()?;

    let client = CloudflareClient::new(http);

    let provider = CloudflareRangeProvider::new(client)?;

    let result = provider.get().await?;

    println!("cache source = {:?}", result.source);

    println!("etag = {:?}", result.etag);

    println!("fetched_at = {:?}", result.fetched_at);

    let ip: IpAddr = "1.1.1.1".parse()?;

    let detection = provider.contains(ip).await?;

    println!("{detection:#?}");

    if result.source == CacheSource::StaleFallback {
        eprintln!("warning: using stale Cloudflare IP range cache");
    }

    Ok(())
}
