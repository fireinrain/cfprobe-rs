mod support;

use std::time::Duration;

use cfprobe::{CacheConfig, CacheSource, CloudflareClient, CloudflareRangeProvider};

use support::mock_cloudflare::{MockCloudflareServer, MockMode};

#[tokio::test]
async fn cache_directory_is_created() {
    cfprobe::init_rustls_crypto();
    let temp_dir = tempfile::TempDir::new().unwrap();
    println!("temp_dir: {:?}", temp_dir.path());

    let http = reqwest::Client::builder()
        .user_agent("cfprobe-test")
        .build()
        .unwrap();

    let client = CloudflareClient::new(http);

    let provider = CloudflareRangeProvider::with_cache_dir(client, temp_dir.path());

    assert!(provider.is_ok());
}

#[tokio::test]
async fn fetch_from_network_on_empty_cache() {
    cfprobe::init_rustls_crypto();
    let server = MockCloudflareServer::start().await;

    let temp = tempfile::TempDir::new().unwrap();

    let http = reqwest::Client::builder()
        .user_agent("cfprobe-test")
        .build()
        .unwrap();

    let client =
        CloudflareClient::with_endpoint(http, format!("{}/client/v4/ips", server.endpoint));

    let provider = CloudflareRangeProvider::with_cache_dir(client, temp.path()).unwrap();

    let result = provider.get().await.unwrap();

    assert_eq!(result.source, CacheSource::Network);

    assert!(result.ranges.contains("104.16.1.1".parse().unwrap()));

    assert_eq!(server.state.request_count(), 1);
}

#[tokio::test]
async fn second_provider_uses_disk_cache() {
    cfprobe::init_rustls_crypto();
    let server = MockCloudflareServer::start().await;

    let temp = tempfile::TempDir::new().unwrap();

    let http = reqwest::Client::new();

    let endpoint = format!("{}/client/v4/ips", server.endpoint);

    let client = CloudflareClient::with_endpoint(http.clone(), endpoint.clone());

    let provider = CloudflareRangeProvider::with_cache_dir(client, temp.path()).unwrap();

    let first = provider.get().await.unwrap();

    assert_eq!(first.source, CacheSource::Network);

    let client2 = CloudflareClient::with_endpoint(http, endpoint);

    let provider2 = CloudflareRangeProvider::with_cache_dir(client2, temp.path()).unwrap();

    let second = provider2.get().await.unwrap();

    assert_eq!(second.source, CacheSource::Disk);

    assert_eq!(server.state.request_count(), 1);
}

#[tokio::test]
async fn stale_cache_uses_etag_and_handles_304() {
    cfprobe::init_rustls_crypto();
    let server = MockCloudflareServer::start().await;

    let temp = tempfile::TempDir::new().unwrap();

    let http = reqwest::Client::new();

    let endpoint = format!("{}/client/v4/ips", server.endpoint);

    let client = CloudflareClient::with_endpoint(http.clone(), endpoint.clone());

    let config = CacheConfig {
        refresh_interval: Duration::from_millis(0),

        stale_if_error: Duration::from_secs(60),

        ..CacheConfig::default()
    };

    let provider = CloudflareRangeProvider::with_cache_dir(client, temp.path())
        .unwrap()
        .with_config(config.clone());

    let first = provider.get().await.unwrap();

    assert_eq!(first.source, CacheSource::Network);

    tokio::time::sleep(Duration::from_millis(10)).await;

    let client2 = CloudflareClient::with_endpoint(http, endpoint);

    let provider2 = CloudflareRangeProvider::with_cache_dir(client2, temp.path())
        .unwrap()
        .with_config(config);

    let second = provider2.get().await.unwrap();

    assert_eq!(second.source, CacheSource::NotModified);

    assert_eq!(server.state.request_count(), 2);
}

#[tokio::test]
async fn http_error_uses_stale_cache() {
    cfprobe::init_rustls_crypto();
    let server = MockCloudflareServer::start().await;

    let temp = tempfile::TempDir::new().unwrap();

    let http = reqwest::Client::new();

    let endpoint = format!("{}/client/v4/ips", server.endpoint);

    let config = CacheConfig {
        refresh_interval: Duration::from_millis(0),

        stale_if_error: Duration::from_secs(60),

        ..CacheConfig::default()
    };

    let client = CloudflareClient::with_endpoint(http.clone(), endpoint.clone());

    let provider = CloudflareRangeProvider::with_cache_dir(client, temp.path())
        .unwrap()
        .with_config(config.clone());

    provider.get().await.unwrap();

    server.state.set_mode(MockMode::InternalServerError).await;

    tokio::time::sleep(Duration::from_millis(10)).await;

    let client2 = CloudflareClient::with_endpoint(http, endpoint);

    let provider2 = CloudflareRangeProvider::with_cache_dir(client2, temp.path())
        .unwrap()
        .with_config(config);

    let result = provider2.get().await.unwrap();

    assert_eq!(result.source, CacheSource::StaleFallback);

    assert!(result.ranges.contains("104.16.1.1".parse().unwrap()));
}

#[tokio::test]
async fn corrupted_cache_is_recovered() {
    cfprobe::init_rustls_crypto();
    let server = MockCloudflareServer::start().await;

    let temp = tempfile::TempDir::new().unwrap();

    let cache_file = temp.path().join("cloudflare-ip-ranges.json");

    tokio::fs::create_dir_all(temp.path()).await.unwrap();

    tokio::fs::write(&cache_file, b"{ invalid json !!!")
        .await
        .unwrap();

    let http = reqwest::Client::new();

    let client =
        CloudflareClient::with_endpoint(http, format!("{}/client/v4/ips", server.endpoint));

    let provider = CloudflareRangeProvider::with_cache_dir(client, temp.path()).unwrap();

    let result = provider.get().await.unwrap();

    assert_eq!(result.source, CacheSource::Network);

    assert!(result.ranges.contains("104.16.1.1".parse().unwrap()));

    assert_eq!(server.state.request_count(), 1);
}

#[tokio::test]
async fn invalid_cidr_cache_is_recovered() {
    cfprobe::init_rustls_crypto();
    let server = MockCloudflareServer::start().await;

    let temp = tempfile::TempDir::new().unwrap();

    let cache_file = temp.path().join("cloudflare-ip-ranges.json");

    let bad_cache = serde_json::json!({
        "schema_version": 2,
        "fetched_at_unix_ms": 1786623456000i64,
        "etag": "\"bad\"",
        "ipv4_cidrs": [
            "this-is-not-cidr"
        ],
        "ipv6_cidrs": []
    });

    tokio::fs::write(&cache_file, serde_json::to_vec(&bad_cache).unwrap())
        .await
        .unwrap();

    let client = CloudflareClient::with_endpoint(
        reqwest::Client::new(),
        format!("{}/client/v4/ips", server.endpoint),
    );

    let provider = CloudflareRangeProvider::with_cache_dir(client, temp.path()).unwrap();

    let result = provider.get().await.unwrap();

    assert_eq!(result.source, CacheSource::Network);

    assert_eq!(server.state.request_count(), 1);
}

#[tokio::test]
async fn concurrent_providers_only_fetch_once() {
    cfprobe::init_rustls_crypto();
    let server = MockCloudflareServer::start().await;

    server
        .state
        .set_delay(Some(Duration::from_millis(100)))
        .await;

    let temp = tempfile::TempDir::new().unwrap();

    let endpoint = format!("{}/client/v4/ips", server.endpoint);

    let client1 = CloudflareClient::with_endpoint(reqwest::Client::new(), endpoint.clone());

    let client2 = CloudflareClient::with_endpoint(reqwest::Client::new(), endpoint);

    let provider1 = CloudflareRangeProvider::with_cache_dir(client1, temp.path()).unwrap();

    let provider2 = CloudflareRangeProvider::with_cache_dir(client2, temp.path()).unwrap();

    let task1 = tokio::spawn(async move { provider1.get().await });

    let task2 = tokio::spawn(async move { provider2.get().await });

    let result1 = task1.await.unwrap().unwrap();

    let result2 = task2.await.unwrap().unwrap();

    assert_eq!(server.state.request_count(), 1);

    assert!(result1.ranges.contains("104.16.1.1".parse().unwrap()));

    assert!(result2.ranges.contains("104.16.1.1".parse().unwrap()));
}

#[tokio::test]
async fn timeout_without_cache_returns_error() {
    cfprobe::init_rustls_crypto();
    let server = MockCloudflareServer::start().await;

    server
        .state
        .set_delay(Some(Duration::from_millis(200)))
        .await;

    let temp = tempfile::TempDir::new().unwrap();

    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();

    let client =
        CloudflareClient::with_endpoint(http, format!("{}/client/v4/ips", server.endpoint));

    let provider = CloudflareRangeProvider::with_cache_dir(client, temp.path()).unwrap();

    let result = provider.get().await;

    assert!(result.is_err());
}
