

use cfprobe::{
    CloudflareClient,
    CloudflareRangeProvider,
};

#[tokio::test]
async fn cache_directory_is_created() {
    let temp_dir =
        tempfile::TempDir::new()
            .unwrap();
    println!("temp_dir: {:?}", temp_dir.path());

    let http =
        reqwest::Client::builder()
            .user_agent("cfprobe-test")
            .build()
            .unwrap();

    let client =
        CloudflareClient::new(http);

    let provider =
        CloudflareRangeProvider::with_cache_dir(
            client,
            temp_dir.path(),
        );

    assert!(
        provider.is_ok()
    );
}