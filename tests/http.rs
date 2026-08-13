use std::net::SocketAddr;
use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use cfprobe::{HttpProbeConfig, HttpProbeStatus, HttpProber, HttpScheme};

#[derive(Clone)]
struct MockHttpResponse {
    status: &'static str,

    headers: Vec<(&'static str, &'static str)>,

    body: &'static str,
}

struct MockHttpServer {
    address: SocketAddr,

    task: tokio::task::JoinHandle<()>,
}

impl MockHttpServer {
    async fn start(response: MockHttpResponse) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let address = listener.local_addr().unwrap();

        let response = Arc::new(response);

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };

                let response = response.clone();

                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 8192];

                    let _ = socket.read(&mut buffer).await;

                    let mut raw = format!("HTTP/1.1 {}\r\n", response.status,);

                    raw.push_str(&format!("Content-Length: {}\r\n", response.body.len(),));

                    for (name, value) in &response.headers {
                        raw.push_str(&format!("{}: {}\r\n", name, value,));
                    }

                    raw.push_str("\r\n");

                    raw.push_str(response.body);

                    let _ = socket.write_all(raw.as_bytes()).await;
                });
            }
        });

        Self { address, task }
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn http_config(port: u16) -> HttpProbeConfig {
    HttpProbeConfig {
        scheme: HttpScheme::Http,

        port,

        timeout: std::time::Duration::from_secs(2),

        connect_timeout: std::time::Duration::from_secs(1),

        ..HttpProbeConfig::default()
    }
}

#[tokio::test]
async fn detects_cloudflare_headers() {
    let server = MockHttpServer::start(MockHttpResponse {
        status: "200 OK",

        headers: vec![
            ("Server", "cloudflare"),
            ("CF-Ray", "abc123-SJC"),
            ("CF-Cache-Status", "HIT"),
            ("CF-IPCountry", "US"),
        ],

        body: "hello",
    })
    .await;

    let prober = HttpProber::new(http_config(server.address.port())).unwrap();

    let result = prober
        .probe("127.0.0.1".parse().unwrap(), "example.com")
        .await
        .unwrap();

    assert_eq!(result.status, HttpProbeStatus::ResponseReceived);

    assert_eq!(result.status_code, Some(200));

    assert_eq!(result.signals.cf_ray.as_deref(), Some("abc123-SJC"));

    assert_eq!(result.signals.cf_cache_status.as_deref(), Some("HIT"));

    assert!(result.signals.server_cloudflare);

    assert!(result.signals.score() > 0);
}

#[tokio::test]
async fn detects_http_version() {
    let server = MockHttpServer::start(MockHttpResponse {
        status: "204 No Content",

        headers: vec![],

        body: "",
    })
    .await;

    let prober = HttpProber::new(http_config(server.address.port())).unwrap();

    let result = prober
        .probe("127.0.0.1".parse().unwrap(), "example.com")
        .await
        .unwrap();

    assert_eq!(result.http_version.as_deref(), Some("HTTP/1.1"));

    assert_eq!(result.status_code, Some(204));
}

#[tokio::test]
async fn detects_redirect_without_following() {
    let server = MockHttpServer::start(MockHttpResponse {
        status: "302 Found",

        headers: vec![("Location", "https://another.example/")],

        body: "",
    })
    .await;

    let prober = HttpProber::new(http_config(server.address.port())).unwrap();

    let result = prober
        .probe("127.0.0.1".parse().unwrap(), "example.com")
        .await
        .unwrap();

    assert_eq!(result.status_code, Some(302));

    assert_eq!(
        result.redirect_location.as_deref(),
        Some("https://another.example/")
    );

    /*
     * 这里最关键：
     *
     * Mock server 只有一个请求机会。
     *
     * 如果 reqwest 跟随 redirect，
     * 这个测试就不成立。
     */
    assert!(result.final_url.as_deref().unwrap().contains("example.com"));
}

#[tokio::test]
async fn body_is_limited() {
    let body = "abcdefghijklmnopqrstuvwxyz";

    let server = MockHttpServer::start(MockHttpResponse {
        status: "200 OK",

        headers: vec![],

        body,
    })
    .await;

    let mut config = http_config(server.address.port());

    config.max_body_bytes = 8;

    let prober = HttpProber::new(config).unwrap();

    let result = prober
        .probe("127.0.0.1".parse().unwrap(), "example.com")
        .await
        .unwrap();

    assert!(result.body_truncated);

    assert_eq!(result.body_bytes_read, 8);

    assert_eq!(result.status, HttpProbeStatus::ResponseBodyLimitReached);
}

#[tokio::test]
async fn unavailable_server_is_request_failed() {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

    let address = server.local_addr().unwrap();

    drop(server);

    let prober = HttpProber::new(http_config(address.port())).unwrap();

    let result = prober
        .probe("127.0.0.1".parse().unwrap(), "example.com")
        .await
        .unwrap();

    assert_eq!(result.status, HttpProbeStatus::RequestFailed);

    assert!(result.error.is_some());
}

#[tokio::test]
// #[ignore = "slow integration test; requires real internet access to Cloudflare edge"]
async fn test_http_probe() {
    let mut cfg = HttpProbeConfig::default();
    cfg.connect_timeout = std::time::Duration::from_millis(800);
    cfg.timeout = std::time::Duration::from_secs(2);

    let prober = HttpProber::new(cfg).unwrap();

    let result = prober
        .probe("104.16.77.250".parse().unwrap(), "example.com")
        .await
        .unwrap();

    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}