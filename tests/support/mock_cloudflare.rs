use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Mutex, oneshot},
    task::JoinHandle,
    time::{Duration, sleep},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockMode {
    Ok,
    InternalServerError,
}

#[derive(Clone)]
pub struct MockState {
    request_count: Arc<AtomicUsize>,

    mode: Arc<Mutex<MockMode>>,

    etag: Arc<Mutex<String>>,

    delay: Arc<Mutex<Option<Duration>>>,
}

impl Default for MockState {
    fn default() -> Self {
        Self {
            request_count: Arc::new(AtomicUsize::new(0)),

            mode: Arc::new(Mutex::new(MockMode::Ok)),

            etag: Arc::new(Mutex::new("\"test-etag-v1\"".to_string())),

            delay: Arc::new(Mutex::new(None)),
        }
    }
}

impl MockState {
    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    pub async fn set_mode(&self, mode: MockMode) {
        *self.mode.lock().await = mode;
    }

    pub async fn set_etag(&self, etag: &str) {
        *self.etag.lock().await = etag.to_string();
    }

    pub async fn set_delay(&self, delay: Option<Duration>) {
        *self.delay.lock().await = delay;
    }
}

pub struct MockCloudflareServer {
    pub endpoint: String,

    pub state: MockState,

    shutdown: Option<oneshot::Sender<()>>,

    task: Option<JoinHandle<()>>,
}

impl MockCloudflareServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let address = listener.local_addr().unwrap();

        let state = MockState::default();

        let task_state = state.clone();

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }

                    result =
                        listener.accept() =>
                    {
                        let Ok((
                            socket,
                            _
                        )) = result
                        else {
                            continue;
                        };

                        let state =
                            task_state.clone();

                        tokio::spawn(
                            async move {
                                handle_connection(
                                    socket,
                                    state,
                                )
                                .await;
                            }
                        );
                    }
                }
            }
        });

        Self {
            endpoint: format!("http://{}", address),

            state,

            shutdown: Some(shutdown_tx),

            task: Some(task),
        }
    }
}

impl Drop for MockCloudflareServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }

        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn handle_connection(mut socket: tokio::net::TcpStream, state: MockState) {
    let mut buffer = vec![0u8; 8192];

    let mut request = Vec::new();

    loop {
        let read = socket.read(&mut buffer).await;

        let Ok(read) = read else {
            return;
        };

        if read == 0 {
            return;
        }

        request.extend_from_slice(&buffer[..read]);

        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }

        if request.len() > 64 * 1024 {
            return;
        }
    }

    state.request_count.fetch_add(1, Ordering::SeqCst);

    let request = String::from_utf8_lossy(&request);

    let delay = *state.delay.lock().await;

    if let Some(delay) = delay {
        sleep(delay).await;
    }

    let mode = *state.mode.lock().await;

    if mode == MockMode::InternalServerError {
        write_response(
            &mut socket,
            500,
            "Internal Server Error",
            &[],
            b"server error",
        )
        .await;

        return;
    }

    let current_etag = state.etag.lock().await.clone();

    let if_none_match = extract_header(&request, "If-None-Match");

    if if_none_match.as_deref() == Some(current_etag.as_str()) {
        write_response(
            &mut socket,
            304,
            "Not Modified",
            &[("ETag", current_etag.as_str())],
            &[],
        )
        .await;

        return;
    }

    let body = serde_json::json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": {
            "etag": current_etag,
            "ipv4_cidrs": [
                "104.16.0.0/13"
            ],
            "ipv6_cidrs": [
                "2606:4700::/32"
            ]
        }
    });

    let body = serde_json::to_vec(&body).unwrap();

    write_response(
        &mut socket,
        200,
        "OK",
        &[
            ("Content-Type", "application/json"),
            ("ETag", current_etag.as_str()),
        ],
        &body,
    )
    .await;
}

fn extract_header(request: &str, target: &str) -> Option<String> {
    for line in request.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };

        if name.eq_ignore_ascii_case(target) {
            return Some(value.trim().to_string());
        }
    }

    None
}

async fn write_response(
    socket: &mut tokio::net::TcpStream,

    status: u16,

    reason: &str,

    extra_headers: &[(&str, &str)],

    body: &[u8],
) {
    let mut response = format!("HTTP/1.1 {} {}\r\n", status, reason,);

    response.push_str(&format!("Content-Length: {}\r\n", body.len()));

    response.push_str("Connection: close\r\n");

    for (name, value) in extra_headers {
        response.push_str(&format!("{}: {}\r\n", name, value,));
    }

    response.push_str("\r\n");

    if socket.write_all(response.as_bytes()).await.is_err() {
        return;
    }

    let _ = socket.write_all(body).await;
}
