use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

use rcgen::generate_simple_self_signed;

use cfprobe::{CertificateVerificationStatus, TlsDetectionStatus, TlsProbeConfig, TlsProber};

struct TestTlsServer {
    address: SocketAddr,

    task: tokio::task::JoinHandle<()>,
}

async fn start_tls_server() -> TestTlsServer {
    let cert = generate_simple_self_signed(vec!["example.com".into()]).unwrap();

    let cert_der: CertificateDer<'static> = CertificateDer::from(cert.cert.der().to_vec());

    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let address = listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };

            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };

                let mut buffer = [0u8; 1024];

                let _ = stream.read(&mut buffer).await;

                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .await;
            });
        }
    });

    TestTlsServer { address, task }
}

impl Drop for TestTlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn tls_observation_fallback_reads_certificate() {
    let server = start_tls_server().await;

    let config = TlsProbeConfig {
        timeout: std::time::Duration::from_secs(2),

        port: server.address.port(),

        verify_certificate: true,

        observation_fallback: true,

        alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };

    let prober = TlsProber::new(config);

    let result = prober
        .probe(IpAddr::V4(Ipv4Addr::LOCALHOST), "example.com")
        .await
        .unwrap();

    assert!(result.handshake_succeeded);

    assert_eq!(
        result.status,
        TlsDetectionStatus::CertificateVerificationFailed
    );

    assert_eq!(
        result.certificate_verification,
        CertificateVerificationStatus::Unknown
    );

    assert!(!result.certificates.is_empty());

    assert!(
        result.certificates[0]
            .dns_names
            .contains(&"example.com".to_string())
    );

    assert!(result.tls_version.is_some());

    assert!(result.cipher_suite.is_some());

    assert_eq!(result.sni.as_deref(), Some("example.com"));
}

#[tokio::test]
async fn certificate_failure_without_fallback_fails() {
    let server = start_tls_server().await;

    let config = TlsProbeConfig {
        timeout: std::time::Duration::from_secs(2),

        port: server.address.port(),

        verify_certificate: true,

        observation_fallback: false,

        alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };

    let prober = TlsProber::new(config);

    let result = prober
        .probe(IpAddr::V4(Ipv4Addr::LOCALHOST), "example.com")
        .await
        .unwrap();

    assert!(!result.handshake_succeeded);

    assert_eq!(result.status, TlsDetectionStatus::HandshakeFailed);
}

#[tokio::test]
async fn observation_only_mode_succeeds() {
    let server = start_tls_server().await;

    let config = TlsProbeConfig {
        timeout: std::time::Duration::from_secs(2),

        port: server.address.port(),

        verify_certificate: false,

        observation_fallback: true,

        alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };

    let prober = TlsProber::new(config);

    let result = prober
        .probe(IpAddr::V4(Ipv4Addr::LOCALHOST), "example.com")
        .await
        .unwrap();

    assert!(result.handshake_succeeded);

    assert_eq!(
        result.certificate_verification,
        CertificateVerificationStatus::Unknown
    );

    assert!(!result.certificates.is_empty());
}

#[tokio::test]
async fn tls_main_test() -> Result<(), Box<dyn std::error::Error>> {
    let prober = TlsProber::new(TlsProbeConfig::default());

    let result = prober
        .probe("104.16.77.250".parse::<IpAddr>()?, "example.com")
        .await?;

    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}
