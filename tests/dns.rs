use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

use cfprobe::{
    CfProbeError, CloudflareRanges, DnsBackend, DnsDetectionStatus, DnsDetector, DnsResolverEntry,
};

struct MockDnsResolver {
    ips: Vec<IpAddr>,

    cname: Vec<String>,

    fail: bool,
}

#[async_trait]
impl DnsBackend for MockDnsResolver {
    async fn lookup_ip(&self, _fqdn: &str) -> Result<Vec<IpAddr>, CfProbeError> {
        if self.fail {
            return Err(CfProbeError::Dns {
                message: "mock DNS failure".to_string(),
            });
        }

        Ok(self.ips.clone())
    }

    async fn lookup_cname(&self, _fqdn: &str) -> Result<Vec<String>, CfProbeError> {
        if self.fail {
            return Err(CfProbeError::Dns {
                message: "mock DNS failure".to_string(),
            });
        }

        Ok(self.cname.clone())
    }
}

fn cloudflare_ranges() -> CloudflareRanges {
    CloudflareRanges::new(
        vec!["104.16.0.0/13".to_string()],
        vec!["2606:4700::/32".to_string()],
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn detects_cloudflare_ip() {
    let detector = DnsDetector::new(vec![DnsResolverEntry {
        name: "mock".to_string(),

        resolver: Arc::new(MockDnsResolver {
            ips: vec!["104.16.1.1".parse().unwrap()],

            cname: vec![],

            fail: false,
        }),
    }]);

    let result = detector
        .detect("example.com", &cloudflare_ranges())
        .await
        .unwrap();

    assert!(result.has_cloudflare_ip);

    assert_eq!(result.status, DnsDetectionStatus::CloudflareIp);
}

#[tokio::test]
async fn detects_non_cloudflare_ip() {
    let detector = DnsDetector::new(vec![DnsResolverEntry {
        name: "mock".to_string(),

        resolver: Arc::new(MockDnsResolver {
            ips: vec!["8.8.8.8".parse().unwrap()],

            cname: vec![],

            fail: false,
        }),
    }]);

    let result = detector
        .detect("example.com", &cloudflare_ranges())
        .await
        .unwrap();

    assert!(!result.has_cloudflare_ip);

    assert_eq!(result.status, DnsDetectionStatus::NoCloudflareIp);
}

#[tokio::test]
async fn dns_failure_is_unknown() {
    let detector = DnsDetector::new(vec![DnsResolverEntry {
        name: "mock".to_string(),

        resolver: Arc::new(MockDnsResolver {
            ips: vec![],

            cname: vec![],

            fail: true,
        }),
    }]);

    let result = detector
        .detect("example.com", &cloudflare_ranges())
        .await
        .unwrap();

    assert_eq!(result.status, DnsDetectionStatus::Unknown);
}

#[tokio::test]
async fn resolver_consensus_detects_cloudflare() {
    let detector = DnsDetector::new(vec![
        DnsResolverEntry {
            name: "resolver-a".to_string(),

            resolver: Arc::new(MockDnsResolver {
                ips: vec!["104.16.1.1".parse().unwrap()],

                cname: vec![],

                fail: false,
            }),
        },
        DnsResolverEntry {
            name: "resolver-b".to_string(),

            resolver: Arc::new(MockDnsResolver {
                ips: vec!["104.16.1.1".parse().unwrap()],

                cname: vec![],

                fail: false,
            }),
        },
        DnsResolverEntry {
            name: "resolver-c".to_string(),

            resolver: Arc::new(MockDnsResolver {
                ips: vec!["104.16.1.1".parse().unwrap()],

                cname: vec![],

                fail: false,
            }),
        },
    ]);

    let result = detector
        .detect("example.com", &cloudflare_ranges())
        .await
        .unwrap();

    assert_eq!(result.cloudflare_resolver_count, 3);

    assert!(result.all_resolvers_agree);

    assert_eq!(result.status, DnsDetectionStatus::CloudflareIp);
}

#[tokio::test]
async fn resolver_disagreement_is_visible() {
    let detector = DnsDetector::new(vec![
        DnsResolverEntry {
            name: "resolver-a".to_string(),

            resolver: Arc::new(MockDnsResolver {
                ips: vec!["104.16.1.1".parse().unwrap()],

                cname: vec![],

                fail: false,
            }),
        },
        DnsResolverEntry {
            name: "resolver-b".to_string(),

            resolver: Arc::new(MockDnsResolver {
                ips: vec!["8.8.8.8".parse().unwrap()],

                cname: vec![],

                fail: false,
            }),
        },
        DnsResolverEntry {
            name: "resolver-c".to_string(),

            resolver: Arc::new(MockDnsResolver {
                ips: vec!["104.16.1.1".parse().unwrap()],

                cname: vec![],

                fail: false,
            }),
        },
    ]);

    let result = detector
        .detect("example.com", &cloudflare_ranges())
        .await
        .unwrap();

    assert_eq!(result.cloudflare_resolver_count, 2);

    assert!(!result.all_resolvers_agree);

    assert_eq!(result.status, DnsDetectionStatus::CloudflareIp);
}
