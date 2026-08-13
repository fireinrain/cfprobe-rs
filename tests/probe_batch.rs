use std::time::Duration;

use cfprobe::{BatchScanConfig, Target};

#[test]
fn batch_config_default_is_valid() {
    let config = BatchScanConfig::default();

    assert!(config.validate().is_ok());

    assert_eq!(config.concurrency, 32);

    assert_eq!(config.requests_per_second, None);
}

#[test]
fn batch_config_rejects_zero_concurrency() {
    let config = BatchScanConfig::default().with_concurrency(0);

    assert!(config.validate().is_err());
}

#[test]
fn batch_config_rejects_zero_rps() {
    let config = BatchScanConfig::default().with_requests_per_second(Some(0));

    assert!(config.validate().is_err());
}

#[test]
fn batch_config_rejects_zero_timeout() {
    let config = BatchScanConfig::default().with_target_timeout(Duration::ZERO);

    assert!(config.validate().is_err());
}

#[test]
fn batch_config_accepts_production_values() {
    let config = BatchScanConfig::default()
        .with_concurrency(64)
        .with_target_timeout(Duration::from_secs(20))
        .with_requests_per_second(Some(50))
        .with_max_targets(Some(10000));

    assert!(config.validate().is_ok());
}

#[test]
fn targets_validate_before_batch_execution() {
    let valid = Target::https("104.16.1.1".parse().unwrap(), "example.com");

    assert!(valid.validate().is_ok());

    let invalid = Target::https("104.16.1.1".parse().unwrap(), "");

    assert!(invalid.validate().is_err());
}
