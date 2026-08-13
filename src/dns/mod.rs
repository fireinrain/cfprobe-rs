mod backend;
mod detector;
mod model;
mod pool;
mod resolver;

pub use backend::DnsBackend;

pub use detector::{DnsDetector, DnsResolverEntry};

pub use model::{DnsDetection, DnsDetectionStatus, ResolverObservation};

pub use resolver::HickoryDnsResolver;
