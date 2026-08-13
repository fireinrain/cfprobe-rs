pub mod backend;
pub mod detector;
pub mod model;
pub mod pool;
pub mod resolver;

pub use backend::DnsBackend;
pub use detector::{DnsDetector, DnsResolverEntry};
pub use model::{DnsDetection, DnsDetectionStatus, ResolverHealth, ResolverObservation};
pub use pool::{DnsCache, DnsCacheConfig, DnsPool};
pub use resolver::HickoryDnsResolver;