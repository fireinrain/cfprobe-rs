mod ip;
mod result;

pub use ip::detect_cloudflare_ip;

pub use result::{CloudflareIpDetection, DetectionKind};
