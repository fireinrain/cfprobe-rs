use std::net::IpAddr;

use crate::{CloudflareIpDetection, CloudflareRanges};

pub fn detect_cloudflare_ip(ranges: &CloudflareRanges, ip: IpAddr) -> CloudflareIpDetection {
    if ranges.contains(ip) {
        CloudflareIpDetection::cloudflare(ip)
    } else {
        CloudflareIpDetection::not_cloudflare(ip)
    }
}
