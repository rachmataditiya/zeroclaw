//! Shared SSRF (Server-Side Request Forgery) guard for all HTTP tools.
//!
//! Provides hostname and IP validation to prevent requests to private/local
//! networks. Used by `web_fetch`, `http_request`, and other HTTP-making tools.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Hostnames that are always blocked (exact match).
const BLOCKED_HOSTNAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
];

/// Hostname suffixes that are always blocked.
const BLOCKED_HOSTNAME_SUFFIXES: &[&str] = &[".localhost", ".local", ".internal"];

/// Returns `true` if the IPv4 address is not globally routable.
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    ip.is_loopback()                                   // 127.0.0.0/8
        || ip.is_private()                             // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()                          // 169.254.0.0/16
        || ip.is_unspecified()                         // 0.0.0.0
        || ip.is_broadcast()                           // 255.255.255.255
        || ip.is_multicast()                           // 224.0.0.0/4
        || (a == 100 && (64..=127).contains(&b))       // Shared address space (RFC 6598)
        || a >= 240                                     // Reserved (240.0.0.0/4)
        || (a == 192 && ip.octets()[1] == 0 && (ip.octets()[2] == 0 || ip.octets()[2] == 2)) // IETF + TEST-NET-1
        || (a == 198 && ip.octets()[1] == 51)          // Documentation (198.51.100.0/24)
        || (a == 203 && ip.octets()[1] == 0)           // Documentation (203.0.113.0/24)
        || (a == 198 && (18..=19).contains(&ip.octets()[1])) // Benchmarking (198.18.0.0/15)
}

/// Returns `true` if the IPv6 address is not globally routable.
pub fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    let segs = ip.segments();
    ip.is_loopback()                                   // ::1
        || ip.is_unspecified()                         // ::
        || ip.is_multicast()                           // ff00::/8
        || (segs[0] & 0xfe00) == 0xfc00               // Unique-local (fc00::/7)
        || (segs[0] & 0xffc0) == 0xfe80               // Link-local (fe80::/10)
        || (segs[0] == 0x2001 && segs[1] == 0x0db8)   // Documentation (2001:db8::/32)
        || ip.to_ipv4_mapped().is_some_and(is_private_ipv4) // IPv4-mapped IPv6
}

/// Returns `true` if the hostname is blocked by exact match or suffix match.
pub fn is_blocked_hostname(host: &str) -> bool {
    let lower = host.to_lowercase();

    if BLOCKED_HOSTNAMES.iter().any(|&h| lower == h) {
        return true;
    }

    if BLOCKED_HOSTNAME_SUFFIXES
        .iter()
        .any(|&suffix| lower.ends_with(suffix))
    {
        return true;
    }

    false
}

/// Returns `true` if the host is a private/local address.
///
/// Checks hostname blocklist first, then tries to parse as an IP address
/// and checks against private IP ranges.
pub fn is_private_or_local_host(host: &str) -> bool {
    // Strip brackets from IPv6 addresses like [::1]
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    if is_blocked_hostname(bare) {
        return true;
    }

    // Check .local TLD
    if bare
        .rsplit('.')
        .next()
        .is_some_and(|label| label == "local")
    {
        return true;
    }

    // Check .localhost subdomain
    if bare.ends_with(".localhost") {
        return true;
    }

    if let Ok(ip) = bare.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => is_private_ipv4(v4),
            IpAddr::V6(v6) => is_private_ipv6(v6),
        };
    }

    false
}

/// Validate a URL for SSRF safety.
///
/// Checks the URL's hostname against the blocklist and IP ranges.
/// Does NOT perform DNS resolution (caller should handle DNS rebinding
/// if needed via connect-time checks).
pub fn validate_url_ssrf(url: &url::Url) -> anyhow::Result<()> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("Only http:// and https:// URLs are allowed, got: {scheme}");
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must include a host"))?;

    if host.is_empty() {
        anyhow::bail!("URL must include a valid host");
    }

    if is_private_or_local_host(host) {
        anyhow::bail!("Blocked local/private host: {host}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_private_ipv4 ────────────────────────────────────────

    #[test]
    fn private_ipv4_loopback() {
        assert!(is_private_ipv4(Ipv4Addr::LOCALHOST));
        assert!(is_private_ipv4(Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn private_ipv4_rfc1918() {
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn private_ipv4_shared_address() {
        assert!(is_private_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(100, 128, 0, 1)));
    }

    #[test]
    fn private_ipv4_special() {
        assert!(is_private_ipv4(Ipv4Addr::UNSPECIFIED)); // unspecified
        assert!(is_private_ipv4(Ipv4Addr::BROADCAST)); // broadcast
        assert!(is_private_ipv4(Ipv4Addr::new(224, 0, 0, 1))); // multicast
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 1, 1))); // link-local
    }

    #[test]
    fn private_ipv4_documentation() {
        assert!(is_private_ipv4(Ipv4Addr::new(192, 0, 2, 1))); // TEST-NET-1
        assert!(is_private_ipv4(Ipv4Addr::new(198, 51, 100, 1))); // TEST-NET-2
        assert!(is_private_ipv4(Ipv4Addr::new(203, 0, 113, 1))); // TEST-NET-3
    }

    #[test]
    fn public_ipv4_allowed() {
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    // ── is_private_ipv6 ────────────────────────────────────────

    #[test]
    fn private_ipv6_loopback_and_unspecified() {
        assert!(is_private_ipv6(Ipv6Addr::LOCALHOST));
        assert!(is_private_ipv6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn private_ipv6_special_ranges() {
        assert!(is_private_ipv6("ff02::1".parse().unwrap())); // multicast
        assert!(is_private_ipv6("fe80::1".parse().unwrap())); // link-local
        assert!(is_private_ipv6("fd00::1".parse().unwrap())); // unique-local
        assert!(is_private_ipv6("2001:db8::1".parse().unwrap())); // documentation
    }

    #[test]
    fn private_ipv6_ipv4_mapped() {
        assert!(is_private_ipv6("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_private_ipv6("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_private_ipv6("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn public_ipv6_allowed() {
        assert!(!is_private_ipv6(
            "2607:f8b0:4004:800::200e".parse().unwrap()
        ));
    }

    // ── is_blocked_hostname ────────────────────────────────────

    #[test]
    fn blocked_hostname_exact() {
        assert!(is_blocked_hostname("localhost"));
        assert!(is_blocked_hostname("LOCALHOST"));
        assert!(is_blocked_hostname("metadata.google.internal"));
    }

    #[test]
    fn blocked_hostname_suffix() {
        assert!(is_blocked_hostname("evil.localhost"));
        assert!(is_blocked_hostname("service.local"));
        assert!(is_blocked_hostname("api.internal"));
    }

    #[test]
    fn allowed_hostname() {
        assert!(!is_blocked_hostname("example.com"));
        assert!(!is_blocked_hostname("api.openai.com"));
    }

    // ── is_private_or_local_host ───────────────────────────────

    #[test]
    fn private_host_localhost() {
        assert!(is_private_or_local_host("localhost"));
        assert!(is_private_or_local_host("evil.localhost"));
    }

    #[test]
    fn private_host_ipv4() {
        assert!(is_private_or_local_host("127.0.0.1"));
        assert!(is_private_or_local_host("192.168.1.1"));
        assert!(is_private_or_local_host("10.0.0.1"));
    }

    #[test]
    fn private_host_ipv6() {
        assert!(is_private_or_local_host("::1"));
        assert!(is_private_or_local_host("[::1]"));
        assert!(is_private_or_local_host("fe80::1"));
    }

    #[test]
    fn public_host_allowed() {
        assert!(!is_private_or_local_host("example.com"));
        assert!(!is_private_or_local_host("8.8.8.8"));
    }

    // ── validate_url_ssrf ──────────────────────────────────────

    #[test]
    fn ssrf_blocks_localhost_url() {
        let url = url::Url::parse("http://localhost:8080/api").unwrap();
        assert!(validate_url_ssrf(&url).is_err());
    }

    #[test]
    fn ssrf_blocks_private_ip_url() {
        let url = url::Url::parse("https://192.168.1.1/admin").unwrap();
        assert!(validate_url_ssrf(&url).is_err());
    }

    #[test]
    fn ssrf_blocks_metadata_url() {
        let url = url::Url::parse("http://metadata.google.internal/computeMetadata").unwrap();
        assert!(validate_url_ssrf(&url).is_err());
    }

    #[test]
    fn ssrf_allows_public_url() {
        let url = url::Url::parse("https://api.example.com/data").unwrap();
        assert!(validate_url_ssrf(&url).is_ok());
    }

    #[test]
    fn ssrf_rejects_ftp_scheme() {
        let url = url::Url::parse("ftp://files.example.com/file").unwrap();
        assert!(validate_url_ssrf(&url).is_err());
    }

    #[test]
    fn ssrf_blocks_internal_suffix() {
        let url = url::Url::parse("http://api.internal/secret").unwrap();
        assert!(validate_url_ssrf(&url).is_err());
    }

    #[test]
    fn ssrf_blocks_ipv4_mapped_ipv6() {
        let url = url::Url::parse("http://[::ffff:127.0.0.1]/").unwrap();
        assert!(validate_url_ssrf(&url).is_err());
    }
}
