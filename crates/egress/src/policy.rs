//! Which addresses an outbound request is allowed to connect to.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where a request may connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressPolicy {
    /// Refuse local and private ranges. The default, and what production
    /// services fetching untrusted URLs should use.
    #[default]
    DenyLocal,
    /// Permit any address. Only for tests, local development, and services
    /// talking to operator-configured internal endpoints.
    AllowAll,
}

impl AddressPolicy {
    /// Whether a connection to `ip` is permitted.
    pub fn permits(self, ip: IpAddr) -> bool {
        match self {
            AddressPolicy::AllowAll => true,
            AddressPolicy::DenyLocal => !is_blocked(ip),
        }
    }
}

// RFC 6052 well-known NAT64 prefix 64:ff9b::/96.
const WELL_KNOWN_NAT64: [u8; 12] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
// RFC 8215 local-use NAT64 prefix 64:ff9b:1::/48.
const LOCAL_NAT64: [u8; 6] = [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01];

/// Whether `ip` is in a range we refuse to connect to.
///
/// Blocked: loopback, link-local (unicast and multicast), private (RFC 1918 and
/// IPv6 ULA), multicast, unspecified, limited broadcast, `0.0.0.0/8` "this
/// network", RFC 6598 carrier-grade NAT, and both NAT64 prefixes. IPv4-mapped
/// IPv6 addresses are classified by the address they map to.
///
/// Invalid or unspecified input cannot reach this function, but a caller
/// holding an `IpAddr` always has a concrete address, so unlike the Go version
/// there is no nil case to fail closed on.
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_blocked(v4),
        IpAddr::V6(v6) => v6_blocked(v6),
    }
}

fn v4_blocked(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_link_local()
        || ip.is_private()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        // 0.0.0.0/8 "this network". `is_unspecified` only covers 0.0.0.0.
        || o[0] == 0
        // RFC 6598 carrier-grade NAT, also used by overlay networks.
        || (o[0] == 100 && (64..=127).contains(&o[1]))
}

fn v6_blocked(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return v4_blocked(mapped);
    }
    let b = ip.octets();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // RFC 4193 unique local (fc00::/7), including cloud metadata at
        // fd00:ec2::254. Written out rather than using `is_unique_local` so
        // the MSRV does not have to track std's stabilisation.
        || (b[0] & 0xfe) == 0xfc
        // fe80::/10 link-local unicast.
        || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
        || b[..12] == WELL_KNOWN_NAT64
        || b[..6] == LOCAL_NAT64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> bool {
        is_blocked(s.parse().expect("test address parses"))
    }

    #[test]
    fn blocks_local_and_private_ranges() {
        // Mirrors the table in the Go client's `ssrf_test.go`.
        for addr in [
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.0.1",
            "169.254.169.254",
            "169.254.255.255",
            "100.64.0.0",
            "100.127.255.255",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "ff02::1",
            "64:ff9b::1.2.3.4",
            "64:ff9b:1::1.2.3.4",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(blocked(addr), "{addr} should be blocked");
        }
    }

    #[test]
    fn permits_public_addresses() {
        for addr in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "64:ff9c::1",
        ] {
            assert!(!blocked(addr), "{addr} should be permitted");
        }
    }

    #[test]
    fn policy_gates_on_the_flag() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!AddressPolicy::DenyLocal.permits(loopback));
        assert!(AddressPolicy::AllowAll.permits(loopback));
    }
}
