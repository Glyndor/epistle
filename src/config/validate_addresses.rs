//! Validation of the optional `public_ipv4` / `public_ipv6` fields: both
//! must be a global unicast address, because the value is what the
//! hostname resolves to on the public internet. Private, loopback or
//! link-local addresses are reachable only from inside the operator's
//! own network and would lie about our outward-facing IP.
//!
//! Pulled into a sibling so `validate.rs` stays under the per-file line
//! limit; the entry point is invoked from `Config::validate`.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::Config;
use super::ConfigError;

impl Config {
	/// Reject a non-global public address: loopback, unspecified,
	/// link-local, multicast or private (RFC 1918 / ULA). The error names
	/// the field and the range, so the operator can fix the value without
	/// trial-and-error.
	pub(super) fn validate_addresses(&self) -> Result<(), ConfigError> {
		if let Some(ip) = self.public_ipv4
			&& let Some(why) = non_global_ipv4_reason(ip)
		{
			return Err(ConfigError::Invalid(format!(
				"public_ipv4 \"{ip}\" is {why}; only a global unicast address is accepted"
			)));
		}
		if let Some(ip) = self.public_ipv6
			&& let Some(why) = non_global_ipv6_reason(ip)
		{
			return Err(ConfigError::Invalid(format!(
				"public_ipv6 \"{ip}\" is {why}; only a global unicast address is accepted"
			)));
		}
		Ok(())
	}
}

/// Human-readable reason an IPv4 address is not a valid public address.
/// `None` when the address is a global unicast and is accepted.
///
/// Exposed for `crate::dns::detect` so the operator-facing `init` flow
/// classifies the machine's own interfaces with the same rule: a private,
/// loopback, link-local, multicast, broadcast, shared (CGNAT), documentation
/// or unspecified address is reachable only from inside the operator's own
/// network and would lie about the outward-facing IP.
pub(crate) fn non_global_ipv4_reason(ip: Ipv4Addr) -> Option<&'static str> {
	if ip.is_unspecified() {
		Some("the unspecified address (0.0.0.0)")
	} else if ip.is_loopback() {
		Some("a loopback address (127.0.0.0/8)")
	} else if ip.is_link_local() {
		Some("a link-local address (169.254.0.0/16)")
	} else if ip.is_multicast() {
		Some("a multicast address (224.0.0.0/4)")
	} else if ip.is_broadcast() {
		Some("the broadcast address (255.255.255.255)")
	} else if ip.is_private() {
		Some("a private address (RFC 1918: 10/8, 172.16/12, 192.168/16)")
	} else if is_shared(ip) {
		// Carrier-grade NAT (RFC 6598, 100.64.0.0/10): ISPs hand these out
		// to subscribers behind a shared translation. The address is
		// non-global for our purposes; stdlib's `is_private()` does not
		// cover the range, so check it manually.
		Some("a shared address (CGNAT, RFC 6598: 100.64.0.0/10)")
	} else if ip.is_documentation() {
		Some("a documentation address (RFC 5737 / 3068: 192.0.2/24, 198.51.100/24, 203.0.113/24)")
	} else {
		None
	}
}

/// `true` when `ip` sits inside 100.64.0.0/10 (RFC 6598). `Ipv4Addr::is_shared`
/// is unstable, so the range is checked by hand.
pub(crate) fn is_shared(ip: Ipv4Addr) -> bool {
	let [a, b, _, _] = ip.octets();
	a == 100 && (64..=127).contains(&b)
}

/// Human-readable reason an IPv6 address is not a valid public address.
/// `None` when the address is a global unicast and is accepted.
pub(crate) fn non_global_ipv6_reason(ip: Ipv6Addr) -> Option<&'static str> {
	// An IPv4-mapped IPv6 (::ffff:a.b.c.d) hides an IPv4 payload from
	// a naive check; unwrap it so a v6 URL cannot smuggle a private v4
	// through validation.
	if let Some(v4) = ip.to_ipv4_mapped()
		&& let Some(why) = non_global_ipv4_reason(v4)
	{
		return Some(match why {
			"a private address (RFC 1918: 10/8, 172.16/12, 192.168/16)" => {
				"an IPv4-mapped IPv6 carrying a private address (RFC 1918)"
			}
			"a loopback address (127.0.0.0/8)" => "an IPv4-mapped IPv6 carrying a loopback address",
			_ => "an IPv4-mapped IPv6 carrying a non-global address",
		});
	}
	if ip.is_unspecified() {
		Some("the unspecified address (::)")
	} else if ip.is_loopback() {
		Some("a loopback address (::1)")
	} else if ip.is_unicast_link_local() {
		Some("a link-local address (fe80::/10)")
	} else if ip.is_multicast() {
		Some("a multicast address (ff00::/8)")
	} else if ip.is_unique_local() {
		Some("a unique-local address (ULA, fc00::/7)")
	} else if is_documentation_v6(ip) {
		// RFC 3849 (2001:db8::/32) reserves a documentation block; stdlib
		// has no stable `is_documentation` for IPv6, so check the prefix
		// manually.
		Some("a documentation address (RFC 3849: 2001:db8::/32)")
	} else {
		None
	}
}

/// `true` when `ip` sits inside 2001:db8::/32 (RFC 3849).
pub(crate) fn is_documentation_v6(ip: Ipv6Addr) -> bool {
	let s = ip.segments();
	s[0] == 0x2001 && s[1] == 0x0db8
}

#[cfg(test)]
#[path = "validate_addresses_tests.rs"]
mod tests;
