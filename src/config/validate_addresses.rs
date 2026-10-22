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
	} else if matches!(ip.octets(), [192, 88, 99, _]) {
		Some("a deprecated relay address (192.88.99.0/24)")
	} else if ip.octets()[0] == 0 {
		Some("the current network (0.0.0.0/8)")
	} else if matches!(ip.octets(), [192, 0, 0, _]) {
		Some("a protocol assignment address (192.0.0.0/24)")
	} else if matches!(ip.octets(), [198, 18..=19, _, _]) {
		Some("a benchmarking address (198.18.0.0/15)")
	} else if ip.octets()[0] >= 240 {
		Some("a reserved address (240.0.0.0/4)")
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

/// The IPv4 payload an IPv6 address carries: an IPv4-mapped address
/// (`::ffff:a.b.c.d`), an IPv4-compatible one (`::a.b.c.d`), a NAT64 address
/// (`64:ff9b::/96`, RFC 6052) or a 6to4 one (`2002::/16`). `None` for a plain
/// IPv6 address, and for `::`, which is the unspecified address rather than a
/// payload of 0.0.0.0.
///
/// One definition of the forms for every caller, so a caller cannot check one
/// set of prefixes while the classifier checks another.
pub(crate) fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
	if ip.is_unspecified() {
		return None;
	}
	ip.to_ipv4().or_else(|| match ip.segments() {
		[0x64, 0xff9b, 0, 0, 0, 0, a, b] | [0x2002, a, b, ..] => {
			Some(Ipv4Addr::from(((a as u32) << 16) | b as u32))
		}
		_ => None,
	})
}

/// `true` for the NAT64 well-known prefix (RFC 6052, 64:ff9b::/96), the same
/// prefix `embedded_ipv4` unwraps, asked as a predicate so the classifier can
/// name the form of an address whose payload is global.
fn is_nat64(ip: Ipv6Addr) -> bool {
	matches!(ip.segments(), [0x64, 0xff9b, 0, 0, 0, 0, ..])
}

/// Why the IPv4 payload an IPv6 address carries is refused, naming both the
/// form that carries it and what is wrong with the payload, so the operator
/// can tell a translation or a transition address from a plain IPv6 one.
fn embedded_reason(ip: Ipv6Addr, why: &'static str) -> &'static str {
	if ip.to_ipv4_mapped().is_some() {
		return match why {
			"a private address (RFC 1918: 10/8, 172.16/12, 192.168/16)" => {
				"an IPv4-mapped IPv6 carrying a private address (RFC 1918)"
			}
			"a loopback address (127.0.0.0/8)" => "an IPv4-mapped IPv6 carrying a loopback address",
			_ => "an IPv4-mapped IPv6 carrying a non-global address",
		};
	}
	if ip.to_ipv4().is_some() {
		return match why {
			"a private address (RFC 1918: 10/8, 172.16/12, 192.168/16)" => {
				"an IPv4-compatible IPv6 carrying a private address (RFC 1918)"
			}
			"a loopback address (127.0.0.0/8)" => {
				"an IPv4-compatible IPv6 carrying a loopback address"
			}
			_ => "an IPv4-compatible IPv6 carrying a non-global address",
		};
	}
	if is_nat64(ip) {
		return match why {
			"a private address (RFC 1918: 10/8, 172.16/12, 192.168/16)" => {
				"a NAT64 address (64:ff9b::/96) carrying a private address (RFC 1918)"
			}
			"a loopback address (127.0.0.0/8)" => {
				"a NAT64 address (64:ff9b::/96) carrying a loopback address"
			}
			_ => "a NAT64 address (64:ff9b::/96) carrying a non-global address",
		};
	}
	// `embedded_ipv4` returned a payload, so what is left is 6to4.
	match why {
		"a private address (RFC 1918: 10/8, 172.16/12, 192.168/16)" => {
			"a 6to4 address (2002::/16) carrying a private address (RFC 1918)"
		}
		"a loopback address (127.0.0.0/8)" => {
			"a 6to4 address (2002::/16) carrying a loopback address"
		}
		_ => "a 6to4 address (2002::/16) carrying a non-global address",
	}
}

/// Human-readable reason an IPv6 address is not a valid public address.
/// `None` when the address is a global unicast and is accepted.
pub(crate) fn non_global_ipv6_reason(ip: Ipv6Addr) -> Option<&'static str> {
	// Any form that carries an IPv4 payload hides it from a naive range check,
	// so unwrap every one of them and classify the IPv4 inside: a v6 address
	// must not be a way in for a loopback, private or reserved IPv4.
	if let Some(v4) = embedded_ipv4(ip)
		&& let Some(why) = non_global_ipv4_reason(v4)
	{
		return Some(embedded_reason(ip, why));
	}
	// With a global payload, the mapped form (what a dual-stack socket
	// reports) and the public NAT64 prefix are global addresses themselves. The
	// deprecated compatible form and 6to4 are not, and fall through to the
	// checks below.
	if ip.to_ipv4_mapped().is_some() || is_nat64(ip) {
		return None;
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
	} else if (ip.segments()[0] & 0xe000) != 0x2000 {
		Some("an address outside global IPv6 unicast space (2000::/3)")
	} else if matches!(ip.segments(), [0x2001, b, ..] if b < 0x200)
		&& !matches!(
			ip.segments(),
			[0x2001, 1, 0, 0, 0, 0, 0, 1..=3]
				| [0x2001, 3, ..]
				| [0x2001, 4, 0x112, ..]
				| [0x2001, 0x20..=0x3f, ..]
		) {
		Some("a non-global IETF protocol assignment (2001::/23)")
	} else if ip.segments()[0] == 0x2002 {
		Some("a transition address (6to4, 2002::/16)")
	} else if ip.segments()[0] == 0x3fff && ip.segments()[1] < 0x1000 {
		Some("a documentation address (3fff::/20)")
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
