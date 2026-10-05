//! Network helpers shared by the listener accept loops.
//!
//! The dual-stack `::` listener (`crate::cli::serve_bind`) accepts
//! both IPv4 and IPv6 connections. Linux reports the peer of an
//! IPv4 connection over that listener as the v4-mapped IPv6 form
//! `::ffff:a.b.c.d`, which then propagates everywhere an `IPv4`-
//! typed value is expected: SPF (`ip4:` mechanisms never match),
//! DNSBL (queries the IPv6 reverse zone instead of the IPv4 one),
//! the ban table, per-IP rate limits, greylisting keys, API-key
//! CIDR allowlists and the audit log.
//!
//! Every `listener.accept()` and every `ConnectInfo<SocketAddr>`
//! extracted by the axum listeners routes the peer through
//! [`canonical_peer`] so the rest of the server sees a single IPv4
//! `IpAddr::V4` for an IPv4 client, never the v4-mapped v6 form.
//! The helper is a one-line wrapper around `IpAddr::to_canonical`
//! (stable since Rust 1.82; the crate's `rust-version` is 1.94) so a
//! future Rust upgrade cannot silently regress this invariant.

use std::net::SocketAddr;

/// Return the peer address with an IPv4 client represented as a
/// plain `IpAddr::V4` regardless of which listener accepted the
/// connection. The port is preserved verbatim.
///
/// IPv6 addresses and already-canonical IPv4 addresses are returned
/// unchanged. The v4-mapped IPv6 form (`::ffff:a.b.c.d`) becomes the
/// equivalent IPv4 address; the helper never allocates.
pub fn canonical_peer(addr: SocketAddr) -> SocketAddr {
	SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

	#[test]
	fn v4_mapped_v6_becomes_plain_v4() {
		let addr: SocketAddr = "[::ffff:192.0.2.7]:25".parse().expect("parse v4-mapped");
		let canonical = super::canonical_peer(addr);
		assert_eq!(canonical.ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
		assert_eq!(canonical.port(), 25);
	}

	#[test]
	fn plain_v4_is_unchanged() {
		let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 25));
		let canonical = super::canonical_peer(addr);
		assert_eq!(
			canonical,
			SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 25))
		);
	}

	#[test]
	fn plain_v6_is_unchanged() {
		let addr = SocketAddr::V6(SocketAddrV6::new(
			Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
			25,
			0,
			0,
		));
		let canonical = super::canonical_peer(addr);
		assert_eq!(
			canonical,
			SocketAddr::V6(SocketAddrV6::new(
				Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
				25,
				0,
				0,
			))
		);
	}

	#[test]
	fn v4_unspecified_is_still_v4() {
		let addr: SocketAddr = "[::ffff:0.0.0.0]:443".parse().expect("parse v4-mapped any");
		let canonical = super::canonical_peer(addr);
		assert_eq!(
			canonical,
			SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443))
		);
	}
}
