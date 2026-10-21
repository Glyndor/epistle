//! Resolve the client address a request came from, honouring the
//! `trusted_proxies` list. The API and WebDAV listeners share this so a
//! peer behind a trusted reverse proxy is logged and rate-limited under
//! the address the proxy reports, not the proxy's own socket address.
//!
//! Trust is configured per deployment (`[api] trusted_proxies = [...]`):
//! empty trusts no proxy and the socket address is always the answer. When
//! the socket address belongs to a trusted CIDR, `X-Forwarded-For` is
//! walked from the right (the closest hop is the most recent addition), so
//! the first untrusted address from the right is the client, and entries
//! to its left, which the client wrote itself, are never read. A malformed
//! entry met before that address -- non-ASCII, an invalid IP, a
//! non-numeric port, or a trailing comma with nothing after it -- was
//! written by a trusted hop, so the header is unusable and the socket
//! address is kept. Garbage to the left of the client address cannot move
//! its failures onto the proxy, which every other user shares.
//!
//! IPv4 clients over a dual-stack listener that arrived as v4-mapped IPv6
//! (`::ffff:a.b.c.d`) are folded back to `IpAddr::V4` before any of the
//! matching runs (see [`crate::net::canonical_peer`]), so one client
//! never shows up under two shapes.

use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

/// Resolve the client address from `peer` and the headers of one request.
/// `trusted` is the configured `trusted_proxies` list (empty means trust
/// no proxy). Returns `None` when `peer` is missing; otherwise the
/// effective client address or the socket peer if the chain is unusable.
pub fn effective(
	trusted: &[crate::cidr::Cidr],
	peer: Option<SocketAddr>,
	headers: &HeaderMap,
) -> Option<IpAddr> {
	let peer = peer?.ip().to_canonical();
	let trusts = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
	if !trusts(peer) {
		return Some(peer);
	}
	// Walk from the right and stop at the first untrusted address: everything
	// to its left was written by that client, so it must not be read, and a
	// malformed value there must not push the failure onto the proxy's own
	// address, which every other user behind the proxy shares. Only a
	// malformed entry at or right of the boundary, written by a trusted hop,
	// leaves the socket address in charge. No chain allocation.
	for value in headers.get_all("x-forwarded-for").iter().rev() {
		let Ok(value) = value.to_str() else {
			return Some(peer);
		};
		for entry in value.rsplit(',') {
			let Ok(ip) = entry.trim().parse::<IpAddr>() else {
				return Some(peer);
			};
			let ip = ip.to_canonical();
			if !trusts(ip) {
				return Some(ip);
			}
		}
	}
	Some(peer)
}

#[cfg(test)]
#[path = "trusted_ip_tests.rs"]
mod tests;
