//! Resolve the client address a request came from, honouring the
//! `trusted_proxies` list. The API and WebDAV listeners share this so a
//! peer behind a trusted reverse proxy is logged and rate-limited under
//! the address the proxy reports, not the proxy's own socket address.
//!
//! Trust is configured per deployment (`[api] trusted_proxies = [...]`):
//! empty trusts no proxy and the socket address is always the answer. When
//! the socket address belongs to a trusted CIDR, `X-Forwarded-For` is
//! walked from the right (the closest hop is the most recent addition), so
//! the leftmost untrusted address on the chain is the client. A malformed
//! entry -- non-ASCII, an invalid IP, a non-numeric port, or a trailing
//! comma with nothing after it -- invalidates the whole header and the
//! socket address is kept, so a peer cannot craft a header that escapes
//! the limiter.
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
	let mut selected = None;
	// Visit all entries, including those left of the trust boundary, so any
	// malformed value makes the entire header unusable. No chain allocation.
	for value in headers.get_all("x-forwarded-for").iter().rev() {
		let Ok(value) = value.to_str() else {
			return Some(peer);
		};
		for entry in value.rsplit(',') {
			let Ok(ip) = entry.trim().parse::<IpAddr>() else {
				return Some(peer);
			};
			let ip = ip.to_canonical();
			if selected.is_none() && !trusts(ip) {
				selected = Some(ip);
			}
		}
	}
	Some(selected.unwrap_or(peer))
}

#[cfg(test)]
#[path = "trusted_ip_tests.rs"]
mod tests;
