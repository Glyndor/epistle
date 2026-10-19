//! Trusted proxy client address resolution shared by bearer and OAuth paths.

use super::ApiState;
use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

impl ApiState {
	/// Configure trusted networks before sharing the state. Empty trusts no proxy.
	pub fn with_trusted_proxies(mut self, proxies: Vec<crate::cidr::Cidr>) -> Self {
		std::sync::Arc::get_mut(&mut self.inner)
			.expect("with_trusted_proxies must be called before the state is shared")
			.trusted_proxies = proxies;
		self
	}

	/// Resolve the first untrusted address from the right of a valid forwarded chain.
	/// Missing peers stay unknown. Invalid or wholly trusted chains use the peer.
	pub(crate) fn effective_client_ip(
		&self,
		peer: Option<SocketAddr>,
		headers: &HeaderMap,
	) -> Option<IpAddr> {
		let peer = peer?.ip().to_canonical();
		let trusted = |ip| {
			self.inner
				.trusted_proxies
				.iter()
				.any(|net| net.contains(ip))
		};
		if !trusted(peer) {
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
				if selected.is_none() && !trusted(ip) {
					selected = Some(ip);
				}
			}
		}
		Some(selected.unwrap_or(peer))
	}
}

#[cfg(test)]
#[path = "state_client_ip_tests.rs"]
mod tests;
