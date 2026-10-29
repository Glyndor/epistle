//! API state's trusted proxy wiring. The shared resolution lives in
//! [`crate::net::trusted_ip`]; this module owns the storage and the
//! pre-share setter.

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
		crate::net::trusted_ip::effective(&self.inner.trusted_proxies, peer, headers)
	}
}

#[cfg(test)]
mod tests;
