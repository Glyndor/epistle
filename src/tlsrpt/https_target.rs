//! Where an `https:` TLS-RPT report may be POSTed.
//!
//! The URI comes from the `rua=` of a `_smtp._tls` record, which the
//! recipient domain publishes: anyone we send mail to chooses it. Posting
//! wherever it points would let that domain aim the server at loopback, the
//! cloud metadata address or a host on the operator's LAN. So the host is
//! resolved first, every address it resolves to must be a global unicast
//! one (the same classifier `public_ipv4`/`public_ipv6` validation uses),
//! and the connection is pinned to those checked addresses so a second DNS
//! answer cannot move it between the check and the connect.

use std::net::{IpAddr, SocketAddr};

use crate::config::{non_global_ipv4_reason, non_global_ipv6_reason};
use crate::net::HttpsUrl;

/// A report destination that passed the checks: the URL, its host name (or
/// IP literal) and the global addresses the connection is pinned to.
pub(crate) struct CheckedTarget {
	pub(crate) url: HttpsUrl,
	pub(crate) host: String,
	pub(crate) addrs: Vec<SocketAddr>,
}

/// Why an address is not a reachable public destination, if it is not one.
pub(crate) fn non_global_reason(ip: IpAddr) -> Option<&'static str> {
	match ip {
		IpAddr::V4(v4) => non_global_ipv4_reason(v4),
		IpAddr::V6(v6) => non_global_ipv6_reason(v6),
	}
}

/// Parse `uri` as an `https:` URL and resolve its host, refusing it unless
/// every address is global. `resolve` maps `(host, port)` to its addresses;
/// production passes the system resolver, tests pass a fixed table.
pub(crate) async fn check<F, Fut>(uri: &str, resolve: F) -> Result<CheckedTarget, String>
where
	F: FnOnce(String, u16) -> Fut,
	Fut: Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
	let url = HttpsUrl::parse(uri).map_err(|error| format!("not an https URL: {error}"))?;
	let host = url
		.as_url()
		.host_str()
		.ok_or_else(|| "URL has no host".to_string())?
		.trim_start_matches('[')
		.trim_end_matches(']')
		.to_string();
	let port = url.as_url().port_or_known_default().unwrap_or(443);
	let addrs = match host.parse::<IpAddr>() {
		Ok(ip) => vec![SocketAddr::new(ip, port)],
		Err(_) => resolve(host.clone(), port)
			.await
			.map_err(|error| format!("resolving {host}: {error}"))?,
	};
	if addrs.is_empty() {
		return Err(format!("{host} resolves to no address"));
	}
	for addr in &addrs {
		if let Some(why) = non_global_reason(addr.ip()) {
			return Err(format!("{host} resolves to {} ({why})", addr.ip()));
		}
	}
	Ok(CheckedTarget { url, host, addrs })
}

/// The system resolver, for [`check`].
pub(crate) async fn system_resolve(host: String, port: u16) -> std::io::Result<Vec<SocketAddr>> {
	Ok(tokio::net::lookup_host((host.as_str(), port))
		.await?
		.collect())
}

#[cfg(test)]
#[path = "https_target_tests.rs"]
mod tests;
