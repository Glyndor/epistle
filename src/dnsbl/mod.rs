//! DNS blocklist (DNSBL) lookups for inbound connection screening.
//!
//! A DNSBL publishes listed addresses as A records under a zone: the client
//! IP is reversed and prefixed to the zone, and any returned address means
//! the IP is listed. Lookups go through the shared [`DnsLookup`] trait so the
//! logic is testable without a network.

use std::net::IpAddr;

use crate::spf::{DnsFailure, DnsLookup};

/// The result of checking a client IP against the configured blocklists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsblOutcome {
	/// The IP is not listed on any configured zone.
	NotListed,
	/// The IP is listed on `zone` (a spam signal, not an automatic reject).
	Listed { zone: String },
	/// Every queried zone failed to resolve; the screen is inconclusive.
	/// DNSBL is advisory, so callers must not reject solely on this.
	Unavailable,
}

/// A set of DNSBL zones to screen connecting clients against.
#[derive(Debug, Clone, Default)]
pub struct Dnsbl {
	zones: Vec<String>,
}

impl Dnsbl {
	/// Build a blocklist checker for the given zones (e.g. `zen.example`).
	pub fn new(zones: impl IntoIterator<Item = String>) -> Self {
		Dnsbl {
			zones: zones.into_iter().map(|z| z.to_ascii_lowercase()).collect(),
		}
	}

	/// Whether any zones are configured.
	pub fn is_empty(&self) -> bool {
		self.zones.is_empty()
	}

	/// Screen `ip` against every zone, returning on the first listing. When no
	/// zone lists the IP but at least one errored, the result is `Unavailable`.
	pub async fn check(&self, ip: IpAddr, dns: &dyn DnsLookup) -> DnsblOutcome {
		let reversed = reverse_ip(ip);
		let mut any_error = false;
		for zone in &self.zones {
			let query = format!("{reversed}.{zone}");
			match dns.addresses(&query).await {
				Ok(addrs) if !addrs.is_empty() => {
					return DnsblOutcome::Listed { zone: zone.clone() };
				}
				Ok(_) => {}
				Err(DnsFailure::Temporary) => any_error = true,
			}
		}
		if any_error {
			DnsblOutcome::Unavailable
		} else {
			DnsblOutcome::NotListed
		}
	}
}

/// The reversed-IP label prefix for a DNSBL query: IPv4 octets in reverse,
/// IPv6 as reversed nibbles (RFC 5782 §2.1 / §2.4).
fn reverse_ip(ip: IpAddr) -> String {
	match ip {
		IpAddr::V4(v4) => {
			let [a, b, c, d] = v4.octets();
			format!("{d}.{c}.{b}.{a}")
		}
		IpAddr::V6(v6) => {
			let mut labels = Vec::with_capacity(32);
			for octet in v6.octets().iter().rev() {
				// Low nibble first, then high nibble (nibbles in reverse order).
				labels.push(format!("{:x}", octet & 0x0f));
				labels.push(format!("{:x}", octet >> 4));
			}
			labels.join(".")
		}
	}
}

#[cfg(test)]
#[path = "dnsbl_tests.rs"]
mod tests;
