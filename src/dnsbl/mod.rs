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
	/// Carries the zone that listed the IP, so callers can log which blocklist
	/// matched.
	Listed {
		/// The DNSBL zone that returned a listing A record for the IP.
		zone: String,
	},
	/// Every queried zone either returned an error code (Spamhaus uses
	/// `127.255.255.0/24` for "open resolver", "over quota", "no key", …) or
	/// failed to resolve. The screen is inconclusive. DNSBL is advisory, so
	/// callers must not reject solely on this.
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
		if self.zones.is_empty() {
			return DnsblOutcome::NotListed;
		}
		let reversed = reverse_ip(ip);
		let mut any_error = false;
		for zone in &self.zones {
			let query = format!("{reversed}.{zone}");
			match dns.addresses(&query).await {
				Ok(addrs) => match classify_answer(&addrs) {
					AnswerClass::Listed => return DnsblOutcome::Listed { zone: zone.clone() },
					AnswerClass::Error => any_error = true,
					AnswerClass::Ignored => {}
				},
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

/// Classify the answer set of one DNSBL query.
enum AnswerClass {
	/// A listed answer (127.0.0.0/8 but outside the Spamhaus error range).
	Listed,
	/// An answer in `127.255.255.0/24` (Spamhaus error range), meaning the
	/// query was rejected (open resolver, quota, no key, …). Treated as an
	/// `Unavailable` signal, not a listing.
	Error,
	/// The answer is outside `127.0.0.0/8` (RFC 5782 §2.1 reserves the loopback
	/// range for listings). Non-loopback answers are ignored.
	Ignored,
}

fn classify_answer(addrs: &[IpAddr]) -> AnswerClass {
	let mut listed = false;
	let mut error = false;
	for ip in addrs {
		let IpAddr::V4(v4) = ip else {
			continue;
		};
		let [a, b, c, _d] = v4.octets();
		if a != 127 {
			continue;
		}
		if b == 255 && c == 255 {
			error = true;
		} else {
			listed = true;
		}
	}
	if listed {
		AnswerClass::Listed
	} else if error {
		AnswerClass::Error
	} else {
		AnswerClass::Ignored
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
