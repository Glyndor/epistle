//! DNS blocklist (DNSBL) lookups for inbound connection screening.
//!
//! A DNSBL publishes listed addresses as A records under a zone: the target
//! identifier (an IP, an envelope-sender domain, or a URL host) is prefixed to
//! the zone and any returned address inside the response range means the
//! identifier is listed. Lookups go through the shared [`DnsLookup`] trait so
//! the logic is testable without a network.

use std::net::IpAddr;

use crate::spf::{DnsFailure, DnsLookup};

/// The result of checking an identifier against the configured blocklists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsblOutcome {
	/// The identifier is not listed on any configured zone.
	NotListed,
	/// The identifier is listed on `zone`. Carries the zone that matched so
	/// callers can log which blocklist fired.
	Listed {
		/// The DNSBL zone that returned a listing A record.
		zone: String,
	},
	/// Every queried zone either returned an error code (Spamhaus uses
	/// `127.255.255.0/24` for "open resolver", "over quota", "no key", …) or
	/// failed to resolve. The screen is inconclusive. DNSBL is advisory, so
	/// callers must not reject solely on this.
	Unavailable,
}

/// A set of DNSBL zones to screen connecting clients against.
///
/// Three independent zone lists share one checker, distinguished by which
/// identifier they screen. Each list is consulted only when non-empty, so
/// operators can enable any subset.
#[derive(Debug, Clone, Default)]
pub struct Dnsbl {
	ip_zones: Vec<String>,
	domain_zones: Vec<String>,
	url_zones: Vec<String>,
}

impl Dnsbl {
	/// Build a blocklist checker that screens only client IPs against `zones`
	/// (e.g. `zen.spamhaus.org`). Use [`Self::with_domain_zones`] and
	/// [`Self::with_url_zones`] to add RHSBL and URIBL lists.
	pub fn new(zones: impl IntoIterator<Item = String>) -> Self {
		Dnsbl {
			ip_zones: zones.into_iter().map(|z| z.to_ascii_lowercase()).collect(),
			domain_zones: Vec::new(),
			url_zones: Vec::new(),
		}
	}

	/// Add right-hand-side (RHSBL) zones that screen the envelope sender's
	/// domain (RFC 5782 §2.3). The returned builder keeps the IP zones
	/// configured on `self`.
	pub fn with_domain_zones(mut self, zones: impl IntoIterator<Item = String>) -> Self {
		self.domain_zones = zones.into_iter().map(|z| z.to_ascii_lowercase()).collect();
		self
	}

	/// Add URI (URIBL) zones that screen the hosts of every URL found in the
	/// body (RFC 5782 §2.3). The returned builder keeps the IP and domain
	/// zones configured on `self`.
	pub fn with_url_zones(mut self, zones: impl IntoIterator<Item = String>) -> Self {
		self.url_zones = zones.into_iter().map(|z| z.to_ascii_lowercase()).collect();
		self
	}

	/// Whether any of the three zone lists is non-empty.
	pub fn is_empty(&self) -> bool {
		self.ip_zones.is_empty() && self.domain_zones.is_empty() && self.url_zones.is_empty()
	}

	/// Whether any zone is configured that screens an IP. Used by the SMTP
	/// path to gate the existing IP lookup.
	pub fn has_ip_zones(&self) -> bool {
		!self.ip_zones.is_empty()
	}

	/// Whether any zone is configured that screens an envelope-sender domain.
	pub fn has_domain_zones(&self) -> bool {
		!self.domain_zones.is_empty()
	}

	/// Whether any zone is configured that screens URL hosts in the body.
	pub fn has_url_zones(&self) -> bool {
		!self.url_zones.is_empty()
	}

	/// Screen `ip` against every IP zone, returning on the first listing. When
	/// no zone lists the IP but at least one errored, the result is
	/// `Unavailable`.
	pub async fn check(&self, ip: IpAddr, dns: &dyn DnsLookup) -> DnsblOutcome {
		if self.ip_zones.is_empty() {
			return DnsblOutcome::NotListed;
		}
		let reversed = reverse_ip(ip);
		let mut any_error = false;
		for zone in &self.ip_zones {
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

	/// Screen `domain` against every RHSBL zone, returning on the first
	/// listing. When no zone lists the domain but at least one errored, the
	/// result is `Unavailable`.
	pub async fn check_domain(&self, domain: &str, dns: &dyn DnsLookup) -> DnsblOutcome {
		if self.domain_zones.is_empty() {
			return DnsblOutcome::NotListed;
		}
		let mut any_error = false;
		for zone in &self.domain_zones {
			let query = format!("{domain}.{zone}");
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

	/// Screen `hosts` (the URL hosts found in the body) against every URIBL
	/// zone. For each host with more than two labels, both the full host and
	/// the registrable domain (Mozilla Public Suffix List) are queried. The
	/// total query budget is capped at `MAX_URL_QUERIES` (200) so a body
	/// with hundreds of links cannot turn the delivery path into a DNS
	/// flood.
	pub async fn check_url_hosts(&self, hosts: &[String], dns: &dyn DnsLookup) -> DnsblOutcome {
		if self.url_zones.is_empty() || hosts.is_empty() {
			return DnsblOutcome::NotListed;
		}
		let mut any_error = false;
		let mut spent = 0usize;
		'zones: for zone in &self.url_zones {
			for host in hosts {
				if spent >= MAX_URL_QUERIES {
					tracing::debug!(
						"URIBL query budget exhausted ({MAX_URL_QUERIES}), treating as not listed"
					);
					break 'zones;
				}
				let query = format!("{host}.{zone}");
				match dns.addresses(&query).await {
					Ok(addrs) => match classify_answer(&addrs) {
						AnswerClass::Listed => return DnsblOutcome::Listed { zone: zone.clone() },
						AnswerClass::Error => any_error = true,
						AnswerClass::Ignored => {}
					},
					Err(DnsFailure::Temporary) => any_error = true,
				}
				spent += 1;
				if host.split('.').count() > 2 && spent < MAX_URL_QUERIES {
					let Some(reg_domain) = registrable_domain(host) else {
						continue;
					};
					if reg_domain == host.as_str() {
						continue;
					}
					let query = format!("{reg_domain}.{zone}");
					match dns.addresses(&query).await {
						Ok(addrs) => match classify_answer(&addrs) {
							AnswerClass::Listed => {
								return DnsblOutcome::Listed { zone: zone.clone() };
							}
							AnswerClass::Error => any_error = true,
							AnswerClass::Ignored => {}
						},
						Err(DnsFailure::Temporary) => any_error = true,
					}
					spent += 1;
				}
			}
		}
		if any_error {
			DnsblOutcome::Unavailable
		} else {
			DnsblOutcome::NotListed
		}
	}
}

/// Maximum number of DNS queries the URL host screen will issue per message.
/// Beyond this the screen returns [`DnsblOutcome::NotListed`] with a debug
/// log so a body with hundreds of links cannot turn the delivery path into a
/// DNS flood.
const MAX_URL_QUERIES: usize = 200;

/// Registrable domain of `host` using the Mozilla Public Suffix List. Hosts
/// with two labels or fewer are returned unchanged.
fn registrable_domain(host: &str) -> Option<String> {
	use psl::Psl;
	let labels: Vec<&str> = host.split('.').collect();
	if labels.len() <= 2 {
		return Some(host.to_string());
	}
	if let Some(d) = psl::List.domain(host.as_bytes())
		&& let Ok(s) = std::str::from_utf8(d.as_bytes())
	{
		return Some(s.to_ascii_lowercase());
	}
	Some(labels[labels.len() - 2..].join("."))
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
