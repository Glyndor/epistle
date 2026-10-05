//! Tests for DNSBL screening.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use super::*;

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// DNS stub: a map of query name → addresses, or a forced temporary failure.
struct ScriptedDns {
	listed: HashMap<String, Vec<IpAddr>>,
	fail: bool,
}

impl ScriptedDns {
	fn with(name: &str) -> Self {
		ScriptedDns {
			listed: HashMap::from([(
				name.to_string(),
				vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))],
			)]),
			fail: false,
		}
	}

	/// Build a stub that returns exactly one A record for `name`. Used by
	/// the Spamhaus error-range and 127/8 mask tests.
	fn with_answer(name: &str, addr: IpAddr) -> Self {
		ScriptedDns {
			listed: HashMap::from([(name.to_string(), vec![addr])]),
			fail: false,
		}
	}
}

impl DnsLookup for ScriptedDns {
	fn txt(&self, _name: &str) -> Fut<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn addresses(&self, name: &str) -> Fut<'_, Vec<IpAddr>> {
		if self.fail {
			return Box::pin(async { Err(DnsFailure::Temporary) });
		}
		let result = self.listed.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(result) })
	}

	fn mx(&self, _name: &str) -> Fut<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

fn ipv4(s: &str) -> IpAddr {
	IpAddr::V4(s.parse::<Ipv4Addr>().expect("ipv4"))
}

#[test]
fn reverses_ipv4_octets() {
	assert_eq!(reverse_ip(ipv4("192.0.2.5")), "5.2.0.192");
}

#[test]
fn reverses_ipv6_nibbles() {
	let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
	// ::1 -> 31 zero nibbles then a 1, all reversed and dot-joined.
	let reversed = reverse_ip(ip);
	assert!(reversed.starts_with("1.0.0.0."), "{reversed}");
	assert_eq!(reversed.split('.').count(), 32);
}

#[tokio::test]
async fn listed_ip_is_flagged() {
	let dns = ScriptedDns::with("5.2.0.192.bl.example");
	let dnsbl = Dnsbl::new(["bl.example".to_string()]);
	assert_eq!(
		dnsbl.check(ipv4("192.0.2.5"), &dns).await,
		DnsblOutcome::Listed {
			zone: "bl.example".to_string()
		}
	);
}

#[tokio::test]
async fn unlisted_ip_is_not_flagged() {
	let dns = ScriptedDns::with("9.9.9.9.bl.example");
	let dnsbl = Dnsbl::new(["bl.example".to_string()]);
	assert_eq!(
		dnsbl.check(ipv4("192.0.2.5"), &dns).await,
		DnsblOutcome::NotListed
	);
}

#[tokio::test]
async fn temporary_failure_is_unavailable() {
	let dns = ScriptedDns {
		listed: HashMap::new(),
		fail: true,
	};
	let dnsbl = Dnsbl::new(["bl.example".to_string()]);
	assert_eq!(
		dnsbl.check(ipv4("192.0.2.5"), &dns).await,
		DnsblOutcome::Unavailable
	);
}

#[tokio::test]
async fn no_zones_never_lists() {
	let dns = ScriptedDns::with("5.2.0.192.bl.example");
	let dnsbl = Dnsbl::default();
	assert!(dnsbl.is_empty());
	assert_eq!(
		dnsbl.check(ipv4("192.0.2.5"), &dns).await,
		DnsblOutcome::NotListed
	);
}

#[tokio::test]
async fn an_answer_in_the_spamhaus_error_range_is_unavailable() {
	// Spamhaus returns 127.255.255.252 for an open resolver (no key). That
	// must NOT be treated as a listing; it must read as Unavailable.
	let dns = ScriptedDns::with_answer("5.2.0.192.bl.example", ipv4("127.255.255.252"));
	let dnsbl = Dnsbl::new(["bl.example".to_string()]);
	assert_eq!(
		dnsbl.check(ipv4("192.0.2.5"), &dns).await,
		DnsblOutcome::Unavailable
	);
}

#[tokio::test]
async fn an_answer_outside_127_8_is_ignored() {
	// RFC 5782 §2.1 reserves 127.0.0.0/8 for listings; any answer outside it
	// is not a listing and must be ignored.
	let dns = ScriptedDns::with_answer("5.2.0.192.bl.example", ipv4("192.0.2.99"));
	let dnsbl = Dnsbl::new(["bl.example".to_string()]);
	assert_eq!(
		dnsbl.check(ipv4("192.0.2.5"), &dns).await,
		DnsblOutcome::NotListed
	);
}

#[tokio::test]
async fn sender_domain_listed_in_a_domain_zone() {
	let dns = ScriptedDns::with("sender.example.bl.example");
	let dnsbl = Dnsbl::default().with_domain_zones(["bl.example".to_string()]);
	assert_eq!(
		dnsbl.check_domain("sender.example", &dns).await,
		DnsblOutcome::Listed {
			zone: "bl.example".to_string()
		}
	);
}

#[tokio::test]
async fn domain_zones_disabled_never_lists() {
	let dns = ScriptedDns::with("sender.example.bl.example");
	let dnsbl = Dnsbl::new(["bl.example".to_string()]); // IP only.
	assert_eq!(
		dnsbl.check_domain("sender.example", &dns).await,
		DnsblOutcome::NotListed
	);
}

#[tokio::test]
async fn url_host_listed_in_a_url_zone() {
	let dns = ScriptedDns::with("spam.example.urlbl.example");
	let dnsbl = Dnsbl::default().with_url_zones(["urlbl.example".to_string()]);
	assert_eq!(
		dnsbl
			.check_url_hosts(&["spam.example".to_string()], &dns)
			.await,
		DnsblOutcome::Listed {
			zone: "urlbl.example".to_string()
		}
	);
}

#[tokio::test]
async fn registrable_domain_of_a_deep_host_is_queried() {
	let dns = ScriptedDns::with("spam.example.urlbl.example");
	let dnsbl = Dnsbl::default().with_url_zones(["urlbl.example".to_string()]);
	assert_eq!(
		dnsbl
			.check_url_hosts(&["foo.bar.spam.example".to_string()], &dns)
			.await,
		DnsblOutcome::Listed {
			zone: "urlbl.example".to_string()
		}
	);
}

#[tokio::test]
async fn the_query_budget_stops_at_200() {
	// 250 hosts and 1 zone would issue 250 queries; the budget is 200. The
	// counting DNS stub records every query it sees and returns no listings,
	// so the only observable signal of the budget being honoured is the call
	// count itself.
	let mut listed = HashMap::new();
	let hosts: Vec<String> = (0..250).map(|i| format!("h{i}.example")).collect();
	for host in &hosts {
		listed.insert(format!("{host}.urlbl.example"), Vec::new());
	}
	let dns = CountingDns {
		listed,
		calls: std::sync::atomic::AtomicUsize::new(0),
	};
	let dnsbl = Dnsbl::default().with_url_zones(["urlbl.example".to_string()]);
	let outcome = dnsbl.check_url_hosts(&hosts, &dns).await;
	assert_eq!(outcome, DnsblOutcome::NotListed);
	assert_eq!(
		dns.calls(),
		200,
		"URIBL budget should cap the lookup at 200 queries"
	);
}

/// DNS stub that counts every addresses() call it receives.
struct CountingDns {
	listed: HashMap<String, Vec<IpAddr>>,
	calls: std::sync::atomic::AtomicUsize,
}

impl CountingDns {
	fn calls(&self) -> usize {
		self.calls.load(std::sync::atomic::Ordering::SeqCst)
	}
}

impl DnsLookup for CountingDns {
	fn txt(&self, _name: &str) -> Fut<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn addresses(&self, name: &str) -> Fut<'_, Vec<IpAddr>> {
		self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
		let result = self.listed.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(result) })
	}

	fn mx(&self, _name: &str) -> Fut<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}
