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
