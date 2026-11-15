//! Own-address blocklist checks: classification, remembered state, links.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use super::*;
use crate::dnsbl::reverse_ip;
use crate::spf::DnsFailure;

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// Canned resolver: names that answer, names that fail, names that hang.
#[derive(Default)]
struct Dns {
	answers: HashMap<String, Vec<IpAddr>>,
	failing: HashSet<String>,
	hanging: HashSet<String>,
}

impl Dns {
	fn listing(name: &str) -> Self {
		let mut dns = Dns::default();
		dns.answers
			.insert(name.into(), vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
		dns
	}
}

impl DnsLookup for Dns {
	fn txt(&self, _name: &str) -> Fut<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn addresses(&self, name: &str) -> Fut<'_, Vec<IpAddr>> {
		let name = name.to_string();
		let failing = self.failing.contains(&name);
		let hanging = self.hanging.contains(&name);
		let found = self.answers.get(&name).cloned().unwrap_or_default();
		Box::pin(async move {
			if hanging {
				std::future::pending::<()>().await;
			}
			if failing {
				return Err(DnsFailure::Temporary);
			}
			Ok(found)
		})
	}
	fn mx(&self, _name: &str) -> Fut<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

fn v4() -> IpAddr {
	IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))
}

fn v6() -> IpAddr {
	IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("v6"))
}

fn zones(names: &[&str]) -> Vec<String> {
	names.iter().map(|name| name.to_string()).collect()
}

fn query(ip: IpAddr, zone: &str) -> String {
	format!("{}.{zone}", reverse_ip(ip))
}

#[tokio::test]
async fn a_listed_address_names_the_zone_and_the_delisting_page() {
	let dns = Dns::listing(&query(v4(), "zen.spamhaus.org"));
	let check = check_address(v4(), &zones(&["zen.spamhaus.org"]), &dns, 7).await;
	assert_eq!(
		check.status,
		Status::Listed {
			zone: "zen.spamhaus.org".into()
		}
	);
	assert_eq!(
		check.delist_url.as_deref(),
		Some("https://check.spamhaus.org/listed/")
	);
}

#[tokio::test]
async fn an_unlisted_address_is_not_listed() {
	let check = check_address(v4(), &zones(&["bl.example"]), &Dns::default(), 7).await;
	assert_eq!(check.status, Status::NotListed);
	assert_eq!(check.delist_url, None);
}

#[tokio::test]
async fn a_failed_lookup_is_unknown_never_clean() {
	let mut dns = Dns::default();
	dns.failing.insert(query(v4(), "bl.example"));
	let check = check_address(v4(), &zones(&["bl.example"]), &dns, 7).await;
	assert_eq!(check.status, Status::Unknown);
}

#[tokio::test(start_paused = true)]
async fn a_lookup_that_times_out_is_unknown_never_clean() {
	let mut dns = Dns::default();
	dns.hanging.insert(query(v4(), "bl.example"));
	let check = check_address(v4(), &zones(&["bl.example"]), &dns, 7).await;
	assert_eq!(check.status, Status::Unknown);
}

#[tokio::test]
async fn one_clean_zone_and_one_failing_zone_stay_unknown() {
	let mut dns = Dns::default();
	dns.failing.insert(query(v4(), "b.example"));
	let check = check_address(v4(), &zones(&["a.example", "b.example"]), &dns, 7).await;
	assert_eq!(check.status, Status::Unknown);
}

#[tokio::test]
async fn a_listing_wins_over_a_zone_that_failed() {
	let mut dns = Dns::listing(&query(v4(), "b.example"));
	dns.failing.insert(query(v4(), "a.example"));
	let check = check_address(v4(), &zones(&["a.example", "b.example"]), &dns, 7).await;
	assert_eq!(
		check.status,
		Status::Listed {
			zone: "b.example".into()
		}
	);
}

#[tokio::test]
async fn an_ipv6_address_is_looked_up_nibble_reversed() {
	let name = query(v6(), "bl.example");
	assert!(name.starts_with("1.0.0.0."), "{name}");
	assert!(name.ends_with("8.b.d.0.1.0.0.2.bl.example"), "{name}");
	let check = check_address(v6(), &zones(&["bl.example"]), &Dns::listing(&name), 7).await;
	assert_eq!(
		check.status,
		Status::Listed {
			zone: "bl.example".into()
		}
	);
}

fn check_of(address: IpAddr, status: Status, at: u64) -> Check {
	Check {
		address,
		status,
		delist_url: None,
		checked_at: at,
	}
}

fn listed(zone: &str) -> Status {
	Status::Listed { zone: zone.into() }
}

#[test]
fn a_listing_is_announced_once_not_on_every_period() {
	let mut state = State::default();
	assert!(
		state
			.apply(check_of(v4(), listed("bl.example"), 1))
			.is_some()
	);
	assert!(
		state
			.apply(check_of(v4(), listed("bl.example"), 2))
			.is_none()
	);
	assert!(
		state
			.apply(check_of(v4(), listed("bl.example"), 3))
			.is_none()
	);
	assert_eq!(state.listing(v4()).expect("kept").first_seen, 1);
}

#[test]
fn a_clean_address_announces_nothing() {
	let mut state = State::default();
	assert!(state.apply(check_of(v4(), Status::NotListed, 1)).is_none());
	assert!(state.listing(v4()).is_none());
}

#[test]
fn delisting_then_relisting_is_announced_again() {
	let mut state = State::default();
	assert!(
		state
			.apply(check_of(v4(), listed("bl.example"), 1))
			.is_some()
	);
	assert!(state.apply(check_of(v4(), Status::NotListed, 2)).is_none());
	assert!(state.listing(v4()).is_none());
	assert!(
		state
			.apply(check_of(v4(), listed("bl.example"), 3))
			.is_some()
	);
}

#[test]
fn an_unknown_round_keeps_the_listing_and_does_not_announce_it_again() {
	let mut state = State::default();
	assert!(
		state
			.apply(check_of(v4(), listed("bl.example"), 1))
			.is_some()
	);
	assert!(state.apply(check_of(v4(), Status::Unknown, 2)).is_none());
	assert!(state.listing(v4()).is_some());
	assert!(
		state
			.apply(check_of(v4(), listed("bl.example"), 3))
			.is_none()
	);
}

#[test]
fn an_unknown_address_is_not_recorded_as_clean() {
	let mut state = State::default();
	state.apply(check_of(v4(), Status::Unknown, 1));
	assert_eq!(state.check(v4()).expect("check").status, Status::Unknown);
}

#[test]
fn a_zone_change_for_a_listed_address_is_not_a_new_listing() {
	let mut state = State::default();
	assert!(
		state
			.apply(check_of(v4(), listed("a.example"), 1))
			.is_some()
	);
	assert!(
		state
			.apply(check_of(v4(), listed("b.example"), 2))
			.is_none()
	);
	assert_eq!(state.listing(v4()).expect("listing").zone, "b.example");
}

#[test]
fn each_address_has_its_own_listing() {
	let mut state = State::default();
	assert!(
		state
			.apply(check_of(v4(), listed("bl.example"), 1))
			.is_some()
	);
	assert!(
		state
			.apply(check_of(v6(), listed("bl.example"), 1))
			.is_some()
	);
}

#[test]
fn the_state_survives_a_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(load(dir.path()).expect("load"), None);
	let mut state = State::default();
	state.apply(check_of(v4(), listed("bl.example"), 1));
	save(dir.path(), &state).expect("save");
	assert_eq!(load(dir.path()).expect("load"), Some(state));
}

#[test]
fn an_unreadable_state_file_is_an_error_not_an_empty_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(path(dir.path()), b"not json").expect("write");
	assert!(load(dir.path()).is_err());
}

#[test]
fn delisting_links_are_only_for_zones_with_a_known_page() {
	assert_eq!(
		delist_url("zen.spamhaus.org."),
		Some("https://check.spamhaus.org/listed/")
	);
	assert_eq!(
		delist_url("B.barracudacentral.org"),
		Some("https://www.barracudacentral.org/lookups")
	);
	assert_eq!(delist_url("bl.example"), None);
	assert_eq!(delist_url("notspamhaus.org"), None);
}
