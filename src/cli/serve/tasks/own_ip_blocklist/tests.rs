//! One check round: a listing is counted once, an unknown answer is never
//! clean, and a relisting after a delisting is counted again.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Mutex;

use super::*;
use crate::spf::DnsFailure;

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// Resolver whose answers the test rewrites between rounds.
struct Dns {
	listed: Mutex<HashMap<String, bool>>,
	failing: Mutex<bool>,
}

impl Dns {
	fn new() -> Self {
		Dns {
			listed: Mutex::new(HashMap::new()),
			failing: Mutex::new(false),
		}
	}
	fn list(&self, name: &str, on: bool) {
		self.listed.lock().expect("lock").insert(name.into(), on);
	}
	fn fail(&self, on: bool) {
		*self.failing.lock().expect("lock") = on;
	}
}

impl DnsLookup for Dns {
	fn txt(&self, _name: &str) -> Fut<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn addresses(&self, name: &str) -> Fut<'_, Vec<IpAddr>> {
		let failing = *self.failing.lock().expect("lock");
		let listed = self
			.listed
			.lock()
			.expect("lock")
			.get(name)
			.copied()
			.unwrap_or(false);
		Box::pin(async move {
			if failing {
				return Err(DnsFailure::Temporary);
			}
			Ok(if listed {
				vec!["127.0.0.2".parse().expect("ip")]
			} else {
				Vec::new()
			})
		})
	}
	fn mx(&self, _name: &str) -> Fut<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

const NAME: &str = "34.216.184.93.bl.example";

fn count(metrics: &Metrics) -> u64 {
	metrics.snapshot()["own_ip_blocklisted"]
}

struct Rig {
	addresses: Vec<IpAddr>,
	zones: Vec<String>,
	dns: Dns,
	state: State,
	metrics: Metrics,
	dir: tempfile::TempDir,
}

impl Rig {
	fn new() -> Self {
		Rig {
			addresses: vec!["93.184.216.34".parse().expect("ip")],
			zones: vec!["bl.example".into()],
			dns: Dns::new(),
			state: State::default(),
			metrics: Metrics::new(),
			dir: tempfile::tempdir().expect("tempdir"),
		}
	}
	async fn round(&mut self) {
		round(
			&self.addresses,
			&self.zones,
			&self.dns,
			&mut self.state,
			&self.metrics,
			self.dir.path(),
		)
		.await;
	}
}

#[tokio::test]
async fn a_listed_address_is_counted_once_across_rounds() {
	let mut rig = Rig::new();
	rig.dns.list(NAME, true);
	for _ in 0..3 {
		rig.round().await;
	}
	assert_eq!(count(&rig.metrics), 1);
	let listings = rig.metrics.own_ip_listings();
	assert_eq!(listings.len(), 1);
	assert_eq!(listings[0].zone, "bl.example");
	let saved = own::load(rig.dir.path()).expect("load").expect("saved");
	assert_eq!(saved.listings.len(), 1);
}

#[tokio::test]
async fn an_unlisted_address_counts_nothing() {
	let mut rig = Rig::new();
	rig.round().await;
	assert_eq!(count(&rig.metrics), 0);
	assert!(rig.metrics.own_ip_listings().is_empty());
	let saved = own::load(rig.dir.path()).expect("load").expect("saved");
	assert_eq!(
		saved.check(rig.addresses[0]).expect("check").status,
		Status::NotListed
	);
}

#[tokio::test]
async fn a_failing_lookup_is_unknown_and_counts_nothing() {
	let mut rig = Rig::new();
	rig.dns.fail(true);
	rig.round().await;
	assert_eq!(count(&rig.metrics), 0);
	let saved = own::load(rig.dir.path()).expect("load").expect("saved");
	assert_eq!(
		saved.check(rig.addresses[0]).expect("check").status,
		Status::Unknown
	);
}

#[tokio::test]
async fn a_failure_while_listed_does_not_count_it_again() {
	let mut rig = Rig::new();
	rig.dns.list(NAME, true);
	rig.round().await;
	rig.dns.fail(true);
	rig.round().await;
	rig.dns.fail(false);
	rig.round().await;
	assert_eq!(count(&rig.metrics), 1);
}

#[tokio::test]
async fn a_relisting_after_a_delisting_is_counted_again() {
	let mut rig = Rig::new();
	rig.dns.list(NAME, true);
	rig.round().await;
	rig.dns.list(NAME, false);
	rig.round().await;
	assert_eq!(count(&rig.metrics), 1);
	assert!(rig.metrics.own_ip_listings().is_empty());
	rig.dns.list(NAME, true);
	rig.round().await;
	assert_eq!(count(&rig.metrics), 2);
}
