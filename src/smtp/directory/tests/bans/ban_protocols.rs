//! One ban store serves every protocol: a client that guesses once per
//! connection, or spreads its guesses over the listeners, is counted as one
//! client, and the ban it earns holds on all of them.

use std::net::IpAddr;
use std::sync::Arc;

use super::Directory;
use super::gate_fixture::*;
use crate::antispam::bans::BanPolicy;
use crate::antispam::bans::tests::base::FakeBanStore;
use crate::config::Protocol;
use crate::test_fixtures as fixtures;

const PROTOCOLS: [Protocol; 6] = [
	Protocol::Submission,
	Protocol::Submissions,
	Protocol::Imaps,
	Protocol::Pop3s,
	Protocol::ManageSieve,
	Protocol::WebDav,
];

fn directory() -> Directory {
	gate_directory().with_ban_store(Arc::new(FakeBanStore::new(BanPolicy::default())))
}

fn from(text: &str) -> Option<IpAddr> {
	Some(text.parse().expect("address"))
}

fn guess(directory: &Directory, protocol: Protocol, ip: Option<IpAddr>) -> Option<String> {
	directory.authenticate_with_ip(OPEN, fixtures::wrong_password(), ip, protocol)
}

fn owner(directory: &Directory, protocol: Protocol, ip: Option<IpAddr>) -> Option<String> {
	directory.authenticate_with_ip(OPEN, fixtures::password(), ip, protocol)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guesses_spread_over_the_listeners_add_up_to_one_ban_that_holds_on_all() {
	let directory = directory();
	let attacker = from("203.0.113.5");
	for protocol in PROTOCOLS.into_iter().take(5) {
		assert_eq!(guess(&directory, protocol, attacker), None);
	}
	for protocol in PROTOCOLS.into_iter().chain([Protocol::Api, Protocol::Imap]) {
		assert_eq!(
			owner(&directory, protocol, attacker),
			None,
			"{protocol:?} must honour the ban the other listeners earned"
		);
	}
	assert_eq!(
		owner(&directory, Protocol::Imaps, from("198.51.100.9")),
		Some(OPEN.to_string()),
		"the ban is on the client, not on the account"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_guess_per_fresh_connection_is_still_counted() {
	let directory = directory();
	let attacker = from("203.0.113.6");
	for _ in 0..5 {
		// A new call stands for a new connection: nothing but the shared
		// store carries the count from one to the next.
		assert_eq!(guess(&directory, Protocol::Submissions, attacker), None);
	}
	assert_eq!(owner(&directory, Protocol::Submissions, attacker), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ipv6_client_changing_its_low_bits_stays_one_client() {
	let directory = directory();
	for (index, protocol) in PROTOCOLS.into_iter().take(5).enumerate() {
		let ip = from(&format!("2001:db8:1:2:{index:x}::{index:x}"));
		assert_eq!(guess(&directory, protocol, ip), None);
	}
	assert_eq!(
		owner(&directory, Protocol::Imaps, from("2001:db8:1:2:ffff::1")),
		None,
		"the whole /64 is banned"
	);
	assert_eq!(
		owner(&directory, Protocol::Imaps, from("2001:db8:1:3::1")),
		Some(OPEN.to_string()),
		"a neighbouring /64 is a different client"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_synchronised_burst_over_every_listener_ends_in_a_ban() {
	let directory = Arc::new(directory());
	let attacker = from("203.0.113.7");
	let mut tasks = Vec::new();
	for round in 0..4 {
		for protocol in PROTOCOLS {
			let directory = Arc::clone(&directory);
			tasks.push(tokio::task::spawn_blocking(move || {
				let _ = round;
				guess(&directory, protocol, attacker)
			}));
		}
	}
	for task in tasks {
		assert_eq!(task.await.expect("guess task"), None);
	}
	assert_eq!(owner(&directory, Protocol::Api, attacker), None);
	assert_eq!(
		owner(&directory, Protocol::Api, from("198.51.100.9")),
		Some(OPEN.to_string())
	);
}
