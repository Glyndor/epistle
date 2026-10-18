//! What counts toward a ban: failures from a client are not reset by that
//! client's successes, an IPv6 client is its /64, and one client alone cannot
//! lock an account out for everyone else.

use std::net::IpAddr;

use super::Directory;
use super::gate_fixture::*;
use crate::antispam::bans::BanPolicy;
use crate::antispam::bans::tests::FakeBanStore;
use crate::config::Protocol;
use crate::test_fixtures as fixtures;

fn directory() -> Directory {
	gate_directory().with_ban_store(std::sync::Arc::new(FakeBanStore::new(BanPolicy::default())))
}

fn ip(text: &str) -> Option<IpAddr> {
	Some(text.parse().expect("address"))
}

fn attempt(directory: &Directory, login: &str, password: &str, from: &str) -> Option<String> {
	directory.authenticate_with_ip(login, password, ip(from), Protocol::Imaps)
}

fn fail(directory: &Directory, login: &str, from: &str) {
	assert_eq!(
		attempt(directory, login, fixtures::wrong_password(), from),
		None
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clients_own_successes_do_not_reset_its_failure_count() {
	let directory = directory();
	let attacker = "203.0.113.5";
	for _ in 0..4 {
		fail(&directory, TWO_FACTOR, attacker);
		assert_eq!(
			attempt(&directory, OPEN, fixtures::password(), attacker),
			Some(OPEN.to_string()),
			"its own account still signs in while it is under the threshold"
		);
	}
	fail(&directory, TWO_FACTOR, attacker);
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), attacker),
		None,
		"five failures in the window ban the client whatever it succeeded at in between"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_client_cannot_lock_an_account_for_everyone() {
	let directory = directory();
	for _ in 0..5 {
		fail(&directory, OPEN, "203.0.113.5");
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "203.0.113.5"),
		None,
		"the guessing client is banned"
	);
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "198.51.100.9"),
		Some(OPEN.to_string()),
		"the owner, from elsewhere, is not"
	);
}

/// `clients` distinct clients each fail `each` times against `alice`, then the
/// owner signs in from elsewhere.
fn owner_after(clients: u8, each: usize) -> Option<String> {
	let directory = directory();
	for client in 1..=clients {
		for _ in 0..each {
			fail(&directory, OPEN, &format!("203.0.113.{client}"));
		}
	}
	attempt(&directory, OPEN, fixtures::password(), "198.51.100.9")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn several_clients_each_exhausting_their_budget_lock_the_account() {
	assert_eq!(
		owner_after(3, 5),
		Some(OPEN.to_string()),
		"three clients are not enough"
	);
	assert_eq!(
		owner_after(4, 5),
		None,
		"four clients, five failures each, lock it"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_guess_spread_over_many_clients_each_under_the_limit_still_ends_in_a_ban() {
	// Two failures each is far below what bans a client or a pair.
	assert_eq!(
		owner_after(9, 2),
		Some(OPEN.to_string()),
		"eighteen failures are under the account limit"
	);
	assert_eq!(owner_after(10, 2), None, "twenty failures lock the account");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ipv6_client_is_its_slash_64() {
	let directory = directory();
	for last in 1..=5 {
		fail(&directory, TWO_FACTOR, &format!("2001:db8:1:2::{last}"));
	}
	assert_eq!(
		attempt(
			&directory,
			OPEN,
			fixtures::password(),
			"2001:db8:1:2:aaaa::9"
		),
		None,
		"rotating inside the /64 does not escape the ban"
	);
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "2001:db8:1:3::1"),
		Some(OPEN.to_string()),
		"another /64 is another client"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_banned_pair_refuses_that_account_from_that_client_only() {
	use crate::antispam::bans::BanInfo;
	let store = FakeBanStore::new(BanPolicy::default());
	store.arm_ban(
		"pair:alice|203.0.113.5",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store));
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "203.0.113.5"),
		None
	);
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "203.0.113.6"),
		Some(OPEN.to_string())
	);
	assert_eq!(
		attempt(
			&directory,
			TWO_FACTOR,
			&format!("{}{}", fixtures::password(), current_totp_code()),
			"203.0.113.5"
		),
		Some(TWO_FACTOR.to_string()),
		"the same client is fine for another account"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_allow_listed_host_is_not_locked_out_by_a_neighbour_in_its_slash_64() {
	let store = FakeBanStore::new(BanPolicy::default());
	store.allow("2001:db8:1:2::10/128");
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store));
	for last in 1..=5 {
		fail(&directory, TWO_FACTOR, &format!("2001:db8:1:2::{last}"));
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "2001:db8:1:2::99"),
		None,
		"the neighbours' /64 is banned"
	);
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "2001:db8:1:2::10"),
		Some(OPEN.to_string()),
		"the allow-listed host in the same /64 is not"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_allow_listed_hosts_failures_never_ban_its_address_or_slash_64() {
	let store = FakeBanStore::new(BanPolicy::default());
	store.allow("2001:db8:1:2::10/128");
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store.clone()));
	for _ in 0..30 {
		fail(&directory, OPEN, "2001:db8:1:2::10");
	}
	assert_eq!(
		store.failure_count("ip:2001:db8:1:2::", 0),
		0,
		"the /64 was not counted"
	);
	assert_eq!(
		attempt(
			&directory,
			TWO_FACTOR,
			&format!("{}{}", fixtures::password(), current_totp_code()),
			"2001:db8:1:2::99"
		),
		Some(TWO_FACTOR.to_string()),
		"a neighbour is not affected"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failures_from_a_trusted_network_still_count_against_the_account() {
	// Ten allow-listed hosts, two failures each: none comes near a client or
	// pair limit, and together they are the guess the account limit exists for.
	let store = FakeBanStore::new(BanPolicy::default());
	store.allow("203.0.113.0/24");
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store));
	for host in 1..=10 {
		for _ in 0..2 {
			fail(&directory, OPEN, &format!("203.0.113.{host}"));
		}
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "198.51.100.9"),
		None,
		"the account is banned, trusted network or not"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_allow_listed_host_is_still_stopped_by_its_pair() {
	let store = FakeBanStore::new(BanPolicy::default());
	store.allow("203.0.113.0/24");
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store));
	for _ in 0..5 {
		fail(&directory, OPEN, "203.0.113.7");
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "203.0.113.7"),
		None
	);
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "198.51.100.9"),
		Some(OPEN.to_string()),
		"and cannot lock the account for its owner"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_client_address_the_account_is_stopped_at_the_base_threshold() {
	let directory = directory();
	let guess = |times: usize| {
		for _ in 0..times {
			assert_eq!(
				directory.authenticate(OPEN, fixtures::wrong_password(), Protocol::Imaps),
				None
			);
		}
	};
	guess(4);
	assert_eq!(
		directory.authenticate(OPEN, fixtures::password(), Protocol::Imaps),
		Some(OPEN.to_string()),
		"four failures are under the limit"
	);
	guess(5);
	assert_eq!(
		directory.authenticate(OPEN, fixtures::password(), Protocol::Imaps),
		None,
		"five failures without an address ban the account, not twenty"
	);
}
