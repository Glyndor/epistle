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
async fn typos_behind_an_allow_listed_proxy_do_not_lock_one_account_out_of_it() {
	let store = FakeBanStore::new(BanPolicy::default());
	store.allow("203.0.113.0/24");
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store.clone()));
	for _ in 0..5 {
		fail(&directory, OPEN, "203.0.113.7");
	}
	assert_eq!(
		store.failure_count("pair:alice|203.0.113.7", 0),
		0,
		"the pair of a trusted client is not counted"
	);
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "203.0.113.7"),
		Some(OPEN.to_string()),
		"the owner behind the same proxy still signs in"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_allow_listed_host_is_still_stopped_by_the_account_ceiling() {
	let store = FakeBanStore::new(BanPolicy::default());
	store.allow("203.0.113.0/24");
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store));
	for _ in 0..19 {
		fail(&directory, OPEN, "203.0.113.7");
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "203.0.113.7"),
		Some(OPEN.to_string()),
		"nineteen failures are under the account's limit"
	);
	for _ in 0..20 {
		fail(&directory, OPEN, "203.0.113.7");
	}
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "198.51.100.9"),
		None,
		"twenty in the window ban the account, trusted network or not"
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

/// The ban store calls (`is_banned`, `record_failure`, `clear_success`) one
/// failed attempt for `login` makes.
fn store_calls_for_a_failure(login: &str) -> (usize, usize) {
	let store = FakeBanStore::new(BanPolicy::default());
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store.clone()));
	fail(&directory, login, "203.0.113.5");
	(
		store.call_count("is_banned"),
		store.call_count("record_failure"),
	)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_login_costs_the_ban_store_what_a_real_one_does() {
	// With PostgreSQL behind it each call is a round trip or a transaction, and
	// SCRAM has no password hash to hide the difference, so a login that
	// touched the store less would be told apart by its time.
	let real = store_calls_for_a_failure(OPEN);
	assert!(real.0 >= 3 && real.1 >= 3, "a real account: {real:?}");
	assert_eq!(store_calls_for_a_failure("nobody-here"), real, "unknown");
	assert_eq!(store_calls_for_a_failure(DISABLED), real, "disabled");
}

fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_unknown_login_is_banned_on_its_own_like_a_real_account() {
	use crate::antispam::bans::{BanStore, subject_account};
	let store = FakeBanStore::new(BanPolicy::default());
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store.clone()));
	// Twenty clients, one failure each: what bans a real account.
	for host in 1..=20 {
		fail(&directory, "ghost-one", &format!("203.0.113.{host}"));
		fail(&directory, OPEN, &format!("198.51.100.{host}"));
	}
	let one = subject_account(&Directory::decoy_account("ghost-one"));
	let other = subject_account(&Directory::decoy_account("ghost-two"));
	assert_ne!(one, other, "a stand-in per login");
	assert!(
		store.is_banned(&one, unix_now()).await.is_some(),
		"the stand-in reaches the same ban as a real account"
	);
	assert!(
		store
			.is_banned(&subject_account(OPEN), unix_now())
			.await
			.is_some()
	);
	assert!(
		store.is_banned(&other, unix_now()).await.is_none(),
		"and another unknown login is not touched by it"
	);
	assert_eq!(store.failure_count(&other, 0), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotating_through_the_slash_64s_of_one_slash_48_ends_in_a_ban_of_the_slash_48() {
	let directory = directory();
	// Four failures from each of ten /64s of 2001:db8:aa::/48, a different
	// login each time (spraying): no /64 reaches its five and no account its
	// twenty, and together they are the forty a /48 is allowed.
	for slash64 in 0..10 {
		for host in 1..=4 {
			fail(
				&directory,
				&format!("spray-{slash64}-{host}"),
				&format!("2001:db8:aa:{slash64:x}::{host:x}"),
			);
		}
	}
	assert_eq!(
		attempt(
			&directory,
			OPEN,
			fixtures::password(),
			"2001:db8:aa:7fff::1"
		),
		None,
		"a /64 that never failed, in the banned /48"
	);
	assert_eq!(
		attempt(&directory, OPEN, fixtures::password(), "2001:db8:ab::1"),
		Some(OPEN.to_string()),
		"another /48 is untouched"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_allow_listed_host_is_not_counted_on_its_slash_48() {
	let store = FakeBanStore::new(BanPolicy::default());
	store.allow("2001:db8:aa::10/128");
	let directory = gate_directory().with_ban_store(std::sync::Arc::new(store.clone()));
	for _ in 0..30 {
		fail(&directory, OPEN, "2001:db8:aa::10");
	}
	assert_eq!(store.failure_count("net:2001:db8:aa::/48", 0), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slash_48_is_not_banned_below_forty_failures() {
	let directory = directory();
	for slash64 in 0..10 {
		for host in 1..=3 {
			fail(
				&directory,
				&format!("spray-{slash64}-{host}"),
				&format!("2001:db8:aa:{slash64:x}::{host:x}"),
			);
		}
	}
	assert_eq!(
		attempt(
			&directory,
			OPEN,
			fixtures::password(),
			"2001:db8:aa:7fff::1"
		),
		Some(OPEN.to_string()),
		"thirty failures in a /48 are under its forty"
	);
}
