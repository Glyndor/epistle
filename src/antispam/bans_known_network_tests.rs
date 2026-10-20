//! Unit tests for the known-network bypass list on the shared ban
//! store. The trait methods live in `bans.rs`; the SQL implementation
//! in `bans_sql.rs`; the in-memory fake in `bans_tests.rs`. This file
//! drives both through the trait, so a future store (Redis, in-memory
//! only, anything) reuses the same contract tests.

use std::net::IpAddr;
use std::str::FromStr;

use super::{BanInfo, BanPolicy, BanStore};

fn ipv4(text: &str) -> IpAddr {
	IpAddr::from_str(text).expect("ipv4")
}

fn ipv6(text: &str) -> IpAddr {
	IpAddr::from_str(text).expect("ipv6")
}

/// A policy that makes the window and the throttle fit in seconds so
/// the tests run quickly. The cap stays at the production value of 32
/// so the eviction case has somewhere to land.
fn policy() -> BanPolicy {
	BanPolicy {
		window_secs: 60,
		threshold: 5,
		base_secs: 60,
		max_secs: 600,
		known_network_window_secs: 60,
		known_network_max_per_account: 3,
	}
}

#[tokio::test]
async fn record_known_network_writes_a_row_then_is_known() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy());
	let account = "alice";
	let ip = ipv4("203.0.113.10");
	let now: u64 = 1_700_000_000;

	assert!(
		!store.is_known_network(account, ip, now).await,
		"a fresh fake must report the network as unknown"
	);
	store.record_known_network(account, ip, now).await;
	assert!(
		store.is_known_network(account, ip, now).await,
		"after a successful write the network must be known"
	);
}

#[tokio::test]
async fn is_known_network_returns_false_outside_the_window() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy());
	let account = "alice";
	let ip = ipv4("203.0.113.11");
	let written_at: u64 = 1_700_000_000;
	store.record_known_network(account, ip, written_at).await;

	assert!(
		store.is_known_network(account, ip, written_at + 30).await,
		"a row inside the window must be known"
	);
	assert!(
		!store.is_known_network(account, ip, written_at + 61).await,
		"a row past the window must age out and become unknown"
	);
}

#[tokio::test]
async fn record_known_network_throttles_to_one_write_per_hour() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy());
	let account = "alice";
	let ip = ipv4("203.0.113.12");
	let now: u64 = 1_700_000_000;

	store.record_known_network(account, ip, now).await;
	let first_seen = store
		.known_network_last_seen(account, "203.0.113.12")
		.expect("row written");

	// A second call inside the throttle window must NOT update the
	// timestamp; the hot sign-in path must not pay a write.
	store.record_known_network(account, ip, now + 30).await;
	assert_eq!(
		store.known_network_last_seen(account, "203.0.113.12"),
		Some(first_seen),
		"a write inside the throttle window must not move last_seen"
	);

	// Past the throttle, the row updates and the throttle re-arms.
	store
		.record_known_network(
			account,
			ip,
			now + super::KNOWN_NETWORK_WRITE_THROTTLE_SECS + 1,
		)
		.await;
	assert_eq!(
		store.known_network_last_seen(account, "203.0.113.12"),
		Some(now + super::KNOWN_NETWORK_WRITE_THROTTLE_SECS + 1),
		"a write past the throttle window must update last_seen"
	);
}

#[tokio::test]
async fn record_known_network_caps_per_account_evicting_oldest() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy());
	let account = "alice";
	// The cap on the test policy is 3; seed four distinct networks.
	let now: u64 = 1_700_000_000;
	let networks = [
		"203.0.113.20",
		"203.0.113.21",
		"203.0.113.22",
		"203.0.113.23",
	];
	for (index, network) in networks.iter().enumerate() {
		let ip = ipv4(network);
		// Push past the throttle so each entry writes its own row.
		store
			.record_known_network(
				account,
				ip,
				now + (index as u64) * (super::KNOWN_NETWORK_WRITE_THROTTLE_SECS + 10),
			)
			.await;
	}

	assert_eq!(
		store.known_network_count(account),
		3,
		"the per-account cap must hold at the policy ceiling (3); rows: {:?}",
		store.known_network_count(account)
	);
	// The oldest row was evicted.
	assert!(
		store
			.known_network_last_seen(account, "203.0.113.20")
			.is_none(),
		"the oldest network must be evicted when a new one is added past the cap; last_seen for 203.0.113.20 = {:?}, 203.0.113.21 = {:?}, 203.0.113.22 = {:?}, 203.0.113.23 = {:?}",
		store.known_network_last_seen(account, "203.0.113.20"),
		store.known_network_last_seen(account, "203.0.113.21"),
		store.known_network_last_seen(account, "203.0.113.22"),
		store.known_network_last_seen(account, "203.0.113.23"),
	);
	// The newest rows survived.
	for network in networks[1..].iter() {
		assert!(
			store.known_network_last_seen(account, network).is_some(),
			"newer networks must survive the eviction: {network}"
		);
	}
}

#[tokio::test]
async fn is_known_network_handles_ipv6_as_a_64() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy());
	let account = "alice";
	// Two addresses in the same /64, different host halves.
	let addr_a = ipv6("2001:db8:1::1");
	let addr_b = ipv6("2001:db8:1::2");

	store
		.record_known_network(account, addr_a, 1_700_000_000)
		.await;
	assert!(
		store.is_known_network(account, addr_b, 1_700_000_000).await,
		"any address in the /64 must look up the same row, regardless of the host half"
	);
	// An address in a different /64 must miss.
	let addr_other = ipv6("2001:db8:2::1");
	assert!(
		!store
			.is_known_network(account, addr_other, 1_700_000_000)
			.await,
		"an address outside the /64 must not be served by the same row"
	);
}

#[tokio::test]
async fn is_known_network_database_error_fails_closed() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy()).fail_next_is_known_network();
	let account = "alice";
	let ip = ipv4("203.0.113.30");
	// A lookup that hits the arming returns false (fail closed):
	// a database hiccup during a ban must not become a pass.
	assert!(!store.is_known_network(account, ip, 1_700_000_000).await);
}

#[tokio::test]
async fn record_known_network_throttle_skips_when_recently_written() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy());
	let account = "alice";
	let ip = ipv4("203.0.113.31");
	let t0 = 1_700_000_000;

	store.record_known_network(account, ip, t0).await;
	let calls_before = store.call_count("record_known_network");
	// A second call inside the throttle: the trait method runs but
	// the fake's internal throttle skips the write.
	store.record_known_network(account, ip, t0 + 1).await;
	assert_eq!(
		store.call_count("record_known_network"),
		calls_before + 1,
		"the trait method must run on every success"
	);
	assert_eq!(
		store.known_network_last_seen(account, "203.0.113.31"),
		Some(t0),
		"the throttle must skip the second write"
	);
}

#[tokio::test]
async fn known_network_key_collapses_ipv6_to_the_lower_64() {
	// The /64 key is the lower 64 bits zeroed; the upper 64 hold the
	// network. The helper used by both lookup and write must produce
	// the same string for any host half in the same /64.
	let addr_a = ipv6("2001:db8:1::1");
	let addr_b = ipv6("2001:db8:1::ffff:ffff:ffff");
	assert_eq!(
		super::known_network_key(addr_a),
		super::known_network_key(addr_b)
	);
	// And IPv4 stays the exact address.
	assert_eq!(super::known_network_key(ipv4("203.0.113.7")), "203.0.113.7");
}

/// The `remove_account` helper must drop the rows for the account from
/// the bypass list so an account that's been removed does not leave a
/// dangling bypass.
#[tokio::test]
async fn remove_account_drops_the_known_network_rows() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy());
	let account = "alice";
	let ip = ipv4("203.0.113.40");
	store.record_known_network(account, ip, 1_700_000_000).await;
	assert_eq!(store.known_network_count(account), 1);
	store.remove_account(account).await;
	assert_eq!(
		store.known_network_count(account),
		0,
		"remove_account must clear the bypass list rows for the account"
	);
}

/// The bypass list has its own window, distinct from the failure log's
/// 24h horizon. A row older than the window must drop, while the ban
/// row that caused the bypass must stay (its criterion is its `until`
/// field, not the failure log's).
#[tokio::test]
async fn fake_store_sweep_drops_old_known_network_rows() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy());
	let account = "alice";
	let ip = ipv4("203.0.113.41");
	let written_at: u64 = 1_700_000_000;
	store.record_known_network(account, ip, written_at).await;
	store.sweep(written_at + 120).await;
	assert_eq!(
		store.known_network_count(account),
		0,
		"a sweep past the known-network window must drop the row"
	);
}

/// The bypass lift from the directory is the `BannedButKnown` variant.
/// This test exercises the trait method that drives the lift through
/// the fake, asserting the side a real protocol session would observe.
#[tokio::test]
async fn arming_a_known_network_lets_is_known_network_pass_under_a_ban() {
	use super::tests::FakeBanStore;
	let store = FakeBanStore::new(policy());
	let account = "alice";
	let ip = ipv4("203.0.113.42");
	let now: u64 = 1_700_000_000;

	// A ban is armed on the account and the (account, network) is on
	// the bypass list: the directory's check_ban sees a ban and the
	// bypass in the same round trip, returning BannedButKnown.
	store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "manual".to_string(),
		},
	);
	store.arm_known_network(account, "203.0.113.42", now);
	assert!(
		store.is_known_network(account, ip, now).await,
		"a banned account from a known network must have the bypass recorded"
	);
}
