//! Unit tests for the ban store: an in-memory fake of the [`BanStore`]
//! trait that asserts the policy thresholds and the backoff doubling,
//! the `clear_success` flow, the `sweep` horizon, and the fail-open path
//! when the lookup errors out. The live-database cases live in
//! `tests/db/core/database.rs`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use super::{BanInfo, BanPolicy, BanStore, subject_ip};

fn ip() -> IpAddr {
	IpAddr::from_str("203.0.113.5").expect("ip")
}

fn policy() -> BanPolicy {
	BanPolicy {
		window_secs: 60,
		threshold: 5,
		base_secs: 60,
		max_secs: 600,
		known_network_window_secs: 60 * 60,
		known_network_max_per_account: 32,
	}
}

/// A `BanStore` impl that holds state in a `Mutex<HashMap<...>>`. The
/// tests are the only callers: the listener tests swap a `FakeBanStore`
/// in for the production `PgBanStore` to assert that a banned subject
/// never reaches the password verifier, and the unit tests here drive
/// the policy thresholds directly.
#[derive(Clone)]
pub struct FakeBanStore {
	policy: BanPolicy,
	failures: Arc<Mutex<HashMap<String, Vec<u64>>>>,
	bans: Arc<Mutex<HashMap<String, BanInfo>>>,
	strikes: Arc<Mutex<HashMap<String, u32>>>,
	next_is_banned_fails: Arc<Mutex<bool>>,
	/// Per-method call counters keyed on the method name, used by the
	/// listener tests to assert the ban store is consulted on every
	/// authentication attempt from every listener.
	calls: Arc<Mutex<HashMap<&'static str, usize>>>,
	/// Allow-list entries (`network/prefix` or a bare address).
	allowed: Arc<Mutex<Vec<String>>>,
	/// Known-network bypass list: `(account, network) -> last_seen`.
	/// The fake mirrors the SQL store's throttling and eviction so a
	/// test that wires the fake to a real listener exercises the same
	/// contract the production store serves.
	known_networks: Arc<Mutex<HashMap<(String, String), u64>>>,
	/// The "next is_known_network call returns false" arming flag,
	/// mirroring `next_is_banned_fails` for the ban check. Used by the
	/// fail-closed tests.
	next_is_known_network_fails: Arc<Mutex<bool>>,
}

impl std::fmt::Debug for FakeBanStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("FakeBanStore")
			.field("policy", &self.policy)
			.finish()
	}
}

impl FakeBanStore {
	/// Build a fake with `policy`. The policy is read but not enforced
	/// inside the fake; the unit tests below are the enforcement.
	pub fn new(policy: BanPolicy) -> Self {
		Self {
			policy,
			failures: Arc::new(Mutex::new(HashMap::new())),
			bans: Arc::new(Mutex::new(HashMap::new())),
			strikes: Arc::new(Mutex::new(HashMap::new())),
			next_is_banned_fails: Arc::new(Mutex::new(false)),
			calls: Arc::new(Mutex::new(HashMap::new())),
			allowed: Arc::new(Mutex::new(Vec::new())),
			known_networks: Arc::new(Mutex::new(HashMap::new())),
			next_is_known_network_fails: Arc::new(Mutex::new(false)),
		}
	}

	/// Put an address or network on the fake's allow list.
	pub fn allow(&self, entry: &str) {
		self.allowed.lock().expect("lock").push(entry.to_string());
	}

	/// Arm the next `is_banned` call to return `None` and then clear the
	/// arming. Mirrors the "database error" path on the production store.
	pub fn fail_next_is_banned(self) -> Self {
		*self.next_is_banned_fails.lock().expect("lock") = true;
		self
	}

	/// Inject a live ban for `subject` so the listener tests can assert
	/// the directory refuses the matching authentication attempt without
	/// driving `record_failure` enough times to trip the threshold. The
	/// ban is in force until the test calls [`Self::clear_success`] or
	/// the fake is dropped.
	pub fn arm_ban(&self, subject: &str, info: BanInfo) {
		self.bans
			.lock()
			.expect("lock")
			.insert(subject.to_string(), info);
	}

	/// Inject a (account, network) entry into the bypass list at
	/// `last_seen` so the listener tests can assert the banned-but-known
	/// path without driving a full successful sign-in. The row ages
	/// out under the policy's window like a real one would.
	pub fn arm_known_network(&self, account: &str, network: &str, last_seen: u64) {
		self.known_networks
			.lock()
			.expect("lock")
			.insert((account.to_string(), network.to_string()), last_seen);
	}

	/// Arm the next `is_known_network` call to return `false` (the
	/// fail-closed posture a database error triggers) and then clear
	/// the arming. The lookup happens on every banned check, so the
	/// fail-closed contract is testable end-to-end.
	pub fn fail_next_is_known_network(self) -> Self {
		*self.next_is_known_network_fails.lock().expect("lock") = true;
		self
	}

	/// How many rows are held for this account in the bypass list. The
	/// listener tests use this to assert the cap eviction ran when a
	/// new row pushed the count past the ceiling.
	pub fn known_network_count(&self, account: &str) -> usize {
		self.known_networks
			.lock()
			.expect("lock")
			.keys()
			.filter(|(stored, _)| stored == account)
			.count()
	}

	/// The most-recent `last_seen` for the given (account, network).
	/// The tests assert the throttle skipped the write when it should
	/// have, and rewrote the row when the window had elapsed.
	pub fn known_network_last_seen(&self, account: &str, network: &str) -> Option<u64> {
		self.known_networks
			.lock()
			.expect("lock")
			.get(&(account.to_string(), network.to_string()))
			.copied()
	}

	/// How many times `method` has been called so far. The listener
	/// tests use this to assert the ban store is consulted (and not
	/// bypassed) on every authentication attempt.
	pub fn call_count(&self, method: &str) -> usize {
		self.calls
			.lock()
			.expect("lock")
			.get(method)
			.copied()
			.unwrap_or(0)
	}

	/// Bump a per-method counter. Used internally by the trait impl.
	fn record_call(&self, method: &'static str) {
		let mut calls = self.calls.lock().expect("lock");
		*calls.entry(method).or_insert(0) += 1;
	}

	/// How many failures are recorded for `subject` at or after `since`.
	pub fn failure_count(&self, subject: &str, since: u64) -> usize {
		let map = self.failures.lock().expect("lock");
		map.get(subject)
			.map(|entries| entries.iter().filter(|t| **t >= since).count())
			.unwrap_or(0)
	}
}

impl BanStore for FakeBanStore {
	fn record_failure(
		&self,
		subject: &str,
		protocol: &str,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let subject = subject.to_string();
		let _protocol = protocol.to_string();
		self.record_call("record_failure");
		Box::pin(async move {
			let mut failures = self.failures.lock().expect("lock");
			failures
				.entry(subject.to_string())
				.or_default()
				.push(now_secs);
			// Drop failures outside the window so the count matches the
			// production SQL's `seen_at >= now - window_secs` predicate.
			if let Some(entries) = failures.get_mut(&subject) {
				entries.retain(|t| *t >= now_secs.saturating_sub(self.policy.window_secs));
			}
			let in_window = failures.get(&subject).map(|v| v.len()).unwrap_or(0);
			drop(failures);

			let threshold = self.policy.threshold_for(&subject) as usize;
			if in_window >= threshold {
				let mut strikes = self.strikes.lock().expect("lock");
				let current = strikes.get(&subject).copied().unwrap_or(0);
				let next = current.saturating_add(1);
				strikes.insert(subject.clone(), next);
				drop(strikes);

				let duration = self.policy.duration_for(next);
				let info = BanInfo {
					until_secs: now_secs.saturating_add(duration.as_secs()),
					reason: format!(
						"{threshold} failed authentications in {} seconds",
						self.policy.window_secs
					),
				};
				self.bans.lock().expect("lock").insert(subject, info);
			}
		})
	}

	fn is_banned(
		&self,
		subject: &str,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<BanInfo>> + Send + '_>> {
		let subject = subject.to_string();
		self.record_call("is_banned");
		Box::pin(async move {
			if std::mem::take(&mut *self.next_is_banned_fails.lock().expect("lock")) {
				return None;
			}
			let map = self.bans.lock().expect("lock");
			map.get(&subject)
				.filter(|info| info.until_secs > now_secs)
				.cloned()
		})
	}

	fn clear_success(
		&self,
		subject: &str,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let subject = subject.to_string();
		self.record_call("clear_success");
		Box::pin(async move {
			let active = self
				.bans
				.lock()
				.expect("lock")
				.get(&subject)
				.is_some_and(|info| info.until_secs > now_secs);
			if active {
				return;
			}
			self.failures.lock().expect("lock").remove(&subject);
			self.bans.lock().expect("lock").remove(&subject);
			self.strikes.lock().expect("lock").remove(&subject);
		})
	}

	fn is_allow_listed(
		&self,
		ip: IpAddr,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
		Box::pin(async move {
			self.allowed
				.lock()
				.expect("lock")
				.iter()
				.filter_map(|entry| crate::cidr::Cidr::parse(entry))
				.any(|cidr| cidr.contains(ip))
		})
	}

	fn sweep(
		&self,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		self.record_call("sweep");
		Box::pin(async move {
			let horizon = now_secs.saturating_sub(24 * 60 * 60);
			let mut failures = self.failures.lock().expect("lock");
			for entries in failures.values_mut() {
				entries.retain(|t| *t >= horizon);
			}
			failures.retain(|_, entries| !entries.is_empty());
			drop(failures);
			let mut bans = self.bans.lock().expect("lock");
			bans.retain(|_, info| info.until_secs >= horizon);
			// The bypass list ages by the policy's known-network window,
			// not the 24h failure-log horizon. A row past its window no
			// longer lifts the ban on its (account, network); drop it so
			// the table does not grow without bound.
			let bypass_horizon = now_secs.saturating_sub(self.policy.known_network_window_secs);
			let mut known = self.known_networks.lock().expect("lock");
			known.retain(|_, last_seen| *last_seen >= bypass_horizon);
		})
	}

	fn remove_account(
		&self,
		account: &str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let account = account.to_string();
		self.record_call("remove_account");
		Box::pin(async move {
			let subject = super::subject_account(&account);
			let pair_prefix = format!("pair:{}|", account.to_ascii_lowercase());
			let ours = |key: &String| *key == subject || key.starts_with(&pair_prefix);
			self.failures
				.lock()
				.expect("lock")
				.retain(|key, _| !ours(key));
			self.bans.lock().expect("lock").retain(|key, _| !ours(key));
			self.strikes
				.lock()
				.expect("lock")
				.retain(|key, _| !ours(key));
			self.known_networks
				.lock()
				.expect("lock")
				.retain(|(stored, _), _| stored != &account);
		})
	}

	fn is_known_network(
		&self,
		account: &str,
		ip: IpAddr,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
		let account = account.to_string();
		self.record_call("is_known_network");
		Box::pin(async move {
			if std::mem::take(&mut *self.next_is_known_network_fails.lock().expect("lock")) {
				return false;
			}
			let network = super::known_network_key(ip);
			let horizon = now_secs.saturating_sub(self.policy.known_network_window_secs);
			let map = self.known_networks.lock().expect("lock");
			map.get(&(account, network))
				.is_some_and(|last_seen| *last_seen >= horizon)
		})
	}

	fn record_known_network(
		&self,
		account: &str,
		ip: IpAddr,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let account = account.to_string();
		let network = super::known_network_key(ip);
		self.record_call("record_known_network");
		Box::pin(async move {
			let mut map = self.known_networks.lock().expect("lock");
			let key = (account.clone(), network.clone());
			// Throttle: skip the write when the prior row is fresher
			// than the throttle window. Mirrors the SQL `WHERE` on the
			// UPDATE side, so a hot sign-in pattern costs one lock
			// acquisition per request and zero writes.
			if let Some(prior) = map.get(&key)
				&& now_secs.saturating_sub(*prior) < super::KNOWN_NETWORK_WRITE_THROTTLE_SECS
			{
				return;
			}
			map.insert(key, now_secs);
			drop(map);
			// Cap eviction: keep at most `known_network_max_per_account`
			// rows per account, evicting the oldest one when the count
			// is past the ceiling. The just-written row has the highest
			// `last_seen`, so once the list is sorted ascending the rows
			// past rank `cap` are exactly the oldest ones (those that
			// have not been used most recently).
			let cap = self.policy.known_network_max_per_account as usize;
			let mut map = self.known_networks.lock().expect("lock");
			let mut entries: Vec<(String, String, u64)> = map
				.iter()
				.filter(|((stored, _), _)| stored == &account)
				.map(|((stored, network), last_seen)| (stored.clone(), network.clone(), *last_seen))
				.collect();
			entries.sort_by_key(|(_, _, last_seen)| std::cmp::Reverse(*last_seen));
			// Rows past rank `cap` (the oldest) get removed.
			for (stored, network, _) in entries.into_iter().skip(cap) {
				map.remove(&(stored, network));
			}
		})
	}
}

#[test]
fn duration_for_doubles_and_caps() {
	let p = policy();
	assert_eq!(p.duration_for(1).as_secs(), 60);
	assert_eq!(p.duration_for(2).as_secs(), 120);
	assert_eq!(p.duration_for(3).as_secs(), 240);
	assert_eq!(p.duration_for(4).as_secs(), 480);
	assert_eq!(p.duration_for(5).as_secs(), 600);
	assert_eq!(p.duration_for(6).as_secs(), 600);
	assert_eq!(p.duration_for(20).as_secs(), 600);
}

#[test]
fn subject_helpers_are_stable() {
	assert_eq!(subject_ip(ip()), "ip:203.0.113.5");
	assert_eq!(super::subject_account("Alice"), "account:alice");
}

#[tokio::test]
async fn fake_store_ban_lifecycle() {
	let store = FakeBanStore::new(policy());
	let subject = "ip:203.0.113.5";
	let now: u64 = 1_700_000_000;

	for _ in 0..4 {
		store.record_failure(subject, "smtp", now).await;
	}
	assert!(store.is_banned(subject, now).await.is_none());
	assert_eq!(store.failure_count(subject, now.saturating_sub(60)), 4);

	store.record_failure(subject, "smtp", now).await;
	let info = store.is_banned(subject, now).await.expect("banned");
	assert!(info.until_secs >= now + 60);
	assert_eq!(info.reason, "5 failed authentications in 60 seconds");
}

#[tokio::test]
async fn fake_store_second_ban_doubles_the_duration() {
	let store = FakeBanStore::new(policy());
	let subject = "ip:203.0.113.5";
	let now: u64 = 1_700_000_000;

	// First ban fires after 5 failures (the 5th trips the threshold).
	for _ in 0..5 {
		store.record_failure(subject, "smtp", now).await;
	}
	let first = store.is_banned(subject, now).await.expect("banned");
	assert_eq!(first.until_secs - now, 60);
	// One more failure re-fires the upsert: the existing ban is found,
	// strikes goes from 1 to 2, and the new duration is base * 2 = 120.
	store.record_failure(subject, "smtp", now).await;
	let second = store.is_banned(subject, now).await.expect("banned");
	assert!(
		second.until_secs > first.until_secs,
		"second ban {} should be longer than first {}",
		second.until_secs,
		first.until_secs
	);
	assert_eq!(second.until_secs - now, 120);
}

#[tokio::test]
async fn fake_store_backoff_caps_at_max_secs() {
	let store = FakeBanStore::new(policy());
	let subject = "ip:203.0.113.5";
	let now: u64 = 1_700_000_000;
	// Trip the threshold once: 5 failures → strikes = 1, 60s.
	for _ in 0..5 {
		store.record_failure(subject, "smtp", now).await;
	}
	let mut info = store.is_banned(subject, now).await.expect("banned");
	assert_eq!(info.until_secs - now, 60);
	// Keep recording failures: each one past the threshold increments
	// strikes and re-upserts the ban with the doubled duration. The cap
	// at 600s should hold once the doubling reaches it.
	let mut expected: u64 = 60;
	for i in 6..=15 {
		store.record_failure(subject, "smtp", now).await;
		info = store.is_banned(subject, now).await.expect("banned");
		expected = expected.saturating_mul(2).min(600);
		assert_eq!(
			info.until_secs - now,
			expected,
			"failure #{i}: duration should be {expected}s"
		);
	}
}

#[tokio::test]
async fn fake_store_success_cannot_lift_an_active_ban() {
	let store = FakeBanStore::new(policy());
	let subject = "ip:203.0.113.5";
	let now: u64 = 1_700_000_000;
	for _ in 0..5 {
		store.record_failure(subject, "smtp", now).await;
	}
	assert!(store.is_banned(subject, now).await.is_some());
	store.clear_success(subject, now).await;
	assert!(store.is_banned(subject, now).await.is_some());
	assert_eq!(store.failure_count(subject, 0), 5);
}

#[tokio::test]
async fn fake_store_success_clears_the_failures_once_the_ban_is_spent() {
	let store = FakeBanStore::new(policy());
	let subject = "ip:203.0.113.5";
	let now: u64 = 1_700_000_000;
	for _ in 0..5 {
		store.record_failure(subject, "smtp", now).await;
	}
	let after_ban = now + policy().base_secs + 1;
	assert!(store.is_banned(subject, after_ban).await.is_none());
	store.clear_success(subject, after_ban).await;
	assert_eq!(store.failure_count(subject, 0), 0);
}

#[tokio::test]
async fn fake_store_sweep_drops_old_rows() {
	let store = FakeBanStore::new(policy());
	let subject = "ip:203.0.113.5";
	let old: u64 = 1_700_000_000;
	store.record_failure(subject, "smtp", old).await;
	store.sweep(old + 25 * 60 * 60).await;
	assert_eq!(store.failure_count(subject, 0), 0);
}

#[tokio::test]
async fn fake_store_database_error_is_not_a_ban() {
	let store = FakeBanStore::new(policy()).fail_next_is_banned();
	let subject = "ip:203.0.113.5";
	let now: u64 = 1_700_000_000;
	assert!(store.is_banned(subject, now).await.is_none());
}
