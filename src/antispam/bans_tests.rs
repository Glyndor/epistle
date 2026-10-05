//! Unit tests for the ban store: an in-memory fake of the [`BanStore`]
//! trait that asserts the policy thresholds and the backoff doubling,
//! the `clear_success` flow, the `sweep` horizon, and the fail-open path
//! when the lookup errors out. The live-database cases live in
//! `tests/database.rs`.

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
		}
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

	fn reason(&self) -> String {
		format!(
			"{} failed authentications in {} seconds",
			self.policy.threshold, self.policy.window_secs
		)
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

			if in_window >= self.policy.threshold as usize {
				let mut strikes = self.strikes.lock().expect("lock");
				let current = strikes.get(&subject).copied().unwrap_or(0);
				let next = current.saturating_add(1);
				strikes.insert(subject.clone(), next);
				drop(strikes);

				let duration = self.policy.duration_for(next);
				let info = BanInfo {
					until_secs: now_secs.saturating_add(duration.as_secs()),
					reason: self.reason(),
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
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
		let subject = subject.to_string();
		self.record_call("clear_success");
		Box::pin(async move {
			self.failures.lock().expect("lock").remove(&subject);
			self.bans.lock().expect("lock").remove(&subject);
			self.strikes.lock().expect("lock").remove(&subject);
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
			self.failures.lock().expect("lock").remove(&subject);
			self.bans.lock().expect("lock").remove(&subject);
			self.strikes.lock().expect("lock").remove(&subject);
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
async fn fake_store_success_clears_both_ban_and_failures() {
	let store = FakeBanStore::new(policy());
	let subject = "ip:203.0.113.5";
	let now: u64 = 1_700_000_000;
	for _ in 0..5 {
		store.record_failure(subject, "smtp", now).await;
	}
	assert!(store.is_banned(subject, now).await.is_some());
	store.clear_success(subject).await;
	assert!(store.is_banned(subject, now).await.is_none());
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
