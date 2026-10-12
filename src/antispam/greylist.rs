//! Greylisting: defer the first delivery attempt from an unseen
//! (client, sender, recipient) triplet, accepting it once the sender retries
//! after a short delay.
//!
//! Legitimate MTAs retry on a 4xx; many spam sources do not, so a brief
//! tempfail filters a lot of junk at almost no cost to real mail. The decision
//! is pure given a store and a clock, so it is fully unit-testable; the store
//! implementation (memory or PostgreSQL) and SMTP wiring are layered on top.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

/// The identity greylisting keys on (RFC-less convention): client IP, envelope
/// sender, and one recipient.
pub struct Triplet<'a> {
	/// The connecting MTA's IP address. This is the SMTP `peer` for the
	/// session, not the envelope sender's domain.
	pub client_ip: IpAddr,
	/// Envelope sender (`MAIL FROM`), without the surrounding angle brackets.
	/// Compared case-insensitively so case variants collapse to one entry.
	pub sender: &'a str,
	/// One envelope recipient (`RCPT TO`), without angle brackets. Compared
	/// case-insensitively. Greylisting keys on each recipient separately,
	/// not on the message as a whole.
	pub recipient: &'a str,
}

impl Triplet<'_> {
	/// A stable key for this triplet. The sender and recipient are lowercased
	/// so case variations map to the same entry.
	pub fn key(&self) -> String {
		format!(
			"{}|{}|{}",
			self.client_ip,
			self.sender.to_ascii_lowercase(),
			self.recipient.to_ascii_lowercase(),
		)
	}
}

/// What to do with a delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
	/// Tempfail (4xx): the triplet is new or has not waited out the delay.
	Defer,
	/// Accept: the sender retried after the delay, as a real MTA does.
	Accept,
}

/// The boxed future every [`GreylistStore`] method returns. Boxed so the
/// production PostgreSQL store and the in-process test stub share the same
/// `Arc<dyn GreylistStore>` shape the SMTP server holds.
pub type StoreFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Records when each triplet was first seen, and remembers the retry. The
/// trait is object-safe and object-dispatched: SMTP holds `Arc<dyn
/// GreylistStore>` and the production wiring in `cli/serve_tasks.rs` chooses
/// the backing store. Both methods are async because the production
/// PostgreSQL store is; the in-memory implementation just returns an
/// already-ready future.
pub trait GreylistStore: Send + Sync {
	/// The UNIX time the triplet was first seen, if ever.
	fn first_seen(&self, key: &str) -> StoreFuture<'_, Option<u64>>;
	/// Remember that the triplet was first seen at `now`.
	fn record(&self, key: &str, now: u64) -> StoreFuture<'_, ()>;
	/// Drop entries first seen more than `max_age` seconds before `now`, so
	/// the store cannot grow without bound. Called by the periodic sweep
	/// the `serve` task spawns; no-op on stores where expiration is the
	/// sweeper's job.
	fn sweep(&self, _now: u64, _max_age: u64) -> StoreFuture<'_, ()> {
		Box::pin(async {})
	}
}

/// Decide whether to accept or defer an attempt from `triplet` at `now`,
/// accepting once `delay_secs` have passed since the first attempt.
pub async fn decide(
	store: &dyn GreylistStore,
	triplet: &Triplet<'_>,
	now: u64,
	delay_secs: u64,
) -> Decision {
	let key = triplet.key();
	match store.first_seen(&key).await {
		// First sighting: remember it and defer.
		None => {
			store.record(&key, now).await;
			Decision::Defer
		}
		// Retried after the delay: a real MTA, accept.
		Some(first_seen) if now.saturating_sub(first_seen) >= delay_secs => Decision::Accept,
		// Retried too soon: keep deferring.
		Some(_) => Decision::Defer,
	}
}

/// An in-memory greylist store: a process-local map of first-seen times.
/// State is ephemeral; a restart re-defers everyone once, which is harmless
/// but means legitimate senders wait out the delay again. The PostgreSQL
/// store is the alternative when persistence matters.
#[derive(Default)]
pub struct MemoryGreylist {
	entries: Mutex<HashMap<String, u64>>,
}

impl MemoryGreylist {
	/// An empty store.
	pub fn new() -> Self {
		Self::default()
	}

	/// Drop entries first seen more than `max_age` seconds before `now`, so the
	/// map cannot grow without bound.
	pub fn prune(&self, now: u64, max_age: u64) {
		self.entries
			.lock()
			.expect("greylist lock")
			.retain(|_, first_seen| now.saturating_sub(*first_seen) < max_age);
	}
}

impl GreylistStore for MemoryGreylist {
	fn first_seen(&self, key: &str) -> StoreFuture<'_, Option<u64>> {
		// The lock is sync; performing the work inside `async {}` keeps the
		// trait surface uniform with the SQL store and avoids a second await
		// point in callers.
		let value = self
			.entries
			.lock()
			.expect("greylist lock")
			.get(key)
			.copied();
		Box::pin(async move { value })
	}
	fn record(&self, key: &str, now: u64) -> StoreFuture<'_, ()> {
		self.entries
			.lock()
			.expect("greylist lock")
			.entry(key.to_string())
			.or_insert(now);
		Box::pin(async {})
	}
	fn sweep(&self, now: u64, max_age: u64) -> StoreFuture<'_, ()> {
		self.prune(now, max_age);
		Box::pin(async {})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn triplet() -> Triplet<'static> {
		Triplet {
			client_ip: "192.0.2.10".parse().unwrap(),
			sender: "Sender@Example.org",
			recipient: "Bob@Example.net",
		}
	}

	const DELAY: u64 = 60;

	fn block_on<F: std::future::Future>(future: F) -> F::Output {
		let runtime = tokio::runtime::Runtime::new().expect("runtime");
		runtime.block_on(future)
	}

	/// Run the same decision cases against every implementation of the
	/// store trait. Returns them so the per-test assertion can target a
	/// specific outcome (deferred, recorded, accepted...) without only
	/// asserting "did not panic" or "returned something".
	fn run_against(store: &dyn GreylistStore) {
		let t = triplet();
		let key = t.key();
		// First sighting: defer and remember it.
		assert_eq!(block_on(decide(store, &t, 1000, DELAY)), Decision::Defer);
		assert_eq!(block_on(store.first_seen(&key)), Some(1000));
		// Retry too soon: still defer (first_seen unchanged).
		assert_eq!(block_on(decide(store, &t, 1030, DELAY)), Decision::Defer);
		assert_eq!(block_on(store.first_seen(&key)), Some(1000));
		// Retry past the delay: accept.
		assert_eq!(block_on(decide(store, &t, 1060, DELAY)), Decision::Accept);
	}

	#[test]
	fn first_attempt_is_deferred_and_recorded() {
		let store = MemoryGreylist::new();
		let t = triplet();
		assert_eq!(block_on(decide(&store, &t, 1000, DELAY)), Decision::Defer);
		assert_eq!(block_on(store.first_seen(&t.key())), Some(1000));
	}

	#[test]
	fn retry_before_delay_is_deferred() {
		let store = MemoryGreylist::new();
		block_on(decide(&store, &triplet(), 1000, DELAY));
		assert_eq!(
			block_on(decide(&store, &triplet(), 1030, DELAY)),
			Decision::Defer
		);
	}

	#[test]
	fn retry_after_delay_is_accepted() {
		let store = MemoryGreylist::new();
		block_on(decide(&store, &triplet(), 1000, DELAY));
		assert_eq!(
			block_on(decide(&store, &triplet(), 1060, DELAY)),
			Decision::Accept
		);
	}

	#[test]
	fn key_is_case_insensitive() {
		let lower = Triplet {
			client_ip: "192.0.2.10".parse().unwrap(),
			sender: "sender@example.org",
			recipient: "bob@example.net",
		};
		assert_eq!(triplet().key(), lower.key());
	}

	#[test]
	fn memory_store_roundtrips_and_prunes() {
		let store = MemoryGreylist::new();
		assert_eq!(
			block_on(decide(&store, &triplet(), 1000, DELAY)),
			Decision::Defer
		);
		// Recorded, so a later retry past the delay is accepted.
		assert_eq!(
			block_on(decide(&store, &triplet(), 1100, DELAY)),
			Decision::Accept
		);
		// Pruning old entries forgets the triplet; it is new again.
		block_on(store.sweep(1000 + 86_400, 3600));
		assert_eq!(block_on(store.first_seen(&triplet().key())), None);
	}

	#[test]
	fn distinct_triplets_are_independent() {
		let store = MemoryGreylist::new();
		block_on(decide(&store, &triplet(), 1000, DELAY));
		let other = Triplet {
			client_ip: "198.51.100.1".parse().unwrap(),
			sender: "sender@example.org",
			recipient: "bob@example.net",
		};
		// A different client is still on its first attempt.
		assert_eq!(
			block_on(decide(&store, &other, 1100, DELAY)),
			Decision::Defer
		);
	}

	/// The memory store is the production default. Pinning it to the
	/// shared contract catches divergence even before the SQL store test
	/// runs (and the SQL test is gated on a live database).
	#[test]
	fn memory_store_matches_the_decision_contract() {
		let store = MemoryGreylist::new();
		run_against(&store);
	}
}
