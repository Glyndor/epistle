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
	/// The UNIX time the triplet was first seen, if ever. `Err` means the
	/// store could not answer (the database is unreachable), which
	/// [`decide`] treats as "accept" rather than as a first sighting.
	fn first_seen(&self, key: &str) -> StoreFuture<'_, Result<Option<u64>, StoreUnavailable>>;
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

/// The store could not be read. Carries no detail: the store logs the cause
/// where it has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreUnavailable;

/// Decide whether to accept or defer an attempt from `triplet` at `now`,
/// accepting once `delay_secs` have passed since the first attempt.
///
/// A store that cannot answer accepts. Greylisting is a filter, not a gate:
/// treating an unreachable database as a first sighting would defer every
/// inbound message on every retry for as long as the outage lasts, until the
/// senders give up and bounce it.
pub async fn decide(
	store: &dyn GreylistStore,
	triplet: &Triplet<'_>,
	now: u64,
	delay_secs: u64,
) -> Decision {
	let key = triplet.key();
	match store.first_seen(&key).await {
		Err(StoreUnavailable) => Decision::Accept,
		// First sighting: remember it and defer.
		Ok(None) => {
			store.record(&key, now).await;
			Decision::Defer
		}
		// Retried after the delay: a real MTA, accept.
		Ok(Some(first_seen)) if now.saturating_sub(first_seen) >= delay_secs => Decision::Accept,
		// Retried too soon: keep deferring.
		Ok(Some(_)) => Decision::Defer,
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
	fn first_seen(&self, key: &str) -> StoreFuture<'_, Result<Option<u64>, StoreUnavailable>> {
		// The lock is sync; performing the work inside `async {}` keeps the
		// trait surface uniform with the SQL store and avoids a second await
		// point in callers.
		let value = self
			.entries
			.lock()
			.expect("greylist lock")
			.get(key)
			.copied();
		Box::pin(async move { Ok(value) })
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
mod tests;
