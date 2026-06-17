//! Greylisting: defer the first delivery attempt from an unseen
//! (client, sender, recipient) triplet, accepting it once the sender retries
//! after a short delay.
//!
//! Legitimate MTAs retry on a 4xx; many spam sources do not, so a brief
//! tempfail filters a lot of junk at almost no cost to real mail. The decision
//! is pure given a store and a clock, so it is fully unit-testable; the store
//! implementation (PostgreSQL) and SMTP wiring are layered on top.

use std::net::IpAddr;

/// The identity greylisting keys on (RFC-less convention): client IP, envelope
/// sender, and one recipient.
pub struct Triplet<'a> {
	pub client_ip: IpAddr,
	pub sender: &'a str,
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

/// Records when each triplet was first seen.
pub trait GreylistStore {
	/// The UNIX time the triplet was first seen, if ever.
	fn first_seen(&self, key: &str) -> Option<u64>;
	/// Remember that the triplet was first seen at `now`.
	fn record(&self, key: &str, now: u64);
}

/// Decide whether to accept or defer an attempt from `triplet` at `now`,
/// accepting once `delay_secs` have passed since the first attempt.
pub fn decide(store: &dyn GreylistStore, triplet: &Triplet, now: u64, delay_secs: u64) -> Decision {
	let key = triplet.key();
	match store.first_seen(&key) {
		// First sighting: remember it and defer.
		None => {
			store.record(&key, now);
			Decision::Defer
		}
		// Retried after the delay: a real MTA — accept.
		Some(first_seen) if now.saturating_sub(first_seen) >= delay_secs => Decision::Accept,
		// Retried too soon: keep deferring.
		Some(_) => Decision::Defer,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::cell::RefCell;
	use std::collections::HashMap;

	/// In-memory store for tests.
	#[derive(Default)]
	struct MemStore(RefCell<HashMap<String, u64>>);

	impl GreylistStore for MemStore {
		fn first_seen(&self, key: &str) -> Option<u64> {
			self.0.borrow().get(key).copied()
		}
		fn record(&self, key: &str, now: u64) {
			self.0.borrow_mut().entry(key.to_string()).or_insert(now);
		}
	}

	fn triplet() -> Triplet<'static> {
		Triplet {
			client_ip: "192.0.2.10".parse().unwrap(),
			sender: "Sender@Example.org",
			recipient: "Bob@Example.net",
		}
	}

	const DELAY: u64 = 60;

	#[test]
	fn first_attempt_is_deferred_and_recorded() {
		let store = MemStore::default();
		assert_eq!(decide(&store, &triplet(), 1000, DELAY), Decision::Defer);
		assert_eq!(store.first_seen(&triplet().key()), Some(1000));
	}

	#[test]
	fn retry_before_delay_is_deferred() {
		let store = MemStore::default();
		decide(&store, &triplet(), 1000, DELAY);
		assert_eq!(decide(&store, &triplet(), 1030, DELAY), Decision::Defer);
	}

	#[test]
	fn retry_after_delay_is_accepted() {
		let store = MemStore::default();
		decide(&store, &triplet(), 1000, DELAY);
		assert_eq!(decide(&store, &triplet(), 1060, DELAY), Decision::Accept);
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
	fn distinct_triplets_are_independent() {
		let store = MemStore::default();
		decide(&store, &triplet(), 1000, DELAY);
		let other = Triplet {
			client_ip: "198.51.100.1".parse().unwrap(),
			sender: "sender@example.org",
			recipient: "bob@example.net",
		};
		// A different client is still on its first attempt.
		assert_eq!(decide(&store, &other, 1100, DELAY), Decision::Defer);
	}
}
