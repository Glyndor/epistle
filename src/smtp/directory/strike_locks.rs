//! Keeps the ban check and the strike of one password sign-in together.
//!
//! A sign-in asks the ban store whether its subjects are banned, hashes the
//! password, and only then writes the strike. Between the question and the
//! strike a burst of guesses all get the same clean answer, so every one of
//! them is verified (as many as the password gate lets run at once) and every
//! one is counted behind a ban that the first few had already earned.
//!
//! [`StrikeLocks::hold`] closes that gap inside the process: the sign-ins that
//! share a subject (the client, the account seen from the client, the account)
//! run one after the other from the second ban question to the strike, so the
//! next one's question already sees what the previous one wrote. Sign-ins
//! that share nothing do not wait for each other.
//!
//! The locks are a fixed set of stripes picked by a hash of the subject, so
//! memory does not follow the number of subjects an attacker invents. Two
//! subjects on one stripe only wait for each other needlessly. A stripe is
//! always taken in ascending order, so two sign-ins that need several of them
//! cannot wait on each other in a circle.
//!
//! This is a bound inside one process. Two processes sharing a database each
//! keep their own stripes; the count and the strike stay atomic in the store
//! (see `PgBanStore`), and what two processes can still do together is the
//! gap this closes, narrowed to the number of processes.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// How many stripes there are. A power of two so the hash maps with a mask.
const STRIPES: usize = 1024;

/// How many sign-ins may wait on any stripe at once, in the whole process,
/// before the next is turned away. A stripe is held for the length of one
/// password check, so a line this long is seconds of queue, which is as far as
/// the password gate's own line goes. The bound is global, not per stripe: a
/// bound per stripe would let an attacker who spreads guesses over many
/// subjects park as many worker threads as stripes times the bound.
const MAX_WAITING: usize = 256;

/// Too many sign-ins are already waiting for a subject of this one.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Crowded;

#[derive(Debug, Default)]
struct Stripe {
	lock: Mutex<()>,
}

/// A set of striped locks keyed by ban subject.
#[derive(Debug)]
pub(crate) struct StrikeLocks {
	stripes: Box<[Stripe]>,
	seed: RandomState,
	waiting: AtomicUsize,
	max_waiting: usize,
}

/// The stripes held by one sign-in, released together when it is dropped.
#[derive(Debug)]
pub(crate) struct Held<'a> {
	_guards: Vec<MutexGuard<'a, ()>>,
}

impl Held<'_> {
	/// Test-only: how many stripes this sign-in holds.
	#[cfg(test)]
	pub(crate) fn len(&self) -> usize {
		self._guards.len()
	}
}

impl Default for StrikeLocks {
	fn default() -> Self {
		Self::new(STRIPES, MAX_WAITING)
	}
}

impl StrikeLocks {
	/// The locks every directory shares, so a directory rebuilt on a reload
	/// does not start a second set.
	pub(crate) fn shared() -> Arc<Self> {
		static LOCKS: OnceLock<Arc<StrikeLocks>> = OnceLock::new();
		Arc::clone(LOCKS.get_or_init(|| {
			// The tests share the process and run many logins in parallel, so
			// there the line has no limit; the limit is tested on a set of
			// its own.
			let max_waiting = if cfg!(test) { usize::MAX } else { MAX_WAITING };
			Arc::new(Self::new(STRIPES, max_waiting))
		}))
	}

	pub(crate) fn new(stripes: usize, max_waiting: usize) -> Self {
		Self {
			stripes: (0..stripes.max(1)).map(|_| Stripe::default()).collect(),
			seed: RandomState::new(),
			waiting: AtomicUsize::new(0),
			max_waiting,
		}
	}

	fn stripe_of(&self, subject: &str) -> usize {
		(self.seed.hash_one(subject) as usize) % self.stripes.len()
	}

	/// Take the stripes of `subjects`, waiting for whoever holds them, or say
	/// [`Crowded`] without waiting when a line is already full. The wait hands
	/// the async worker over (see `util::blocking`).
	pub(crate) fn hold(&self, subjects: &[String]) -> Result<Held<'_>, Crowded> {
		let mut wanted: Vec<usize> = subjects.iter().map(|s| self.stripe_of(s)).collect();
		wanted.sort_unstable();
		wanted.dedup();
		crate::util::blocking::may_block(|| {
			let mut held = Vec::with_capacity(wanted.len());
			for index in wanted {
				held.push(self.take(&self.stripes[index])?);
			}
			Ok(Held { _guards: held })
		})
	}

	fn take<'a>(&self, stripe: &'a Stripe) -> Result<MutexGuard<'a, ()>, Crowded> {
		if let Ok(guard) = stripe.lock.try_lock() {
			return Ok(guard);
		}
		if self.waiting.fetch_add(1, Ordering::SeqCst) >= self.max_waiting {
			self.waiting.fetch_sub(1, Ordering::SeqCst);
			return Err(Crowded);
		}
		let guard = stripe.lock.lock().unwrap_or_else(|p| p.into_inner());
		self.waiting.fetch_sub(1, Ordering::SeqCst);
		Ok(guard)
	}
}

#[cfg(test)]
mod tests;
