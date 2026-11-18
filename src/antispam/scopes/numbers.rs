//! The numeric settings a scope can override: the Bayesian thresholds and
//! the two delays. The most specific scope in reach wins, and a message for
//! several recipients gets the strictest value any of them has.

use super::{Scopes, Target};

/// The numbers one message is judged by.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SpamNumbers {
	/// Score at or above which the message goes to Junk.
	pub junk_at: f64,
	/// Score at or above which the message is refused. Never below
	/// `junk_at`.
	pub reject_at: Option<f64>,
	/// Seconds an unseen triplet is greylisted; `0` is off.
	pub greylist_delay_secs: u64,
	/// Seconds a never seen sender waits; `0` is off.
	pub first_time_delay_secs: u64,
}

/// What one scope overrides.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct Overrides {
	pub(super) junk_at: Option<f64>,
	pub(super) reject_at: Option<f64>,
	pub(super) greylist_delay_secs: Option<u64>,
	pub(super) first_time_delay_secs: Option<u64>,
}

impl Overrides {
	pub(super) fn is_empty(&self) -> bool {
		*self == Self::default()
	}

	/// `numbers` with this scope's settings on top.
	fn apply(&self, numbers: SpamNumbers) -> SpamNumbers {
		SpamNumbers {
			junk_at: self.junk_at.unwrap_or(numbers.junk_at),
			reject_at: self.reject_at.or(numbers.reject_at),
			greylist_delay_secs: self
				.greylist_delay_secs
				.unwrap_or(numbers.greylist_delay_secs),
			first_time_delay_secs: self
				.first_time_delay_secs
				.unwrap_or(numbers.first_time_delay_secs),
		}
	}
}

impl SpamNumbers {
	/// The stricter of two: the lower threshold, the longer delay, and a
	/// rejection threshold when either has one.
	fn stricter(self, other: Self) -> Self {
		Self {
			junk_at: self.junk_at.min(other.junk_at),
			reject_at: match (self.reject_at, other.reject_at) {
				(Some(a), Some(b)) => Some(a.min(b)),
				(a, b) => a.or(b),
			},
			greylist_delay_secs: self.greylist_delay_secs.max(other.greylist_delay_secs),
			first_time_delay_secs: self.first_time_delay_secs.max(other.first_time_delay_secs),
		}
	}

	/// With a rejection threshold that is never below the junk one, so the
	/// rejected band stays inside the junked one whatever the scopes set.
	fn consistent(mut self) -> Self {
		self.reject_at = self.reject_at.map(|reject| reject.max(self.junk_at));
		self
	}
}

impl Scopes {
	/// The numbers for mail to `targets`, starting from `server`, the
	/// server-wide values, and applying the tenant, the domain and the
	/// account of each target in turn.
	pub fn spam_numbers(&self, targets: &[Target], server: SpamNumbers) -> SpamNumbers {
		let mut merged: Option<SpamNumbers> = None;
		for target in targets {
			let numbers = self
				.layers(target)
				.fold(server, |numbers, layer| layer.numbers.apply(numbers))
				.consistent();
			merged = Some(match merged {
				Some(seen) => seen.stricter(numbers),
				None => numbers,
			});
		}
		merged.unwrap_or(server)
	}
}
