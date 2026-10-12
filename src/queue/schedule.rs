//! When the queue retries a recipient, and when it warns that delivery is
//! taking long.
//!
//! The wait after the n-th failed attempt is `base * 2^(n-1)`, capped at
//! `cap`, then spread by a random factor in `[1 - JITTER, 1 + JITTER]` so
//! messages deferred together by a destination that was down do not all come
//! back in the same second when it recovers. The schedule applies to each
//! pending recipient on its own.

/// Default first wait: one minute.
pub const DEFAULT_BASE_SECS: u64 = 60;
/// Default longest wait: one hour.
pub const DEFAULT_CAP_SECS: u64 = 3600;
/// Default age of the one "delivery delayed" warning: four hours.
pub const DEFAULT_DELAY_WARNING_SECS: u64 = 4 * 3600;
/// Shortest first wait accepted in the configuration.
pub const MIN_BASE_SECS: u64 = 60;
/// How far each wait is spread around its computed value (20%).
pub const JITTER: f64 = 0.2;

/// The retry schedule of the outbound queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrySchedule {
	/// Wait after the first failed attempt, in seconds.
	pub base: u64,
	/// Longest wait between attempts, in seconds.
	pub cap: u64,
	/// Message age at which the delay warning DSN is sent, in seconds.
	pub delay_warning: u64,
}

impl Default for RetrySchedule {
	fn default() -> Self {
		RetrySchedule {
			base: DEFAULT_BASE_SECS,
			cap: DEFAULT_CAP_SECS,
			delay_warning: DEFAULT_DELAY_WARNING_SECS,
		}
	}
}

impl RetrySchedule {
	/// The schedule from the configured values; an absent or zero value
	/// keeps its default.
	pub fn from_config(base: Option<u64>, cap: Option<u64>, delay_warning: Option<u64>) -> Self {
		let defaults = RetrySchedule::default();
		let set = |value: Option<u64>, default: u64| value.filter(|v| *v != 0).unwrap_or(default);
		RetrySchedule {
			base: set(base, defaults.base),
			cap: set(cap, defaults.cap),
			delay_warning: set(delay_warning, defaults.delay_warning),
		}
	}

	/// Seconds to wait after `attempts` failed attempts (at least one),
	/// spread by `factor`, which the caller draws from
	/// `[1 - JITTER, 1 + JITTER]`.
	pub fn wait(&self, attempts: u32, factor: f64) -> u64 {
		let doublings = attempts.saturating_sub(1).min(32);
		let wait = self
			.base
			.saturating_mul(1u64 << doublings)
			.min(self.cap.max(self.base));
		let factor = factor.clamp(1.0 - JITTER, 1.0 + JITTER);
		((wait as f64) * factor).round() as u64
	}
}

/// A random spread factor in `[1 - JITTER, 1 + JITTER]`.
pub fn random_factor() -> f64 {
	1.0 - JITTER + rand::random::<f64>() * 2.0 * JITTER
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn waits_double_from_the_base_up_to_the_cap() {
		let schedule = RetrySchedule {
			base: 300,
			cap: 1000,
			delay_warning: 7200,
		};
		let waits: Vec<u64> = (1..=5).map(|n| schedule.wait(n, 1.0)).collect();
		assert_eq!(waits, [300, 600, 1000, 1000, 1000]);
	}

	#[test]
	fn the_spread_stays_within_twenty_percent() {
		let schedule = RetrySchedule::default();
		assert_eq!(schedule.wait(1, 0.8), 48);
		assert_eq!(schedule.wait(1, 1.2), 72);
		// A factor outside the band is clamped to it.
		assert_eq!(schedule.wait(1, 5.0), 72);
		for _ in 0..1000 {
			let factor = random_factor();
			assert!((0.8..=1.2).contains(&factor), "{factor}");
		}
	}

	#[test]
	fn zero_or_absent_values_keep_the_defaults() {
		assert_eq!(
			RetrySchedule::from_config(None, Some(0), None),
			RetrySchedule::default()
		);
		assert_eq!(
			RetrySchedule::from_config(Some(120), Some(600), Some(3600)),
			RetrySchedule {
				base: 120,
				cap: 600,
				delay_warning: 3600
			}
		);
	}
}
