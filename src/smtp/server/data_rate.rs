//! A minimum average transfer rate for one DATA body or one BDAT chunk.
//!
//! The per-read idle timeout alone lets a client that sends one byte every
//! few minutes keep its connection, its per-IP slot and its share of the
//! message memory budget forever. Once the grace period from the start of
//! the body (or chunk) is over, the average rate since that start must stay
//! at or above the floor; below it the client is answered `421 4.4.2` and
//! the connection is closed, which drops the session and with it every
//! reservation it held.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use super::Reply;

/// Default floor, in bytes per second: a 25 MiB message has about 43
/// minutes.
pub const DEFAULT_MIN_DATA_RATE: u64 = 10 * 1024;

/// Default grace period in seconds before the floor applies.
pub const DEFAULT_DATA_RATE_GRACE_SECS: u64 = 120;

/// The floor and its grace period, as one listener applies them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataRate {
	bytes_per_sec: u64,
	grace: Duration,
}

impl Default for DataRate {
	fn default() -> Self {
		Self::new(
			DEFAULT_MIN_DATA_RATE,
			Duration::from_secs(DEFAULT_DATA_RATE_GRACE_SECS),
		)
	}
}

impl DataRate {
	/// A floor of `bytes_per_sec` judged after `grace`; `0` turns it off.
	pub const fn new(bytes_per_sec: u64, grace: Duration) -> Self {
		DataRate {
			bytes_per_sec,
			grace,
		}
	}

	/// Start the window of one body or one chunk now.
	pub(super) fn start(self) -> RateWindow {
		RateWindow {
			rate: self,
			start: Instant::now(),
			bytes: 0,
		}
	}
}

/// The bytes read since one body or chunk started.
#[derive(Debug)]
pub(super) struct RateWindow {
	rate: DataRate,
	start: Instant,
	bytes: u64,
}

impl RateWindow {
	/// A window that never cuts: what everything but a body is read with.
	pub(super) fn off() -> Self {
		DataRate::new(0, Duration::ZERO).start()
	}

	/// Count `bytes` more read off the wire.
	pub(super) fn record(&mut self, bytes: usize) {
		self.bytes = self.bytes.saturating_add(bytes as u64);
	}

	/// The first instant at which, with no further byte, the client is
	/// below the floor: past the grace and past the time its bytes cover
	/// at the floor (one nanosecond later, so a client exactly at the
	/// floor is never cut). `None` when the floor is off or too far away
	/// to represent.
	fn deadline(&self) -> Option<Instant> {
		let covered = (u128::from(self.bytes) * 1_000_000_000)
			.checked_div(u128::from(self.rate.bytes_per_sec))?
			+ 1;
		let covered = Duration::from_nanos(u64::try_from(covered).unwrap_or(u64::MAX));
		self.start.checked_add(covered.max(self.rate.grace))
	}

	/// Await `read`, or `None` once the client falls below the floor.
	/// Bytes that are already waiting win over a deadline due at the
	/// same moment.
	pub(super) async fn guard<F: Future>(&self, read: F) -> Option<F::Output> {
		let Some(deadline) = self.deadline() else {
			return Some(read.await);
		};
		tokio::select! {
			biased;
			output = read => Some(output),
			() = tokio::time::sleep_until(deadline) => None,
		}
	}
}

/// What the client gets before a connection below the floor is closed.
pub(super) fn too_slow() -> Reply {
	Reply::single(421, "4.4.2 transfer too slow, closing connection")
}

/// Why a chunk read ended without the chunk.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Cut {
	/// The peer closed, or went idle past the per-read timeout.
	Closed,
	/// The average rate fell below the floor.
	TooSlow,
}

#[cfg(test)]
#[path = "data_rate_tests.rs"]
mod tests;
