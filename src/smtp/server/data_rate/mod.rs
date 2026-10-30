//! A minimum average transfer rate for one message transaction.
//!
//! The per-read idle timeout alone lets a client that sends one byte every
//! few minutes keep its connection, its per-IP slot and its share of the
//! message memory budget forever. The window opens at the 354 of DATA or
//! at the first BDAT chunk and lasts until the final dot or the LAST chunk
//! (or until anything else ends the transaction). The grace is given once
//! per transaction, and the time between BDAT chunks counts, commands
//! included, though they bring no octets: otherwise tiny chunks, each
//! inside its own grace, would hold a reservation for ever. Once the grace
//! is over the average rate since the start must stay at or above the
//! floor; below it the client is answered `421 4.4.2` and the connection
//! is closed, which drops the session and with it every reservation it
//! held.
//!
//! A fast burst followed by a drip is bounded too: the octets received
//! buy exactly the time they cover at the floor, and only octets up to
//! `max_message_size` count (an oversized DATA is still read to the dot,
//! but buys nothing), so one transaction lasts at most the grace or
//! `max_message_size / floor`, whichever is longer: about 43 minutes for
//! 25 MiB at 10 KiB/s.

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

	/// Start the window of one transaction now.
	pub(super) fn start(self) -> RateWindow {
		RateWindow {
			rate: self,
			start: Instant::now(),
			bytes: 0,
			counted: u64::MAX,
		}
	}
}

/// The message octets read since one transaction started.
#[derive(Debug)]
pub(super) struct RateWindow {
	rate: DataRate,
	start: Instant,
	bytes: u64,
	/// The most octets that buy time: past the size cap DATA is still read
	/// to the dot, but those octets are thrown away.
	counted: u64,
}

impl RateWindow {
	/// A window that never cuts: what a connection with no message in
	/// progress is read with.
	pub(super) fn off() -> Self {
		DataRate::new(0, Duration::ZERO).start()
	}

	/// Count `bytes` more read off the wire.
	pub(super) fn record(&mut self, bytes: usize) {
		self.bytes = self.bytes.saturating_add(bytes as u64).min(self.counted);
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

impl super::Server {
	/// Open the window of a message on this listener: only octets up to
	/// its size cap count.
	pub(super) fn message_window(&self) -> RateWindow {
		RateWindow {
			counted: self.max_message_size as u64,
			..self.data_rate.start()
		}
	}
}

/// Write `reply` while the transaction `window` belongs to is open: the
/// write is held to the window as a read is, so a client that leaves its
/// replies unread cannot stretch the transaction one blocked write at a
/// time. `Ok(false)` when the window ran out first; the connection is then
/// closed without a 421 that client would not read either.
pub(super) async fn send_within(
	stream: &mut Box<dyn super::Connection>,
	reply: &Reply,
	window: Option<&RateWindow>,
) -> std::io::Result<bool> {
	let Some(window) = window else {
		return super::send(stream, reply).await.map(|()| true);
	};
	match window.guard(super::send(stream, reply)).await {
		Some(sent) => sent.map(|()| true),
		None => {
			tracing::info!(
				"closing a client below the DATA/BDAT rate floor that leaves its replies unread"
			);
			Ok(false)
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
mod tests;
