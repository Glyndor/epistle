//! The one time reference the evidence and the queue share.
//!
//! The wall clock is the machine's to set, and it gets set wrong: a dead
//! RTC battery, a restored snapshot, a time source that is not what it
//! says. What a wrong clock costs depends on what reads it. A record dated
//! in the future drags every later one into that day; sealing at a clock
//! that is ahead seals the day that is still open; purging at one deletes
//! kept messages before their retention; the queue gives up on mail that
//! only waited. The deletions cannot be undone.
//!
//! So none of those read the wall clock raw. [`TimeRef::read`] cross-checks
//! it against what the process itself can know:
//!
//! - after a reading it accepted, the monotonic clock says how much time
//!   passed, so a wall clock that is more than [`SLACK_SECS`] ahead of that,
//!   or [`BEHIND_SECS`] behind, has jumped;
//! - with no reading yet, the newest record (or timestamp token) the disk
//!   holds is a time that really happened, so a wall clock before it, or
//!   more than [`MAX_IDLE_SECS`] after it, is not believed;
//! - a timestamp token is a time somebody else vouches for: [`TimeRef::witness`]
//!   makes it the reference.
//!
//! A reading that is not believed is not used. [`Reading::time`] is then the
//! best estimate (the last believed time plus the monotonic clock), which
//! can lag the truth but never run ahead of it, and [`Reading::sound`] is
//! false: whoever deletes, expires or seals on it must not.

use std::sync::Mutex;
use std::time::Instant;

/// How far the wall clock may run ahead of what the monotonic clock says
/// passed since a believed reading, in seconds.
pub const SLACK_SECS: u64 = 300;
/// How far the wall clock may fall behind it (or behind the newest record),
/// in seconds: a step back of the clock, not a clock gone wrong.
pub const BEHIND_SECS: u64 = 3600;
/// The longest the server may have been stopped, as far as a wall clock is
/// believed on the strength of the newest record alone, in seconds.
pub const MAX_IDLE_SECS: u64 = 35 * 86_400;
/// A believed reading moves the reference at most this often, so a clock
/// that creeps ahead at [`SLACK_SECS`] per reading cannot be walked away.
const REFRESH_SECS: u64 = 60;

/// The time to act on, and whether it was believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
	/// Epoch seconds: the wall clock when it was believed, else the estimate.
	pub time: u64,
	/// Whether the wall clock agreed with everything known about the time.
	pub sound: bool,
	/// The wall clock as it was read.
	pub wall: u64,
}

impl Reading {
	/// The time to judge age and give-up windows by: the wall clock when it
	/// is believed, else the earlier of it and the estimate. Mail that waits
	/// is never expired because a clock ran ahead, and one that is behind
	/// does not make it older either.
	pub fn cautious(&self) -> u64 {
		if self.sound {
			self.wall
		} else {
			self.wall.min(self.time)
		}
	}
}

#[derive(Debug, Default)]
struct State {
	/// The newest time known to have happened: a record, a token.
	floor: u64,
	/// The last believed reading, with the monotonic clock then.
	anchor: Option<(u64, Instant)>,
	/// Where the estimate starts until a reading is believed.
	fallback: Option<(u64, Instant)>,
	/// Whether the last reading was refused, to say so once.
	refused: bool,
}

/// The shared time reference. One per process, behind an `Arc`.
#[derive(Debug, Default)]
pub struct TimeRef {
	state: Mutex<State>,
	/// Added to the wall clock by [`TimeRef::read`], for tests.
	#[cfg(test)]
	skew: std::sync::atomic::AtomicI64,
}

fn elapsed(since: Instant, now: Instant) -> u64 {
	now.saturating_duration_since(since).as_secs()
}

impl TimeRef {
	/// A reference that knows `floor` (epoch seconds, `0` for none) happened.
	pub fn new(floor: u64) -> Self {
		TimeRef {
			state: Mutex::new(State {
				floor,
				..State::default()
			}),
			#[cfg(test)]
			skew: std::sync::atomic::AtomicI64::new(0),
		}
	}

	/// The time now.
	pub fn read(&self) -> Reading {
		let wall = crate::storage::delivery_log::now_epoch();
		#[cfg(test)]
		let wall = wall.saturating_add_signed(self.skew.load(std::sync::atomic::Ordering::Relaxed));
		self.read_at(wall, Instant::now())
	}

	/// Make the wall clock read `secs` more from now on, for tests.
	#[cfg(test)]
	pub(crate) fn skew(&self, secs: i64) {
		self.skew.store(secs, std::sync::atomic::Ordering::Relaxed);
	}

	/// [`TimeRef::read`] with both clocks given.
	pub fn read_at(&self, wall: u64, mono: Instant) -> Reading {
		let Ok(mut state) = self.state.lock() else {
			// A poisoned lock believes nothing.
			return Reading {
				time: wall,
				sound: false,
				wall,
			};
		};
		let believed = match state.anchor {
			Some((time, then)) => {
				let expected = time.saturating_add(elapsed(then, mono));
				wall <= expected.saturating_add(SLACK_SECS)
					&& wall.saturating_add(BEHIND_SECS) >= expected
			}
			None => {
				state.floor == 0
					|| (wall.saturating_add(BEHIND_SECS) >= state.floor
						&& wall <= state.floor.saturating_add(MAX_IDLE_SECS))
			}
		};
		if believed {
			let moves = state
				.anchor
				.is_none_or(|(_, then)| elapsed(then, mono) >= REFRESH_SECS);
			if moves {
				state.anchor = Some((wall, mono));
			}
			state.refused = false;
			return Reading {
				time: wall,
				sound: true,
				wall,
			};
		}
		let time = match (state.anchor, state.fallback) {
			(Some((time, then)), _) | (None, Some((time, then))) => {
				time.saturating_add(elapsed(then, mono))
			}
			(None, None) => {
				let floor = state.floor;
				state.fallback = Some((floor, mono));
				floor
			}
		};
		if !state.refused {
			state.refused = true;
			tracing::error!(
				wall,
				estimate = time,
				"the clock does not agree with what the evidence knows about the time; \
				 nothing is deleted, sealed or expired on it"
			);
		}
		Reading {
			time: time.max(state.floor),
			sound: false,
			wall,
		}
	}

	/// Note that `time` happened (a record was written at it).
	pub fn raise_floor(&self, time: u64) {
		if let Ok(mut state) = self.state.lock() {
			state.floor = state.floor.max(time);
		}
	}

	/// A timestamp authority said it is `time`: the reference is that, from
	/// `mono` on, whatever the wall clock says.
	pub fn witness(&self, time: u64, mono: Instant) {
		if let Ok(mut state) = self.state.lock() {
			state.floor = state.floor.max(time);
			state.anchor = Some((time, mono));
		}
	}
}

#[cfg(test)]
#[path = "timeref_tests.rs"]
mod tests;
