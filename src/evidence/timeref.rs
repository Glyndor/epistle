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
//! - after a reading it believed, the monotonic clock says how much time
//!   passed. The reference moves only forward with the monotonic clock (never
//!   to a wall clock that is ahead of it), so a clock that gains a little on
//!   every reading is not walked ahead by small steps: it drifts away from
//!   the reference until it is not believed;
//! - with no reading yet, the newest record the disk holds is a time that
//!   really happened, so a wall clock before it, or more than
//!   [`START_SLACK_SECS`] after it, is not believed. The same goes for a start
//!   that could not read the log at all: nothing is believed;
//! - a timestamp token is a time somebody else vouches for:
//!   [`TimeRef::witness`] makes it the reference, which is the only way out
//!   of a start that is not believed (or the operator saying the date is
//!   right).
//!
//! A reading that is not believed is not used. [`Reading::time`] is then the
//! best estimate (the last believed time plus the monotonic clock), which
//! can lag the truth but never run ahead of it, and [`Reading::sound`] is
//! false: whoever deletes, expires or seals on it must not. A value that
//! cannot be read never grants more than a value that can.

use std::sync::Mutex;
use std::time::Instant;

/// How far the wall clock may run ahead of what the monotonic clock says
/// passed since the reference was set, in seconds.
pub const SLACK_SECS: u64 = 300;
/// On top of [`SLACK_SECS`], the wall clock may run ahead by one second per
/// this many seconds since the reference was set: the drift of a real clock
/// (1000 ppm is far more than any), and no more.
const DRIFT_DIVISOR: u64 = 1000;
/// How far the wall clock may fall behind it (or behind the newest record),
/// in seconds: a step back of the clock, not a clock gone wrong.
pub const BEHIND_SECS: u64 = 3600;
/// How long after the newest record a start is believed without a token, in
/// seconds. A server that was down longer waits for a timestamp authority
/// (or the operator) to say what day it is before it seals or purges.
pub const START_SLACK_SECS: u64 = 86_400;
/// How long after the newest record a start still dates records by the
/// clock, and the operator's own commands (a key rotation, which names the
/// day it happens) go ahead, in seconds. Dating is not deleting: past
/// [`START_SLACK_SECS`] nothing is sealed, purged or expired, but the
/// log keeps taking records.
pub const DATING_SLACK_SECS: u64 = 35 * 86_400;
/// The reference moves at most this often, in seconds.
const REFRESH_SECS: u64 = 60;

/// The time to act on, and whether it was believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
	/// Epoch seconds to date a record by: the wall clock when it was believed
	/// (or, at a start, when it is within [`DATING_SLACK_SECS`] of the
	/// newest record: a record dated a little wrong harms nothing that
	/// deleting on it would), else the estimate.
	pub time: u64,
	/// Whether the wall clock agreed with everything known about the time.
	pub sound: bool,
	/// The wall clock as it was read.
	pub wall: u64,
	/// The last believed time plus the monotonic clock since, which can lag
	/// the truth but not run ahead of it.
	pub estimate: u64,
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
			self.wall.min(self.estimate)
		}
	}
}

#[derive(Debug, Default)]
struct State {
	/// The newest time known to have happened: a record, a token.
	floor: u64,
	/// The log could not be read at start: nothing is believed until a
	/// timestamp authority (or the operator) says what time it is.
	unknown: bool,
	/// When the reference was set from outside the process (a first
	/// believed reading, a token), for the drift allowed since.
	origin: Option<Instant>,
	/// The reference: a time and the monotonic clock then.
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
		Self::with(State {
			floor,
			..State::default()
		})
	}

	/// A reference that could not read the log to learn what happened last:
	/// it believes nothing until [`TimeRef::witness`].
	pub fn unknown() -> Self {
		Self::with(State {
			unknown: true,
			..State::default()
		})
	}

	fn with(state: State) -> Self {
		TimeRef {
			state: Mutex::new(state),
			#[cfg(test)]
			skew: std::sync::atomic::AtomicI64::new(0),
		}
	}

	/// The newest time known to have happened, `0` for none.
	pub fn floor(&self) -> u64 {
		self.state.lock().map_or(u64::MAX, |state| state.floor)
	}

	/// Whether `wall` is a time an operator's own command (a key rotation,
	/// which seals the closed days and names today) may act on: not before
	/// the newest record, nor more than [`DATING_SLACK_SECS`] after it. A
	/// log that could not be read allows nothing.
	pub fn allows_operator(&self, wall: u64) -> bool {
		self.state.lock().is_ok_and(|state| {
			!state.unknown
				&& (state.floor == 0
					|| (wall.saturating_add(BEHIND_SECS) >= state.floor
						&& wall <= state.floor.saturating_add(DATING_SLACK_SECS)))
		})
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
				estimate: 0,
			};
		};
		let near_floor = |state: &State, slack: u64| {
			!state.unknown
				&& (state.floor == 0
					|| (wall.saturating_add(BEHIND_SECS) >= state.floor
						&& wall <= state.floor.saturating_add(slack)))
		};
		let believed = match state.anchor {
			Some((time, then)) => {
				let expected = time.saturating_add(elapsed(then, mono));
				let drift = state
					.origin
					.map_or(0, |origin| elapsed(origin, mono) / DRIFT_DIVISOR);
				wall <= expected.saturating_add(SLACK_SECS).saturating_add(drift)
					&& wall.saturating_add(BEHIND_SECS) >= expected
			}
			None => near_floor(&state, START_SLACK_SECS),
		};
		if believed {
			match state.anchor {
				None => {
					state.anchor = Some((wall, mono));
					state.origin = Some(mono);
				}
				Some((time, then)) if elapsed(then, mono) >= REFRESH_SECS => {
					// Never to a wall clock that is ahead: the reference
					// follows the monotonic clock, so being a little ahead
					// at every refresh does not add up to a believed jump.
					let expected = time.saturating_add(elapsed(then, mono));
					state.anchor = Some((wall.min(expected), mono));
				}
				Some(_) => {}
			}
			state.refused = false;
			return Reading {
				time: wall,
				sound: true,
				wall,
				estimate: wall,
			};
		}
		let estimate = match (state.anchor, state.fallback) {
			(Some((time, then)), _) | (None, Some((time, then))) => {
				time.saturating_add(elapsed(then, mono))
			}
			(None, None) => {
				let base = if state.unknown { wall } else { state.floor };
				state.fallback = Some((base, mono));
				base
			}
		}
		.max(state.floor);
		if !state.refused {
			state.refused = true;
			tracing::error!(
				wall,
				estimate,
				"the clock does not agree with what the evidence knows about the time; \
				 nothing is deleted, sealed or expired on it"
			);
		}
		// A start a while after the newest record dates by the clock; any
		// other clock that is not believed, by the estimate.
		let dating = state.anchor.is_none() && near_floor(&state, DATING_SLACK_SECS);
		Reading {
			time: if dating { wall } else { estimate },
			sound: false,
			wall,
			estimate,
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
			state.origin = Some(mono);
			state.unknown = false;
		}
	}
}

#[cfg(test)]
#[path = "timeref_tests.rs"]
mod tests;
