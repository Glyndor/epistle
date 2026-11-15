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
//! - a clean shutdown the server recorded ([`stop`]) says the gap since the
//!   newest record is a stop, not a clock gone wrong: a clock that agrees with
//!   the time of that stop, within [`MAX_KNOWN_STOP_SECS`], is believed, and the
//!   log says how long the server was stopped.
//!
//! A reading that is not believed is not used. [`Reading::time`] is then the
//! best estimate (the last believed time plus the monotonic clock), which
//! can lag the truth but never run ahead of it, and [`Reading::sound`] is
//! false: whoever deletes, expires or seals on it must not. A value that
//! cannot be read never grants more than a value that can.

use std::sync::Mutex;
use std::time::Instant;

pub mod stop;

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
/// seconds: the margin of a normal restart, not of a stop. A process that
/// starts later than that (every command, and a server after a longer
/// stop) waits for a timestamp authority, the running server's word or the
/// operator to say what day it is before it dates, seals or purges.
pub const START_SLACK_SECS: u64 = 600;
/// The most the allowance for a real clock's drift ever grows to, in seconds,
/// however long ago the reference was set.
const DRIFT_CAP_SECS: u64 = 600;
/// How long after midnight a day waits to be sealed, in seconds: more than
/// the clock may be ahead of the true time at its widest believed (the start
/// margin, the slack and the drift together), so that a believed clock that
/// is a little ahead never seals a day that has not ended.
pub const SEAL_MARGIN_SECS: u64 = 1800;
/// The longest stop, in seconds, that a recorded clean shutdown explains. The
/// record cannot say whether the clock was set while the host was down, so
/// what it vouches for has a ceiling: a clock ahead by more than this is not
/// a stop, whatever the file says.
pub const MAX_KNOWN_STOP_SECS: u64 = 7 * 86_400;
/// The reference moves at most this often, in seconds.
const REFRESH_SECS: u64 = 60;

/// The time to act on, and whether it was believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
	/// Epoch seconds to date a record by: the wall clock when it was believed,
	/// else the estimate. A record is never dated by a clock nobody agrees
	/// with: the dates of the log are what it is for.
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
	/// The running server's word that the wall clock read this was right, with
	/// the monotonic clock then. It makes a reading believed; it is not a
	/// reference (it moves no anchor or floor), and it never clears `unknown`.
	vouched: Option<(u64, Instant)>,
	/// When the first reading of a run that is refused was made, to say so
	/// once and, when a reading is believed again, for how long it was not.
	refused_at: Option<Instant>,
	/// The time of the last clean shutdown, which explains a gap since the
	/// newest record.
	stop: Option<u64>,
}

/// The shared time reference. One per process, behind an `Arc`.
#[derive(Debug, Default)]
pub struct TimeRef {
	state: Mutex<State>,
	/// Added to the wall clock by [`TimeRef::read`], for tests.
	#[cfg(test)]
	skew: std::sync::atomic::AtomicI64,
}

/// A length of time for a log line: `7h 3m`, `2d 4h`, `42s`.
fn span(secs: u64) -> String {
	match secs {
		0..=119 => format!("{secs}s"),
		120..=7199 => format!("{}m", secs / 60),
		7200..=172_799 => format!("{}h {}m", secs / 3600, secs % 3600 / 60),
		_ => format!("{}d {}h", secs / 86_400, secs % 86_400 / 3600),
	}
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

	/// The same reference, told when the server last stopped cleanly.
	pub fn after_stop(self, stop: Option<u64>) -> Self {
		if let Ok(mut state) = self.state.lock() {
			state.stop = stop;
		}
		self
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
		let near_floor = |state: &State| {
			!state.unknown
				&& (state.floor == 0
					|| (wall.saturating_add(BEHIND_SECS) >= state.floor
						&& wall <= state.floor.saturating_add(START_SLACK_SECS)))
		};
		// How long the server was stopped, when a recorded clean shutdown
		// explains why the clock is far from the newest record.
		let stopped_for = match (state.anchor, state.stop) {
			(None, Some(stop))
				if !state.unknown
					&& !near_floor(&state)
					&& stop.saturating_add(START_SLACK_SECS) >= state.floor
					&& wall.saturating_add(BEHIND_SECS) >= stop
					&& wall <= stop.saturating_add(MAX_KNOWN_STOP_SECS) =>
			{
				Some(wall.saturating_sub(stop))
			}
			_ => None,
		};
		let believed = match state.anchor {
			Some((time, then)) => {
				let expected = time.saturating_add(elapsed(then, mono));
				let drift = state.origin.map_or(0, |origin| {
					(elapsed(origin, mono) / DRIFT_DIVISOR).min(DRIFT_CAP_SECS)
				});
				wall <= expected.saturating_add(SLACK_SECS).saturating_add(drift)
					&& wall.saturating_add(BEHIND_SECS) >= expected
			}
			None => {
				near_floor(&state)
					|| stopped_for.is_some()
					|| (!state.unknown
						&& state.vouched.is_some_and(|(wall_then, then)| {
							let expected = wall_then.saturating_add(elapsed(then, mono));
							wall <= expected.saturating_add(SLACK_SECS)
								&& wall.saturating_add(BEHIND_SECS) >= expected
						}))
			}
		};
		if believed {
			if let Some(down) = stopped_for {
				tracing::info!(
					wall,
					downtime_secs = down,
					"the server was stopped for {} since its last clean shutdown; the clock is believed from that stop",
					span(down)
				);
			}
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
			if let Some(since) = state.refused_at.take() {
				let secs = elapsed(since, mono);
				tracing::info!(
					wall,
					refused_secs = secs,
					"the clock agrees with what the evidence knows about the time again, after {}; \
					 deleting, sealing and expiring resume",
					span(secs)
				);
			}
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
		if state.refused_at.is_none() {
			state.refused_at = Some(mono);
			if state.unknown {
				tracing::error!(
					wall,
					"the evidence log could not be read, so the clock has nothing to be compared with; \
					 nothing is deleted, sealed or expired, and transactional mail is held, until a \
					 timestamp authority or `epistle evidence clock accept` confirms the date"
				);
			} else {
				tracing::error!(
					wall,
					estimate,
					differ_secs = wall.abs_diff(estimate),
					"the wall clock and the estimate from the evidence log (its newest record plus the \
					 monotonic clock since) differ by {}; nothing is deleted, sealed or expired, and \
					 transactional mail is held, until they agree, a timestamp authority confirms the \
					 date, or `epistle evidence clock accept` does",
					span(wall.abs_diff(estimate))
				);
			}
		}
		Reading {
			time: estimate,
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

	/// The running server said the clock reading `wall` is right. Only the
	/// readings that follow from it are believed; a log that could not be read
	/// is still not believed on this word.
	pub fn vouch(&self, wall: u64, mono: Instant) {
		if let Ok(mut state) = self.state.lock() {
			state.vouched = Some((wall, mono));
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
mod tests;
