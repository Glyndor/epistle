//! What the end of a day and the operator's orders do to each group's cap.
//!
//! These are pure functions over the state; the controller
//! ([`super::Warmup`]) calls them under its lock and writes the result.

use super::Group;
use super::health::DayTally;
use super::policy::{START_CAP, Verdict, filled, grown, judge, step_back};
use super::settings::Action;
use super::state::{DayRecord, GroupState, Raise, RaiseOutcome, State};

/// How a judged day is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
	/// A good day: the cap grew, or a raise was kept, or the day was too
	/// light to grow on.
	Ok,
	/// A bad day: the cap held.
	Held,
	/// A very bad day, or a raise that went badly: the cap went back.
	Backoff,
}

impl EventKind {
	/// `warmup.ok`, `warmup.held` or `warmup.backoff`.
	pub fn label(self) -> &'static str {
		match self {
			EventKind::Ok => "warmup.ok",
			EventKind::Held => "warmup.held",
			EventKind::Backoff => "warmup.backoff",
		}
	}
}

/// One group's judged day, to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
	/// How it is reported.
	pub kind: EventKind,
	/// The group.
	pub group: Group,
	/// The day as kept in the history.
	pub record: DayRecord,
}

/// Judge `day` for every group that sent mail on it, move each cap by the
/// verdict, keep the record, and return what to report. Nothing moves
/// while `paused`.
pub fn close_day(state: &mut State, day: i64, tally: &DayTally, paused: bool) -> Vec<Event> {
	let mut events = Vec::new();
	for group in Group::ALL {
		let schedule = state.group_mut(group);
		if schedule.sent == 0 {
			continue;
		}
		let counts = tally.of(group);
		let verdict = judge(group, &counts);
		let cap = schedule.cap;
		let raise = match paused {
			true => schedule.raise.map(|_| RaiseOutcome::Pending),
			false => decide(schedule, day, verdict),
		};
		let record = DayRecord {
			day,
			cap,
			sent: schedule.sent,
			attempted: counts.attempted,
			deferred: counts.deferred,
			bounced: counts.bounced,
			spam_blocks: counts.spam_blocks,
			verdict,
			next_cap: schedule.cap,
			raise,
			paused,
			causes: tally.causes(group),
		};
		schedule.remember(record.clone());
		let kind = match (verdict, raise) {
			(Verdict::Idle, _) => continue,
			(_, Some(RaiseOutcome::Reverted)) => EventKind::Backoff,
			(Verdict::Good, _) => EventKind::Ok,
			(Verdict::Bad, _) => EventKind::Held,
			(Verdict::VeryBad, _) => EventKind::Backoff,
		};
		events.push(Event {
			kind,
			group,
			record,
		});
	}
	events
}

/// Move the cap of `schedule` after `day` was judged `verdict`, and say
/// what became of a raise on trial.
fn decide(schedule: &mut GroupState, day: i64, verdict: Verdict) -> Option<RaiseOutcome> {
	if let Some(raise) = schedule.raise {
		if day < raise.trial_day || verdict == Verdict::Idle {
			return Some(RaiseOutcome::Pending);
		}
		schedule.raise = None;
		if verdict == Verdict::Good {
			return Some(RaiseOutcome::Kept);
		}
		schedule.cap = Some(raise.from);
		return Some(RaiseOutcome::Reverted);
	}
	let Some(cap) = schedule.cap else {
		// Warmed up: the day is reported, nothing moves.
		return None;
	};
	schedule.cap = match verdict {
		Verdict::Good if filled(schedule.sent, cap) => grown(cap),
		Verdict::VeryBad => Some(step_back(cap)),
		Verdict::Good | Verdict::Bad | Verdict::Idle => Some(cap),
	};
	None
}

/// Start a new day: every group's use goes back to zero.
pub fn open_day(state: &mut State, day: i64) {
	state.day = day;
	for schedule in state.groups.values_mut() {
		schedule.sent = 0;
		schedule.senders.clear();
	}
}

/// Apply one operator order to `schedule` on `today`. A raise or a skip
/// ahead is on trial the next day; a raise over one still on trial keeps
/// the cap the first one would go back to.
pub fn apply(schedule: &mut GroupState, action: Action, today: i64) {
	let trial = |from: u32, pending: Option<Raise>| {
		Some(Raise {
			from: pending.map_or(from, |raise| raise.from),
			trial_day: today.saturating_add(1),
		})
	};
	match (action, schedule.cap) {
		(Action::Set { cap }, Some(current)) if cap > current => {
			schedule.raise = trial(current, schedule.raise);
			schedule.cap = Some(cap);
		}
		(Action::Set { cap }, _) => {
			schedule.raise = None;
			schedule.cap = Some(cap);
		}
		(Action::Next, Some(current)) => {
			schedule.raise = trial(current, schedule.raise);
			schedule.cap = grown(current);
		}
		(Action::Next, None) => {}
		(Action::Start { cap }, _) => {
			schedule.raise = None;
			schedule.cap = cap;
		}
		(Action::Reset, _) => {
			schedule.raise = None;
			schedule.cap = Some(START_CAP);
			schedule.tat_ms = 0;
		}
	}
}

#[cfg(test)]
#[path = "schedule_tests.rs"]
mod tests;
