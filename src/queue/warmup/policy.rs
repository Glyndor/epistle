//! The warm-up rules: where a group's cap starts, how a day is judged, and
//! what the judgement does to the cap.
//!
//! Defaults, all per receiver group and per UTC day:
//!
//! - The cap starts at [`START_CAP`] recipients a day and grows by half
//!   (×1.5, rounded up) after each good day that used at least half of
//!   it. Past [`UNCAPPED_AT`] the group is warmed up and has no cap.
//! - A day is good when under 2 % of its recipients were deferred for
//!   rate or reputation, under 2 % bounced, and no provider refused a
//!   message as spam. A good day with too little mail to judge the cap by
//!   keeps it.
//! - A day is very bad when over 10 % were deferred that way, or a
//!   provider refused a message as spam: the cap goes back one step, never
//!   below the start. Any other day is bad and the cap holds.
//!
//! For [`Group::Other`] a spam refusal is counted with the bounces, as a
//! share of the day, rather than on its own: anyone who owns a domain
//! answers for its exchangers, so one receiver refusing us must not be able
//! to hold back every other receiver of the group. A day is very bad there
//! when over 10 % bounced or were refused.

use serde::{Deserialize, Serialize};

use super::Group;
use super::health::Tally;

/// The cap a group starts at, in recipients a day.
pub const START_CAP: u32 = 50;
/// A cap that would grow past this is lifted: the group is warmed up.
pub const UNCAPPED_AT: u32 = 5000;
/// The highest cap an operator may set.
pub const MAX_CAP: u32 = 1_000_000;
/// Growth after a good day, in thousandths: ×1.5.
const GROWTH_PERMILLE: u64 = 1500;
/// The share of the cap a good day must have used to grow it, in percent.
const MIN_FILL_PERCENT: u64 = 50;
/// Deferral and bounce shares a good day stays under, in thousandths.
const GOOD_PERMILLE: u64 = 20;
/// The deferral (or, for [`Group::Other`], refusal) share past which a
/// day is very bad, in thousandths.
const VERY_BAD_PERMILLE: u64 = 100;

/// How a day went for one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
	/// Within every threshold.
	Good,
	/// Over a good-day threshold: the cap holds.
	Bad,
	/// Far over: the cap goes back one step.
	VeryBad,
	/// Nothing was sent, or no remote answered: nothing to judge.
	Idle,
}

impl Verdict {
	/// `good`, `bad`, `very_bad` or `idle`.
	pub fn label(self) -> &'static str {
		match self {
			Verdict::Good => "good",
			Verdict::Bad => "bad",
			Verdict::VeryBad => "very_bad",
			Verdict::Idle => "idle",
		}
	}
}

/// Whether `part` is more than `permille` thousandths of `whole`.
fn over(part: u32, whole: u32, permille: u64) -> bool {
	u64::from(part) * 1000 > u64::from(whole) * permille
}

/// Whether `part` is under `permille` thousandths of `whole`.
fn under(part: u32, whole: u32, permille: u64) -> bool {
	u64::from(part) * 1000 < u64::from(whole) * permille
}

/// Judge one day of `group` from its tally.
pub fn judge(group: Group, tally: &Tally) -> Verdict {
	let whole = tally.attempted;
	if whole == 0 {
		return Verdict::Idle;
	}
	let (refused, spam_alone) = match group.is_provider() {
		true => (tally.bounced, tally.spam_blocks),
		false => (tally.bounced.saturating_add(tally.spam_blocks), 0),
	};
	if over(tally.deferred, whole, VERY_BAD_PERMILLE) || spam_alone > 0 {
		return Verdict::VeryBad;
	}
	if !group.is_provider() && over(refused, whole, VERY_BAD_PERMILLE) {
		return Verdict::VeryBad;
	}
	if under(tally.deferred, whole, GOOD_PERMILLE) && under(refused, whole, GOOD_PERMILLE) {
		return Verdict::Good;
	}
	Verdict::Bad
}

/// The cap after a good day at `cap`, or `None` once it would pass
/// [`UNCAPPED_AT`].
pub fn grown(cap: u32) -> Option<u32> {
	let next = (u64::from(cap) * GROWTH_PERMILLE).div_ceil(1000);
	match next > u64::from(UNCAPPED_AT) {
		true => None,
		false => Some(u32::try_from(next).unwrap_or(UNCAPPED_AT)),
	}
}

/// The cap one step back from `cap`, never under [`START_CAP`].
pub fn step_back(cap: u32) -> u32 {
	let back = u64::from(cap) * 1000 / GROWTH_PERMILLE;
	u32::try_from(back).unwrap_or(cap).max(START_CAP).min(cap)
}

/// Whether `sent` used enough of `cap` for a good day to grow it.
pub fn filled(sent: u32, cap: u32) -> bool {
	u64::from(sent) * 100 >= u64::from(cap) * MIN_FILL_PERCENT
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
