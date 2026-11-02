//! What a verification found and the range it covers.

use crate::evidence::day::Day;
use crate::evidence::verify::Break;

/// What `verify` found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
	/// Days walked.
	pub days: u32,
	/// Records walked.
	pub records: u64,
	/// Days with a valid checkpoint.
	pub sealed: u32,
	/// Days with a valid timestamp token.
	pub stamped: u32,
	/// Days not sealed yet (today, or just closed).
	pub open: Vec<Day>,
	/// Breaks an operator acknowledged; the walk went on after each.
	pub acknowledged: Vec<Break>,
	/// The first break nobody acknowledged, when there is one.
	pub first_break: Option<Break>,
}

/// The range and trust of a verification.
#[derive(Debug, Clone)]
pub struct Options {
	/// First day to verify, or the oldest kept.
	pub from: Option<Day>,
	/// Last day to verify, or today.
	pub to: Option<Day>,
	/// Pinned timestamp authority keys (SPKI SHA-256).
	pub anchors: Vec<[u8; 32]>,
	/// The current time, epoch seconds.
	pub now: u64,
}
