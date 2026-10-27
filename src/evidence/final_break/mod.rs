//! The breaks only the whole walk can find, and what an acknowledgement of
//! one of them covers.
//!
//! An acknowledgement names a break by the digest of its description. A
//! break found from some inputs (a record, a file on disk, a key, the chain
//! as it stands) must name all of them, or an old acknowledgement covers a
//! new state that merely reads the same. So each kind carries, as fields,
//! everything its check read, and the identity is the digest of the whole
//! value: a field cannot be left out of the identity without being left out
//! of the kind. A new kind has to be added to [`FinalBreak::samples`], whose
//! test changes every field of every sample and demands another identity.

use serde::{Deserialize, Serialize};

use super::anchor::Anchor;
use super::day::Day;
use super::record::{Purge, sha256, to_hex};
use super::rotation::Rotation;
use super::verify::{Break, Problem};

/// A break found after the walk, with every input it was judged from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum FinalBreak {
	/// A day was sealed by a key that was not in force.
	Signer {
		day: String,
		key: String,
		checkpoint: String,
		why: String,
		timeline: String,
	},
	/// The signer changed with no hand-over record to explain it.
	Switch {
		day: String,
		key: String,
		before: String,
		checkpoint: String,
		timeline: String,
	},
	/// A hand-over record that does not verify, or names another day.
	HandOver {
		day: String,
		line: u64,
		record: Rotation,
		files: String,
		why: String,
	},
	/// A purge statement that does not verify.
	Purge {
		day: String,
		line: u64,
		record: Purge,
		files: String,
		timeline: String,
		why: String,
	},
	/// The purge anchor and the last purge record disagree.
	AnchorMismatch {
		day: String,
		anchor: Anchor,
		record: Purge,
	},
	/// Days were purged and no record says so.
	AnchorOrphan { day: String, anchor: Anchor },
	/// The head is gone.
	HeadMissing { day: String, end: String },
	/// The chain ends before the head.
	Rollback {
		day: String,
		head: String,
		end: String,
	},
}

/// A digest of `value` in full.
fn digest(value: &impl Serialize) -> String {
	let json = serde_json::to_string(value).unwrap_or_default();
	to_hex(&sha256(json.as_bytes()))
}

impl FinalBreak {
	/// The day and line the break sits on.
	fn place(&self) -> (Day, u64) {
		let (day, line) = match self {
			Self::Signer { day, .. }
			| Self::Switch { day, .. }
			| Self::AnchorMismatch { day, .. }
			| Self::AnchorOrphan { day, .. }
			| Self::HeadMissing { day, .. }
			| Self::Rollback { day, .. } => (day, 0),
			Self::HandOver { day, line, .. } | Self::Purge { day, line, .. } => (day, *line),
		};
		(Day::parse(day).unwrap_or(Day(0)), line)
	}

	/// What it says.
	fn words(&self) -> String {
		match self {
			Self::Signer { why, .. } | Self::HandOver { why, .. } | Self::Purge { why, .. } => {
				why.clone()
			}
			Self::Switch { .. } => "signed with a different evidence key than the day before, and no rotation record explains it".into(),
			Self::AnchorMismatch { .. } => "the purge anchor does not match the last purge record".into(),
			Self::AnchorOrphan { .. } => "days were purged without a purge record".into(),
			Self::HeadMissing { .. } => "the head is missing: the evidence may have been restored from an older copy".into(),
			Self::Rollback { .. } => "rollback: the chain ends before its recorded head (a truncated tail or a deleted latest day)".into(),
		}
	}

	/// The break to report. Its description ends with the digest of the
	/// whole value, which is what an acknowledgement names.
	pub(super) fn to_break(&self) -> Break {
		let (day, line) = self.place();
		Break {
			day,
			line,
			problem: Problem::Checkpoint(format!("{} [state {}]", self.words(), digest(self))),
		}
	}
}

#[cfg(test)]
mod tests;
