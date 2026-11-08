//! The walk over the days: what it carries from one day to the next and how a
//! day is read, counted and judged.

use std::path::Path;

use super::day::check_day;
use super::grace::SEAL_GRACE_SECS;
use super::{Options, Report, broken};
use crate::evidence::checkpoint;
use crate::evidence::day::Day;
use crate::evidence::merkle::{TreeBuilder, leaf_hash};
use crate::evidence::record::{Entry, Position};
use crate::evidence::rotation::At;
use crate::evidence::verify::{Break, walk_day_accepting};

/// What the walk carries from one day to the next. Nothing of it is
/// stored: every verification starts from the oldest kept day.
pub(super) struct Walker {
	pub(super) expected: Option<Position>,
	pub(super) previous_checkpoint: Option<String>,
	pub(super) previous_key: Option<String>,
	pub(super) timestamping: bool,
	pub(super) head: Option<[u8; 32]>,
	pub(super) head_seen: bool,
	pub(super) last_purge: Option<crate::evidence::record::Purge>,
	/// Every purge record met, oldest first, with its place: each
	/// statement is checked against the key in force there.
	pub(super) purges: Vec<(At, crate::evidence::record::Purge)>,
	/// The pinned key and the keys it took over from, by signed rotations.
	pub(super) lineage: Vec<String>,
	/// Every key rotation record met, oldest first, with its place.
	pub(super) handovers: Vec<(At, crate::evidence::rotation::Rotation)>,
	/// The day and signer of every checkpoint verified, in order.
	pub(super) signers: Vec<(Day, String, String)>,
	/// The signer of the newest checkpoint before the first day walked.
	pub(super) before: Option<String>,
	/// Where the last day walked ends.
	pub(super) end: Option<Position>,
	/// The oldest day under verification: where breaks about the chain as a
	/// whole are put.
	pub(super) first_day: Day,
}

/// The most purge records one verification checks.
const MAX_PURGES: usize = 10_000;

/// The most breaks of one day a verification goes past, acknowledged.
pub(super) const MAX_ACKNOWLEDGED_PER_DAY: usize = 64;

/// Where a day stopped verifying.
pub(super) enum Stop {
	/// Reading the day's lines: nothing of the day is counted yet.
	Line(Break),
	/// Judging the day as a whole (its seal, its purges, its keys): its
	/// records were read and counted.
	Seal(Break),
}

impl Stop {
	pub(super) fn at(&self) -> &Break {
		match self {
			Stop::Line(at) | Stop::Seal(at) => at,
		}
	}
}

pub(super) fn walk_and_check(
	evidence_root: &Path,
	day: Day,
	today: Day,
	options: &Options,
	walker: &mut Walker,
	report: &mut Report,
	accepted: &[u64],
) -> Result<(), Stop> {
	let mut tree = TreeBuilder::new();
	let mut timestamping = walker.timestamping;
	let head = walker.head;
	let mut head_seen = false;
	let mut purges = Vec::new();
	let mut rotations = Vec::new();
	let walk = walk_day_accepting(
		evidence_root,
		day,
		walker.expected,
		accepted,
		|line, record, hash| {
			tree.push(leaf_hash(hash));
			head_seen |= head.as_ref() == Some(hash);
			match &record.entry {
				Entry::Purge(purge) => purges.push(((day, line), purge.clone())),
				Entry::KeyRotated(rotation) => rotations.push(((day, line), rotation.clone())),
				Entry::Setting(setting) if setting.name == "timestamp" => {
					timestamping = setting.value.starts_with("enabled");
				}
				_ => {}
			}
		},
	)
	.map_err(Stop::Line)?;
	walker.head_seen |= head_seen;
	walker.expected = Some(walk.last);
	walker.end = Some(walk.last);
	if let Some((_, last)) = purges.last() {
		walker.last_purge = Some(last.clone());
	}
	walker.purges.extend(purges);
	if walker.purges.len() > MAX_PURGES {
		return Err(Stop::Seal(broken(
			day,
			"more purge records than a verification checks",
		)));
	}
	walker.handovers.extend(rotations);
	if walker.handovers.len() > crate::evidence::rotation::MAX_ROTATIONS {
		return Err(Stop::Seal(broken(
			day,
			"more key rotations than a verification follows",
		)));
	}
	walker.timestamping = timestamping;
	report.days += 1;
	report.records += walk.records;
	let just_closed = day.0 + 1 == today.0 && options.now < today.start_epoch() + SEAL_GRACE_SECS;
	if (day >= today || just_closed)
		&& checkpoint::load(evidence_root, day)
			.ok()
			.flatten()
			.is_none()
	{
		report.open.push(day);
		return Ok(());
	}
	let (root, _) = tree.finish(&[]);
	let stamped =
		check_day(evidence_root, day, &walk, &root, walker, options).map_err(Stop::Seal)?;
	report.sealed += 1;
	walker
		.signers
		.push((day, stamped.2.clone(), stamped.0.clone()));
	report.stamped += u32::from(stamped.1);
	walker.previous_checkpoint = Some(stamped.0);
	walker.previous_key = Some(stamped.2);
	Ok(())
}
