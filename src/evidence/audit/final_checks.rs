//! What can only be judged once every day was walked.

use std::path::Path;

use super::walker::Walker;
use crate::evidence::anchor;
use crate::evidence::final_break::FinalBreak;
use crate::evidence::record::to_hex;
use crate::evidence::verify::Break;

/// The most breaks the whole-walk checks report at once.
const MAX_FINAL_BREAKS: usize = 16;

/// What can only be judged once every day was walked: who signed what, the
/// hand-overs and purges, the purge anchor and the head. Every break is
/// returned, so an acknowledged one does not hide the next. Those about the
/// chain as a whole are put on the oldest day under verification, which does
/// not change from one run to the next, so an acknowledgement keeps naming
/// the same break.
pub(super) fn final_checks(
	evidence_root: &Path,
	purged: &Option<anchor::Anchor>,
	walker: &Walker,
	(from_start, to_end): (bool, bool),
	head: Option<&crate::evidence::head::Head>,
) -> Vec<Break> {
	let whole = walker.first_day.name();
	let mut found: Vec<FinalBreak> = Vec::new();
	let timeline = crate::evidence::rotation::Timeline::new(
		walker.lineage.clone(),
		walker.handovers.clone(),
		to_end,
	);
	// What the key checks were judged from, besides the day itself.
	let placed: Vec<(String, u64, &crate::evidence::rotation::Rotation)> = walker
		.handovers
		.iter()
		.map(|((day, line), rotation)| (day.name(), *line, rotation))
		.collect();
	let inputs = serde_json::to_string(&(&walker.lineage, placed)).unwrap_or_default();
	// A change of signer between two sealed days needs the record that
	// hands over, even when the walk stopped before the end of the chain.
	let mut previous = walker.before.as_deref();
	for (day, signer, checkpoint) in &walker.signers {
		if let Err(fault) = timeline.check_seal(signer, *day) {
			found.push(FinalBreak::Signer {
				day: day.name(),
				key: signer.clone(),
				checkpoint: checkpoint.clone(),
				why: fault.to_string(),
				timeline: inputs.clone(),
			});
		} else if let Some(before) = previous
			&& before != signer
			&& !timeline.explains(before, signer, *day)
		{
			found.push(FinalBreak::Switch {
				day: day.name(),
				key: signer.clone(),
				before: before.to_string(),
				checkpoint: checkpoint.clone(),
				timeline: inputs.clone(),
			});
		}
		previous = Some(signer);
	}
	for ((day, line), rotation) in &walker.handovers {
		let why = match crate::evidence::rotation::check_record(evidence_root, rotation) {
			Err(why) => why,
			Ok(()) if rotation.day != day.name() => {
				"the key rotation record names another day than the one it sits in"
			}
			Ok(()) => continue,
		};
		found.push(FinalBreak::HandOver {
			day: day.name(),
			line: *line,
			record: rotation.clone(),
			files: crate::evidence::rotation::files_digest(evidence_root, rotation),
			why: why.to_string(),
		});
	}
	for ((day, line), purge) in &walker.purges {
		if let Err(why) = crate::evidence::retention::check_statement(
			evidence_root,
			purge,
			(*day, *line),
			&timeline,
		) {
			found.push(FinalBreak::Purge {
				day: day.name(),
				line: *line,
				record: purge.clone(),
				files: crate::evidence::retention::statement_files_digest(evidence_root, purge),
				timeline: inputs.clone(),
				why: why.to_string(),
			});
		}
	}
	match (purged, &walker.last_purge) {
		(Some(anchor), Some(purge))
			if anchor.last_hash != purge.last_hash
				|| anchor.checkpoint != purge.checkpoint
				|| anchor.through != purge.through =>
		{
			found.push(FinalBreak::AnchorMismatch {
				day: whole.clone(),
				anchor: anchor.clone(),
				record: purge.clone(),
			});
		}
		(Some(anchor), None) if from_start && to_end => {
			found.push(FinalBreak::AnchorOrphan {
				day: whole.clone(),
				anchor: anchor.clone(),
			});
		}
		_ => {}
	}
	// Where the chain ends: the same words for another end is another break.
	let ends = walker.end.map_or_else(
		|| "no day".to_string(),
		|end| format!("{} {} {}", end.seq, to_hex(&end.hash), end.time),
	);
	if to_end && head.is_none() {
		found.push(FinalBreak::HeadMissing {
			day: whole,
			end: ends,
		});
	} else if to_end && !walker.head_seen {
		found.push(FinalBreak::Rollback {
			day: whole,
			head: head.map_or_else(String::new, |head| {
				serde_json::to_string(head).unwrap_or_default()
			}),
			end: ends,
		});
	}
	found.truncate(MAX_FINAL_BREAKS);
	found.iter().map(FinalBreak::to_break).collect()
}
