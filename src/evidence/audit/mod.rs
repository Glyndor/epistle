//! `epistle evidence verify`: the chain, the checkpoints and the tokens.
//!
//! Days are walked oldest first. Every record must chain onto the one before
//! it; every closed day must have a checkpoint that matches the day exactly
//! (count, Merkle root, first and last hash, the previous checkpoint),
//! signed by an evidence key whose id is the hash of the published key; and
//! every checkpoint sealed with timestamping on must carry a token that
//! stamps its hash, from after the day ended, chaining to a pinned
//! authority. The first thing that does not hold is reported, precisely.
//!
//! A day whose checkpoint was re-signed after the fact (by anyone holding
//! the key, the operator included) shows up here: its token stamps the
//! old checkpoint, or it has none, and the next day's checkpoint names the
//! old one.

use std::path::Path;

use crate::evidence::anchor;
use crate::evidence::chain::{CHAIN_DIR, Chain};
use crate::evidence::checkpoint;
#[cfg(test)]
use crate::evidence::checkpoint::{Checkpoint, files};
use crate::evidence::day::Day;
use crate::evidence::record::{Position, hash_from_hex, sha256, to_hex};
use crate::evidence::verify::{Break, Problem};

mod day;
mod final_checks;
mod grace;
mod report;
mod walker;

pub(crate) use grace::token_window;
pub use grace::{SEAL_GRACE_SECS, TOKEN_GRACE_SECS};
pub use report::{Options, Report};

use day::parse;
use final_checks::final_checks;
use walker::{MAX_ACKNOWLEDGED_PER_DAY, Stop, Walker, walk_and_check};

fn broken(day: Day, why: impl Into<String>) -> Break {
	Break {
		day,
		line: 0,
		problem: Problem::Checkpoint(why.into()),
	}
}

/// Verify the evidence under `evidence_root`.
pub fn verify(evidence_root: &Path, options: &Options) -> std::io::Result<Report> {
	let chain = Chain::open(evidence_root)?;
	let purged = anchor::load(&evidence_root.join(CHAIN_DIR))?;
	let purged_through = purged
		.as_ref()
		.and_then(|anchor| Day::parse(&anchor.through));
	let today = Day::of_epoch(options.now);
	let mut days: Vec<Day> = chain
		.days()?
		.into_iter()
		.filter(|day| purged_through.is_none_or(|through| *day > through))
		.collect();
	let from_start = options
		.from
		.is_none_or(|from| days.first().is_none_or(|first| *first >= from));
	let to_end = options
		.to
		.is_none_or(|to| days.last().is_none_or(|last| *last <= to));
	days.retain(|day| {
		options.from.is_none_or(|from| *day >= from) && options.to.is_none_or(|to| *day <= to)
	});
	let mut report = Report::default();
	let head = super::head::load(evidence_root)?;
	let Some(first) = days.first().copied() else {
		if head.is_some() && from_start && to_end {
			report.first_break = Some(broken(
				today,
				"rollback: the head names a record, and no day is kept",
			));
		}
		return Ok(report);
	};
	// Where the first day must start: the previous checkpoint, the purge
	// anchor, or the very beginning.
	let previous = checkpoint::previous(evidence_root, first)?;
	let previous = previous.and_then(|(_, bytes)| parse(&bytes).ok().map(|cp| (cp, bytes)));
	let mut walker = Walker {
		expected: match (&previous, &purged) {
			(Some((cp, _)), _) => hash_from_hex(&cp.last_hash).map(|hash| Position {
				hash,
				seq: cp.last_seq,
				time: cp.last_time,
			}),
			(None, Some(anchor)) => anchor.position(),
			(None, None) if from_start => Some(Position::START),
			(None, None) => None,
		},
		previous_checkpoint: match (&previous, &purged) {
			(Some((_, bytes)), _) => Some(to_hex(&sha256(bytes))),
			(None, Some(anchor)) => Some(anchor.checkpoint.clone()),
			(None, None) => None,
		},
		previous_key: previous.as_ref().map(|(cp, _)| cp.key.clone()),
		timestamping: previous
			.as_ref()
			.is_none_or(|(cp, _)| cp.timestamp == "enabled"),
		head: head.as_ref().and_then(super::head::Head::hash),
		head_seen: false,
		last_purge: None,
		purges: Vec::new(),
		lineage: super::rotation::lineage(evidence_root)?,
		handovers: Vec::new(),
		signers: Vec::new(),
		before: previous.as_ref().map(|(cp, _)| cp.key.clone()),
		first_day: first,
		end: None,
	};
	for day in days {
		let mut accepted: Vec<u64> = Vec::new();
		while let Err(stop) = walk_and_check(
			evidence_root,
			day,
			today,
			options,
			&mut walker,
			&mut report,
			&accepted,
		) {
			let at = stop.at().clone();
			if accepted.len() >= MAX_ACKNOWLEDGED_PER_DAY
				|| !super::ack::is_acknowledged(evidence_root, &at)
			{
				report.first_break = Some(at);
				return Ok(report);
			}
			// Accepted by the operator, as the day was when they looked. What
			// follows is still checked: the rest of the day, the day's seal
			// and the link to the next day.
			report.acknowledged.push(at.clone());
			match stop {
				Stop::Line(_) if at.line > 0 => accepted.push(at.line),
				Stop::Line(_) => {
					walker.expected = None;
					walker.previous_checkpoint = None;
					break;
				}
				Stop::Seal(_) => {
					walker.previous_checkpoint = checkpoint::load(evidence_root, day)
						.ok()
						.flatten()
						.map(|(_, bytes)| to_hex(&sha256(&bytes)));
					break;
				}
			}
		}
	}
	for fault in final_checks(
		evidence_root,
		&purged,
		&walker,
		(from_start, to_end),
		head.as_ref(),
	) {
		match super::ack::is_acknowledged(evidence_root, &fault) {
			true => report.acknowledged.push(fault),
			false if report.first_break.is_none() => report.first_break = Some(fault),
			false => {}
		}
	}
	Ok(report)
}

#[cfg(test)]
pub(crate) mod tests;
