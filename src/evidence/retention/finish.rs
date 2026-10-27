//! Finishing a purge that was cut short, and deleting what an anchor covers.
//!
//! Both act on files that sit on disk between two sweeps, so neither takes
//! their word for anything: see [`resume`] and [`finish_deleting`].

use std::path::Path;

use super::super::chain::{CHAIN_DIR, Chain};
use super::super::checkpoint::{self, Checkpoint, files};
use super::super::day::Day;
use super::super::record::{Entry, Position, hash_from_hex, sha256, to_hex};
use super::{PURGES_DIR, Statement};

/// The statement of a purge the anchor has not caught up with, with its bytes.
fn unfinished(evidence_root: &Path) -> std::io::Result<Option<(Day, Statement, Vec<u8>)>> {
	let reached = crate::evidence::anchor::load(&evidence_root.join(CHAIN_DIR))?
		.and_then(|anchor| Day::parse(&anchor.through));
	let entries = match std::fs::read_dir(evidence_root.join(PURGES_DIR)) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error),
	};
	let mut newest: Option<Day> = None;
	for entry in entries {
		let name = entry?.file_name();
		let Some(through) = name
			.to_str()
			.and_then(|name| name.strip_suffix(".json"))
			.and_then(Day::parse)
		else {
			continue;
		};
		if reached.is_none_or(|reached| through > reached) && newest.is_none_or(|n| through > n) {
			newest = Some(through);
		}
	}
	let Some(through) = newest else {
		return Ok(None);
	};
	let path = evidence_root.join(PURGES_DIR).join(through.name());
	let Some(bytes) = checkpoint::read_bounded(&path.with_extension("json"), 1024 * 1024)? else {
		return Ok(None);
	};
	let statement = serde_json::from_slice(&bytes)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
	Ok(Some((through, statement, bytes)))
}

/// Whether the chain names the statement `digest` in a `purge` record. A day
/// that cannot be read leaves it unknown, which is not the same as no.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Named {
	Yes,
	No,
	Unknown,
}

pub(super) fn recorded(
	evidence_root: &Path,
	chain: &Chain,
	digest: &str,
) -> std::io::Result<Named> {
	let mut found = false;
	let mut unreadable = false;
	for day in chain.days()? {
		let walked =
			crate::evidence::ack::walk_day_acknowledged(evidence_root, day, |_, record, _| {
				found |= matches!(&record.entry, Entry::Purge(purge) if purge.statement == digest);
			});
		unreadable |= walked.is_err();
	}
	Ok(match (found, unreadable) {
		(true, _) => Named::Yes,
		(false, false) => Named::No,
		(false, true) => Named::Unknown,
	})
}

/// Finish a purge that was cut short. The whole evidence has to verify first.
/// A statement the chain never named, with every day read cleanly, is dropped
/// (nothing was decided); one it names gets its anchor, and the days the
/// anchor covers are deleted. When it cannot be told, nothing is touched and
/// the sweep says so.
pub(super) fn resume(
	evidence_root: &Path,
	chain: &Chain,
	anchors: &[[u8; 32]],
	now: u64,
) -> std::io::Result<()> {
	let Some((named, statement, bytes)) = unfinished(evidence_root)? else {
		return Ok(());
	};
	let kept = |why: &str| {
		std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			format!("a purge was cut short and is kept as it is: {why}"),
		)
	};
	let report = crate::evidence::audit::verify(
		evidence_root,
		&crate::evidence::audit::Options {
			from: None,
			to: None,
			anchors: anchors.to_vec(),
			now,
		},
	)?;
	if report.first_break.is_some() {
		return Err(kept("the evidence does not verify"));
	}
	// The path is made from the day the file is named for, never from what the
	// file says: a statement that names another day is not one of ours.
	if statement.through != named.name() {
		return Err(kept("the statement names another day than its file"));
	}
	let base = evidence_root.join(PURGES_DIR).join(named.name());
	match recorded(evidence_root, chain, &to_hex(&sha256(&bytes)))? {
		Named::Unknown => return Err(kept("a day of the chain cannot be read")),
		Named::No => {
			let _ = std::fs::remove_file(base.with_extension("json"));
			let _ = std::fs::remove_file(base.with_extension("sig"));
			return Ok(());
		}
		Named::Yes => {}
	}
	let invalid =
		|what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
	let position = Position {
		hash: hash_from_hex(&statement.last_hash)
			.ok_or_else(|| invalid("a purge statement holds a bad hash"))?,
		seq: statement.last_seq,
		time: statement.last_time,
	};
	let checkpoint_hash = hash_from_hex(&statement.checkpoint)
		.ok_or_else(|| invalid("a purge statement holds a bad checkpoint hash"))?;
	crate::evidence::anchor::write(
		&evidence_root.join(CHAIN_DIR),
		&statement.through,
		&position,
		&checkpoint_hash,
	)?;
	finish_deleting(evidence_root, chain, (anchors, now))
}

/// Delete the day files and checkpoints the anchor says were purged, once
/// the anchor is shown to be a purge's and not just a file that parses: the
/// whole evidence verifies, a signed statement for the anchor's day says the
/// same as the anchor, and every day to go is named by that statement with the
/// checkpoint it has now and has outlived its retention. Anything else, and
/// nothing is deleted.
pub(super) fn finish_deleting(
	evidence_root: &Path,
	chain: &Chain,
	(anchors, now): (&[[u8; 32]], u64),
) -> std::io::Result<()> {
	let Some(anchor) = crate::evidence::anchor::load(&evidence_root.join(CHAIN_DIR))? else {
		return Ok(());
	};
	let Some(through) = Day::parse(&anchor.through) else {
		return Ok(());
	};
	let going: Vec<Day> = chain
		.days()?
		.into_iter()
		.filter(|day| *day <= through)
		.collect();
	if going.is_empty() {
		return Ok(());
	}
	let kept = |why: &str| {
		std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			format!("the days the purge anchor covers are kept: {why}"),
		)
	};
	let report = crate::evidence::audit::verify(
		evidence_root,
		&crate::evidence::audit::Options {
			from: None,
			to: None,
			anchors: anchors.to_vec(),
			now,
		},
	)?;
	if report.first_break.is_some() {
		return Err(kept("the evidence does not verify"));
	}
	let base = evidence_root.join(PURGES_DIR).join(through.name());
	let read = |path: &Path| checkpoint::read_bounded(path, 1024 * 1024);
	let (Some(bytes), Some(_)) = (
		read(&base.with_extension("json"))?,
		read(&base.with_extension("sig"))?,
	) else {
		return Err(kept("there is no signed statement for the anchor"));
	};
	let statement: Statement = serde_json::from_slice(&bytes)
		.map_err(|_| kept("the statement for the anchor is malformed"))?;
	if statement.through != anchor.through
		|| statement.last_hash != anchor.last_hash
		|| statement.checkpoint != anchor.checkpoint
	{
		return Err(kept(
			"the statement for the anchor does not say what it says",
		));
	}
	for day in &going {
		let paths = files(evidence_root, *day);
		let named = statement.days.iter().find(|named| named.day == day.name());
		let sealed = read(&paths.json)?;
		let (Some(named), Some(sealed)) = (named, sealed) else {
			return Err(kept(&format!("{day} is not a purged day of the statement")));
		};
		let outlived = serde_json::from_slice::<Checkpoint>(&sealed)
			.ok()
			.and_then(|cp| Day::parse(&cp.retain_until))
			.is_some_and(|until| until < Day::of_epoch(now));
		if named.checkpoint != to_hex(&sha256(&sealed)) || !outlived {
			return Err(kept(&format!(
				"{day} is not the day the statement purged, or its retention has not passed"
			)));
		}
	}
	for day in going {
		let paths = files(evidence_root, day);
		for path in [chain.day_file(day), paths.json, paths.sig, paths.tsr] {
			match std::fs::remove_file(&path) {
				Ok(()) => {}
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
				Err(error) => return Err(error),
			}
		}
	}
	Ok(())
}
