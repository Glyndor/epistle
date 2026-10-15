//! Purging what has outlived its retention, without breaking the chain.
//!
//! Kept messages live in `messages/<day>/<days>/`: a whole directory goes
//! once `<day> + <days>` has passed. Records and checkpoints go a day at a
//! time, oldest first, and only a contiguous run of the oldest days whose
//! checkpoint says everything in them may go (`retain_until` passed). A
//! purge leaves three things behind:
//!
//! - a statement in `purges/<through>.json`, signed in `.sig` with the
//!   evidence key, naming the purged days and where the chain stood after
//!   them;
//! - a `purge` record in the chain, carrying the statement's hash, so the
//!   purge itself is sealed and timestamped like any other record;
//! - the anchor, so the next record and `verify` start from that position.
//!
//! The order makes a crash safe: statement, record, anchor, then deletion.
//! Days the anchor covers that are still on disk (a crash during deletion)
//! are deleted at the start of the next sweep.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::chain::{CHAIN_DIR, Chain, create_private_dir};
use super::checkpoint::{self, files};
use super::day::Day;
use super::key::EvidenceKey;
use super::record::{Entry, Position, Purge, hash_from_hex, sha256, to_hex};
use super::service::MESSAGES_DIR;

/// The purge statements directory, under the evidence root.
pub const PURGES_DIR: &str = "purges";
/// The most days purged by one sweep.
pub const MAX_DAYS_PER_SWEEP: usize = 366;
/// The most kept-message directories removed by one sweep.
pub const MAX_MESSAGE_DIRS_PER_SWEEP: usize = 10_000;

/// What a purge statement says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
	/// Format version.
	pub v: u32,
	/// The first and last purged day.
	pub from: String,
	/// The last purged day.
	pub through: String,
	/// Hex hash, sequence and time of the last purged record.
	pub last_hash: String,
	/// Its sequence number.
	pub last_seq: u64,
	/// Its time.
	pub last_time: u64,
	/// Hex SHA-256 of the last purged day's checkpoint.
	pub checkpoint: String,
	/// The latest `retain_until` of the purged days.
	pub retain_until: String,
	/// When the purge ran, epoch seconds.
	pub time: u64,
	/// The id of the key that signed this statement.
	pub key: String,
}

/// What one sweep did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sweep {
	/// Kept-message directories removed.
	pub message_dirs: usize,
	/// Days of records and checkpoints purged.
	pub days: usize,
}

/// Run one sweep at `now`.
pub fn sweep(evidence_root: &Path, key: &EvidenceKey, now: u64) -> std::io::Result<Sweep> {
	let today = Day::of_epoch(now);
	let mut done = Sweep {
		message_dirs: sweep_messages(evidence_root, today)?,
		..Sweep::default()
	};
	let chain = Chain::open(evidence_root)?;
	finish_deleting(evidence_root, &chain)?;
	let mut purgeable = Vec::new();
	let mut retain_until = Day(i64::MIN);
	for day in chain.days()? {
		if day.0 + 1 >= today.0 || purgeable.len() >= MAX_DAYS_PER_SWEEP {
			break;
		}
		let Some((checkpoint, _)) = checkpoint::load(evidence_root, day)? else {
			break;
		};
		match Day::parse(&checkpoint.retain_until) {
			Some(until) if until < today => {
				retain_until = retain_until.max(until);
				purgeable.push(day);
			}
			_ => break,
		}
	}
	let (Some(first), Some(through)) = (purgeable.first(), purgeable.last()) else {
		return Ok(done);
	};
	let (last, bytes) = checkpoint::load(evidence_root, *through)?.ok_or_else(|| {
		std::io::Error::new(std::io::ErrorKind::NotFound, "the checkpoint went missing")
	})?;
	let checkpoint_hash = sha256(&bytes);
	let position = Position {
		hash: hash_from_hex(&last.last_hash).ok_or_else(|| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"a checkpoint holds a bad hash",
			)
		})?,
		seq: last.last_seq,
		time: last.last_time,
	};
	let statement = Statement {
		v: 1,
		from: first.name(),
		through: through.name(),
		last_hash: last.last_hash.clone(),
		last_seq: last.last_seq,
		last_time: last.last_time,
		checkpoint: to_hex(&checkpoint_hash),
		retain_until: retain_until.name(),
		time: now,
		key: key.id(),
	};
	let statement_bytes = serde_json::to_vec_pretty(&statement).map_err(std::io::Error::other)?;
	let dir = evidence_root.join(PURGES_DIR);
	create_private_dir(&dir)?;
	let base = dir.join(through.name());
	crate::storage::write_secret(&base.with_extension("sig"), &key.sign(&statement_bytes))?;
	crate::storage::write_secret(&base.with_extension("json"), &statement_bytes)?;
	chain.append_at(
		now,
		Entry::Purge(Purge {
			through: through.name(),
			last_hash: last.last_hash,
			checkpoint: to_hex(&checkpoint_hash),
			statement: to_hex(&sha256(&statement_bytes)),
		}),
	)?;
	super::anchor::write(
		&evidence_root.join(CHAIN_DIR),
		&through.name(),
		&position,
		&checkpoint_hash,
	)?;
	finish_deleting(evidence_root, &chain)?;
	done.days = purgeable.len();
	Ok(done)
}

/// Delete the day files and checkpoints the anchor says were purged.
fn finish_deleting(evidence_root: &Path, chain: &Chain) -> std::io::Result<()> {
	let Some(anchor) = super::anchor::load(&evidence_root.join(CHAIN_DIR))? else {
		return Ok(());
	};
	let Some(through) = Day::parse(&anchor.through) else {
		return Ok(());
	};
	for day in chain.days()?.into_iter().filter(|day| *day <= through) {
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

/// Remove `messages/<day>/<days>/` directories whose retention has passed.
fn sweep_messages(evidence_root: &Path, today: Day) -> std::io::Result<usize> {
	let root = evidence_root.join(MESSAGES_DIR);
	let days = match std::fs::read_dir(&root) {
		Ok(days) => days,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
		Err(error) => return Err(error),
	};
	let mut removed = 0;
	for entry in days {
		let entry = entry?;
		let Some(day) = entry.file_name().to_str().and_then(Day::parse) else {
			continue;
		};
		if !entry.file_type()?.is_dir() {
			continue;
		}
		for kept in std::fs::read_dir(entry.path())? {
			let kept = kept?;
			let Some(days) = kept
				.file_name()
				.to_str()
				.and_then(|name| name.parse::<u32>().ok())
			else {
				continue;
			};
			if kept.file_type()?.is_dir() && day.0 + i64::from(days) < today.0 {
				std::fs::remove_dir_all(kept.path())?;
				removed += 1;
				if removed >= MAX_MESSAGE_DIRS_PER_SWEEP {
					return Ok(removed);
				}
			}
		}
		let _ = std::fs::remove_dir(entry.path());
	}
	Ok(removed)
}

#[cfg(test)]
#[path = "retention_tests.rs"]
mod tests;
