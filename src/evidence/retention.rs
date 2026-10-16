//! Purging what has outlived its retention, without breaking the chain and
//! without ever covering up a change.
//!
//! Kept messages live in `messages/<day>/<days>/`: a whole directory goes
//! once `<day> + <days>` has passed. That is the only thing deleted early.
//! Records and checkpoints go a day at a time, oldest first, and only a
//! contiguous run of the oldest days that:
//!
//! - closed before yesterday, and whose checkpoint says every record in
//!   them may go (`retain_until` passed);
//! - still match their checkpoint (recomputed from the records now);
//! - carry a timestamp token that verifies against a trusted anchor;
//! - come before any break an operator acknowledged.
//!
//! Before anything goes, the whole evidence is verified; a purge is
//! refused while it does not verify, so a changed day is never purged
//! away, and the refusal is reported. A purge never writes a checkpoint.
//!
//! A purge leaves three things behind:
//!
//! - a statement in `purges/<through>.json`, signed in `.sig` with the
//!   evidence key, naming each purged day with its record count, Merkle
//!   root and checkpoint hash, and where the chain stood after them;
//! - a `purge` record appended to the chain after the verified head,
//!   carrying the range, the count and the statement's hash, so the purge
//!   itself is sealed and timestamped like any other record;
//! - the anchor, so the next record and `verify` start from that position.
//!
//! The order makes a crash safe: statement, record, anchor, then deletion.
//! Days the anchor covers that are still on disk (a crash during deletion)
//! are deleted at the start of the next sweep.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::chain::{CHAIN_DIR, Chain, create_private_dir};
use super::checkpoint::{self, Checkpoint, files};
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

/// One purged day, as the statement names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgedDay {
	/// The day.
	pub day: String,
	/// Its records.
	pub records: u64,
	/// Its Merkle root.
	pub merkle_root: String,
	/// Hex SHA-256 of its checkpoint file.
	pub checkpoint: String,
}

/// What a purge statement says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
	/// Format version.
	pub v: u32,
	/// The first purged day.
	pub from: String,
	/// The last purged day.
	pub through: String,
	/// Records purged, over every day.
	pub records: u64,
	/// Each purged day.
	pub days: Vec<PurgedDay>,
	/// Hex hash of the last purged record.
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
	/// Why expired days were kept, when some were.
	pub refused: Option<String>,
}

/// A day whose retention passed, with its checkpoint and its bytes.
type Expired = (Day, Checkpoint, Vec<u8>);

/// The oldest contiguous days whose retention passed, up to the cap.
fn expired_days(evidence_root: &Path, chain: &Chain, today: Day) -> std::io::Result<Vec<Expired>> {
	let mut expired = Vec::new();
	for day in chain.days()? {
		if day.0 + 1 >= today.0 || expired.len() >= MAX_DAYS_PER_SWEEP {
			break;
		}
		let Some((checkpoint, bytes)) = checkpoint::load(evidence_root, day)? else {
			break;
		};
		match Day::parse(&checkpoint.retain_until) {
			Some(until) if until < today => expired.push((day, checkpoint, bytes)),
			_ => break,
		}
	}
	Ok(expired)
}

/// Why `day` may not be purged, or `None` when it may: its records must
/// still be the ones its checkpoint names, and its token must verify.
fn unpurgeable(
	evidence_root: &Path,
	day: Day,
	sealed: &Checkpoint,
	bytes: &[u8],
	anchors: &[[u8; 32]],
	now: u64,
) -> Option<String> {
	let recomputed = checkpoint::compute(evidence_root, day, &sealed.key, true, now);
	let matches = recomputed.is_ok_and(|now| {
		now.records == sealed.records
			&& now.merkle_root == sealed.merkle_root
			&& now.last_hash == sealed.last_hash
			&& now.retain_until == sealed.retain_until
	});
	if !matches {
		return Some(format!("{day}: the records no longer match the checkpoint"));
	}
	let token = checkpoint::read_bounded(&files(evidence_root, day).tsr, 64 * 1024)
		.ok()
		.flatten();
	let stamp =
		token.and_then(|token| super::tsa::verify(&token, &sha256(bytes), None, anchors).ok());
	let Some(stamp) = stamp else {
		return Some(format!("{day}: no timestamp token that verifies"));
	};
	if let Err(why) = super::audit::token_window(day, sealed, &stamp) {
		return Some(format!("{day}: no timestamp token that verifies: {why}"));
	}
	None
}

/// Run one sweep at `now`, trusting the timestamp keys in `anchors`.
pub fn sweep(
	evidence_root: &Path,
	key: &EvidenceKey,
	anchors: &[[u8; 32]],
	now: u64,
) -> std::io::Result<Sweep> {
	let today = Day::of_epoch(now);
	let mut done = Sweep {
		message_dirs: sweep_messages(evidence_root, today)?,
		..Sweep::default()
	};
	let chain = Chain::open(evidence_root)?;
	finish_deleting(evidence_root, &chain)?;
	let expired = expired_days(evidence_root, &chain, today)?;
	if expired.is_empty() {
		return Ok(done);
	}
	// Nothing goes while anything is wrong: a purge must not hide a change.
	let report = super::audit::verify(
		evidence_root,
		&super::audit::Options {
			from: None,
			to: None,
			anchors: anchors.to_vec(),
			now,
		},
	)?;
	if let Some(at) = &report.first_break {
		done.refused = Some(format!(
			"purge refused: the evidence does not verify ({at})"
		));
		return Ok(done);
	}
	let acknowledged = report.acknowledged.iter().map(|at| at.day).min();
	let mut purgeable: Vec<Expired> = Vec::new();
	for (day, sealed, bytes) in expired {
		if acknowledged.is_some_and(|first| day >= first) {
			done.refused = Some(format!(
				"purge stopped at {day}: an acknowledged break is kept"
			));
			break;
		}
		if let Some(why) = unpurgeable(evidence_root, day, &sealed, &bytes, anchors, now) {
			done.refused = Some(format!("purge stopped at {why}"));
			break;
		}
		purgeable.push((day, sealed, bytes));
	}
	let (Some((first, _, _)), Some((through, last, last_bytes))) =
		(purgeable.first(), purgeable.last())
	else {
		return Ok(done);
	};
	let checkpoint_hash = sha256(last_bytes);
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
	let days: Vec<PurgedDay> = purgeable
		.iter()
		.map(|(day, sealed, bytes)| PurgedDay {
			day: day.name(),
			records: sealed.records,
			merkle_root: sealed.merkle_root.clone(),
			checkpoint: to_hex(&sha256(bytes)),
		})
		.collect();
	let records = days.iter().map(|day| day.records).sum();
	let retain_until = purgeable
		.iter()
		.filter_map(|(_, sealed, _)| Day::parse(&sealed.retain_until))
		.max()
		.unwrap_or(*through);
	let statement = Statement {
		v: 1,
		from: first.name(),
		through: through.name(),
		records,
		days,
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
			from: first.name(),
			through: through.name(),
			records,
			last_hash: last.last_hash.clone(),
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

/// Whether the signed statement of `purge` is there, is the one the record
/// names, was signed by the evidence key in force at `at` (where the purge
/// record sits), and says what the record says.
pub fn check_statement(
	evidence_root: &Path,
	purge: &Purge,
	at: super::rotation::At,
	timeline: &super::rotation::Timeline,
) -> Result<(), &'static str> {
	let Some(through) = Day::parse(&purge.through) else {
		return Err("the purge record names no day");
	};
	let base = evidence_root.join(PURGES_DIR).join(through.name());
	let read = |path: &Path| checkpoint::read_bounded(path, 1024 * 1024).ok().flatten();
	let (Some(bytes), Some(signature)) = (
		read(&base.with_extension("json")),
		read(&base.with_extension("sig")),
	) else {
		return Err("the purge statement is missing");
	};
	if to_hex(&sha256(&bytes)) != purge.statement {
		return Err("the purge statement is not the one its record names");
	}
	// The statement names its signer, who must be the key in force where the
	// purge record sits in the chain.
	let statement: Statement =
		serde_json::from_slice(&bytes).map_err(|_| "the purge statement is malformed")?;
	if timeline.check(&statement.key, at).is_err() {
		return Err("the purge statement was not signed by the evidence key in force");
	}
	let public =
		super::rotation::public_key(&evidence_root.join(super::key::KEYS_DIR), &statement.key)
			.ok_or("the evidence key that signed the statement is unreadable")?;
	if !super::key::verify(&public, &bytes, &signature) {
		return Err("the purge statement's signature does not verify");
	}
	if statement.from != purge.from
		|| statement.through != purge.through
		|| statement.records != purge.records
		|| statement.last_hash != purge.last_hash
		|| statement.checkpoint != purge.checkpoint
		|| statement.days.iter().map(|day| day.records).sum::<u64>() != statement.records
	{
		return Err("the purge statement does not say what its record says");
	}
	Ok(())
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
