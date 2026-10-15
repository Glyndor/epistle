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

use super::anchor;
use super::chain::{CHAIN_DIR, Chain};
use super::checkpoint::{self, Checkpoint, files};
use super::day::Day;
use super::key;
use super::merkle::{TreeBuilder, leaf_hash};
use super::record::{Entry, GENESIS, hash_from_hex, sha256, to_hex};
use super::verify::{Break, Problem, walk_day};

/// Grace after midnight before a missing checkpoint is a break: the server
/// seals closed days on a timer.
pub const SEAL_GRACE_SECS: u64 = 3600;

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
	/// The first break, when there is one.
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
	days.retain(|day| {
		options.from.is_none_or(|from| *day >= from) && options.to.is_none_or(|to| *day <= to)
	});
	let mut report = Report::default();
	let Some(first) = days.first().copied() else {
		return Ok(report);
	};
	// Where the first day must start: the previous checkpoint, the purge
	// anchor, or the very beginning.
	let previous = checkpoint::previous(evidence_root, first)?;
	let mut expected: Option<[u8; 32]> = match (&previous, &purged) {
		(Some((_, bytes)), _) => parse(bytes)
			.ok()
			.and_then(|cp| hash_from_hex(&cp.last_hash)),
		(None, Some(anchor)) => hash_from_hex(&anchor.last_hash),
		(None, None) if from_start => Some(GENESIS),
		(None, None) => None,
	};
	let mut previous_checkpoint: Option<String> = match (&previous, &purged) {
		(Some((_, bytes)), _) => Some(to_hex(&sha256(bytes))),
		(None, Some(anchor)) => Some(anchor.checkpoint.clone()),
		(None, None) => None,
	};
	let mut last_purge: Option<super::record::Purge> = None;
	for day in days {
		let mut tree = TreeBuilder::new();
		let walk = walk_day(evidence_root, day, expected, |_, record, hash| {
			tree.push(leaf_hash(hash));
			if let Entry::Purge(purge) = &record.entry {
				last_purge = Some(purge.clone());
			}
		});
		let walk = match walk {
			Ok(walk) => walk,
			Err(at) => {
				report.first_break = Some(at);
				return Ok(report);
			}
		};
		report.days += 1;
		report.records += walk.records;
		expected = Some(walk.last);
		if day >= today
			|| (day.0 + 1 == today.0 && options.now < today.start_epoch() + SEAL_GRACE_SECS)
		{
			if checkpoint::load(evidence_root, day)?.is_none() {
				report.open.push(day);
				continue;
			}
		}
		let (root, _) = tree.finish(&[]);
		match check_day(
			evidence_root,
			day,
			&walk,
			&root,
			previous_checkpoint.as_deref(),
			options,
		) {
			Ok((hash, stamped)) => {
				report.sealed += 1;
				report.stamped += u32::from(stamped);
				previous_checkpoint = Some(hash);
			}
			Err(at) => {
				report.first_break = Some(at);
				return Ok(report);
			}
		}
	}
	match (&purged, &last_purge) {
		(Some(anchor), Some(purge))
			if anchor.last_hash != purge.last_hash
				|| anchor.checkpoint != purge.checkpoint
				|| anchor.through != purge.through =>
		{
			report.first_break = Some(broken(
				today,
				"the purge anchor does not match the last purge record",
			));
		}
		(Some(_), None) if from_start && options.to.is_none() => {
			report.first_break = Some(broken(today, "days were purged without a purge record"));
		}
		_ => {}
	}
	Ok(report)
}

fn parse(bytes: &[u8]) -> Result<Checkpoint, String> {
	serde_json::from_slice(bytes).map_err(|error| format!("unreadable checkpoint ({error})"))
}

/// Check `day`'s checkpoint against its walk; returns the checkpoint hash
/// and whether a valid token covers it.
fn check_day(
	evidence_root: &Path,
	day: Day,
	walk: &super::verify::DayWalk,
	root: &[u8; 32],
	previous_checkpoint: Option<&str>,
	options: &Options,
) -> Result<(String, bool), Break> {
	let io = |error: std::io::Error| broken(day, format!("cannot read ({})", error.kind()));
	let (checkpoint, bytes) = checkpoint::load(evidence_root, day)
		.map_err(io)?
		.ok_or_else(|| broken(day, "missing: the day was never sealed"))?;
	let mismatch = |what: &str| broken(day, format!("{what} does not match the day's records"));
	if checkpoint.day != day.name() {
		return Err(mismatch("the day"));
	}
	if checkpoint.records != walk.records {
		return Err(mismatch("the record count"));
	}
	if checkpoint.merkle_root != to_hex(root) {
		return Err(mismatch("the Merkle root"));
	}
	if checkpoint.first_prev != to_hex(&walk.first_prev)
		|| checkpoint.last_hash != to_hex(&walk.last)
	{
		return Err(mismatch("the first or last hash"));
	}
	if let Some(expected) = previous_checkpoint
		&& checkpoint.prev_checkpoint.as_deref() != Some(expected)
	{
		return Err(broken(
			day,
			"does not name the previous checkpoint: a checkpoint was replaced",
		));
	}
	let signature = checkpoint::read_bounded(&files(evidence_root, day).sig, 64)
		.map_err(io)?
		.ok_or_else(|| broken(day, "the signature is missing"))?;
	let public = std::fs::read_to_string(key::public_key_path(evidence_root, &checkpoint.key))
		.ok()
		.and_then(|pem| key::parse_public_pem(&pem))
		.filter(|public| key::key_id(public) == checkpoint.key)
		.ok_or_else(|| broken(day, "the signing key is not published"))?;
	if !key::verify(&public, &bytes, &signature) {
		return Err(broken(day, "the signature does not verify"));
	}
	let hash = to_hex(&sha256(&bytes));
	if checkpoint.timestamp != "enabled" {
		return Ok((hash, false));
	}
	let token = checkpoint::read_bounded(
		&files(evidence_root, day).tsr,
		super::tsa::token::MAX_RESPONSE as u64,
	)
	.map_err(io)?
	.ok_or_else(|| {
		broken(
			day,
			"not timestamped: the token is missing (still being requested, or the day was re-signed)",
		)
	})?;
	let stamp = super::tsa::verify(&token, &sha256(&bytes), None, &options.anchors)
		.map_err(|error| broken(day, format!("timestamp: {error}")))?;
	if stamp.gen_time < Day(day.0 + 1).start_epoch() {
		return Err(broken(
			day,
			"timestamp: the token predates the end of the day",
		));
	}
	Ok((hash, true))
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
