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
use super::record::{Entry, Position, hash_from_hex, sha256, to_hex};
use super::rotation::At;
use super::verify::{Break, Problem, walk_day};

/// Grace after midnight before a missing checkpoint is a break: the server
/// seals closed days on a timer.
pub const SEAL_GRACE_SECS: u64 = 3600;
/// The latest a token may be issued after its checkpoint was made.
pub const TOKEN_GRACE_SECS: u64 = 3 * 86_400;

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

fn broken(day: Day, why: impl Into<String>) -> Break {
	Break {
		day,
		line: 0,
		problem: Problem::Checkpoint(why.into()),
	}
}

/// What the walk carries from one day to the next. Nothing of it is
/// stored: every verification starts from the oldest kept day.
struct Walker {
	expected: Option<Position>,
	previous_checkpoint: Option<String>,
	previous_key: Option<String>,
	timestamping: bool,
	head: Option<[u8; 32]>,
	head_seen: bool,
	last_purge: Option<super::record::Purge>,
	/// Every purge record met, oldest first, with its place: each
	/// statement is checked against the key in force there.
	purges: Vec<(At, super::record::Purge)>,
	/// The pinned key and the keys it took over from, by signed rotations.
	lineage: Vec<String>,
	/// Every key rotation record met, oldest first, with its place.
	handovers: Vec<(At, super::rotation::Rotation)>,
	/// The day and signer of every checkpoint verified, in order.
	signers: Vec<(Day, String)>,
}

/// The most purge records one verification checks.
const MAX_PURGES: usize = 10_000;

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
	};
	for day in days {
		if let Err(at) =
			walk_and_check(evidence_root, day, today, options, &mut walker, &mut report)
		{
			if super::ack::is_acknowledged(evidence_root, &at) {
				// Accepted by the operator: carry on, unanchored, from the next day.
				report.acknowledged.push(at);
				walker.expected = None;
				walker.previous_checkpoint = None;
				continue;
			}
			report.first_break = Some(at);
			return Ok(report);
		}
	}
	report.first_break = final_checks(
		evidence_root,
		&purged,
		&walker,
		(from_start, to_end),
		today,
		head.is_some(),
	);
	Ok(report)
}

/// What can only be judged once every day was walked: the purge anchor and
/// the head.
fn final_checks(
	evidence_root: &Path,
	purged: &Option<anchor::Anchor>,
	walker: &Walker,
	(from_start, to_end): (bool, bool),
	today: Day,
	has_head: bool,
) -> Option<Break> {
	let timeline =
		super::rotation::Timeline::new(walker.lineage.clone(), walker.handovers.clone(), to_end);
	for (day, signer) in &walker.signers {
		if let Err(fault) = timeline.check_seal(signer, *day) {
			return Some(broken(*day, fault.to_string()));
		}
	}
	for (_, rotation) in &walker.handovers {
		if let Err(why) = super::rotation::check_record(evidence_root, rotation) {
			return Some(broken(today, why));
		}
	}
	for (at, purge) in &walker.purges {
		if let Err(why) = super::retention::check_statement(evidence_root, purge, *at, &timeline) {
			return Some(broken(today, why));
		}
	}
	match (purged, &walker.last_purge) {
		(Some(anchor), Some(purge))
			if anchor.last_hash != purge.last_hash
				|| anchor.checkpoint != purge.checkpoint
				|| anchor.through != purge.through =>
		{
			return Some(broken(
				today,
				"the purge anchor does not match the last purge record",
			));
		}
		(Some(_), None) if from_start && to_end => {
			return Some(broken(today, "days were purged without a purge record"));
		}
		_ => {}
	}
	if !to_end {
		return None;
	}
	if !has_head {
		return Some(broken(
			today,
			"the head is missing: the evidence may have been restored from an older copy",
		));
	}
	if !walker.head_seen {
		return Some(broken(
			today,
			"rollback: the chain ends before its recorded head (a truncated tail or a deleted latest day)",
		));
	}
	None
}

fn walk_and_check(
	evidence_root: &Path,
	day: Day,
	today: Day,
	options: &Options,
	walker: &mut Walker,
	report: &mut Report,
) -> Result<(), Break> {
	let mut tree = TreeBuilder::new();
	let mut timestamping = walker.timestamping;
	let head = walker.head;
	let mut head_seen = false;
	let mut purges = Vec::new();
	let mut rotations = Vec::new();
	let walk = walk_day(evidence_root, day, walker.expected, |line, record, hash| {
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
	})?;
	walker.head_seen |= head_seen;
	if let Some((_, last)) = purges.last() {
		walker.last_purge = Some(last.clone());
	}
	walker.purges.extend(purges);
	if walker.purges.len() > MAX_PURGES {
		return Err(broken(day, "more purge records than a verification checks"));
	}
	walker.handovers.extend(rotations);
	if walker.handovers.len() > super::rotation::MAX_ROTATIONS {
		return Err(broken(
			day,
			"more key rotations than a verification follows",
		));
	}
	walker.timestamping = timestamping;
	report.days += 1;
	report.records += walk.records;
	walker.expected = Some(walk.last);
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
	let stamped = check_day(evidence_root, day, &walk, &root, walker, options)?;
	report.sealed += 1;
	walker.signers.push((day, stamped.2.clone()));
	report.stamped += u32::from(stamped.1);
	walker.previous_checkpoint = Some(stamped.0);
	walker.previous_key = Some(stamped.2);
	Ok(())
}

fn parse(bytes: &[u8]) -> Result<Checkpoint, String> {
	serde_json::from_slice(bytes).map_err(|error| format!("unreadable checkpoint ({error})"))
}

/// Check `day`'s checkpoint against its walk; returns the checkpoint hash,
/// whether a valid token covers it, and the key that signed it.
fn check_day(
	evidence_root: &Path,
	day: Day,
	walk: &super::verify::DayWalk,
	root: &[u8; 32],
	walker: &Walker,
	options: &Options,
) -> Result<(String, bool, String), Break> {
	let io = |error: std::io::Error| broken(day, format!("cannot read ({})", error.kind()));
	let (checkpoint, bytes) = checkpoint::load(evidence_root, day)
		.map_err(io)?
		.ok_or_else(|| broken(day, "missing: the day was never sealed"))?;
	if checkpoint.v != checkpoint::CHECKPOINT_VERSION {
		return Err(broken(
			day,
			format!("unsupported checkpoint version {}", checkpoint.v),
		));
	}
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
		|| checkpoint.last_hash != to_hex(&walk.last.hash)
		|| checkpoint.last_seq != walk.last.seq
		|| checkpoint.last_time != walk.last.time
	{
		return Err(mismatch("the first or last hash"));
	}
	if let Some(expected) = &walker.previous_checkpoint
		&& checkpoint.prev_checkpoint.as_deref() != Some(expected.as_str())
	{
		return Err(broken(
			day,
			"does not name the previous checkpoint: a checkpoint was replaced",
		));
	}
	if walker.lineage.is_empty() {
		return Err(broken(day, "the evidence key pin is missing"));
	}
	if !walker.lineage.contains(&checkpoint.key) {
		return Err(broken(
			day,
			"signed with a key other than the pinned evidence key, or one it took over from by a signed rotation",
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
	let enabled = checkpoint.timestamp == "enabled";
	if enabled != walker.timestamping {
		return Err(broken(
			day,
			"timestamping is marked disabled while the chain has it enabled: a downgrade",
		));
	}
	if !enabled {
		return Ok((hash, false, checkpoint.key));
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
	token_window(day, &checkpoint, &stamp)
		.map_err(|why| broken(day, format!("timestamp: {why}")))?;
	Ok((hash, true, checkpoint.key))
}

/// The times a token for `day`'s checkpoint may carry: after the day ended
/// (every record of the day existed) and within [`TOKEN_GRACE_SECS`] of the
/// seal. Shared by the audit and by the purge, which must not judge a token
/// by a looser rule than the audit does.
pub(crate) fn token_window(
	day: Day,
	checkpoint: &checkpoint::Checkpoint,
	stamp: &super::tsa::Stamp,
) -> Result<(), &'static str> {
	if stamp.gen_time < Day(day.0 + 1).start_epoch() {
		return Err("the token predates the end of the day");
	}
	if stamp.gen_time > checkpoint.created.saturating_add(TOKEN_GRACE_SECS) {
		return Err("the token was issued more than 3 days after the checkpoint");
	}
	Ok(())
}

#[cfg(test)]
#[path = "audit_tests.rs"]
pub(crate) mod tests;
