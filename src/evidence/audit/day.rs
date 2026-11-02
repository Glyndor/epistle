//! One day's checkpoint judged against the walk of its records.

use std::path::Path;

use super::grace::token_window;
use super::walker::Walker;
use super::{Options, broken};
use crate::evidence::checkpoint::{self, Checkpoint, files};
use crate::evidence::day::Day;
use crate::evidence::key;
use crate::evidence::record::{sha256, to_hex};
use crate::evidence::verify::Break;

pub(super) fn parse(bytes: &[u8]) -> Result<Checkpoint, String> {
	serde_json::from_slice(bytes).map_err(|error| format!("unreadable checkpoint ({error})"))
}

/// Check `day`'s checkpoint against its walk; returns the checkpoint hash,
/// whether a valid token covers it, and the key that signed it.
pub(super) fn check_day(
	evidence_root: &Path,
	day: Day,
	walk: &crate::evidence::verify::DayWalk,
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
	let public = checkpoint::read_bounded(
		&key::public_key_path(evidence_root, &checkpoint.key),
		64 * 1024,
	)
	.ok()
	.flatten()
	.and_then(|pem| String::from_utf8(pem).ok())
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
		crate::evidence::tsa::token::MAX_RESPONSE as u64,
	)
	.map_err(io)?
	.ok_or_else(|| {
		broken(
			day,
			"not timestamped: the token is missing (still being requested, or the day was re-signed)",
		)
	})?;
	let stamp = crate::evidence::tsa::verify(&token, &sha256(&bytes), None, &options.anchors)
		.map_err(|error| broken(day, format!("timestamp: {error}")))?;
	token_window(day, &checkpoint, &stamp)
		.map_err(|why| broken(day, format!("timestamp: {why}")))?;
	Ok((hash, true, checkpoint.key))
}
