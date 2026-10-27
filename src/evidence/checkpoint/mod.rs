//! The daily checkpoint: one signed statement that seals a closed UTC day.
//!
//! `checkpoints/YYYY-MM-DD.json` holds the day's record count, its Merkle
//! root, the `prev` of its first record (the last hash of the day before),
//! the hash of its last record, and the SHA-256 of the previous checkpoint
//! file, so days are linked by their checkpoints as well as by their
//! records. `.sig` next to it is the raw Ed25519 signature of the exact JSON
//! bytes, and `.tsr` is the RFC 3161 timestamp response over their SHA-256
//! once a timestamp authority answered. Only that hash ever leaves the
//! server.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::chain::create_private_dir;
use super::day::Day;
use super::key::EvidenceKey;
use super::merkle::{TreeBuilder, leaf_hash};
use super::record::{Position, hash_from_hex, sha256, to_hex};
use super::verify::{Break, walk_day};

/// The checkpoint directory, under the evidence root.
pub const CHECKPOINT_DIR: &str = "checkpoints";
/// The checkpoint format version.
pub const CHECKPOINT_VERSION: u32 = 1;
/// The most days sealed by one call of [`seal_closed_days`].
pub const MAX_DAYS_PER_PASS: usize = 31;

/// The signed statement for one day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
	/// Format version.
	pub v: u32,
	/// The day (`YYYY-MM-DD`).
	pub day: String,
	/// Records in the day.
	pub records: u64,
	/// Hex Merkle root over the day's records.
	pub merkle_root: String,
	/// Hex `prev` of the first record: the last hash of the day before.
	pub first_prev: String,
	/// Hex hash of the last record.
	pub last_hash: String,
	/// Sequence number of the last record.
	pub last_seq: u64,
	/// Time of the last record, epoch seconds.
	pub last_time: u64,
	/// Hex SHA-256 of the previous checkpoint file, `None` for the first.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prev_checkpoint: Option<String>,
	/// The last day any record of this day must be kept (`YYYY-MM-DD`).
	pub retain_until: String,
	/// `enabled` when a timestamp token is expected for this checkpoint.
	pub timestamp: String,
	/// The id of the key that signed it.
	pub key: String,
	/// Epoch seconds it was made.
	pub created: u64,
}

/// The files of one day's checkpoint.
#[derive(Debug, Clone)]
pub struct CheckpointFiles {
	/// The signed JSON.
	pub json: PathBuf,
	/// The raw Ed25519 signature.
	pub sig: PathBuf,
	/// The RFC 3161 timestamp response.
	pub tsr: PathBuf,
}

/// The files of `day`'s checkpoint under `evidence_root`.
pub fn files(evidence_root: &Path, day: Day) -> CheckpointFiles {
	let base = evidence_root.join(CHECKPOINT_DIR).join(day.name());
	CheckpointFiles {
		json: base.with_extension("json"),
		sig: base.with_extension("sig"),
		tsr: base.with_extension("tsr"),
	}
}

/// Why a day could not be sealed.
#[derive(Debug)]
pub enum SealError {
	/// The day does not verify; it is not sealed.
	Broken(Break),
	/// A file could not be read or written.
	Io(std::io::Error),
}

impl std::fmt::Display for SealError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			SealError::Broken(at) => write!(formatter, "the chain is broken: {at}"),
			SealError::Io(error) => write!(formatter, "{error}"),
		}
	}
}

impl From<std::io::Error> for SealError {
	fn from(error: std::io::Error) -> Self {
		SealError::Io(error)
	}
}

/// Read the checkpoint of `day` and its raw bytes, or `None` when the day
/// has none. A file larger than any checkpoint is refused.
pub fn load(evidence_root: &Path, day: Day) -> std::io::Result<Option<(Checkpoint, Vec<u8>)>> {
	let bytes = match read_bounded(&files(evidence_root, day).json, 16 * 1024)? {
		Some(bytes) => bytes,
		None => return Ok(None),
	};
	let checkpoint = serde_json::from_slice(&bytes)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
	Ok(Some((checkpoint, bytes)))
}

/// The bytes of `path`, `None` when it is missing, refused past `limit`.
pub fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Option<Vec<u8>>> {
	use std::io::Read;
	let file = match std::fs::File::open(path) {
		Ok(file) => file,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error),
	};
	let mut bytes = Vec::new();
	file.take(limit + 1).read_to_end(&mut bytes)?;
	if bytes.len() as u64 > limit {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			format!("{} is larger than expected", crate::log_id::path(path)),
		));
	}
	Ok(Some(bytes))
}

/// The newest checkpoint strictly before `day`: its day and file bytes.
pub fn previous(evidence_root: &Path, day: Day) -> std::io::Result<Option<(Day, Vec<u8>)>> {
	let mut best: Option<Day> = None;
	let dir = evidence_root.join(CHECKPOINT_DIR);
	let entries = match std::fs::read_dir(&dir) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error),
	};
	for entry in entries {
		let name = entry?.file_name();
		let Some(found) = name
			.to_str()
			.and_then(|name| name.strip_suffix(".json"))
			.and_then(Day::parse)
		else {
			continue;
		};
		if found < day && best.is_none_or(|best| found > best) {
			best = Some(found);
		}
	}
	let Some(found) = best else {
		return Ok(None);
	};
	Ok(read_bounded(&files(evidence_root, found).json, 16 * 1024)?.map(|bytes| (found, bytes)))
}

/// Build the checkpoint of `day` from its records: the chain must verify
/// from the day before (its checkpoint, the purge anchor or the start).
pub fn compute(
	evidence_root: &Path,
	day: Day,
	key_id: &str,
	timestamp: bool,
	now: u64,
) -> Result<Checkpoint, SealError> {
	let before = previous(evidence_root, day)?;
	let expected = match &before {
		Some((_, bytes)) => {
			let previous: Checkpoint = serde_json::from_slice(bytes)
				.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
			hash_from_hex(&previous.last_hash).map(|hash| Position {
				hash,
				seq: previous.last_seq,
				time: previous.last_time,
			})
		}
		None => Some(
			super::anchor::read(&evidence_root.join(super::chain::CHAIN_DIR))?
				.unwrap_or(Position::START),
		),
	};
	// The timestamp mode is the chain's: the previous checkpoint's, changed
	// by any setting record of the day. `timestamp` only seeds the first.
	let mut timestamp = match &before {
		Some((_, bytes)) => serde_json::from_slice::<Checkpoint>(bytes)
			.map(|previous| previous.timestamp == "enabled")
			.unwrap_or(timestamp),
		None => timestamp,
	};
	let mut tree = TreeBuilder::new();
	let mut retain_until = day;
	let walk = walk_day(evidence_root, day, expected, |_, record, hash| {
		tree.push(leaf_hash(hash));
		if let super::record::Entry::Setting(setting) = &record.entry
			&& setting.name == "timestamp"
		{
			timestamp = setting.value.starts_with("enabled");
		}
		let until = Day(day.0 + i64::from(record.entry.retain_days()));
		retain_until = retain_until.max(until);
	})
	.map_err(SealError::Broken)?;
	let (root, _) = tree.finish(&[]);
	Ok(Checkpoint {
		v: CHECKPOINT_VERSION,
		day: day.name(),
		records: walk.records,
		merkle_root: to_hex(&root),
		first_prev: to_hex(&walk.first_prev),
		last_hash: to_hex(&walk.last.hash),
		last_seq: walk.last.seq,
		last_time: walk.last.time,
		// After a purge the previous checkpoint is gone; the anchor keeps its
		// hash.
		prev_checkpoint: match before {
			Some((_, bytes)) => Some(to_hex(&sha256(&bytes))),
			None => super::anchor::load(&evidence_root.join(super::chain::CHAIN_DIR))?
				.map(|anchor| anchor.checkpoint),
		},
		retain_until: retain_until.name(),
		timestamp: if timestamp { "enabled" } else { "disabled" }.to_string(),
		key: key_id.to_string(),
		created: now,
	})
}

/// Seal `day`: compute its checkpoint, write it and its signature. Returns
/// the JSON bytes written. A day that already has a checkpoint is left as it
/// is and its bytes returned.
pub fn seal(
	evidence_root: &Path,
	day: Day,
	key: &EvidenceKey,
	timestamp: bool,
	now: u64,
) -> Result<Vec<u8>, SealError> {
	if let Some((_, bytes)) = load(evidence_root, day)? {
		return Ok(bytes);
	}
	let checkpoint = compute(evidence_root, day, &key.id(), timestamp, now)?;
	let bytes = serde_json::to_vec_pretty(&checkpoint).map_err(std::io::Error::other)?;
	let paths = files(evidence_root, day);
	create_private_dir(&evidence_root.join(CHECKPOINT_DIR))?;
	// Signature first: a JSON without its signature never looks complete.
	crate::storage::write_secret(&paths.sig, &key.sign(&bytes))?;
	crate::storage::write_secret(&paths.json, &bytes)?;
	Ok(bytes)
}

/// Seal every closed day (before the day of `now`) that has records and no
/// checkpoint yet, oldest first, at most [`MAX_DAYS_PER_PASS`] of them.
/// Returns the days sealed; stops at the first day that cannot be.
pub fn seal_closed_days(
	evidence_root: &Path,
	key: &EvidenceKey,
	timestamp: bool,
	now: u64,
) -> Result<Vec<Day>, SealError> {
	let today = Day::of_epoch(now);
	let chain = super::chain::Chain::open(evidence_root)?;
	let mut sealed = Vec::new();
	for day in chain.days()? {
		if day >= today || sealed.len() >= MAX_DAYS_PER_PASS {
			break;
		}
		if files(evidence_root, day).json.exists() {
			continue;
		}
		// Under the chain lock: no record of this day can still be in flight.
		chain.locked(|| seal(evidence_root, day, key, timestamp, now))??;
		sealed.push(day);
	}
	Ok(sealed)
}

#[cfg(test)]
mod tests;
