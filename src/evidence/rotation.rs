//! Changing the evidence key without breaking what the old one vouched for.
//!
//! A rotation is a statement, signed by the old key, that names the new
//! key's id. It is kept in `keys/rotations/<new id>.json` and also written
//! as a `key_rotated` record in the chain, so the day it happened is sealed
//! (by the new key) and timestamped like any other. A reader who pinned the
//! old id can then follow the signed rotations to every later key; nothing
//! else makes a key trusted.
//!
//! The order makes a crash safe: the new key is staged in `key.next.pk8`,
//! the statement and its public key are written, the record is appended,
//! then the staged key replaces the old one and the pin moves. A crash
//! before the replacement leaves the old key in force (a later rotation
//! reuses the staged key); a crash between the replacement and the pin is
//! repaired on the next load, because the signed statement names the step.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::chain::Chain;
use super::day::Day;
use super::key::{self, EvidenceKey};
use super::record::{Entry, hash_from_hex, to_hex};

/// Where rotation statements live, under the evidence root.
pub const ROTATIONS_DIR: &str = "keys/rotations";
/// The longest chain of rotations followed.
pub const MAX_ROTATIONS: usize = 64;

/// One rotation: `old` hands over to `new`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotation {
	/// The id of the key handing over.
	pub old: String,
	/// The id of the key taking over.
	pub new: String,
	/// The UTC day (`YYYY-MM-DD`) of the hand-over: the first day the new key
	/// seals, and the first the old key may not.
	pub day: String,
	/// Hex Ed25519 signature by `old` over [`statement`].
	pub signature: String,
}

/// The bytes a rotation signs: the date is part of it, so a reader who holds
/// the old key's id learns from the statement alone when the key stopped.
pub fn statement(old: &str, new: &str, day: &str) -> Vec<u8> {
	format!("epistle evidence key rotation\n{old}\n{new}\n{day}\n").into_bytes()
}

impl Rotation {
	/// The hand-over from `old` to the key `new`, effective on `day`, signed
	/// by `old`.
	pub fn signed(old: &EvidenceKey, new: &str, day: &str) -> Rotation {
		Rotation {
			old: old.id(),
			new: new.to_string(),
			day: day.to_string(),
			signature: to_hex(&old.sign(&statement(&old.id(), new, day))),
		}
	}

	/// Whether the ids are key ids, the day is a day and `old_public` (whose
	/// id must be `old`) signed the hand-over.
	pub fn verifies(&self, old_public: &[u8; 32]) -> bool {
		let Some(signature) = hex_bytes(&self.signature) else {
			return false;
		};
		hash_from_hex(&self.old).is_some()
			&& hash_from_hex(&self.new).is_some()
			&& Day::parse(&self.day).is_some()
			&& key::key_id(old_public) == self.old
			&& key::verify(
				old_public,
				&statement(&self.old, &self.new, &self.day),
				&signature,
			)
	}
}

fn hex_bytes(value: &str) -> Option<Vec<u8>> {
	if value.len() != 128 {
		return None;
	}
	(0..value.len())
		.step_by(2)
		.map(|at| u8::from_str_radix(value.get(at..at + 2)?, 16).ok())
		.collect()
}

/// Where the statement handing over to `new` is kept.
pub fn path(evidence_root: &Path, new: &str) -> PathBuf {
	evidence_root
		.join(ROTATIONS_DIR)
		.join(format!("{new}.json"))
}

/// The rotation that handed over to `new`, when it is there and parses.
pub fn load(dir: &Path, new: &str) -> Option<Rotation> {
	hash_from_hex(new)?;
	let bytes = super::checkpoint::read_bounded(&dir.join(format!("{new}.json")), 4096).ok()??;
	serde_json::from_slice(&bytes).ok()
}

/// The published public key `id` under `keys_dir`, when its id matches.
pub fn public_key(keys_dir: &Path, id: &str) -> Option<[u8; 32]> {
	hash_from_hex(id)?;
	let pem = super::checkpoint::read_bounded(&keys_dir.join(format!("{id}.pem")), 4096).ok()??;
	std::str::from_utf8(&pem)
		.ok()
		.and_then(key::parse_public_pem)
		.filter(|public| key::key_id(public) == id)
}

/// The rotation to `new`, verified by the old key published beside it.
fn verified(evidence_root: &Path, new: &str) -> Option<Rotation> {
	let rotation = load(&evidence_root.join(ROTATIONS_DIR), new)?;
	let old = public_key(&evidence_root.join(key::KEYS_DIR), &rotation.old)?;
	(rotation.new == new && rotation.verifies(&old)).then_some(rotation)
}

/// The pinned key and every key before it, newest first, as far as signed
/// rotations lead.
pub fn lineage(evidence_root: &Path) -> std::io::Result<Vec<String>> {
	let Some(mut current) = key::pinned_id(evidence_root)? else {
		return Ok(Vec::new());
	};
	let mut ids = vec![current.clone()];
	while ids.len() <= MAX_ROTATIONS {
		let Some(rotation) = verified(evidence_root, &current) else {
			break;
		};
		if ids.contains(&rotation.old) {
			break;
		}
		ids.push(rotation.old.clone());
		current = rotation.old;
	}
	Ok(ids)
}

/// Whether `rotation` is the verified statement handing over to its `new`
/// key, as the evidence record that names it must be.
pub fn check_record(evidence_root: &Path, rotation: &Rotation) -> Result<(), &'static str> {
	match verified(evidence_root, &rotation.new) {
		Some(kept) if &kept == rotation => Ok(()),
		Some(_) => Err("the key rotation record differs from its statement"),
		None => Err("the key rotation statement is missing or not signed by the old key"),
	}
}

/// The verified statements from `id` back to the oldest key they lead to,
/// newest first: what a reader needs to follow `id` to an anchor.
pub fn ancestry(evidence_root: &Path, id: &str) -> Vec<Rotation> {
	let mut found: Vec<Rotation> = Vec::new();
	let mut current = id.to_string();
	while found.len() < MAX_ROTATIONS {
		let Some(rotation) = verified(evidence_root, &current) else {
			break;
		};
		if found.iter().any(|seen| seen.old == rotation.old) || rotation.old == id {
			break;
		}
		current = rotation.old.clone();
		found.push(rotation);
	}
	found
}

/// Whether the key now in `key.pk8` (`id`) took over from the pinned one by
/// a signed rotation: the repair after a crash between the two.
pub(crate) fn took_over(evidence_root: &Path, pinned: &str, id: &str) -> bool {
	verified(evidence_root, id).is_some_and(|rotation| rotation.old == pinned)
}

/// A place in the chain: the day and the 1-based line in its file.
pub type At = (Day, u64);

/// Why a key may not sign at a place in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
	/// It is not the pinned key nor one it took over from.
	Unknown,
	/// The rotation that introduced it comes later in the chain.
	NotYet,
	/// A rotation record before this place handed over from it.
	HandedOver,
	/// Another key took over from it, and the chain has no record of when.
	Unrecorded,
}

impl std::fmt::Display for Fault {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(match self {
			Fault::Unknown => {
				"signed with a key other than the pinned evidence key, or one it took over from by a signed rotation"
			}
			Fault::NotYet => "signed with a key before the rotation record that introduces it",
			Fault::HandedOver => {
				"signed with a key that had already handed over to another: only the key now in force signs after a rotation"
			}
			Fault::Unrecorded => {
				"signed with a key another took over from, with no rotation record in the chain"
			}
		})
	}
}

/// Which key is in force at each place of the chain: the one rule the audit,
/// the acknowledgements and the purge statements share. A key signs from the
/// rotation record that introduces it to the one that hands over from it.
/// A record of the hand-over that is not in the chain walked is taken to lie
/// before everything kept (purged), unless the walk stopped early.
#[derive(Debug, Clone)]
pub struct Timeline {
	lineage: Vec<String>,
	handovers: Vec<(At, Rotation)>,
	reaches_end: bool,
}

impl Timeline {
	/// A timeline from the `lineage` (newest first) and the rotation records
	/// met in chain order. `reaches_end` is false when the walk stopped
	/// before the end of the chain, so a missing record may still come.
	pub fn new(lineage: Vec<String>, handovers: Vec<(At, Rotation)>, reaches_end: bool) -> Self {
		Timeline {
			lineage,
			handovers,
			reaches_end,
		}
	}

	/// The timeline of the whole chain under `evidence_root`, from the rotation
	/// records whose statement verifies (signed by the key they replace). A
	/// day is read as far as it goes, so a day with a break in it, which an
	/// acknowledgement exists for, does not hide the rotations around it.
	/// More verified rotations than [`MAX_ROTATIONS`] is an error, never a
	/// truncation.
	pub fn load(evidence_root: &Path) -> std::io::Result<Self> {
		let lineage = lineage(evidence_root)?;
		let mut handovers = Vec::new();
		let mut seen = 0usize;
		for day in Chain::open(evidence_root)?.days()? {
			let _ = super::verify::walk_day(evidence_root, day, None, |line, record, _| {
				if let Entry::KeyRotated(rotation) = &record.entry
					&& check_record(evidence_root, rotation).is_ok()
				{
					seen += 1;
					if seen <= MAX_ROTATIONS {
						handovers.push(((day, line), rotation.clone()));
					}
				}
			});
		}
		if seen > MAX_ROTATIONS {
			return Err(std::io::Error::other(
				"more key rotations than the evidence follows",
			));
		}
		Ok(Timeline::new(lineage, handovers, true))
	}

	fn position(&self, old: &str, new: &str) -> Option<At> {
		self.handovers
			.iter()
			.find(|(_, rotation)| rotation.old == old && rotation.new == new)
			.map(|(at, _)| *at)
	}

	/// Whether `key` is the one in force at `at`.
	pub fn check(&self, key: &str, at: At) -> Result<(), Fault> {
		let index = self
			.lineage
			.iter()
			.position(|known| known == key)
			.ok_or(Fault::Unknown)?;
		if let Some(predecessor) = self.lineage.get(index + 1)
			&& let Some(introduced) = self.position(predecessor, key)
			&& introduced >= at
		{
			return Err(Fault::NotYet);
		}
		if index > 0 {
			match self.position(key, &self.lineage[index - 1]) {
				Some(handed_over) if at < handed_over => {}
				Some(_) => return Err(Fault::HandedOver),
				None if !self.reaches_end => {}
				None => return Err(Fault::Unrecorded),
			}
		}
		Ok(())
	}

	/// Whether a rotation record from `old` to `new` was written before the
	/// day `day` was sealed: what must explain a change of signer between
	/// two sealed days, whether or not the walk reached the end.
	pub fn explains(&self, old: &str, new: &str, day: Day) -> bool {
		self.position(old, new)
			.is_some_and(|at| at < (Day(day.0 + 1), 0))
	}

	/// Whether `key` may seal `day`: the key in force once every rotation
	/// record of that day was written, since a day is sealed after it ends.
	pub fn check_seal(&self, key: &str, day: Day) -> Result<(), Fault> {
		self.check(key, (Day(day.0 + 1), 0))
	}
}

/// Rotate the evidence key at `now`: returns the new key's id.
///
/// Every closed day is sealed with the old key first, so no day is left to
/// be sealed by the new one without a record explaining the change.
pub fn rotate(evidence_root: &Path, timestamp: bool, now: u64) -> std::io::Result<String> {
	let old = EvidenceKey::load_or_create(evidence_root)?;
	super::checkpoint::seal_closed_days(evidence_root, &old, timestamp, now)
		.map_err(|error| std::io::Error::other(error.to_string()))?;
	let new = EvidenceKey::stage_next(evidence_root)?;
	let rotation = Rotation::signed(&old, &new.id(), &Day::of_epoch(now).name());

	let bytes = serde_json::to_vec_pretty(&rotation).map_err(std::io::Error::other)?;
	super::chain::create_private_dir(&evidence_root.join(ROTATIONS_DIR))?;
	crate::storage::write_secret(&path(evidence_root, &rotation.new), &bytes)?;
	Chain::open(evidence_root)?.append_at(now, Entry::KeyRotated(rotation.clone()))?;
	EvidenceKey::promote_next(evidence_root, &rotation.new)?;
	Ok(rotation.new)
}

#[cfg(test)]
#[path = "rotation_tests.rs"]
mod tests;
