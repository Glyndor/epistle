//! The keys a reader anchors, and what they are anchored for.
//!
//! A bundle cannot vouch for the key that signed it, and a key that handed
//! over must not be able to seal a day after the hand-over. So the reader
//! brings the keys, each older one with the day its period ended
//! (`KEY@YYYY-MM-DD`), and at most one without: the current key. The signed
//! hand-overs inside the bundle name their own day, so a bundle that carries
//! one retires the old key whatever the reader anchored.

use std::collections::BTreeSet;
use std::path::Path;

use super::check::read;
use crate::evidence::day::Day;
use crate::evidence::key;
use crate::evidence::record::hash_from_hex;
use crate::evidence::rotation::{MAX_ROTATIONS, ROTATIONS_DIR, Rotation};

/// One anchored key and, for an older one, the day its period ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Anchor {
	id: String,
	until: Option<Day>,
}

/// The anchored keys of a check.
#[derive(Debug, Clone, Default)]
pub(super) struct Anchors(Vec<Anchor>);

impl Anchors {
	/// Parse `ID` or `ID@YYYY-MM-DD` for each given key.
	pub(super) fn parse(given: &[String]) -> Result<Anchors, String> {
		if given.is_empty() {
			return Err(
				"no key given: pass --key <fingerprint|file> with the key the operator published"
					.into(),
			);
		}
		let mut anchors = Vec::new();
		for value in given {
			let (id, until) = match value.split_once('@') {
				Some((id, day)) => (
					id,
					Some(Day::parse(day).ok_or("a key period is KEY@YYYY-MM-DD")?),
				),
				None => (value.as_str(), None),
			};
			if hash_from_hex(id).is_none() {
				return Err("a key is its id: 64 hex digits".into());
			}
			anchors.push(Anchor {
				id: id.to_string(),
				until,
			});
		}
		if anchors
			.iter()
			.filter(|anchor| anchor.until.is_none())
			.count() > 1
		{
			return Err("give the period of every key but the current one (KEY@YYYY-MM-DD)".into());
		}
		Ok(Anchors(anchors))
	}

	fn get(&self, id: &str) -> Option<&Anchor> {
		self.0.iter().find(|anchor| anchor.id == id)
	}
}

/// Every hand-over the bundle carries whose old key signed it.
pub(super) fn statements(dir: &Path) -> Result<Vec<Rotation>, String> {
	let folder = dir.join(ROTATIONS_DIR);
	let entries = match std::fs::read_dir(&folder) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
		Err(error) => return Err(format!("{ROTATIONS_DIR}: {}", error.kind())),
	};
	let mut found = Vec::new();
	for entry in entries {
		let entry = entry.map_err(|error| error.kind().to_string())?;
		if found.len() >= MAX_ROTATIONS {
			return Err("more hand-overs than a bundle follows".into());
		}
		let name = entry.file_name().to_string_lossy().to_string();
		let Some(new) = name.strip_suffix(".json") else {
			continue;
		};
		let relative = format!("{ROTATIONS_DIR}/{name}");
		let rotation: Rotation = serde_json::from_slice(&read(&entry.path())?)
			.map_err(|_| format!("{relative}: not a hand-over"))?;
		let pem = read(&dir.join("keys").join(format!("{}.pem", rotation.old)))
			.map_err(|why| format!("keys/{}.pem: {why}", rotation.old))?;
		let old = std::str::from_utf8(&pem)
			.ok()
			.and_then(key::parse_public_pem)
			.ok_or("the previous key's file is not an Ed25519 public key")?;
		if rotation.new != new || !rotation.verifies(&old) {
			return Err(format!(
				"{relative}: not signed by the key it says it took over from"
			));
		}
		found.push(rotation);
	}
	Ok(found)
}

/// Whether `signer` may seal `day` under the anchors and the hand-overs in
/// the bundle, and the bundle paths that showed it.
pub(super) fn vouch(
	signer: &str,
	day: Day,
	anchors: &Anchors,
	handovers: &[Rotation],
) -> Result<Vec<String>, String> {
	// A hand-over in the bundle retires its old key, whoever anchored it.
	if let Some(rotation) = handovers.iter().find(|rotation| rotation.old == signer)
		&& Day::parse(&rotation.day).is_some_and(|handed| day >= handed)
	{
		return Err(format!(
			"signed by key {signer} on {day}, but it handed over on {}",
			rotation.day
		));
	}
	let mut files = Vec::new();
	let mut current = signer.to_string();
	let mut seen = BTreeSet::new();
	let mut anchored = false;
	for hop in 0..=MAX_ROTATIONS {
		if let Some(anchor) = anchors.get(&current) {
			// The period binds the key only when it signed the day itself.
			if hop == 0
				&& let Some(until) = anchor.until
				&& day >= until
			{
				return Err(format!(
					"signed by key {current} on {day}, but it was in force only until {until}"
				));
			}
			anchored = true;
		}
		if !seen.insert(current.clone()) {
			break;
		}
		let Some(rotation) = handovers.iter().find(|rotation| rotation.new == current) else {
			break;
		};
		// The new key seals nothing before the day it took over.
		if hop == 0 && Day::parse(&rotation.day).is_some_and(|taken| day < taken) {
			return Err(format!(
				"signed by key {signer} on {day}, before it took over on {}",
				rotation.day
			));
		}
		// An older key the reader gave a period can hand over only on the day
		// the period ended, and only to a key the reader anchored too.
		if let Some(older) = anchors.get(&rotation.old)
			&& let Some(until) = older.until
		{
			if rotation.day != until.name() {
				return Err(format!(
					"the hand-over from {} names another day than the period given ({until})",
					rotation.old
				));
			}
			if anchors.get(&current).is_none() {
				return Err(format!(
					"key {} took over from {}, which has a period, but you did not anchor it",
					current, rotation.old
				));
			}
		}
		files.push(format!("{ROTATIONS_DIR}/{current}.json"));
		files.push(format!("keys/{}.pem", rotation.old));
		current = rotation.old.clone();
	}
	match anchored {
		true => Ok(files),
		false => Err(format!(
			"signed by key {signer}, which is neither an anchored key nor took over from one by signed hand-overs"
		)),
	}
}
