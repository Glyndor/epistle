//! Entries a crash left staged under `tmp/`.
//!
//! A message is written to `tmp/`, its evidence recorded, then renamed into
//! `new/`. A crash in between leaves it staged: never queued, never sent,
//! and the client was never told it was accepted. At start-up the server
//! lists these, records `abandoned` for those that carried evidence, and
//! discards them.

use std::fs;
use std::path::Path;

use uuid::Uuid;

use super::{FsSpool, SpoolDir};
use crate::util::path_component::MessageExt;

/// One staged entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leftover {
	/// Its queue id.
	pub id: Uuid,
	/// Whether its envelope says evidence was being recorded. An entry whose
	/// envelope never reached the disk, or cannot be read, is counted as
	/// carrying evidence: an `abandoned` record for nothing costs nothing,
	/// a missing one leaves an acceptance without an end.
	pub evidence: bool,
}

impl FsSpool {
	/// The entries staged under `tmp/` (names `<uuid>.eml` or
	/// `<uuid>.json`), at most `limit` of them. Only call this before the
	/// server takes submissions: a submission in flight is staged too.
	pub fn leftovers(&self, limit: usize) -> std::io::Result<Vec<Leftover>> {
		let dir = self.path_in(Path::new(SpoolDir::Tmp.name()))?;
		let mut ids: Vec<Uuid> = Vec::new();
		for entry in crate::util::fs_walk::read_dir(&dir)? {
			let name = entry?.file_name();
			let Some(name) = name.to_str() else {
				continue;
			};
			let stem = name
				.strip_suffix(".json")
				.or_else(|| name.strip_suffix(".eml"));
			if let Some(id) = stem.and_then(|stem| Uuid::parse_str(stem).ok())
				&& !ids.contains(&id)
			{
				ids.push(id);
				if ids.len() == limit {
					break;
				}
			}
		}
		ids.sort();
		Ok(ids
			.into_iter()
			.map(|id| Leftover {
				id,
				evidence: self.staged_evidence(id).unwrap_or(true),
			})
			.collect())
	}

	fn staged_evidence(&self, id: Uuid) -> Option<bool> {
		let path = self.entry_file(SpoolDir::Tmp, id, MessageExt::Json).ok()?;
		let bytes = crate::util::fs_walk::read(path).ok()?;
		let (envelope, _) = self.decode_envelope_bytes(id, &bytes).ok()?;
		Some(envelope.evidence)
	}

	/// Remove the temporary files a rewrite of an envelope left under `tmp/`
	/// (`<uuid>.<uuid>.json`: the message id and a unique suffix). The message
	/// is queued and its evidence is recorded, so these are not abandoned
	/// submissions: the file is only a copy that was never renamed over the
	/// envelope, and nothing else removes it. Same condition as
	/// [`Self::leftovers`]: call it before the server takes submissions.
	/// Returns how many it removed.
	pub fn sweep_envelope_rewrites(&self) -> std::io::Result<usize> {
		let dir = self.path_in(Path::new(SpoolDir::Tmp.name()))?;
		let mut removed = 0;
		for entry in crate::util::fs_walk::read_dir(&dir)? {
			let entry = entry?;
			let name = entry.file_name();
			if name.to_str().is_some_and(is_envelope_rewrite) {
				match fs::remove_file(entry.path()) {
					Ok(()) => removed += 1,
					Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
					Err(error) => return Err(error),
				}
			}
		}
		Ok(removed)
	}

	/// Remove the staged files of `id`.
	pub fn discard_leftover(&self, id: Uuid) -> std::io::Result<()> {
		for ext in [MessageExt::Json, MessageExt::Eml] {
			match fs::remove_file(self.entry_file(SpoolDir::Tmp, id, ext)?) {
				Ok(()) => {}
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
				Err(error) => return Err(error),
			}
		}
		Ok(())
	}
}

/// Whether `name` is `<uuid>.<uuid>.json`, the temporary name of an envelope
/// rewrite.
fn is_envelope_rewrite(name: &str) -> bool {
	let Some(stem) = name.strip_suffix(".json") else {
		return false;
	};
	let Some((id, suffix)) = stem.split_once('.') else {
		return false;
	};
	Uuid::parse_str(id).is_ok() && Uuid::parse_str(suffix).is_ok()
}
