//! Where a blob lives under `<data_dir>/blobs/`.
//!
//! Blobs were stored flat. One directory holding every blob an install has
//! ever accepted makes the two periodic passes that walk it — the reclaim
//! sweep and the quota usage count — proportional to the whole history rather
//! than to what is there now, and most filesystems slow down badly past a few
//! tens of thousands of entries in a single directory.
//!
//! **The shard comes from the end of the id, not the start.** Blob ids are
//! UUIDv7, whose first 48 bits are a timestamp: every blob written in the same
//! era shares its leading characters, so sharding on them would file almost
//! everything into one bucket. That failure is invisible — the layout looks
//! sharded and behaves exactly like the flat directory it replaced. The tail
//! of a v7 UUID is random, so that is what is used.
//!
//! Reads fall back to the flat location when the sharded one is absent, so an
//! upgrade needs no migration step and blobs written by an older version keep
//! being served.

use std::path::{Path, PathBuf};

/// Hex characters per shard level. Two levels of two characters is 65,536
/// buckets, which keeps a directory small well past any single-node install.
const SHARD_CHARS: usize = 2;

/// The root of the blob store.
pub(crate) fn blob_root(data_dir: &Path) -> PathBuf {
	data_dir.join("blobs")
}

/// Whether `blob_id` is safe to put in a path.
///
/// Every caller parses the id before it gets here — the download handler, the
/// type and owner readers, and the backfill each do. The check lives in this
/// module as well because that is the shape of a bug this codebase has already
/// shipped: `validate_name` had a single caller, three of the four places an
/// account name could arrive were checking it, and the fourth walked a path
/// traversal into the data directory. A path-building helper that trusts its
/// input is one new caller away from the same thing.
fn is_safe_id(blob_id: &str) -> bool {
	uuid::Uuid::parse_str(blob_id).is_ok()
}

/// The directory `blob_id` shards into. `None` for an id too short to shard,
/// which cannot happen for a UUID but keeps the function total.
pub(super) fn shard_dir(data_dir: &Path, blob_id: &str) -> Option<PathBuf> {
	if !is_safe_id(blob_id) {
		return None;
	}
	let id = blob_id.as_bytes();
	if id.len() < SHARD_CHARS * 2 {
		return None;
	}
	let tail = &blob_id[blob_id.len() - SHARD_CHARS * 2..];
	let (outer, inner) = tail.split_at(SHARD_CHARS);
	Some(blob_root(data_dir).join(outer).join(inner))
}

/// Where a new file for `blob_id` is written. `suffix` is `""` for the
/// payload, or `.type` / `.owner` for a sidecar.
pub(crate) fn write_path(data_dir: &Path, blob_id: &str, suffix: &str) -> Option<PathBuf> {
	Some(shard_dir(data_dir, blob_id)?.join(format!("{blob_id}{suffix}")))
}

/// Where an existing file for `blob_id` is, preferring the sharded location
/// and falling back to the flat one an older version wrote.
///
/// The fallback is what makes this upgrade free: nothing has to be moved, and
/// a blob written before this change is still found.
pub(crate) fn read_path(data_dir: &Path, blob_id: &str, suffix: &str) -> Option<PathBuf> {
	let sharded = write_path(data_dir, blob_id, suffix)?;
	if sharded.exists() {
		return Some(sharded);
	}
	Some(blob_root(data_dir).join(format!("{blob_id}{suffix}")))
}

/// Every blob payload under the store, sharded or flat, as `(id, path)`.
///
/// Sidecars are skipped: a caller that wants one asks for it by id. Walking
/// both layouts is what lets the reclaim sweep and the usage count keep
/// working across the upgrade instead of quietly ignoring older blobs.
pub(super) fn walk(data_dir: &Path) -> Vec<(String, PathBuf)> {
	let root = blob_root(data_dir);
	let mut out = Vec::new();
	collect(&root, &mut out);
	for outer in read_dir_names(&root) {
		let outer_path = root.join(&outer);
		collect(&outer_path, &mut out);
		for inner in read_dir_names(&outer_path) {
			collect(&outer_path.join(inner), &mut out);
		}
	}
	out
}

/// File names directly inside `dir`, ignoring anything unreadable.
fn read_dir_names(dir: &Path) -> Vec<String> {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return Vec::new();
	};
	entries
		.flatten()
		.filter(|entry| entry.path().is_dir())
		.filter_map(|entry| entry.file_name().into_string().ok())
		.collect()
}

/// Append the payload files directly inside `dir` to `out`.
fn collect(dir: &Path, out: &mut Vec<(String, PathBuf)>) {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return;
	};
	for entry in entries.flatten() {
		let path = entry.path();
		if path.is_dir() {
			continue;
		}
		let Ok(name) = entry.file_name().into_string() else {
			continue;
		};
		// A payload is named by the bare id; `.type` and `.owner` are not.
		if name.contains('.') {
			continue;
		}
		out.push((name, path));
	}
}

#[cfg(test)]
#[path = "blob_path_tests.rs"]
mod tests;
