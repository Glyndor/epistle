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

use uuid::Uuid;

/// Hex characters per shard level. Two levels of two characters is 65,536
/// buckets, which keeps a directory small well past any single-node install.
const SHARD_CHARS: usize = 2;

/// The root of the blob store.
pub(crate) fn blob_root(data_dir: &Path) -> PathBuf {
	data_dir.join("blobs")
}

/// The directory `blob_id` shards into.
///
/// Taking a [`Uuid`] rather than a string is the whole safety argument. A
/// caller cannot hand this a path fragment, because the only way to get one
/// is to parse it and parsing rejects anything that is not a UUID. The
/// previous version checked at run time, which a new caller could reach with
/// a bad value and only find out when it ran; this one they cannot write.
pub(super) fn shard_dir(data_dir: &Path, blob_id: Uuid) -> PathBuf {
	// A hyphenated UUID is 36 characters, so the tail always exists.
	let id = blob_id.to_string();
	let tail = &id[id.len() - SHARD_CHARS * 2..];
	let (outer, inner) = tail.split_at(SHARD_CHARS);
	blob_root(data_dir).join(outer).join(inner)
}

/// Where a new file for `blob_id` is written. `suffix` is `""` for the
/// payload, or `.type` / `.owner` for a sidecar.
pub(crate) fn write_path(data_dir: &Path, blob_id: Uuid, suffix: &str) -> PathBuf {
	shard_dir(data_dir, blob_id).join(format!("{blob_id}{suffix}"))
}

/// Where an existing file for `blob_id` is, preferring the sharded location
/// and falling back to the flat one an older version wrote.
///
/// The fallback is what makes this upgrade free: nothing has to be moved, and
/// a blob written before this change is still found.
pub(crate) fn read_path(data_dir: &Path, blob_id: Uuid, suffix: &str) -> PathBuf {
	let sharded = write_path(data_dir, blob_id, suffix);
	if sharded.exists() {
		return sharded;
	}
	blob_root(data_dir).join(format!("{blob_id}{suffix}"))
}

/// Every blob payload under the store, sharded or flat, as `(id, path)`.
///
/// Sidecars are skipped: a caller that wants one asks for it by id. Walking
/// both layouts is what lets the reclaim sweep and the usage count keep
/// working across the upgrade instead of quietly ignoring older blobs.
pub(super) fn walk(data_dir: &Path) -> Vec<(Uuid, PathBuf)> {
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
fn collect(dir: &Path, out: &mut Vec<(Uuid, PathBuf)>) {
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
		// A payload is named by the bare id; `.type` and `.owner` are not,
		// and anything that is not a UUID was not written by us.
		let Ok(id) = Uuid::parse_str(&name) else {
			continue;
		};
		out.push((id, path));
	}
}

#[cfg(test)]
#[path = "blob_path_tests.rs"]
mod tests;
