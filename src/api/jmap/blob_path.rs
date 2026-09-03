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
//!
//! **The walk only descends into what the store writes.** A name read off the
//! disk is never joined into a path as it came: a shard directory is accepted
//! only if it has exactly the shape [`shard_dir`] produces, a payload only if
//! its name is exactly what [`write_path`] produces, and the path handed back
//! is rebuilt from the parsed value. So a directory or file that this module
//! did not write, whatever it is called, is not part of the sweep.

use std::path::{Path, PathBuf};

use uuid::Uuid;

/// The root of the blob store.
pub(crate) fn blob_root(data_dir: &Path) -> PathBuf {
	data_dir.join("blobs")
}

/// One level of the shard tree: the index of a bucket among the 256 a level
/// holds. Two levels is 65,536 buckets, which keeps a directory small well
/// past any single-node install.
///
/// A `Shard` comes either from a byte of the blob id, when writing, or from a
/// directory name that has exactly the shape [`Shard::dir_name`] produces,
/// when walking. Either way the directory name is rendered from the index,
/// never taken from the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shard(u8);

impl Shard {
	/// The directory name `dir_name` renders and `parse` accepts: two
	/// lowercase hex digits.
	const NAME_LEN: usize = 2;

	/// Accept a directory name only if it is exactly what [`Shard::dir_name`]
	/// would have written: two lowercase hex digits, nothing else. Uppercase,
	/// a third character, `..` and an empty name are all refused.
	fn parse(name: &str) -> Option<Shard> {
		let lower_hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
		if name.len() != Self::NAME_LEN || !name.bytes().all(lower_hex) {
			return None;
		}
		u8::from_str_radix(name, 16).ok().map(Shard)
	}

	fn dir_name(self) -> String {
		format!("{:02x}", self.0)
	}
}

/// The directory `blob_id` shards into.
///
/// Taking a [`Uuid`] rather than a string is the whole safety argument. A
/// caller cannot hand this a path fragment, because the only way to get one
/// is to parse it and parsing rejects anything that is not a UUID. The
/// previous version checked at run time, which a new caller could reach with
/// a bad value and only find out when it ran; this one they cannot write.
///
/// The last two bytes of the id are the last four hex characters of its
/// string form, so `ab/cd` for an id ending in `abcd`.
pub(super) fn shard_dir(data_dir: &Path, blob_id: Uuid) -> PathBuf {
	let bytes = blob_id.as_bytes();
	let outer = Shard(bytes[14]);
	let inner = Shard(bytes[15]);
	blob_root(data_dir)
		.join(outer.dir_name())
		.join(inner.dir_name())
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
///
/// Only the two layouts the store writes are visited: payloads directly
/// under the root, and payloads two shard levels down. Every path returned
/// is rebuilt from validated parts, so it is under [`blob_root`] by
/// construction.
pub(crate) fn walk(data_dir: &Path) -> Vec<(Uuid, PathBuf)> {
	let root = blob_root(data_dir);
	let mut out = Vec::new();
	collect(&root, &mut out);
	for outer in shards_in(&root) {
		let outer_path = root.join(outer.dir_name());
		for inner in shards_in(&outer_path) {
			collect(&outer_path.join(inner.dir_name()), &mut out);
		}
	}
	out
}

/// The shard directories directly inside `dir`, in index order.
///
/// The listing decides which of the 256 buckets exist; the names the walk
/// then joins are rendered from those indices. A directory the store did
/// not write has no index and is never descended into, whether it is an
/// operator's `lost+found`, a `tmp`, an uppercase `AB` or a `..`. A symlink
/// is refused even when its name fits, because what it points at is not
/// something this module wrote either.
fn shards_in(dir: &Path) -> Vec<Shard> {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return Vec::new();
	};
	let mut present = [false; 256];
	for entry in entries.flatten() {
		let is_real_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
		if let Some(name) = entry.file_name().to_str()
			&& let Some(shard) = Shard::parse(name)
			&& is_real_dir
		{
			present[usize::from(shard.0)] = true;
		}
	}
	(0..=u8::MAX)
		.filter(|index| present[usize::from(*index)])
		.map(Shard)
		.collect()
}

/// Append the payload files directly inside `dir` to `out`.
///
/// A payload is named by its bare id, rendered the way `write_path` renders
/// it: hyphenated, lowercase. The name is parsed and then rendered again,
/// and only an exact round trip counts, so `.type` and `.owner` sidecars,
/// an uppercase spelling and anything that is not a UUID are all skipped as
/// not written by us. The path returned is `dir` joined with that
/// rendering, not the entry's own path.
fn collect(dir: &Path, out: &mut Vec<(Uuid, PathBuf)>) {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return;
	};
	for entry in entries.flatten() {
		if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
			continue;
		}
		let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
			continue;
		};
		let Ok(id) = Uuid::parse_str(&name) else {
			continue;
		};
		let rendered = id.to_string();
		if rendered != name {
			continue;
		}
		out.push((id, dir.join(rendered)));
	}
}

#[cfg(test)]
#[path = "blob_path_tests.rs"]
mod tests;
