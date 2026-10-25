//! The structural bounds of the DAV tree: how many entries a collection holds
//! and how deep a path goes. They hold whether or not the account has a
//! storage quota, for every way of creating an entry (`PUT`, `MKCOL`, `COPY`
//! and `MOVE`), because the cost of listing and walking a tree grows with
//! them, not with the bytes in it.
//!
//! A collection that is already past a bound (made before it existed) stays
//! usable: it can be read, listed, changed and deleted; only creating another
//! entry in it is refused. The entry count of a collection is kept for a
//! minute, raised by each create and dropped by each removal, so a create does
//! not list its collection.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

/// The most entries one collection holds.
pub const MAX_MEMBERS: usize = 50_000;

/// The deepest path, in collections below the account root.
pub const MAX_DEPTH: usize = 16;

/// How long the kept entry count of a collection is trusted.
const COUNT_TTL: Duration = Duration::from_secs(60);

/// How many collections have a kept count before the table is cleared.
const COUNTED_COLLECTIONS: usize = 4096;

/// Why a create was refused.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refusal {
	TooDeep,
	TooMany,
	/// The check could not run; the create is not allowed to go on.
	Unavailable,
}

static COUNTS: LazyLock<Mutex<HashMap<PathBuf, (usize, Instant)>>> =
	LazyLock::new(|| Mutex::new(HashMap::new()));

/// Forget the kept counts affected by removing or moving `paths`: the
/// collections that held them and everything below them. Other collections
/// keep their counts, and so do the creates already counted in them, so a
/// removal in one account does not reopen the bound for another.
pub(super) fn forget_counts(paths: &[&Path]) {
	let mut counts = COUNTS.lock().unwrap_or_else(|poison| poison.into_inner());
	counts.retain(|collection, _| {
		!paths
			.iter()
			.any(|path| collection == path.parent().unwrap_or(path) || collection.starts_with(path))
	});
}

/// The reply to a refused create: `403`, a plain statement of the bound. It
/// is not `507`/`sufficient-disk-space`, which would tell a client the
/// account is out of space.
pub(super) fn refusal_response(refusal: Refusal) -> Response {
	let text = match refusal {
		Refusal::TooDeep => "the path is deeper than this server allows",
		Refusal::TooMany => "the collection holds as many entries as this server allows",
		Refusal::Unavailable => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};
	(
		StatusCode::FORBIDDEN,
		[(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
		text,
	)
		.into_response()
}

/// Check that `target` can be created below `root`. Called with the account's
/// lock held, after which the create follows, so the depth of `subtree` and the
/// count of the collection cannot change in between. `subtree` is the tree
/// being copied or moved there: its own depth adds to the target's.
pub(super) async fn check_create(
	root: &Path,
	target: &Path,
	subtree: Option<&Path>,
	members: usize,
) -> Result<(), Refusal> {
	let (root, target, subtree) = (
		root.to_path_buf(),
		target.to_path_buf(),
		subtree.map(Path::to_path_buf),
	);
	tokio::task::spawn_blocking(move || check_now(&root, &target, subtree.as_deref(), members))
		.await
		.unwrap_or(Err(Refusal::Unavailable))
}

fn check_now(
	root: &Path,
	target: &Path,
	subtree: Option<&Path>,
	members: usize,
) -> Result<(), Refusal> {
	let depth = target
		.strip_prefix(root)
		.map_or(0, |relative| relative.components().count());
	if depth + subtree.map_or(0, subtree_depth) > MAX_DEPTH {
		return Err(Refusal::TooDeep);
	}
	// Replacing an entry adds none.
	if std::fs::symlink_metadata(target).is_ok() {
		return Ok(());
	}
	let Some(parent) = target.parent() else {
		return Ok(());
	};
	let mut counts = COUNTS.lock().unwrap_or_else(|poison| poison.into_inner());
	if counts.len() >= COUNTED_COLLECTIONS {
		counts.clear();
	}
	let kept = counts
		.get(parent)
		.filter(|(_, at)| at.elapsed() < COUNT_TTL)
		.map(|(count, _)| *count);
	let count = kept.unwrap_or_else(|| {
		std::fs::read_dir(parent).map_or(0, |entries| entries.take(members + 1).count())
	});
	if count >= members {
		counts.insert(parent.to_path_buf(), (count, Instant::now()));
		return Err(Refusal::TooMany);
	}
	counts.insert(parent.to_path_buf(), (count + 1, Instant::now()));
	Ok(())
}

/// How many collections deep the tree at `path` goes below it; `0` for a file
/// or a collection with no collection in it. Symlinks are not followed.
pub(super) fn subtree_depth(path: &Path) -> usize {
	let mut deepest = 0;
	let mut pending = vec![(path.to_path_buf(), 0usize)];
	while let Some((next, depth)) = pending.pop() {
		let Ok(meta) = std::fs::symlink_metadata(&next) else {
			continue;
		};
		if !meta.is_dir() {
			continue;
		}
		deepest = deepest.max(depth);
		if let Ok(entries) = std::fs::read_dir(&next) {
			pending.extend(entries.flatten().map(|entry| (entry.path(), depth + 1)));
		}
	}
	deepest
}

#[cfg(test)]
#[path = "bounds_tests.rs"]
mod tests;
