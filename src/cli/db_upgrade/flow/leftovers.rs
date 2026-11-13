//! What a verified `db upgrade` removes of the major it moved away from: the
//! old cluster in the volume, the dump taken before the move and the old
//! PostgreSQL image. They only exist so a failed move can go back, and a
//! dump holds password hashes and keys. A failure here is a leftover the
//! operator is told about, not a failed upgrade.

use std::path::Path;

use super::Stack;
use crate::cli::stack::images::Change;

/// Where the `db` service mounts the `epistle-pgdata` volume.
const VOLUME: &str = "/var/lib/postgresql";

/// The directories that make up the old cluster inside the `db` container.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Cluster {
	/// The data directory the old server reported, removed with its tree.
	pub(super) tree: String,
	/// Its parent, removed only when it is empty and holds nothing of the new
	/// cluster: `/var/lib/postgresql/18` around `/var/lib/postgresql/18/docker`.
	pub(super) parent: Option<String>,
}

/// What to remove of the cluster the old server reported at `old`, with the
/// new server reporting `new`. `Err` says why nothing may be removed: `old`
/// is not a plain directory inside the volume, or the two clusters overlap.
pub(super) fn cluster(old: &str, new: &str) -> Result<Cluster, String> {
	if !inside_volume(old) {
		return Err(format!(
			"{old} is not a directory inside the epistle-pgdata volume ({VOLUME})"
		));
	}
	if under(new, old) || under(old, new) {
		return Err(format!(
			"the new cluster at {new} overlaps it, so removing it would remove live data"
		));
	}
	let parent = old
		.rsplit_once('/')
		.map(|(parent, _)| parent)
		.filter(|parent| *parent != VOLUME && !under(new, parent))
		.map(str::to_string);
	Ok(Cluster {
		tree: old.to_string(),
		parent,
	})
}

/// A path below the volume, made only of plain names: no `.`, `..`, empty
/// part, trailing slash or character a shell or podman could read as more.
fn inside_volume(path: &str) -> bool {
	let Some(rest) = path
		.strip_prefix(VOLUME)
		.and_then(|rest| rest.strip_prefix('/'))
	else {
		return false;
	};
	!rest.is_empty()
		&& rest.split('/').all(|part| {
			!part.is_empty()
				&& part != "."
				&& part != ".."
				&& !part.starts_with('-')
				&& part
					.bytes()
					.all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
		})
}

/// Whether `path` is `base` or lies below it.
fn under(path: &str, base: &str) -> bool {
	path == base
		|| path
			.strip_prefix(base)
			.is_some_and(|rest| rest.starts_with('/'))
}

/// Remove the PostgreSQL `from` cluster the old server reported at
/// `old_dir`, the dump at `dump` and the images `change` retired, reporting
/// each to the operator. Called only once the new major is verified.
pub(super) fn discard(
	stack: &mut impl Stack,
	from: u32,
	old_dir: &str,
	dump: &Path,
	change: &Change,
) {
	match stack
		.data_directory()
		.and_then(|new_dir| cluster(old_dir, &new_dir))
	{
		Ok(Cluster { tree, parent }) => match stack.remove_in_db(&tree, true) {
			Ok(()) => {
				// An emptied major directory is a leftover too, but one that
				// still holds something stays: `rmdir` refuses it.
				if let Some(parent) = parent {
					let _ = stack.remove_in_db(&parent, false);
				}
				stack.log(&format!(
					"removed the PostgreSQL {from} cluster at {tree}, which the upgrade stopped using"
				));
			}
			Err(error) => stack.log(&format!(
				"could not remove the PostgreSQL {from} cluster at {tree}: {error}"
			)),
		},
		Err(error) => stack.log(&format!(
			"kept the PostgreSQL {from} cluster at {old_dir}: {error}"
		)),
	}
	match stack.remove_dump(dump) {
		Ok(()) => stack.log(&format!(
			"removed the dump {} taken before the upgrade",
			dump.display()
		)),
		Err(error) => stack.log(&format!(
			"could not remove the dump {}: {error}",
			dump.display()
		)),
	}
	match stack.discard_images(change) {
		Ok(outcome) => {
			for reference in &outcome.removed {
				stack.log(&format!(
					"removed the image {reference}, which the upgrade stopped using"
				));
			}
			for line in &outcome.kept {
				stack.log(&format!("kept the image {line}"));
			}
		}
		Err(error) => stack.log(&format!(
			"could not tell whether the PostgreSQL {from} image is still used, so it was kept: {error}"
		)),
	}
}
