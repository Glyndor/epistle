//! The copies a service edit leaves in the configuration directory, and the
//! sweep that takes them.
//!
//! A command killed between its two renames can not restore anything, so the
//! copies it staged stay next to the file it was editing until the next
//! command under the lock finds them. Without a sweep they pile up one pair
//! per death, and each holds a whole copy of `mail.toml` or of the generated
//! compose file.
//!
//! A copy that a failed rollback named in its error is a different thing: it is
//! the only original left, so it carries its own name and a longer age, and
//! the operator keeps it for a week.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The prefix and suffix every staged copy carries, so a reader can tell a
/// staged candidate from an operator's file.
const STAGING: (&str, &str) = (".service.", ".tmp");

/// A staged copy older than this belongs to a command that died: a command
/// still running holds the configuration lock this sweep runs under, and its
/// own copies are younger than any plausible edit.
const ORPHAN_AGE: Duration = Duration::from_secs(3600);

/// The prefix and suffix of the copy a failed rollback leaves. It is the only
/// original of the file left, so it does not share the staged name: an hour
/// after the failure the sweep would take the one copy the error tells the
/// operator to use.
pub(super) const RECOVERY: (&str, &str) = (".service-recovery.", ".bak");

/// How long a recovery copy is kept. A week is what an operator needs to read
/// the failure, put the file back and check the installation; until then it
/// costs one file next to the one it protects.
const RECOVERY_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

/// Where a staged copy goes next to the file it protects.
pub(super) fn staged_path(next_to: &Path) -> PathBuf {
	next_to.join(format!(
		"{}{}{}",
		STAGING.0,
		uuid::Uuid::now_v7(),
		STAGING.1
	))
}

/// Where a recovery copy goes next to the file it protects.
pub(super) fn recovery_path(next_to: &Path) -> PathBuf {
	next_to.join(format!(
		"{}{}{}",
		RECOVERY.0,
		uuid::Uuid::now_v7(),
		RECOVERY.1
	))
}

/// Whether a name is a recovery copy rather than a staged one.
pub(super) fn is_recovery(name: &str) -> bool {
	is_copy(name) == Some(true)
}

/// Which of our copies a name is, and only that: both writers put a UUID
/// between the prefix and the suffix, so a file of the operator's that happens
/// to share the two ends is not one of ours and the sweep leaves it alone.
/// `Some(false)` is a staged copy, `Some(true)` a recovery copy.
fn is_copy(name: &str) -> Option<bool> {
	if between(name, RECOVERY).is_some() {
		Some(true)
	} else if between(name, STAGING).is_some() {
		Some(false)
	} else {
		None
	}
}

/// The UUID between the prefix and the suffix of `name`, when the name is
/// exactly a prefix, a UUID and a suffix and nothing else.
fn between(name: &str, (prefix, suffix): (&str, &str)) -> Option<uuid::Uuid> {
	uuid::Uuid::parse_str(name.strip_prefix(prefix)?.strip_suffix(suffix)?).ok()
}

/// Remove the copies a dead command left in `dir` and name the ones that went.
/// A staged copy is taken an hour after it was written; a recovery copy, which
/// is the only original of a file a failed rollback could not put back, waits a
/// week. Only the names our writers build are taken, so an operator's file
/// that shares the prefix and the suffix stays.
pub(crate) fn sweep_orphans(dir: &Path) -> Vec<PathBuf> {
	let Ok(entries) = fs::read_dir(dir) else {
		return Vec::new();
	};
	let now = SystemTime::now();
	let mut swept = Vec::new();
	for entry in entries.flatten() {
		let name = entry.file_name();
		let name = name.to_string_lossy();
		let Some(recovery) = is_copy(&name) else {
			continue;
		};
		let Ok(metadata) = entry.metadata() else {
			continue;
		};
		if !metadata.is_file() {
			continue;
		}
		let age = if recovery { RECOVERY_AGE } else { ORPHAN_AGE };
		if metadata
			.modified()
			.is_ok_and(|written| now.duration_since(written).unwrap_or_default() < age)
		{
			continue;
		}
		if fs::remove_file(entry.path()).is_ok() {
			swept.push(entry.path());
		}
	}
	swept
}

/// Say on stderr which copies a sweep removed, so the operator hears that a
/// command died there instead of finding the files later. The two kinds are
/// named apart: one is debris, the other is a file to put back by hand.
pub(crate) fn announce_swept(swept: &[PathBuf]) {
	if swept.is_empty() {
		return;
	}
	let (recovery, staged): (Vec<&PathBuf>, Vec<&PathBuf>) = swept
		.iter()
		.partition(|path| is_recovery(&path.file_name().unwrap_or_default().to_string_lossy()));
	if !staged.is_empty() {
		crate::cli::style::warn(format!(
			"removed {} staged cop{} left by an interrupted command in {}: {}",
			staged.len(),
			if staged.len() == 1 { "y" } else { "ies" },
			where_(staged[0]),
			names(&staged)
		));
	}
	if !recovery.is_empty() {
		crate::cli::style::warn(format!(
			"removed {} recovery cop{} a failed rollback left in {}: {}",
			recovery.len(),
			if recovery.len() == 1 { "y" } else { "ies" },
			where_(recovery[0]),
			names(&recovery)
		));
	}
}

/// The directory a removed copy was in.
fn where_(first: &Path) -> String {
	first
		.parent()
		.map(|dir| dir.display().to_string())
		.unwrap_or_default()
}

/// The removed copies as one list.
fn names(paths: &[&PathBuf]) -> String {
	paths
		.iter()
		.map(|path| path.display().to_string())
		.collect::<Vec<_>>()
		.join(", ")
}

#[cfg(test)]
#[path = "sweep_tests.rs"]
mod tests;
