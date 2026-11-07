//! The journal of a re-encryption run: which direction it goes and which
//! accounts it last scanned. A resumed run revalidates every account: keys
//! and files may have changed while the server or another offline writer ran.
//!
//! It lives at `<data_dir>/rekey-journal.json`, written `0600` through a
//! temporary file and a rename after every finished account, and is removed
//! when the run completes. Its presence is what `status` reports as an
//! unfinished re-encryption. It holds account names and counts, no key.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name of the journal under `data_dir`.
pub const JOURNAL_FILE: &str = "rekey-journal.json";

/// Which way a run moves stored mail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
	/// Every account's mail to the key it should use now: its tenant's key,
	/// or the current server key.
	Forward,
	/// Every account's mail back to the server key, in the version 1 format
	/// a release without tenant keys reads.
	Rollback,
}

impl std::fmt::Display for Direction {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Direction::Forward => "forward",
			Direction::Rollback => "rollback",
		})
	}
}

/// The persisted progress of one run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
	/// Format version of this file.
	pub version: u32,
	/// The direction the run goes.
	pub direction: Direction,
	/// Accounts scanned in the interrupted pass, for status only. Resume
	/// scans them again against the current keys and files.
	pub done: Vec<String>,
	/// Files rewritten so far, across every finished account.
	pub rewritten: u64,
}

impl Journal {
	/// A fresh journal for a run in `direction`.
	pub fn new(direction: Direction) -> Self {
		Journal {
			version: 1,
			direction,
			done: Vec::new(),
			rewritten: 0,
		}
	}
}

/// Where the journal lives under `data_dir`.
pub fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(JOURNAL_FILE)
}

/// Read the journal, `Ok(None)` when there is none.
///
/// # Errors
/// When the file exists and cannot be read or parsed: a run must not
/// guess at its own progress.
pub fn read(data_dir: &Path) -> std::io::Result<Option<Journal>> {
	match std::fs::read_to_string(path(data_dir)) {
		Ok(text) => serde_json::from_str(&text)
			.map(Some)
			.map_err(|error| std::io::Error::other(format!("{JOURNAL_FILE}: {error}"))),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
		Err(error) => Err(error),
	}
}

/// Write the journal crash-safely: temporary file, fsync, rename, fsync of
/// the directory.
pub fn write(data_dir: &Path, journal: &Journal) -> std::io::Result<()> {
	let target = path(data_dir);
	let temp = data_dir.join(format!(".{JOURNAL_FILE}.tmp"));
	let text = serde_json::to_vec_pretty(journal).map_err(std::io::Error::other)?;
	crate::storage::spool::write_sync(&temp, &text)?;
	std::fs::rename(&temp, &target)?;
	sync_dir(data_dir)
}

/// Remove the journal once a run has finished.
pub fn remove(data_dir: &Path) -> std::io::Result<()> {
	match std::fs::remove_file(path(data_dir)) {
		Ok(()) => sync_dir(data_dir),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(error),
	}
}

/// fsync a directory so a rename inside it survives a crash.
pub(super) fn sync_dir(dir: &Path) -> std::io::Result<()> {
	std::fs::File::open(dir)?.sync_all()
}
