//! What has been copied so far, per local account, source and remote
//! folder, so a rerun copies only what is new.
//!
//! One small JSON file per folder under
//! `<data_dir>/migrate/<account>/<digest>.json`, where the digest covers the
//! source (user and host) and the remote folder name, so neither ever
//! names a file. Each file is replaced atomically (written to a temporary
//! file, synced, renamed over the old one) with mode 0600.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::util::path_component::AccountName;
use crate::util::path_containment::contained_child;

use super::ledger::Ledger;
use super::state_files;

/// The largest state file read back. A real one is under 300 bytes.
const MAX_STATE_BYTES: u64 = 64 * 1024;

/// How often a run asks again for a lock another run holds.
const LOCK_POLL: Duration = Duration::from_millis(100);

/// The progress of one remote folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FolderState {
	/// The remote folder, for an operator reading the file.
	pub(crate) folder: String,
	/// The UIDVALIDITY the UIDs below belong to.
	pub(crate) uid_validity: u32,
	/// Every message with a UID up to this one has been handled.
	pub(crate) last_uid: u32,
	/// A batch was being written when this file was saved. If the process
	/// died there, some of its messages may already be stored, so the next
	/// run replays the confirmed prefix before matching pending copies.
	/// Recovery stays active until the folder has been replayed.
	#[serde(default)]
	pub(crate) in_progress: bool,
	/// Messages stored by every run so far.
	#[serde(default)]
	pub(crate) copied: u64,
}

/// The state files of one local account and one source.
#[derive(Debug, Clone)]
pub(crate) struct StateDir {
	root: std::sync::Arc<std::fs::File>,
	account: String,
	dir: PathBuf,
	source: String,
}

impl StateDir {
	/// The state directory for `account`; nothing is created until the
	/// first [`Self::save`]. `source` identifies the remote account (user
	/// and host).
	pub(crate) fn open(data_dir: &Path, account: &str, source: &str) -> std::io::Result<Self> {
		let account = AccountName::new(account)?;
		let base = contained_child(data_dir, "migrate")?;
		let dir = contained_child(&base, account.as_str())?;
		let root = std::sync::Arc::new(state_files::root(data_dir)?);
		match state_files::directory(&root, account.as_str(), false) {
			Ok(_) => {}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
		Ok(StateDir {
			root,
			account: account.as_str().to_string(),
			dir,
			source: source.to_string(),
		})
	}

	fn path(&self, folder: &[u8]) -> std::io::Result<PathBuf> {
		self.file(folder, "json")
	}

	/// The progress file of `folder`, or its ledger of confirmed messages.
	fn file(&self, folder: &[u8], kind: &str) -> std::io::Result<PathBuf> {
		let mut key = self.source.as_bytes().to_vec();
		key.push(0);
		key.extend_from_slice(folder);
		let digest = ring::digest::digest(&ring::digest::SHA256, &key);
		let hex: String = digest
			.as_ref()
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect();
		contained_child(&self.dir, &format!("{hex}.{kind}"))
	}

	/// The ledger of confirmed messages of `folder`. It is created, appended
	/// to and discarded only when `writable`.
	pub(super) fn ledger(
		&self,
		folder: &[u8],
		uid_validity: u32,
		writable: bool,
	) -> std::io::Result<Ledger> {
		let path = self.file(folder, "ledger")?;
		super::ledger::open(
			self.root.as_ref(),
			&self.account,
			path,
			uid_validity,
			writable,
		)
	}

	/// Where the ledger of `folder` is kept, for a test that reads it.
	#[cfg(test)]
	pub(super) fn ledger_path(&self, folder: &[u8]) -> std::io::Result<PathBuf> {
		self.file(folder, "ledger")
	}

	/// The saved progress of `folder`, `None` when it was never copied. A
	/// file that cannot be parsed is an error, not a fresh start: guessing
	/// would copy everything again.
	pub(crate) fn load(&self, folder: &[u8]) -> std::io::Result<Option<FolderState>> {
		let path = self.path(folder)?;
		let file = match state_files::directory(&self.root, &self.account, false)
			.and_then(|dir| state_files::read(&dir, &path))
		{
			Ok(file) => file,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
			Err(error) => return Err(error),
		};
		let mut text = String::new();
		std::io::Read::read_to_string(
			&mut std::io::Read::take(file, MAX_STATE_BYTES + 1),
			&mut text,
		)?;
		if text.len() as u64 > MAX_STATE_BYTES {
			return Err(std::io::Error::other(
				"migration state exceeds its size limit",
			));
		}
		serde_json::from_str(&text).map(Some).map_err(|error| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!("{}: {error}", path.display()),
			)
		})
	}

	/// Replace the saved progress of `folder` atomically.
	pub(crate) fn save(&self, folder: &[u8], state: &FolderState) -> std::io::Result<()> {
		let dir = state_files::directory(&self.root, &self.account, true)?;
		let path = self.path(folder)?;
		let body = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
		state_files::replace(&dir, &path, &body, "state-file", "state-directory")
	}

	/// Hold this account's migration lock, waiting up to `wait` for a run that
	/// has it. It is taken once per run instead of once per folder, because two
	/// runs of the same account would append to the same ledgers from a length
	/// each one read for itself, and neither would learn about the records of
	/// the other.
	pub(super) async fn lock(&self, wait: Duration) -> std::io::Result<AccountLock> {
		let file = state_files::lock_file(self.root.as_ref(), &self.account, true)?;
		let deadline = tokio::time::Instant::now() + wait;
		loop {
			if try_lock(&file)? {
				return Ok(AccountLock { file });
			}
			if tokio::time::Instant::now() >= deadline {
				return Err(std::io::Error::other(format!(
					"another migration of the account {} holds {}: wait for it to finish and run again",
					self.account,
					self.dir.join(state_files::LOCK).display()
				)));
			}
			tokio::time::sleep(LOCK_POLL).await;
		}
	}
}

/// The lock of one account's migration directory, held from here until the
/// guard is dropped.
#[derive(Debug)]
pub(super) struct AccountLock {
	file: std::fs::File,
}

impl Drop for AccountLock {
	fn drop(&mut self) {
		// SAFETY: the descriptor is open and owned by this guard.
		unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
	}
}

/// Whether the lock is free, waiting for no one.
fn try_lock(file: &std::fs::File) -> std::io::Result<bool> {
	// SAFETY: flock reads the descriptor, which is open for the whole call.
	if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
		return Ok(true);
	}
	let error = std::io::Error::last_os_error();
	if error.kind() == std::io::ErrorKind::WouldBlock {
		return Ok(false);
	}
	Err(error)
}

#[cfg(test)]
mod tests;

/// Open disposable recovery storage below the validated data directory.
pub(super) fn scratch(data_dir: &Path) -> std::io::Result<std::fs::File> {
	state_files::scratch(&state_files::root(data_dir)?)
}
