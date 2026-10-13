//! What has been copied so far, per local account, source and remote
//! folder, so a rerun copies only what is new.
//!
//! One small JSON file per folder under
//! `<data_dir>/migrate/<account>/<digest>.json`, where the digest covers the
//! source (user and host) and the remote folder name, so neither ever
//! names a file. Each file is replaced atomically (written to a temporary
//! file, synced, renamed over the old one) with mode 0600.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util::path_component::AccountName;
use crate::util::path_containment::contained_child;

/// The largest state file read back. A real one is under 300 bytes.
const MAX_STATE_BYTES: u64 = 64 * 1024;

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
	/// run checks each message against what is already there.
	#[serde(default)]
	pub(crate) in_progress: bool,
	/// Messages stored by every run so far.
	#[serde(default)]
	pub(crate) copied: u64,
}

/// The state files of one local account and one source.
#[derive(Debug, Clone)]
pub(crate) struct StateDir {
	base: PathBuf,
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
		Ok(StateDir {
			base,
			dir,
			source: source.to_string(),
		})
	}

	fn path(&self, folder: &[u8]) -> std::io::Result<PathBuf> {
		let mut key = self.source.as_bytes().to_vec();
		key.push(0);
		key.extend_from_slice(folder);
		let digest = ring::digest::digest(&ring::digest::SHA256, &key);
		let hex: String = digest
			.as_ref()
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect();
		contained_child(&self.dir, &format!("{hex}.json"))
	}

	/// The saved progress of `folder`, `None` when it was never copied. A
	/// file that cannot be parsed is an error, not a fresh start: guessing
	/// would copy everything again.
	pub(crate) fn load(&self, folder: &[u8]) -> std::io::Result<Option<FolderState>> {
		let path = self.path(folder)?;
		let file = match std::fs::File::open(&path) {
			Ok(file) => file,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
			Err(error) => return Err(error),
		};
		let mut text = String::new();
		std::io::Read::read_to_string(&mut std::io::Read::take(file, MAX_STATE_BYTES), &mut text)?;
		serde_json::from_str(&text).map(Some).map_err(|error| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!("{}: {error}", path.display()),
			)
		})
	}

	/// Replace the saved progress of `folder` atomically.
	pub(crate) fn save(&self, folder: &[u8], state: &FolderState) -> std::io::Result<()> {
		create_private_dir(&self.base)?;
		create_private_dir(&self.dir)?;
		let path = self.path(folder)?;
		let tmp = path.with_extension("json.tmp");
		let body = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
		let mut options = std::fs::OpenOptions::new();
		options.write(true).create(true).truncate(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		let mut file = options.open(&tmp)?;
		file.write_all(&body)?;
		file.sync_all()?;
		drop(file);
		std::fs::rename(&tmp, &path)?;
		std::fs::File::open(&self.dir)?.sync_all()
	}
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
	let mut builder = std::fs::DirBuilder::new();
	#[cfg(unix)]
	{
		use std::os::unix::fs::DirBuilderExt;
		builder.mode(0o700);
	}
	match builder.create(dir) {
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
		other => other,
	}
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
