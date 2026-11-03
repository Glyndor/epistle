//! The dns-01 records published and not yet withdrawn.
//!
//! A TXT record lives at the DNS provider, outside the process, so a server
//! that stops before its withdrawal (SIGKILL after the grace period, a
//! crash, a power cut) would leave it in the zone. With a journal, every
//! record is written to disk before the provider is asked to publish it and
//! leaves the file only once the provider removed it; the next start reads
//! the file and withdraws what an earlier run left behind.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::dns::provider::DnsRecord;

/// Journal file name under `<data_dir>/acme/`.
pub const PENDING_FILE: &str = "dns01-pending.json";

/// The journal path for a data directory.
pub fn journal_path(data_dir: &Path) -> PathBuf {
	data_dir.join("acme").join(PENDING_FILE)
}

/// One published record: the challenge it answers, the zone that holds it,
/// and the record itself, so it can be removed without the account key and
/// without asking the provider which zone holds the name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PendingTxt {
	pub(super) domain: String,
	pub(super) token: String,
	pub(super) zone: String,
	pub(super) record: DnsRecord,
}

/// The records published and not yet withdrawn, in memory and, when a
/// journal path is set, on disk.
pub(super) struct Pending {
	entries: Mutex<Vec<PendingTxt>>,
	journal: Option<PathBuf>,
}

impl Pending {
	/// Kept in memory only.
	pub(super) fn in_memory() -> Self {
		Pending {
			entries: Mutex::new(Vec::new()),
			journal: None,
		}
	}

	/// Kept in `path` as well, starting from what an earlier run left there.
	/// A file that cannot be read is logged and treated as empty: it is
	/// replaced by the next write. Every entry is a record the start deletes
	/// at the provider, so the journal is read only from a regular file with
	/// one name ([`read_unshared`](crate::storage::unshared::read_unshared)):
	/// a symlink or a hard link the mail container left there before a split
	/// would let it keep choosing what `certs` deletes.
	pub(super) fn with_journal(path: PathBuf) -> Self {
		let entries = match crate::storage::unshared::read_unshared(&path) {
			Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
				tracing::warn!(%error, path = %path.display(), "dns-01: the pending challenge journal is unreadable; starting empty");
				Vec::new()
			}),
			Ok(None) => Vec::new(),
			Err(error) => {
				tracing::warn!(%error, path = %path.display(), "dns-01: the pending challenge journal cannot be read; starting empty");
				Vec::new()
			}
		};
		Pending {
			entries: Mutex::new(entries),
			journal: Some(path),
		}
	}

	/// The entries, recovered when a thread that held the lock panicked:
	/// they record what was published, and a panic elsewhere must not take
	/// the withdrawal down with it.
	fn lock(&self) -> MutexGuard<'_, Vec<PendingTxt>> {
		self.entries
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Record `entry` before its publish starts. Fails when the journal
	/// cannot be written: a record that could not be withdrawn after a
	/// crash is not published at all.
	pub(super) fn insert(&self, entry: PendingTxt) -> std::io::Result<()> {
		let mut entries = self.lock();
		entries.retain(|held| !(held.domain == entry.domain && held.token == entry.token));
		entries.push(entry);
		self.persist(&entries)
	}

	/// The entry of one challenge.
	pub(super) fn get(&self, domain: &str, token: &str) -> Option<PendingTxt> {
		self.lock()
			.iter()
			.find(|held| held.domain == domain && held.token == token)
			.cloned()
	}

	/// Every entry, oldest first.
	pub(super) fn all(&self) -> Vec<PendingTxt> {
		self.lock().clone()
	}

	/// Forget one challenge once the provider removed its record. A journal
	/// that cannot be rewritten keeps a record that is gone; the next start
	/// removes it again, which the provider takes as a no-op.
	pub(super) fn remove(&self, domain: &str, token: &str) {
		let mut entries = self.lock();
		entries.retain(|held| !(held.domain == domain && held.token == token));
		if let Err(error) = self.persist(&entries) {
			tracing::warn!(%error, %domain, "dns-01: the pending challenge journal was not updated");
		}
	}

	/// Write the whole list, or remove the file once nothing is pending.
	fn persist(&self, entries: &[PendingTxt]) -> std::io::Result<()> {
		let Some(path) = &self.journal else {
			return Ok(());
		};
		if entries.is_empty() {
			return match std::fs::remove_file(path) {
				Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
				_ => Ok(()),
			};
		}
		if let Some(parent) = path.parent() {
			std::fs::create_dir_all(parent)?;
		}
		let bytes = serde_json::to_vec(entries).map_err(std::io::Error::other)?;
		super::super::renew::write_atomic(path, &bytes, 0o600)
	}
}
