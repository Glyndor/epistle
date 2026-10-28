//! Save a copy of every account-submitted message into the account's
//! `Sent` folder, with a Message-ID guard so a client that APPENDs its
//! own copy after the SMTP submission does not end up with two messages
//! for the same Message-ID in `Sent`.
//!
//! Three actors touch this module:
//!  * the three submission paths (SMTP after AUTH, `/api/v1/send`,
//!    JMAP `EmailSubmission/set`) call [`store_copy`] once the message
//!    bytes are final and the Bcc header has been stripped;
//!  * the IMAP APPEND path consults [`Guard::is_recent`] when the
//!    destination is the `Sent` folder and the literal already carries
//!    a Message-ID, so a client-side append of a Message-ID the server
//!    just stored is silently deduplicated;
//!  * the same submission paths also call [`Guard::is_recent`] before
//!    storing, so the rarer case (the client appended first, then the
//!    submission-side save fires) does not double-store.
//!
//! The guard is a per-account bounded file: at most
//! [`Guard::MAX_ENTRIES`] entries, each entry a `(message_id, epoch)`
//! pair kept for [`Guard::WINDOW_SECS`] seconds. Reads ignore entries
//! older than the window, so a full file is pruned lazily on every
//! write. Writes go through `flock` to stay crash-safe and to coexist
//! with the CLI and any sibling server. The file lives under
//! `<data_dir>/accounts/<name>/sent_guard.json`; one file per account
//! keeps concurrent sessions independent.

use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::imap::mailbox::{self, Flag};
use crate::storage::MessageCrypto;
use crate::util::path_component::{AccountName, FixedDir};
use crate::util::path_containment::contained_child;

/// The maximum number of recent Message-IDs kept per account. The bound
/// keeps the file small and the prune on every write cheap; the window
/// below is the freshness gate that matters for correctness.
pub const MAX_ENTRIES: usize = 1000;

/// How long a Message-ID stays "recent" for dedup purposes. RFC 5322
/// section 3.6.4 allows a sender to reuse an id only in the same
/// thread; with the rolling window being a day, a Sunday-night client
/// that took a week to retry does not lose its copy on the second
/// submission.
pub const WINDOW_SECS: u64 = 24 * 60 * 60;

/// One entry in the guard file: the Message-ID (the unfolded value of
/// the `Message-ID:` header, with angle brackets kept verbatim) and the
/// epoch second it was stored at.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(dead_code)]
pub struct Entry {
	/// `Message-ID:` value, exactly as written in the message (brackets
	/// included).
	pub message_id: String,
	/// Epoch second the entry was recorded.
	pub stored_at: u64,
}

/// One Message-ID the server stored recently, with the epoch second it
/// was stored. Used by the IMAP APPEND fast path to answer
/// `OK [APPENDUID ...]` with the UID already on disk so the client
/// thinks its APPEND landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recent {
	pub message_id: String,
	pub stored_at: u64,
}

/// The per-account guard. Cheap to clone: the only field is the
/// on-disk path; every operation re-reads the file under a flock.
#[derive(Debug, Clone)]
pub struct Guard {
	path: PathBuf,
}

/// A reason the saver refuses to add the copy. Failure is logged and
/// ignored: the submission must never fail because the Sent copy
/// failed.
#[derive(Debug, thiserror::Error)]
pub enum SaveError {
	/// Filesystem I/O failed before or during the copy.
	#[error("io: {0}")]
	Io(String),
	/// At-rest encryption refused the payload.
	#[error("crypto: {0}")]
	Crypto(String),
	/// The account name was malformed or the account directory is missing.
	#[error("account: {0}")]
	Account(String),
	/// The copy would put the account over its storage quota.
	#[error("the copy would put the account over its quota")]
	OverQuota,
}

/// Where the decision to skip the save came from, for tests and for
/// the `tracing` line that names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
	/// `save_sent: false` on the per-request override, the app password
	/// or the account wins (per-request > app password > account).
	Disabled,
	/// The Message-ID the client (or the server) tried to store is
	/// already in the Sent folder, so a duplicate would land.
	DuplicateInSent,
	/// The JMAP EmailSubmission already references an Email that lives
	/// in Sent (or will be moved there), so another copy is wrong.
	JmapEmailInSent,
}

/// The outcome of a save call: the copy was added, or it was skipped
/// for one of the reasons above. Tests assert on `Added.uid` (the
/// freshly-assigned UID) and on `Skipped.reason`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveOutcome {
	/// The copy was stored into `Sent`. `uid` is the UID the IMAP
	/// side will see on the appended message.
	Added {
		/// The UID assigned by the Sent mailbox.
		uid: u32,
	},
	/// The copy was deliberately skipped.
	Skipped {
		/// Why the saver chose not to store.
		reason: SkipReason,
		/// When `reason` is `DuplicateInSent`, the UID of the message
		/// already in Sent so the caller can echo it back to a client
		/// appending its own copy. `None` for the other reasons.
		existing_uid: Option<u32>,
	},
}

/// An open file lock guard. Held for the duration of the critical
/// section; `Drop` releases it.
struct LockGuard {
	_file: std::fs::File,
}

impl LockGuard {
	fn acquire(path: &Path) -> std::io::Result<Self> {
		let file = std::fs::OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.truncate(false)
			.open(path)?;
		// Best effort: if the lock cannot be taken the save goes on, and two
		// concurrent writers race on the read-modify-write, one wins.
		let _ = file.lock();
		Ok(LockGuard { _file: file })
	}
}

impl Guard {
	/// Open the guard for `account` under `data_dir`. A missing file
	/// is an empty guard; the file is created lazily on the first
	/// write.
	pub fn open(data_dir: &Path, account: &str) -> std::io::Result<Self> {
		let account = AccountName::new(account).map_err(|error| {
			std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
		})?;
		let root = account.root(data_dir)?;
		let _ = root.child(FixedDir::Tmp)?;
		let path = contained_child(root.as_path(), "sent_guard.json")?;
		Ok(Guard { path })
	}

	/// The maximum number of recent Message-IDs kept (used by tests
	/// that want to assert the bound is enforced).
	pub const fn max_entries() -> usize {
		MAX_ENTRIES
	}

	/// The freshness window in seconds.
	pub const fn window_secs() -> u64 {
		WINDOW_SECS
	}

	/// The on-disk path of this guard's file. Tests use it to read
	/// the raw file and to confirm `count_entries` matches.
	pub fn path(&self) -> &Path {
		&self.path
	}

	/// Read the file, drop entries older than the freshness window,
	/// and return the surviving list as a queue (oldest first, so the
	/// file stays in insertion order).
	fn read_pruned(&self, now: u64) -> std::io::Result<VecDeque<Entry>> {
		let Ok(mut file) = std::fs::File::open(&self.path) else {
			return Ok(VecDeque::new());
		};
		let mut text = String::new();
		file.read_to_string(&mut text)?;
		if text.trim().is_empty() {
			return Ok(VecDeque::new());
		}
		let entries: Vec<Entry> = serde_json::from_str(&text).unwrap_or_default();
		let cutoff = now.saturating_sub(WINDOW_SECS);
		Ok(entries
			.into_iter()
			.filter(|entry| entry.stored_at >= cutoff)
			.collect())
	}

	/// Replace the on-disk file with `entries`. Uses a temp + rename
	/// so a crash never leaves a half-written file.
	fn write_locked(&self, entries: &VecDeque<Entry>) -> std::io::Result<()> {
		let _lock = LockGuard::acquire(&self.path)?;
		// Re-read inside the lock so a sibling process that just wrote
		// is not silently overwritten.
		let now = epoch_now();
		let mut current = self.read_pruned(now).unwrap_or_default();
		// Merge: keep everything the file already had, append the new
		// entries. The caller already pruned the in-memory list, so
		// the merge only adds.
		let known: std::collections::HashSet<String> =
			current.iter().map(|e| e.message_id.clone()).collect();
		for entry in entries {
			if !known.contains(&entry.message_id) {
				current.push_back(entry.clone());
			}
		}
		while current.len() > MAX_ENTRIES {
			current.pop_front();
		}
		let serialised = serde_json::to_string(&current).map_err(std::io::Error::other)?;
		write_atomic(&self.path, serialised.as_bytes())
	}

	/// Whether `message_id` was stored recently. The IMAP APPEND fast
	/// path uses this to drop a duplicate; the submission path uses it
	/// to avoid storing a duplicate after a client already APPENDed.
	pub fn is_recent(&self, message_id: &str) -> std::io::Result<Option<Recent>> {
		let now = epoch_now();
		let entries = self.read_pruned(now)?;
		let cutoff = now.saturating_sub(WINDOW_SECS);
		Ok(entries
			.into_iter()
			.find(|entry| entry.message_id == message_id && entry.stored_at >= cutoff)
			.map(|entry| Recent {
				message_id: entry.message_id,
				stored_at: entry.stored_at,
			}))
	}

	/// Whether `message_id` was stored recently, with a count of how
	/// many fresh entries the file currently holds. The count is used
	/// in tests to assert the bound.
	pub fn count_entries(&self) -> std::io::Result<(usize, Option<Recent>)> {
		let now = epoch_now();
		let entries = self.read_pruned(now)?;
		let last = entries.back().map(|entry| Recent {
			message_id: entry.message_id.clone(),
			stored_at: entry.stored_at,
		});
		Ok((entries.len(), last))
	}

	/// Record `message_id` as just-stored. The fresh entry is appended
	/// and the file is rewritten so the next `is_recent` sees it.
	pub fn record(&self, message_id: &str) -> std::io::Result<()> {
		let now = epoch_now();
		let mut entries = self.read_pruned(now)?;
		// Re-record: replace the existing entry's timestamp when the
		// Message-ID is already present, so a duplicate save bumps
		// the freshness instead of growing the file with a second
		// entry.
		if let Some(existing) = entries.iter_mut().find(|e| e.message_id == message_id) {
			existing.stored_at = now;
		} else {
			entries.push_back(Entry {
				message_id: message_id.to_string(),
				stored_at: now,
			});
			while entries.len() > MAX_ENTRIES {
				entries.pop_front();
			}
		}
		self.write_locked(&entries)
	}

	/// Drop every entry older than the freshness window now,
	/// regardless of a write happening. Tests call this after `record`
	/// to assert pruning; production code does not need it.
	pub fn prune(&self) -> std::io::Result<()> {
		let now = epoch_now();
		let entries = self.read_pruned(now)?;
		self.write_locked(&entries)
	}

	/// Read the file without taking the internal lock (the caller
	/// takes the file lock first if it needs atomicity).
	pub fn raw_entries(&self) -> std::io::Result<Vec<Entry>> {
		let now = epoch_now();
		Ok(self.read_pruned(now)?.into_iter().collect())
	}
}

/// Best-effort current epoch second. `SystemTime::duration_since` is
/// fallible; when the clock is before the epoch (impossible on a sane
/// server, but the trait's signature is fallible) we treat it as 0.
fn epoch_now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Write `bytes` to a temp file in the same directory and rename over
/// `path`. Crash-safe: the rename is atomic on the same filesystem.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let unique = uuid::Uuid::now_v7();
	let tmp = path.with_extension(format!("json.{unique}.tmp"));
	{
		let mut file = std::fs::File::create(&tmp)?;
		file.write_all(bytes)?;
		file.sync_all()?;
	}
	if let Err(error) = fs::rename(&tmp, path) {
		let _ = fs::remove_file(&tmp);
		return Err(error);
	}
	Ok(())
}

/// Extract the first `Message-ID:` header from a raw message. Returns
/// the value verbatim, including the angle brackets, because the guard
/// matches on exactly the same bytes the client sent. `None` when the
/// header is absent or has no value; the caller decides whether to
/// mint one.
#[allow(dead_code)]
pub fn first_message_id(data: &[u8]) -> Option<String> {
	let header_end = header_block_end(data);
	let block = String::from_utf8_lossy(&data[..header_end]);
	for line in block.split('\n') {
		let line = line.trim_end_matches('\r');
		if line.is_empty() {
			return None;
		}
		if matches!(line.as_bytes().first(), Some(b' ' | b'\t')) {
			continue;
		}
		let Some((name, value)) = line.split_once(':') else {
			continue;
		};
		if name.trim().eq_ignore_ascii_case("message-id") {
			return Some(value.trim().to_string());
		}
	}
	None
}

/// The byte index of the body's first byte (the blank-line separator
/// that ends the header block). Mirrors the helper in
/// `crate::smtp::trace`, kept local so the saver stays in this file.
#[allow(dead_code)]
fn header_block_end(data: &[u8]) -> usize {
	let mut i = 0;
	while i < data.len() {
		if data[i] == b'\n' {
			match data.get(i + 1) {
				Some(b'\n') | Some(b'\r') => return i + 1,
				_ => {}
			}
		}
		i += 1;
	}
	data.len()
}

/// Store `data` into `account`'s `Sent` folder with the `\Seen` flag,
/// record `message_id` in the guard so a subsequent client APPEND does
/// not create a second copy, and return the assigned UID. A failure at
/// any step returns `SaveError` and the caller logs and ignores: the
/// submission itself must not fail because the Sent copy did.
pub fn store_copy(
	data_dir: &Path,
	account: &str,
	data: &[u8],
	message_id: &str,
	crypto: &MessageCrypto,
	quota: Option<u64>,
) -> Result<u32, SaveError> {
	// The copy is stored mail like any other: it counts against the
	// account's quota, and one that would not fit is not stored.
	if let Some(limit) = quota
		&& mailbox::account_usage(data_dir, account, crypto).saturating_add(data.len() as u64)
			> limit
	{
		return Err(SaveError::OverQuota);
	}
	let flag = Flag::Seen;
	// Ensure the Sent mailbox exists. The IMAP side expects one;
	// `ensure_defaults` creates the standard five (Sent, Drafts, ...)
	// when the account directory is first opened.
	mailbox::ensure_defaults(data_dir, account).map_err(|e| SaveError::Account(e.to_string()))?;
	if !mailbox::exists(data_dir, account, "Sent") {
		mailbox::create(data_dir, account, "Sent")
			.map_err(|e| SaveError::Account(e.to_string()))?;
	}
	let id = mailbox::append_dated(
		data_dir,
		account,
		"Sent",
		std::slice::from_ref(&flag),
		None,
		data,
		crypto,
	)
	.map_err(|e| SaveError::Io(e.to_string()))?;
	let (_validity, uid) = mailbox::appenduid(data_dir, account, "Sent", id)
		.ok_or_else(|| SaveError::Io("mailbox vanished after append".into()))?;
	// Record only after the file is on disk: a failed record keeps the
	// copy and triggers a second attempt next submission, which then
	// dedupes through the same guard. A missing record after a saved
	// copy is the harmless direction; a record without a copy would be
	// the harmful one (the IMAP APPEND path would silently drop the
	// client's copy).
	let _ = Guard::open(data_dir, account)
		.map_err(|e| SaveError::Account(e.to_string()))?
		.record(message_id);
	Ok(uid)
}

/// Look up the UID of a message that lives in `Sent` and has the given
/// Message-ID. Used by the saver to populate the `existing_uid` field
/// on a duplicate skip.
#[allow(dead_code)]
pub fn lookup_sent_uid(
	data_dir: &Path,
	account: &str,
	message_id: &str,
) -> std::io::Result<Option<u32>> {
	mailbox::lookup_message_id_in_sent(data_dir, account, message_id)
}

#[cfg(test)]
mod tests;
