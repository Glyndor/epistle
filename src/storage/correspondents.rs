//! Per-account correspondent store: addresses an account has previously
//! written to, recorded the first time the message was accepted.
//!
//! The store serves two features from one marker file:
//!
//! - A daily cap on the number of *new* recipients a single account may
//!   submit (plan 4.10). The marker's mtime is the first time the account
//!   wrote to that address; only markers younger than 24 h count toward
//!   the limit, so the cap resets on a rolling window.
//! - A fast path for inbound replies from a known correspondent (plan
//!   4.6). A lowercased envelope sender is checked against every
//!   recipient account's markers; if any of them knows the sender, the
//!   greylist deferral and the reputation first-time delay are skipped.
//!
//! Files live at `<data_dir>/correspondents/<sha256(account)>/<sha256(addr)>`,
//! the same shape `src/queue/suppression.rs` uses for its per-account
//! suppression list. The digest is computed over the ASCII-lowercased
//! address so the lookup is case-insensitive and the filename is always
//! safe.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// SHA-256 hex of a lowercased value, safe as a filename. Duplicated
/// locally to keep the storage module free of a queue-internal
/// dependency; the function is pure and the cost of the duplicate is
/// one helper.
fn digest_name(value: &str) -> String {
	let digest = ring::digest::digest(&ring::digest::SHA256, value.to_ascii_lowercase().as_bytes());
	digest.as_ref().iter().fold(String::new(), |mut acc, byte| {
		use std::fmt::Write;
		let _ = write!(acc, "{byte:02x}");
		acc
	})
}

/// Filesystem-backed per-account correspondent set.
///
/// The store is **not** thread-safe at the directory level: callers
/// serialise their checks against the same account through the SMTP
/// session's MAIL-FROM/RCPT-TO/DATA cadence or the API handler's
/// await chain. Two simultaneous `record` calls on the same account
/// are safe because each writes to a distinct address path; the only
/// racy operation is `new_in_last_day`, which reads a stat per marker
/// and tolerates a fresh write appearing between the directory walk
/// and the per-file stat.
pub struct CorrespondentStore {
	dir: PathBuf,
}

/// Outcome of [`CorrespondentStore::record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recorded {
	/// Addresses that did not previously have a marker and now do.
	pub new: u32,
	/// Addresses that already had a marker for this account.
	pub known: u32,
}

impl CorrespondentStore {
	/// Open (creating if needed) the correspondent store under `data_dir`.
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		let dir = data_dir.join("correspondents");
		fs::create_dir_all(&dir)?;
		Ok(Self { dir })
	}

	/// The directory holding one account's correspondent markers.
	fn account_dir(&self, account: &str) -> PathBuf {
		self.dir.join(digest_name(account))
	}

	/// The marker path for one address under one account.
	fn marker(&self, account: &str, address: &str) -> PathBuf {
		self.account_dir(account).join(digest_name(address))
	}

	/// Whether `account` has previously written to `address`. Lookup is
	/// case-insensitive (the digest is over the lowercased value).
	pub fn knows(&self, account: &str, address: &str) -> bool {
		self.marker(account, address).exists()
	}

	/// Mark every address in `recipients` as one `account` has written to.
	/// Markers that already exist are not touched (mtime is the *first*
	/// time, not the most recent — the daily cap keys off that). Returns
	/// the count of freshly-created versus pre-existing markers.
	///
	/// An empty `account` or an empty recipient list is a no-op; an
	/// address that fails to parse as UTF-8 is recorded verbatim
	/// (the digest is over bytes; the SMTP layer normalises incoming
	/// addresses, but the store accepts whatever it is given).
	pub fn record(&self, account: &str, recipients: &[&str]) -> std::io::Result<Recorded> {
		if account.is_empty() || recipients.is_empty() {
			return Ok(Recorded { new: 0, known: 0 });
		}
		let dir = self.account_dir(account);
		fs::create_dir_all(&dir)?;
		let mut recorded = Recorded { new: 0, known: 0 };
		for address in recipients {
			let path = self.marker(account, address);
			if path.exists() {
				recorded.known += 1;
				continue;
			}
			// Atomic write: a half-written marker would count toward
			// the daily cap without being readable by `knows`. Create
			// the file `O_EXCL` so a parallel `record` cannot lose the
			// race and silently double-count.
			match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
				Ok(_) => recorded.new += 1,
				Err(error) if error.kind() == ErrorKind::AlreadyExists => recorded.known += 1,
				Err(error) => return Err(error),
			}
		}
		Ok(recorded)
	}

	/// Number of markers under `account` whose mtime is in the last
	/// 24 hours. Used to enforce the daily new-recipient cap (plan
	/// 4.10); the limit is `count + new_recipients_in_flight <= limit`.
	///
	/// Returns `0` when the account directory does not exist (a
	/// never-sent account). The mtime of a fresh marker is `now`, so
	/// a marker created milliseconds ago counts.
	pub fn new_in_last_day(&self, account: &str) -> std::io::Result<u32> {
		let dir = self.account_dir(account);
		let entries = match fs::read_dir(&dir) {
			Ok(entries) => entries,
			Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
			Err(error) => return Err(error),
		};
		let now = std::time::SystemTime::now();
		let cutoff = now
			.checked_sub(std::time::Duration::from_secs(24 * 60 * 60))
			.unwrap_or(now);
		let mut count = 0u32;
		for entry in entries.flatten() {
			let meta = match entry.metadata() {
				Ok(meta) => meta,
				Err(_) => continue,
			};
			let modified = match meta.modified() {
				Ok(time) => time,
				Err(_) => continue,
			};
			if modified >= cutoff {
				count += 1;
			}
		}
		Ok(count)
	}

	/// Drop every per-account marker for `account`. Returns the number
	/// removed. Idempotent: a missing account directory returns `Ok(0)`.
	/// Hooked into
	/// [`crate::directory_store::removal::remove_account`] so removing
	/// an account also clears its footprint in the correspondent set
	/// (otherwise a re-created account would inherit yesterday's
	/// recipient list and slip the daily cap).
	pub fn remove_all_for(&self, account: &str) -> std::io::Result<u32> {
		let dir = self.account_dir(account);
		let entries = match fs::read_dir(&dir) {
			Ok(entries) => entries,
			Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
			Err(error) => return Err(error),
		};
		let mut removed = 0u32;
		for entry in entries.flatten() {
			match fs::remove_file(entry.path()) {
				Ok(()) => removed += 1,
				Err(error) if error.kind() == ErrorKind::NotFound => {}
				Err(error) => return Err(error),
			}
		}
		match fs::remove_dir(&dir) {
			Ok(()) => {}
			Err(error) if error.kind() == ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
		Ok(removed)
	}
}

#[cfg(test)]
#[path = "correspondents_tests.rs"]
mod tests;
