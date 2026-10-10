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
/// Cap checks and marker creation share an account-specific file lock.
/// Cloned and independently opened stores therefore reserve against the
/// same baseline, including submissions handled by different protocols.
#[derive(Debug, Clone)]
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

/// The decision returned by [`CorrespondentStore::enforce_new_recipient_cap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOutcome {
	/// No cap is configured (or the store is unset), so the message is
	/// always allowed through. Recipients are recorded before returning.
	Uncapped,
	/// The message fits inside the cap and its recipients are reserved.
	Allowed {
		/// Number of fresh markers created by the reservation.
		new: u32,
	},
	/// The message would exceed the cap. The caller rejects without
	/// recording (no marker is written), so a retry tomorrow starts
	/// from the same baseline.
	Limited {
		/// Number of fresh recipients this message would have introduced.
		new: u32,
		/// Markers already in the 24h window before this message.
		already: u32,
		/// Configured cap.
		limit: u32,
	},
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

	// Keep lock files outside marker directories so they never count toward
	// the cap. Retain them during account removal: replacing a lock file
	// while another caller holds it would split the critical section.
	fn lock_account(&self, account: &str) -> std::io::Result<fs::File> {
		let path = self.dir.join(format!("{}.lock", digest_name(account)));
		let lock = fs::OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.truncate(false)
			.open(path)?;
		lock.lock()?;
		Ok(lock)
	}

	/// Whether `account` has previously written to `address`. Lookup is
	/// case-insensitive (the digest is over the lowercased value).
	pub fn knows(&self, account: &str, address: &str) -> bool {
		self.marker(account, address).exists()
	}

	/// Mark every address in `recipients` as one `account` has written to.
	/// Markers that already exist are not touched (mtime is the *first*
	/// time, not the most recent; the daily cap keys off that). Returns
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
		let _lock = self.lock_account(account)?;
		self.record_locked(account, recipients)
	}

	fn record_locked(&self, account: &str, recipients: &[&str]) -> std::io::Result<Recorded> {
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
			match fs::OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(&path)
			{
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
		let entries = match crate::util::fs_walk::read_dir(&dir) {
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
			if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
				continue;
			}
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

	/// Check the rolling 24h cap and reserve allowed recipients under one
	/// per-account critical section. Refused submissions create no markers.
	/// Uncapped submissions also record recipients for first-contact checks.
	/// Empty accounts and recipient lists are no-ops returning `Uncapped`.
	pub fn enforce_new_recipient_cap(
		&self,
		account: &str,
		recipients: &[&str],
		limit: Option<u32>,
	) -> std::io::Result<CapOutcome> {
		if account.is_empty() || recipients.is_empty() {
			return Ok(CapOutcome::Uncapped);
		}
		let _lock = self.lock_account(account)?;
		let Some(limit) = limit else {
			self.record_locked(account, recipients)?;
			return Ok(CapOutcome::Uncapped);
		};
		let dir = self.account_dir(account);
		let new = recipients
			.iter()
			.map(|address| digest_name(address))
			.collect::<std::collections::HashSet<_>>()
			.iter()
			.filter(|name| !dir.join(name).exists())
			.count() as u32;
		let already = self.new_in_last_day(account)?;
		if new > 0 && already.saturating_add(new) > limit {
			return Ok(CapOutcome::Limited {
				new,
				already,
				limit,
			});
		}
		self.record_locked(account, recipients)?;
		Ok(CapOutcome::Allowed { new })
	}

	/// Drop every per-account marker for `account`. Returns the number
	/// removed. Idempotent: a missing account directory returns `Ok(0)`.
	/// Hooked into
	/// [`crate::directory_store::removal::remove_account`] so removing
	/// an account also clears its footprint in the correspondent set
	/// (otherwise a re-created account would inherit yesterday's
	/// recipient list and slip the daily cap).
	pub fn remove_all_for(&self, account: &str) -> std::io::Result<u32> {
		let _lock = self.lock_account(account)?;
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

#[cfg(test)]
#[path = "correspondents_tests_cap.rs"]
mod tests_cap;
