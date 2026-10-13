//! Outbound suppression list: recipients that hard-bounced (a permanent 5xx)
//! are recorded so the server stops sending to them, protecting the sending
//! IP's reputation. Backed by one marker file per address under
//! `<data_dir>/suppression/`, named by the SHA-256 of the lowercased address so
//! the filename is always safe.
//!
//! Suppression is tracked at two scopes: a **global** list (shared by every
//! sender) and a **per-account** list keyed by the sending account, under
//! `suppression/accounts/<sha256(account)>/`, so one account's bounces do not
//! have to suppress another's — and an operator can see which recipients
//! bounced for a given account. A recipient is skipped when suppressed at
//! either scope.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// A filesystem-backed set of suppressed recipient addresses.
pub struct SuppressionList {
	dir: PathBuf,
}

/// SHA-256 hex of the stored form of a value (see
/// [`crate::util::address::normalize`]), safe as a filename.
fn digest_name(value: &str) -> String {
	let stored = crate::util::address::normalize(value);
	let digest = ring::digest::digest(&ring::digest::SHA256, stored.as_bytes());
	digest.as_ref().iter().fold(String::new(), |mut acc, byte| {
		use std::fmt::Write;
		let _ = write!(acc, "{byte:02x}");
		acc
	})
}

impl SuppressionList {
	/// Open (creating if needed) the suppression list under `data_dir`.
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		let dir = data_dir.join("suppression");
		fs::create_dir_all(&dir)?;
		Ok(Self { dir })
	}

	/// The marker path for an address in the global list.
	fn path(&self, address: &str) -> PathBuf {
		self.dir.join(digest_name(address))
	}

	/// The directory holding one account's per-account suppression markers.
	fn account_dir(&self, account: &str) -> PathBuf {
		self.dir.join("accounts").join(digest_name(account))
	}

	/// Add an address to the global suppression list (idempotent). The marker
	/// stores the address so it can be listed back.
	pub fn suppress(&self, address: &str) {
		let _ = fs::write(
			self.path(address),
			crate::util::address::normalize(address).as_bytes(),
		);
	}

	/// Add an address to the global list, recording when (epoch seconds) and
	/// why: the remote reply that proved the address bad.
	pub fn suppress_because(&self, address: &str, reason: &str, now: u64) {
		let _ = fs::write(self.path(address), marker(address, reason, now));
	}

	/// Every globally suppressed address with its date and reason, sorted.
	pub fn entries(&self) -> Vec<Suppressed> {
		read_entries(&self.dir)
	}

	/// Whether an address is suppressed globally.
	pub fn is_suppressed(&self, address: &str) -> bool {
		self.path(address).exists()
	}

	/// Remove an address from the global suppression list (idempotent).
	pub fn remove(&self, address: &str) -> std::io::Result<()> {
		remove_marker(&self.path(address))
	}

	/// Every globally suppressed address, sorted.
	pub fn list(&self) -> Vec<String> {
		read_addresses(&self.dir)
	}

	/// Suppress an address for one sending account only (idempotent).
	pub fn suppress_for(&self, account: &str, address: &str) {
		let dir = self.account_dir(account);
		if fs::create_dir_all(&dir).is_ok() {
			let _ = fs::write(
				dir.join(digest_name(address)),
				crate::util::address::normalize(address).as_bytes(),
			);
		}
	}

	/// Suppress an address for one sending account, recording when and why.
	pub fn suppress_for_because(&self, account: &str, address: &str, reason: &str, now: u64) {
		let dir = self.account_dir(account);
		if fs::create_dir_all(&dir).is_ok() {
			let _ = fs::write(dir.join(digest_name(address)), marker(address, reason, now));
		}
	}

	/// Every address suppressed for `account` with its date and reason, sorted.
	pub fn entries_for(&self, account: &str) -> Vec<Suppressed> {
		read_entries(&self.account_dir(account))
	}

	/// Whether an address is suppressed for a specific account.
	pub fn is_suppressed_for(&self, account: &str, address: &str) -> bool {
		self.account_dir(account)
			.join(digest_name(address))
			.exists()
	}

	/// Remove an address from an account's suppression list (idempotent).
	pub fn remove_for(&self, account: &str, address: &str) -> std::io::Result<()> {
		remove_marker(&self.account_dir(account).join(digest_name(address)))
	}

	/// Drop every per-account suppression entry for `account`
	/// (case-insensitive). Returns the number removed. Idempotent: a
	/// missing account directory returns `Ok(0)`. The directory itself is
	/// also removed when it becomes empty, so a freshly re-created account
	/// never inherits a previous owner's suppression file under that path.
	/// Used by [`crate::directory_store::removal::remove_account`] to clear
	/// the account's whole footprint in one pass.
	pub fn remove_all_for(&self, account: &str) -> std::io::Result<u32> {
		let dir = self.account_dir(account);
		let entries = match std::fs::read_dir(&dir) {
			Ok(entries) => entries,
			Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
			Err(error) => return Err(error),
		};
		let mut removed = 0u32;
		for entry in entries.flatten() {
			// Skip the directory's own non-address bookkeeping if any is
			// ever written; today read_addresses only returns true address
			// markers, but `remove_dir_all` on the account_dir already
			// handles the empty case. We only count address markers here.
			match std::fs::remove_file(entry.path()) {
				Ok(()) => removed += 1,
				Err(error) if error.kind() == ErrorKind::NotFound => {}
				Err(error) => return Err(error),
			}
		}
		// Best effort: drop the empty parent dir so a recreated account
		// starts clean. An `Err(NotFound)` is fine (already gone); other
		// errors surface so the operator knows.
		match std::fs::remove_dir(&dir) {
			Ok(()) => {}
			Err(error) if error.kind() == ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
		Ok(removed)
	}

	/// Every address suppressed for a specific account, sorted.
	pub fn list_for(&self, account: &str) -> Vec<String> {
		read_addresses(&self.account_dir(account))
	}
}

/// Remove a marker file, treating "not found" as success.
fn remove_marker(path: &Path) -> std::io::Result<()> {
	match fs::remove_file(path) {
		Ok(()) => Ok(()),
		Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
		Err(error) => Err(error),
	}
}

/// One suppressed address, with when and why when that was recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppressed {
	/// The suppressed address (lowercased).
	pub address: String,
	/// Epoch seconds it was suppressed at, when recorded.
	pub since: Option<u64>,
	/// Why: the remote reply that proved the address bad, when recorded.
	pub reason: Option<String>,
}

/// The content of a marker: the address on the first line, then the epoch
/// and the reason (control characters flattened) separated by a tab. A
/// marker holding only the address, as `suppress` and older releases
/// write it, is still valid.
fn marker(address: &str, reason: &str, now: u64) -> String {
	let reason: String = reason
		.chars()
		.map(|c| if c.is_control() { ' ' } else { c })
		.take(512)
		.collect();
	format!(
		"{}\n{now}\t{}\n",
		address.to_ascii_lowercase(),
		reason.trim()
	)
}

/// Parse a marker written by [`marker`] or by `suppress`.
fn parse_marker(content: &str) -> Option<Suppressed> {
	let mut lines = content.lines();
	let address = lines.next()?.trim().to_string();
	if address.is_empty() {
		return None;
	}
	let (since, reason) = match lines.next().and_then(|line| line.split_once('\t')) {
		Some((since, reason)) => (since.trim().parse().ok(), Some(reason.trim().to_string())),
		None => (None, None),
	};
	Some(Suppressed {
		address,
		since,
		reason: reason.filter(|reason| !reason.is_empty()),
	})
}

/// Read every marker (a regular file) in a directory, sorted by address.
/// The `accounts/` subdirectory is skipped because it is not a regular file.
fn read_entries(dir: &Path) -> Vec<Suppressed> {
	let mut found = Vec::new();
	if let Ok(entries) = crate::util::fs_walk::read_dir(dir) {
		for entry in entries.flatten() {
			if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
				continue;
			}
			if let Some(parsed) = fs::read_to_string(entry.path())
				.ok()
				.as_deref()
				.and_then(parse_marker)
			{
				found.push(parsed);
			}
		}
	}
	found.sort_by(|a, b| a.address.cmp(&b.address));
	found
}

/// Every address in a directory's markers, sorted.
fn read_addresses(dir: &Path) -> Vec<String> {
	read_entries(dir)
		.into_iter()
		.map(|entry| entry.address)
		.collect()
}

#[cfg(test)]
#[path = "suppression_tests.rs"]
mod tests;
