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

/// SHA-256 hex of a lowercased value, safe as a filename.
fn digest_name(value: &str) -> String {
	let digest = ring::digest::digest(&ring::digest::SHA256, value.to_ascii_lowercase().as_bytes());
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
		let _ = fs::write(self.path(address), address.to_ascii_lowercase().as_bytes());
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
				address.to_ascii_lowercase().as_bytes(),
			);
		}
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

/// Read every address marker (a regular file) in a directory, sorted. The
/// `accounts/` subdirectory is skipped because it is not a regular file.
fn read_addresses(dir: &Path) -> Vec<String> {
	let mut addresses = Vec::new();
	if let Ok(entries) = fs::read_dir(dir) {
		for entry in entries.flatten() {
			if let Ok(address) = fs::read_to_string(entry.path()) {
				let address = address.trim().to_string();
				if !address.is_empty() {
					addresses.push(address);
				}
			}
		}
	}
	addresses.sort();
	addresses
}

#[cfg(test)]
#[path = "suppression_tests.rs"]
mod tests;
