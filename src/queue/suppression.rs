//! Outbound suppression list: recipients that hard-bounced (a permanent 5xx)
//! are recorded so the server stops sending to them, protecting the sending
//! IP's reputation. Backed by one marker file per address under
//! `<data_dir>/suppression/`, named by the SHA-256 of the lowercased address so
//! the filename is always safe.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// A filesystem-backed set of suppressed recipient addresses.
pub struct SuppressionList {
	dir: PathBuf,
}

impl SuppressionList {
	/// Open (creating if needed) the suppression list under `data_dir`.
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		let dir = data_dir.join("suppression");
		fs::create_dir_all(&dir)?;
		Ok(Self { dir })
	}

	/// The marker path for an address (SHA-256 hex of the lowercased address).
	fn path(&self, address: &str) -> PathBuf {
		let digest = ring::digest::digest(
			&ring::digest::SHA256,
			address.to_ascii_lowercase().as_bytes(),
		);
		let name = digest.as_ref().iter().fold(String::new(), |mut acc, byte| {
			use std::fmt::Write;
			let _ = write!(acc, "{byte:02x}");
			acc
		});
		self.dir.join(name)
	}

	/// Add an address to the suppression list (idempotent). The marker stores
	/// the address so it can be listed back.
	pub fn suppress(&self, address: &str) {
		let _ = fs::write(self.path(address), address.to_ascii_lowercase().as_bytes());
	}

	/// Whether an address is suppressed.
	pub fn is_suppressed(&self, address: &str) -> bool {
		self.path(address).exists()
	}

	/// Remove an address from the suppression list (idempotent).
	pub fn remove(&self, address: &str) -> std::io::Result<()> {
		match fs::remove_file(self.path(address)) {
			Ok(()) => Ok(()),
			Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
			Err(error) => Err(error),
		}
	}

	/// Every suppressed address, sorted.
	pub fn list(&self) -> Vec<String> {
		let mut addresses = Vec::new();
		if let Ok(entries) = fs::read_dir(&self.dir) {
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
}

#[cfg(test)]
#[path = "suppression_tests.rs"]
mod tests;
