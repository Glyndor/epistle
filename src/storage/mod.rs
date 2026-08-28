//! Message storage.
//!
//! Messages are stored as individual RFC 5322 files plus a JSON envelope
//! sidecar, written crash-safely (write to a temporary file, fsync, rename).
//! An embedded index and the account/mailbox model build on top of this
//! spool; PostgreSQL stays an option for deployments that need it, but the
//! default install must work with zero external services.

mod crypto;
mod delivery;
mod routing;
mod spool;

// KEY_LEN, MAGIC and OVERHEAD are re-exported because the public docs of the
// items above already describe the contract in terms of them: a key is
// "exactly KEY_LEN bytes", a file "carries MAGIC", a plaintext length is
// "file_len - OVERHEAD". They were pub inside a private module, so a reader
// could see the promise and not the value it refers to.
pub use crypto::{CryptoError, KEY_LEN, MAGIC, MessageCrypto, OVERHEAD, generate_key_base64};
pub use delivery::LocalDelivery;

#[cfg(test)]
#[path = "crypto_e2e_tests.rs"]
mod crypto_e2e_tests;
pub use routing::SplitDelivery;
pub use spool::{Envelope, FsSpool, SpoolEntry};

/// Atomically write `bytes` to `path` with owner-only (`0600`) permissions.
///
/// The file is created `O_EXCL` at `0600` from the start — never written at the
/// umask default and tightened afterwards — so a file holding secrets (account
/// TOTP/credential stores, corpus keys) is never briefly group- or
/// world-readable. Writes to a sibling temp, fsyncs, then renames onto `path`.
pub(crate) fn write_secret(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
	use std::io::Write;
	let tmp = path.with_extension("secret.tmp");
	// A leftover temp from a crashed write would make create_new fail.
	let _ = std::fs::remove_file(&tmp);
	let mut options = std::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	{
		let mut file = options.open(&tmp)?;
		file.write_all(bytes)?;
		file.sync_all()?;
	}
	std::fs::rename(&tmp, path)
}

#[cfg(all(test, unix))]
mod secret_write_tests {
	use std::os::unix::fs::PermissionsExt;

	#[test]
	fn write_secret_is_owner_only() {
		let dir = tempfile::tempdir().expect("tempdir");
		let path = dir.path().join("creds.toml");
		super::write_secret(&path, b"totp_secret = \"JBSWY3DPEHPK3PXP\"").expect("write");
		let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
		assert_eq!(
			mode & 0o777,
			0o600,
			"secret file must be 0600, got {:o}",
			mode & 0o777
		);
		assert_eq!(
			std::fs::read(&path).expect("read"),
			b"totp_secret = \"JBSWY3DPEHPK3PXP\""
		);
	}
}
