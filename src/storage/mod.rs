//! Message storage.
//!
//! Messages are stored as individual RFC 5322 files plus a JSON envelope
//! sidecar, written crash-safely (write to a temporary file, fsync, rename).
//! An embedded index and the account/mailbox model build on top of this
//! spool; PostgreSQL stays an option for deployments that need it, but the
//! default install must work with zero external services.

pub(crate) mod blob_backend;
pub mod correspondents;
mod crypto;
mod delivery;
mod routing;
mod spool;

// KEY_LEN, MAGIC and OVERHEAD are re-exported because the public docs of the
// items above already describe the contract in terms of them: a key is
// "exactly KEY_LEN bytes", a file "carries MAGIC", a plaintext length is
// "file_len - OVERHEAD". They were pub inside a private module, so a reader
// could see the promise and not the value it refers to.
pub use blob_backend::{BlobBackend, BlobError, FsBackend, S3Backend, build as build_blob_backend};
pub use correspondents::{CapOutcome, CorrespondentStore, Recorded};
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

/// Load a 32-byte per-instance key stored under `data_dir`/`name`, generating and
/// persisting a fresh key on first use. The file is written via
/// [`write_secret`] so it is `0600` from the start and survives a mid-write
/// crash: a partial file on disk is treated as absent and rewritten.
///
/// Used by the Bayesian corpus and SubjectPass to keep their symmetric keys
/// outside the database (so a DB compromise cannot reverse any HMAC they
/// produce) and outside the world (so an opportunistic file read does not
/// disclose them).
pub(crate) fn load_or_create_key_file(
	data_dir: &std::path::Path,
	name: &str,
) -> std::io::Result<[u8; 32]> {
	let path = data_dir.join(name);
	if let Ok(bytes) = std::fs::read(&path)
		&& bytes.len() == 32
	{
		let mut key = [0u8; 32];
		key.copy_from_slice(&bytes);
		return Ok(key);
	}
	use ring::rand::SecureRandom;
	let mut key = [0u8; 32];
	ring::rand::SystemRandom::new()
		.fill(&mut key)
		.map_err(|_| std::io::Error::other("rng failure"))?;
	std::fs::create_dir_all(data_dir)?;
	write_secret(&path, &key)?;
	Ok(key)
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
