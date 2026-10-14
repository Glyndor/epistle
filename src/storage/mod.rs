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
pub mod delivery_log;
pub(crate) mod lock;
pub(crate) mod locked;
mod routing;
mod routing_forward;
pub(crate) mod save_sent;
mod spool;
mod spool_recipients;
pub(crate) mod vacation_markers;
pub mod vacation_store;

// KEY_LEN, MAGIC and OVERHEAD are re-exported because the public docs of the
// items above already describe the contract in terms of them: a key is
// "exactly KEY_LEN bytes", a file "carries MAGIC", a plaintext length is
// "file_len - OVERHEAD". They were pub inside a private module, so a reader
// could see the promise and not the value it refers to.
pub use blob_backend::{
	BlobAccount, BlobBackend, BlobError, FsBackend, S3Backend, build as build_blob_backend,
};
pub use correspondents::{CapOutcome, CorrespondentStore, Recorded};
pub use crypto::{CryptoError, KEY_LEN, MAGIC, MessageCrypto, OVERHEAD, generate_key_base64};
pub use delivery::LocalDelivery;
pub use delivery_log::{DEFAULT_DELIVERY_LOG_DAYS, DeliveryLog, DeliveryOutcome, DeliveryRecord};

#[cfg(test)]
#[path = "crypto_e2e_tests.rs"]
mod crypto_e2e_tests;
pub use routing::SplitDelivery;
pub use save_sent::{
	Guard as SentGuard, SaveError as SentSaveError, SaveOutcome, SkipReason, first_message_id,
	store_copy as save_sent_copy,
};
pub use spool::{Envelope, FsSpool, RecipientState, RecipientStatus, SpoolEntry};
pub use vacation_store::{
	MAX_BODY_BYTES, VacationSetting, clear as clear_vacation, read as read_vacation,
	write as write_vacation,
};

/// Atomically write `bytes` to `path` with owner-only (`0600`) permissions.
///
/// The file is created `O_EXCL` at `0600` from the start — never written at the
/// umask default and tightened afterwards — so a file holding secrets (account
/// TOTP/credential stores, corpus keys) is never briefly group- or
/// world-readable. The temp file lives in the same directory as `path` and
/// carries a UUID v7 suffix so two concurrent writers never share a name (the
/// older fixed `<file>.secret.tmp` name would let a second writer `unlink`
/// the first's temp mid-write). The temp is `fsync(2)`'d before the rename,
/// and the parent directory is `fsync(2)`'d afterwards so the rename survives
/// a power failure between the rename and a follow-up dirent write.
pub(crate) fn write_secret(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
	use std::io::Write;
	let parent = path
		.parent()
		.filter(|p| !p.as_os_str().is_empty())
		.unwrap_or(std::path::Path::new("."));
	let name = path
		.file_name()
		.and_then(|n| n.to_str())
		.unwrap_or("secret");
	let unique = uuid::Uuid::now_v7();
	let tmp = parent.join(format!(".{name}.{unique}.tmp"));
	let mut options = std::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	let mut file = options.open(&tmp)?;
	// From here on the temp exists: any failure before the rename lands
	// removes it, so a failed write never leaves a stray secret copy
	// beside the destination.
	let staged = file
		.write_all(bytes)
		.and_then(|()| file.sync_all())
		.and_then(|()| {
			drop(file);
			std::fs::rename(&tmp, path)
		});
	if let Err(error) = staged {
		let _ = std::fs::remove_file(&tmp);
		return Err(error);
	}
	// `fsync(2)` the parent directory so the rename survives a power
	// failure that hits the file but not the dirent write.
	std::fs::File::open(parent).and_then(|dir| dir.sync_all())?;
	Ok(())
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

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;

#[cfg(test)]
#[path = "locked_tests.rs"]
mod locked_tests;

#[cfg(test)]
#[path = "secret_write_concurrency_tests.rs"]
mod secret_write_concurrency_tests;
