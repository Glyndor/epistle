//! Evidence bundles: what `epistle evidence export` writes and `epistle
//! evidence check` verifies, offline, without the server.
//!
//! A bundle is a directory:
//!
//! - `records/<day>.jsonl`: the selected records, byte for byte;
//! - `proofs/<day>.json`: for each, its position in the day and the RFC 6962
//!   inclusion proof up to the day's Merkle root;
//! - `checkpoints/<day>.json`, `.sig`, `.tsr`: the signed checkpoint and its
//!   RFC 3161 token;
//! - `tsa/<day>-chain.pem`: the certificates the token carries;
//! - `keys/<id>.pem`: the public evidence key;
//! - `messages/<id>.eml`: the exact bytes, when they were kept;
//! - `README.md` and `SHA256SUMS`.

mod check;
mod export;
mod readme;
mod sums;

pub use check::{CheckReport, check};
pub use export::{Exported, Selector, export};

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The most records one bundle holds.
pub const MAX_RECORDS: usize = 10_000;
/// The most days one export scans.
pub const MAX_SCAN_DAYS: usize = 800;
/// The most files a bundle may hold.
pub const MAX_FILES: usize = 30_000;
/// The largest single file `check` reads, besides records (64 MiB).
pub const MAX_FILE: u64 = 64 * 1024 * 1024;

/// Why an export or a check could not run.
#[derive(Debug)]
pub enum BundleError {
	/// A file could not be read or written.
	Io(std::io::Error),
	/// The request cannot be served as asked.
	Refused(String),
}

impl From<std::io::Error> for BundleError {
	fn from(error: std::io::Error) -> Self {
		BundleError::Io(error)
	}
}

impl std::fmt::Display for BundleError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			BundleError::Io(error) => write!(formatter, "{}", error.kind()),
			BundleError::Refused(why) => formatter.write_str(why),
		}
	}
}

/// The inclusion proofs of one day's records in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DayProof {
	/// The day.
	pub day: String,
	/// Records in the day (the checkpoint's count).
	pub tree_size: u64,
	/// The day's Merkle root (the checkpoint's).
	pub merkle_root: String,
	/// One entry per record in `records/<day>.jsonl`, in the same order.
	pub entries: Vec<ProofEntry>,
}

/// One record's place in its day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofEntry {
	/// Its 0-based position in the day.
	pub index: u64,
	/// SHA-256 of its line.
	pub sha256: String,
	/// The audit path, bottom-up.
	pub proof: Vec<String>,
}

/// Write `bytes` to a new file `path`, `0600`, never through a link, in
/// a `0700` directory: a bundle holds addresses and, when kept, messages.
pub(super) fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
	use std::io::Write;
	use std::os::unix::fs::OpenOptionsExt;
	if let Some(parent) = path.parent() {
		super::chain::create_private_dir(parent)?;
	}
	let mut options = std::fs::OpenOptions::new();
	options
		.write(true)
		.create_new(true)
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW);
	let mut file = options.open(path)?;
	file.write_all(bytes)?;
	file.sync_all()
}

/// Create the bundle directory `out`, `0700`. It must not exist, not even
/// as a link; its parent must.
pub(super) fn create_root(out: &Path) -> Result<(), BundleError> {
	use std::os::unix::fs::DirBuilderExt;
	if std::fs::symlink_metadata(out).is_ok() {
		return Err(BundleError::Refused(
			"the output path already exists (or is a link)".into(),
		));
	}
	std::fs::DirBuilder::new().mode(0o700).create(out)?;
	Ok(())
}

/// The certificates a token carries, as PEM, signer first.
pub(super) fn token_chain_pem(token: &[u8]) -> Result<String, String> {
	use base64::Engine;
	let report = super::tsa::check(
		token,
		&super::tsa::Expected {
			digest: &[0; 32],
			nonce: None,
			anchors: &[],
			policy: None,
		},
	)
	.map_err(|error| error.to_string())?;
	let mut pem = String::new();
	for der in report.certificates {
		let body = base64::engine::general_purpose::STANDARD.encode(der);
		pem.push_str("-----BEGIN CERTIFICATE-----\n");
		for chunk in body.as_bytes().chunks(64) {
			pem.push_str(&String::from_utf8_lossy(chunk));
			pem.push('\n');
		}
		pem.push_str("-----END CERTIFICATE-----\n");
	}
	Ok(pem)
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "bundle_tests_private.rs"]
mod tests_private;
