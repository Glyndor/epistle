//! The anchor a purge leaves for the chain: the hash of the last record of
//! the last purged day. When every day file before today is gone, the next
//! record chains onto it, and a verifier starts from it.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::record::{hash_from_hex, to_hex};

/// The file name, inside the chain directory.
const FILE: &str = "anchor.json";

/// What the anchor holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
	/// The last purged day (`YYYY-MM-DD`).
	pub through: String,
	/// Hex SHA-256 of its last record.
	pub last_hash: String,
	/// Hex SHA-256 of its checkpoint file.
	pub checkpoint: String,
}

/// The anchor's last hash, or `None` when nothing was ever purged.
pub fn read(chain_dir: &Path) -> std::io::Result<Option<[u8; 32]>> {
	Ok(load(chain_dir)?.and_then(|anchor| hash_from_hex(&anchor.last_hash)))
}

/// The whole anchor, or `None` when nothing was ever purged.
pub fn load(chain_dir: &Path) -> std::io::Result<Option<Anchor>> {
	let bytes = match std::fs::read(chain_dir.join(FILE)) {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error),
	};
	if bytes.len() > 4096 {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			"evidence anchor is larger than any anchor this server writes",
		));
	}
	serde_json::from_slice(&bytes)
		.map(Some)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Replace the anchor, owner-only and crash-safe.
pub fn write(
	chain_dir: &Path,
	through: &str,
	last: &[u8; 32],
	checkpoint: &[u8; 32],
) -> std::io::Result<()> {
	let anchor = Anchor {
		through: through.to_string(),
		last_hash: to_hex(last),
		checkpoint: to_hex(checkpoint),
	};
	let bytes = serde_json::to_vec(&anchor).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&chain_dir.join(FILE), &bytes)
}
