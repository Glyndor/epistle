//! The anchor a purge leaves for the chain: where the chain stood after the
//! last record of the last purged day. When every day file before today is
//! gone, the next record chains onto it, and a verifier starts from it.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::record::{Position, hash_from_hex, to_hex};

/// The file name, inside the chain directory.
const FILE: &str = "anchor.json";

/// What the anchor holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
	/// The last purged day (`YYYY-MM-DD`).
	pub through: String,
	/// Hex SHA-256 of its last record.
	pub last_hash: String,
	/// The sequence number of that record.
	pub last_seq: u64,
	/// Its time, epoch seconds.
	pub last_time: u64,
	/// Hex SHA-256 of its checkpoint file.
	pub checkpoint: String,
}

impl Anchor {
	/// Where the chain stood after the last purged record.
	pub fn position(&self) -> Option<Position> {
		Some(Position {
			hash: hash_from_hex(&self.last_hash)?,
			seq: self.last_seq,
			time: self.last_time,
		})
	}
}

/// The position the purge left the chain at, or `None` when nothing was
/// ever purged. An anchor that does not hold a position is an error.
pub fn read(chain_dir: &Path) -> std::io::Result<Option<Position>> {
	match load(chain_dir)? {
		None => Ok(None),
		Some(anchor) => anchor.position().map(Some).ok_or_else(|| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"evidence anchor is malformed",
			)
		}),
	}
}

/// The whole anchor, or `None` when nothing was ever purged.
pub fn load(chain_dir: &Path) -> std::io::Result<Option<Anchor>> {
	let Some(bytes) = super::checkpoint::read_bounded(&chain_dir.join(FILE), 4096)? else {
		return Ok(None);
	};
	serde_json::from_slice(&bytes)
		.map(Some)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Replace the anchor, owner-only and crash-safe.
pub fn write(
	chain_dir: &Path,
	through: &str,
	last: &Position,
	checkpoint: &[u8; 32],
) -> std::io::Result<()> {
	let anchor = Anchor {
		through: through.to_string(),
		last_hash: to_hex(&last.hash),
		last_seq: last.seq,
		last_time: last.time,
		checkpoint: to_hex(checkpoint),
	};
	let bytes = serde_json::to_vec(&anchor).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&chain_dir.join(FILE), &bytes)
}
