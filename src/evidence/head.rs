//! The head: the hash of the newest record, kept outside the evidence
//! directory.
//!
//! Every file inside `<data_dir>/evidence/` can be restored from an older
//! copy that is internally consistent: the chain simply ends earlier, and
//! nothing inside says it should not. The head lives next to it, in
//! `<data_dir>/evidence.head`, and is rewritten after every append. A
//! restore of the directory leaves the head naming a record the chain no
//! longer holds, and `verify` reports the rollback: a truncated tail or a
//! deleted latest day.
//!
//! The head may lag the chain (the server stopped between the record and
//! the head), never lead it, so `verify` only requires that the head names a
//! record of the chain.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::record::{hash_from_hex, to_hex};

/// What the head records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
	/// Epoch seconds of the newest record.
	pub time: u64,
	/// Hex hash of the newest record.
	pub last_hash: String,
}

impl Head {
	/// The newest record's hash.
	pub fn hash(&self) -> Option<[u8; 32]> {
		hash_from_hex(&self.last_hash)
	}
}

/// Where the head of the evidence under `evidence_root` lives.
pub fn path(evidence_root: &Path) -> PathBuf {
	evidence_root.with_extension("head")
}

/// The head, `None` when none was ever written.
pub fn load(evidence_root: &Path) -> std::io::Result<Option<Head>> {
	let Some(bytes) = super::checkpoint::read_bounded(&path(evidence_root), 4096)? else {
		return Ok(None);
	};
	serde_json::from_slice(&bytes)
		.map(Some)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Record `hash`, written at `time`, as the head.
pub fn write(evidence_root: &Path, time: u64, hash: &[u8; 32]) -> std::io::Result<()> {
	let head = Head {
		time,
		last_hash: to_hex(hash),
	};
	let bytes = serde_json::to_vec(&head).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&path(evidence_root), &bytes)
}
