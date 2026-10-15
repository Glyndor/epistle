//! An operator's acknowledgement of a break in the evidence.
//!
//! While the evidence does not verify, new transactional mail is refused:
//! its evidence would be appended to a chain that cannot prove anything.
//! The operator lifts that with `epistle evidence acknowledge`, which names
//! the exact break being accepted and a reason. The acknowledgement is
//! signed with the evidence key into `<evidence>/acknowledged/<id>.json`
//! (`<id>` is the SHA-256 of the break's description) and recorded in the
//! chain, so the acceptance itself becomes evidence. It covers that break
//! only: a different or later one refuses transactional mail again.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::key::{self, EvidenceKey};
use super::record::{Entry, Setting, bounded, sha256, to_hex};

/// The directory of acknowledgements, under the evidence root.
pub const ACK_DIR: &str = "acknowledged";

/// What an acknowledgement says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acknowledgement {
	/// The break, as `verify` described it.
	pub break_text: String,
	/// Why the operator accepts it.
	pub reason: String,
	/// Epoch seconds it was made.
	pub time: u64,
	/// The id of the key that signed it.
	pub key: String,
}

/// The id of the break described by `break_text`.
pub fn id(break_text: &str) -> String {
	to_hex(&sha256(break_text.as_bytes()))
}

fn paths(evidence_root: &Path, break_text: &str) -> (PathBuf, PathBuf) {
	let base = evidence_root.join(ACK_DIR).join(id(break_text));
	(base.with_extension("json"), base.with_extension("sig"))
}

/// Acknowledge `break_text` for `reason`: sign it, store it, and record it
/// in the chain, stamped with the clock.
pub fn acknowledge(
	evidence_root: &Path,
	key: &EvidenceKey,
	break_text: &str,
	reason: &str,
) -> std::io::Result<()> {
	acknowledge_at(
		evidence_root,
		key,
		break_text,
		reason,
		crate::storage::delivery_log::now_epoch(),
	)
}

/// [`acknowledge`] at a fixed time.
pub(crate) fn acknowledge_at(
	evidence_root: &Path,
	key: &EvidenceKey,
	break_text: &str,
	reason: &str,
	now: u64,
) -> std::io::Result<()> {
	let acknowledgement = Acknowledgement {
		break_text: bounded(break_text),
		reason: bounded(reason),
		time: now,
		key: key.id(),
	};
	let bytes = serde_json::to_vec_pretty(&acknowledgement).map_err(std::io::Error::other)?;
	super::chain::create_private_dir(&evidence_root.join(ACK_DIR))?;
	let (json, sig) = paths(evidence_root, break_text);
	crate::storage::write_secret(&sig, &key.sign(&bytes))?;
	crate::storage::write_secret(&json, &bytes)?;
	super::chain::Chain::open(evidence_root)?.append_at(
		now,
		Entry::Setting(Setting {
			name: "acknowledge".into(),
			value: format!("{} {}", id(break_text), bounded(reason)),
		}),
	)?;
	Ok(())
}

/// Whether `break_text` was acknowledged with a valid signature by a
/// published evidence key.
pub fn is_acknowledged(evidence_root: &Path, break_text: &str) -> bool {
	let (json, sig) = paths(evidence_root, break_text);
	let (Ok(bytes), Ok(signature)) = (std::fs::read(&json), std::fs::read(&sig)) else {
		return false;
	};
	let Ok(acknowledgement) = serde_json::from_slice::<Acknowledgement>(&bytes) else {
		return false;
	};
	if acknowledgement.break_text != bounded(break_text) {
		return false;
	}
	std::fs::read_to_string(key::public_key_path(evidence_root, &acknowledgement.key))
		.ok()
		.and_then(|pem| key::parse_public_pem(&pem))
		.filter(|public| key::key_id(public) == acknowledgement.key)
		.is_some_and(|public| key::verify(&public, &bytes, &signature))
}
