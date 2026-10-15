//! The Ed25519 key that signs evidence checkpoints.
//!
//! It is its own key, never a DKIM or TLS key: generated on first use,
//! stored PKCS#8 in `<evidence>/key.pk8` at `0600`, and published as an
//! SPKI PEM under `<evidence>/keys/<id>.pem`, where `<id>` is the SHA-256
//! of the SPKI in hex. Checkpoints name the key by that id, so a key that
//! was replaced still verifies the days it signed.
//!
//! Two processes may reach first use at once (the server and a CLI
//! command). The key is staged under a unique name and linked into place
//! with `link(2)`, which never replaces an existing file, so exactly one
//! key wins and both processes end up using it.

use std::path::{Path, PathBuf};

use base64::Engine;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use super::record::{sha256, to_hex};

/// The private key file, under the evidence root.
const KEY_FILE: &str = "key.pk8";
/// The directory of published public keys, under the evidence root.
pub const KEYS_DIR: &str = "keys";
/// The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410).
const SPKI_PREFIX: [u8; 12] = [
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The evidence signing key.
pub struct EvidenceKey {
	pair: Ed25519KeyPair,
}

impl std::fmt::Debug for EvidenceKey {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("EvidenceKey")
			.field("id", &self.id())
			.finish_non_exhaustive()
	}
}

impl EvidenceKey {
	/// Load the key under `evidence_root`, generating it on first use.
	pub fn load_or_create(evidence_root: &Path) -> std::io::Result<Self> {
		super::chain::create_private_dir(evidence_root)?;
		let path = evidence_root.join(KEY_FILE);
		if !path.exists() {
			generate_into(&path)?;
		}
		let pkcs8 = std::fs::read(&path)?;
		let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"evidence key is not an Ed25519 PKCS#8 key",
			)
		})?;
		let key = EvidenceKey { pair };
		match pinned_id(evidence_root)? {
			Some(pinned) if pinned != key.id() => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"the evidence key does not match the pinned key: refusing to sign with it",
				));
			}
			Some(_) => {}
			None => pin(evidence_root, &key.id())?,
		}
		key.publish(evidence_root)?;
		Ok(key)
	}

	/// The raw 32-byte public key.
	pub fn public_key(&self) -> [u8; 32] {
		let mut out = [0u8; 32];
		out.copy_from_slice(self.pair.public_key().as_ref());
		out
	}

	/// The key id: hex SHA-256 of its SPKI.
	pub fn id(&self) -> String {
		key_id(&self.public_key())
	}

	/// The signature of `message`.
	pub fn sign(&self, message: &[u8]) -> [u8; 64] {
		let mut out = [0u8; 64];
		out.copy_from_slice(self.pair.sign(message).as_ref());
		out
	}

	/// Write the public key under `keys/` unless it is already there.
	fn publish(&self, evidence_root: &Path) -> std::io::Result<()> {
		let dir = evidence_root.join(KEYS_DIR);
		super::chain::create_private_dir(&dir)?;
		let path = public_key_path(evidence_root, &self.id());
		if path.exists() {
			return Ok(());
		}
		crate::storage::write_secret(&path, public_pem(&self.public_key()).as_bytes())
	}
}

/// Generate a key and link it into `path`, unless another process did first.
fn generate_into(path: &Path) -> std::io::Result<()> {
	let rng = ring::rand::SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
		.map_err(|_| std::io::Error::other("evidence key generation failed"))?;
	let staged = path.with_extension(format!("{}.tmp", uuid::Uuid::now_v7()));
	crate::storage::write_secret(&staged, pkcs8.as_ref())?;
	let linked = std::fs::hard_link(&staged, path);
	let _ = std::fs::remove_file(&staged);
	match linked {
		Ok(()) => {
			if let Some(parent) = path.parent() {
				std::fs::File::open(parent).and_then(|dir| dir.sync_all())?;
			}
			Ok(())
		}
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
		Err(error) => Err(error),
	}
}

/// Where the id of the evidence key is pinned: next to the evidence
/// directory, so replacing the key inside it is visible.
pub fn pin_path(evidence_root: &Path) -> PathBuf {
	evidence_root.with_extension("key-id")
}

/// The pinned key id, `None` when no key was ever made.
pub fn pinned_id(evidence_root: &Path) -> std::io::Result<Option<String>> {
	let Some(bytes) = super::checkpoint::read_bounded(&pin_path(evidence_root), 128)? else {
		return Ok(None);
	};
	let id = String::from_utf8(bytes)
		.ok()
		.map(|text| text.trim().to_string())
		.filter(|id| super::record::hash_from_hex(id).is_some())
		.ok_or_else(|| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"the evidence key pin is malformed",
			)
		})?;
	Ok(Some(id))
}

fn pin(evidence_root: &Path, id: &str) -> std::io::Result<()> {
	crate::storage::write_secret(&pin_path(evidence_root), format!("{id}\n").as_bytes())
}

/// The SPKI DER of a raw Ed25519 public key.
pub fn spki_der(public_key: &[u8; 32]) -> Vec<u8> {
	[SPKI_PREFIX.as_slice(), public_key.as_slice()].concat()
}

/// The id of a raw Ed25519 public key.
pub fn key_id(public_key: &[u8; 32]) -> String {
	to_hex(&sha256(&spki_der(public_key)))
}

/// The PEM `PUBLIC KEY` block of a raw Ed25519 public key, the form
/// `openssl pkeyutl -verify -pubin` reads.
pub fn public_pem(public_key: &[u8; 32]) -> String {
	let body = base64::engine::general_purpose::STANDARD.encode(spki_der(public_key));
	format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n")
}

/// The raw public key in a PEM `PUBLIC KEY` block, or `None` when it is not
/// an Ed25519 SPKI.
pub fn parse_public_pem(pem: &str) -> Option<[u8; 32]> {
	let body: String = pem
		.lines()
		.map(str::trim)
		.filter(|line| !line.starts_with("-----"))
		.collect();
	let der = base64::engine::general_purpose::STANDARD
		.decode(body.as_bytes())
		.ok()?;
	let raw = der.strip_prefix(SPKI_PREFIX.as_slice())?;
	raw.try_into().ok()
}

/// Where the public key with `id` is published.
pub fn public_key_path(evidence_root: &Path, id: &str) -> PathBuf {
	evidence_root.join(KEYS_DIR).join(format!("{id}.pem"))
}

/// Whether `signature` is `public_key`'s signature of `message`.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
	UnparsedPublicKey::new(&ED25519, public_key)
		.verify(message, signature)
		.is_ok()
}

#[cfg(test)]
#[path = "key_tests.rs"]
mod tests;
