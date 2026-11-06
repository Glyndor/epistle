//! Sealing and opening the two envelope versions.
//!
//! - Version 1: `EPENC1\0 ‖ nonce ‖ ciphertext+tag`, sealed with the raw
//!   server key and the caller's associated data. The header names no key.
//! - Version 2: `EPENC2\0 ‖ key id ‖ nonce ‖ ciphertext+tag`, sealed with the
//!   HKDF-expanded key the id names. The associated data is the header
//!   (magic and id) followed by the caller's, so a header cannot be swapped
//!   onto another file's ciphertext without the tag failing.

use ring::aead::{Aad, NONCE_LEN, Nonce};
use ring::rand::{SecureRandom, SystemRandom};

use super::keyring::{KEY_ID_LEN, KeyId, KeyOwner, Keyring, StoredKey};
use super::{MAGIC, OVERHEAD};

/// Magic prefix of a version 2 envelope, which names its key.
pub const MAGIC_V2: &[u8] = b"EPENC2\0";

/// Bytes a version 2 envelope adds over the plaintext.
pub const OVERHEAD_V2: usize = MAGIC_V2.len() + KEY_ID_LEN + NONCE_LEN + 16;

/// The larger of the two overheads: the bound a reader that has not looked
/// at the header yet must allow for.
pub const MAX_OVERHEAD: usize = if OVERHEAD_V2 > OVERHEAD {
	OVERHEAD_V2
} else {
	OVERHEAD
};

/// Which envelope a stored buffer carries, read from its header alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeKind {
	/// No envelope: plaintext from before encryption was on.
	Plain,
	/// Version 1, sealed with a server key it does not name.
	V1,
	/// Version 2, sealed with the key this id names.
	V2(KeyId),
	/// It starts with a magic but is too short to hold its header.
	Truncated,
}

/// Read the envelope kind of `stored` without any key.
pub fn kind(stored: &[u8]) -> EnvelopeKind {
	if stored.starts_with(MAGIC) {
		return EnvelopeKind::V1;
	}
	if let Some(rest) = stored.strip_prefix(MAGIC_V2) {
		let Some(id) = rest.get(..KEY_ID_LEN) else {
			return EnvelopeKind::Truncated;
		};
		let mut bytes = [0u8; KEY_ID_LEN];
		bytes.copy_from_slice(id);
		return EnvelopeKind::V2(KeyId::from_bytes(bytes));
	}
	EnvelopeKind::Plain
}

/// Whether `stored` starts with either envelope magic.
pub fn is_envelope(stored: &[u8]) -> bool {
	stored.starts_with(MAGIC) || stored.starts_with(MAGIC_V2)
}

/// Why an envelope could not be opened.
#[derive(Debug)]
pub(super) enum OpenError {
	/// An envelope, and no key loaded at all.
	NoKey,
	/// A version 2 envelope whose key is not loaded.
	UnknownKey(KeyId),
	/// Too short to hold its header and nonce.
	Truncated,
	/// Tag mismatch: tamper, wrong key or wrong associated data.
	Authentication,
}

impl std::fmt::Display for OpenError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			OpenError::NoKey => f.write_str("encrypted message but no decryption key loaded"),
			OpenError::UnknownKey(id) => write!(
				f,
				"encrypted message sealed with storage key {}, which is not loaded",
				id.short()
			),
			OpenError::Truncated => f.write_str("encrypted message: truncated envelope"),
			OpenError::Authentication => f.write_str("encrypted message: authentication failed"),
		}
	}
}

/// A fresh random nonce.
fn nonce(rng: &SystemRandom) -> std::io::Result<[u8; NONCE_LEN]> {
	let mut bytes = [0u8; NONCE_LEN];
	rng.fill(&mut bytes)
		.map_err(|_| std::io::Error::other("CSPRNG failure generating nonce"))?;
	Ok(bytes)
}

/// Seal `plaintext` as a version 1 envelope under `key`'s raw form.
pub(super) fn seal_v1(
	key: &StoredKey,
	rng: &SystemRandom,
	plaintext: &[u8],
	aad: &[u8],
) -> std::io::Result<Vec<u8>> {
	let nonce_bytes = nonce(rng)?;
	let mut buffer = plaintext.to_vec();
	key.raw
		.seal_in_place_append_tag(
			Nonce::assume_unique_for_key(nonce_bytes),
			Aad::from(aad),
			&mut buffer,
		)
		.map_err(|_| std::io::Error::other("AEAD sealing failed"))?;
	let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
	out.extend_from_slice(MAGIC);
	out.extend_from_slice(&nonce_bytes);
	out.extend_from_slice(&buffer);
	Ok(out)
}

/// The associated data of a version 2 envelope: its header, then the
/// caller's.
fn v2_aad(id: &KeyId, aad: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(MAGIC_V2.len() + KEY_ID_LEN + aad.len());
	out.extend_from_slice(MAGIC_V2);
	out.extend_from_slice(id.as_bytes());
	out.extend_from_slice(aad);
	out
}

/// Seal `plaintext` as a version 2 envelope under `key`.
pub(super) fn seal_v2(
	key: &StoredKey,
	rng: &SystemRandom,
	plaintext: &[u8],
	aad: &[u8],
) -> std::io::Result<Vec<u8>> {
	let nonce_bytes = nonce(rng)?;
	let mut buffer = plaintext.to_vec();
	key.derived
		.seal_in_place_append_tag(
			Nonce::assume_unique_for_key(nonce_bytes),
			Aad::from(v2_aad(&key.id, aad)),
			&mut buffer,
		)
		.map_err(|_| std::io::Error::other("AEAD sealing failed"))?;
	let mut out = Vec::with_capacity(OVERHEAD_V2 + plaintext.len());
	out.extend_from_slice(MAGIC_V2);
	out.extend_from_slice(key.id.as_bytes());
	out.extend_from_slice(&nonce_bytes);
	out.extend_from_slice(&buffer);
	Ok(out)
}

/// Open `ciphertext` (nonce, then sealed bytes) under one key form.
fn open_with(
	key: &ring::aead::LessSafeKey,
	sealed: &[u8],
	aad: &[u8],
) -> Result<Vec<u8>, OpenError> {
	if sealed.len() < NONCE_LEN {
		return Err(OpenError::Truncated);
	}
	let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
	let nonce =
		Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| OpenError::Authentication)?;
	let mut buffer = ciphertext.to_vec();
	let plaintext = key
		.open_in_place(nonce, Aad::from(aad), &mut buffer)
		.map_err(|_| OpenError::Authentication)?;
	Ok(plaintext.to_vec())
}

/// Open `stored` with whichever key its header calls for. `Ok(None)` means
/// it carries no envelope at all. Never returns ciphertext as plaintext.
pub(super) fn open(
	keys: &Keyring,
	stored: &[u8],
	aad: &[u8],
) -> Result<Option<(Vec<u8>, KeyOwner)>, OpenError> {
	match kind(stored) {
		EnvelopeKind::Plain => Ok(None),
		EnvelopeKind::Truncated => Err(OpenError::Truncated),
		EnvelopeKind::V1 => {
			let sealed = &stored[MAGIC.len()..];
			let mut last = OpenError::NoKey;
			for key in keys.v1_candidates() {
				match open_with(&key.raw, sealed, aad) {
					Ok(plain) => return Ok(Some((plain, key.owner.clone()))),
					Err(error) => last = error,
				}
			}
			Err(last)
		}
		EnvelopeKind::V2(id) => {
			let key = keys.find(&id).ok_or(if keys.is_empty() {
				OpenError::NoKey
			} else {
				OpenError::UnknownKey(id)
			})?;
			let sealed = &stored[MAGIC_V2.len() + KEY_ID_LEN..];
			open_with(&key.derived, sealed, &v2_aad(&id, aad))
				.map(|plain| Some((plain, key.owner.clone())))
		}
	}
}
