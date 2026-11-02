//! The keys at-rest encryption holds, how each one is named on disk, and
//! the rule that keeps two owners from sharing one.
//!
//! Every loaded key is known by a [`KeyId`]: sixteen bytes expanded with
//! HKDF-SHA256 from the key itself under a fixed label. The id is a PRF
//! output, so it says which key sealed a file without saying anything about
//! the key, and it is what a version 2 envelope carries in its header. The
//! sealing key of a version 2 envelope is expanded from the same input under
//! a different label, so the id and the cipher key never share an output.
//! A version 1 envelope is sealed with the raw key, as it always was.

use std::collections::HashMap;
use std::sync::Arc;

use ring::aead::{CHACHA20_POLY1305, LessSafeKey, UnboundKey};
use ring::hkdf;

use super::{CryptoError, KEY_LEN};

/// Length of a [`KeyId`] in bytes.
pub const KEY_ID_LEN: usize = 16;

/// HKDF salt shared by every derivation below. Changing it changes every id
/// and every version 2 sealing key, so it is part of the on-disk format.
const SALT: &[u8] = b"epistle storage key v2";
/// HKDF info for the key id.
const INFO_ID: &[u8] = b"key id";
/// HKDF info for the version 2 sealing key.
const INFO_AEAD: &[u8] = b"chacha20-poly1305";

/// The public name of a storage key: what a version 2 envelope records and
/// what `status` and `account show` print. Not secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId([u8; KEY_ID_LEN]);

impl KeyId {
	/// Build an id from the bytes a version 2 header carries.
	pub fn from_bytes(bytes: [u8; KEY_ID_LEN]) -> Self {
		KeyId(bytes)
	}

	/// The raw id bytes, as written into a version 2 header.
	pub fn as_bytes(&self) -> &[u8; KEY_ID_LEN] {
		&self.0
	}

	/// The first six bytes in hex: enough to tell keys apart in a listing.
	pub fn short(&self) -> String {
		crate::evidence::record::to_hex(&self.0[..6])
	}
}

impl std::fmt::Display for KeyId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&crate::evidence::record::to_hex(&self.0))
	}
}

impl std::fmt::Debug for KeyId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "KeyId({})", self.short())
	}
}

/// Who a loaded key belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyOwner {
	/// The `[storage]` key: data in no tenant, and every write when tenant
	/// keys are off.
	Server,
	/// A previous server key listed in `[storage] retired_key_files`, kept
	/// only so what it sealed can still be read and re-encrypted. The index
	/// is its position in that list.
	Retired(usize),
	/// The `encryption_key_file` of the `[[tenant]]` with this name.
	Tenant(String),
}

impl std::fmt::Display for KeyOwner {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			KeyOwner::Server => f.write_str("the server key"),
			KeyOwner::Retired(index) => write!(f, "retired server key #{}", index + 1),
			KeyOwner::Tenant(name) => write!(f, "the key of tenant \"{name}\""),
		}
	}
}

/// One loaded key, with both forms an envelope may need.
pub(super) struct StoredKey {
	pub(super) id: KeyId,
	pub(super) owner: KeyOwner,
	/// The raw key, which seals and opens version 1 envelopes.
	pub(super) raw: LessSafeKey,
	/// The HKDF-expanded key, which seals and opens version 2 envelopes.
	pub(super) derived: LessSafeKey,
}

/// `hkdf::KeyType` for an output of `len` bytes.
struct Len(usize);

impl hkdf::KeyType for Len {
	fn len(&self) -> usize {
		self.0
	}
}

impl StoredKey {
	/// Load `raw` (exactly [`KEY_LEN`] bytes) for `owner`.
	pub(super) fn new(raw: &[u8], owner: KeyOwner) -> Result<Self, CryptoError> {
		if raw.len() != KEY_LEN {
			return Err(CryptoError::KeyMalformed);
		}
		let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, SALT).extract(raw);
		let mut id = [0u8; KEY_ID_LEN];
		prk.expand(&[INFO_ID], Len(KEY_ID_LEN))
			.and_then(|okm| okm.fill(&mut id))
			.map_err(|_| CryptoError::KeyMalformed)?;
		let derived = prk
			.expand(&[INFO_AEAD], &CHACHA20_POLY1305)
			.map(UnboundKey::from)
			.map_err(|_| CryptoError::KeyMalformed)?;
		let raw =
			UnboundKey::new(&CHACHA20_POLY1305, raw).map_err(|_| CryptoError::KeyMalformed)?;
		Ok(StoredKey {
			id: KeyId(id),
			owner,
			raw: LessSafeKey::new(raw),
			derived: LessSafeKey::new(derived),
		})
	}
}

/// Every key the process holds, by role and by id.
#[derive(Default)]
pub(super) struct Keyring {
	pub(super) server: Option<Arc<StoredKey>>,
	pub(super) retired: Vec<Arc<StoredKey>>,
	/// Tenant name to its key, for tenants that configure one.
	pub(super) tenants: HashMap<String, Arc<StoredKey>>,
	/// Lowercased domain to the tenant that lists it, for every tenant,
	/// keyed or not: an account in a tenant without a key stays on the
	/// server key, and that is a decision this map has to see.
	pub(super) domains: HashMap<String, String>,
	by_id: HashMap<KeyId, Arc<StoredKey>>,
}

impl Keyring {
	/// Add `key` under its owner. Two owners with the same key material are
	/// refused: one leaked file would open both, which is what a separate
	/// key is meant to prevent, and an id could no longer say whose it is.
	pub(super) fn insert(&mut self, key: StoredKey) -> Result<(), CryptoError> {
		if let Some(existing) = self.by_id.get(&key.id) {
			return Err(CryptoError::DuplicateKey {
				first: existing.owner.to_string(),
				second: key.owner.to_string(),
			});
		}
		let key = Arc::new(key);
		self.by_id.insert(key.id, Arc::clone(&key));
		match &key.owner {
			KeyOwner::Server => self.server = Some(key),
			KeyOwner::Retired(_) => self.retired.push(key),
			KeyOwner::Tenant(name) => {
				self.tenants.insert(name.clone(), key);
			}
		}
		Ok(())
	}

	/// The key a version 2 header names, if it is loaded.
	pub(super) fn find(&self, id: &KeyId) -> Option<&Arc<StoredKey>> {
		self.by_id.get(id)
	}

	/// Whether any key at all is loaded.
	pub(super) fn is_empty(&self) -> bool {
		self.by_id.is_empty()
	}

	/// The keys a version 1 envelope may have been sealed with: the server
	/// key first, then the retired ones. A version 1 header names no key, so
	/// the AEAD tag is what tells them apart.
	pub(super) fn v1_candidates(&self) -> impl Iterator<Item = &Arc<StoredKey>> {
		self.server.iter().chain(self.retired.iter())
	}

	/// Every loaded key, server first, then retired, then tenants by name.
	pub(super) fn listing(&self) -> Vec<(KeyOwner, KeyId)> {
		let mut tenants: Vec<_> = self.tenants.values().collect();
		tenants.sort_by_key(|key| key.owner.to_string());
		self.v1_candidates()
			.chain(tenants)
			.map(|key| (key.owner.clone(), key.id))
			.collect()
	}
}
