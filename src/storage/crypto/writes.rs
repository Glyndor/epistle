//! Which key a write uses: the server key, or the key of the account's
//! tenant when `[storage] tenant_keys` is on.

use super::{KeyOwner, MessageCrypto, TenantChoice, envelope};

impl MessageCrypto {
	/// Whether accounts in a keyed tenant write under their tenant key.
	pub fn tenant_writes(&self) -> bool {
		self.inner.tenant_writes
	}

	/// Whether `owner` has a loaded key.
	pub fn has_key(&self, owner: &KeyOwner) -> bool {
		self.key_of(owner).is_some()
	}

	/// The key a new write for `account` uses, or `None` when writes are
	/// not encrypted. A tenant key is chosen only with tenant writes on, an
	/// account whose addresses are all in that one tenant, and the tenant's
	/// key loaded; everything else stays on the server key.
	pub fn write_owner_for_account(&self, account: &str) -> Option<KeyOwner> {
		if !self.inner.enabled || self.inner.keys.server.is_none() {
			return None;
		}
		if self.inner.tenant_writes
			&& let TenantChoice::One(name) = self.tenant_of_account(account)
		{
			let owner = KeyOwner::Tenant(name);
			if self.has_key(&owner) {
				return Some(owner);
			}
		}
		Some(KeyOwner::Server)
	}

	/// Encode `plaintext` for storage in `account`'s mailbox or blob
	/// partition: under its tenant key as a version 2 envelope when
	/// [`write_owner_for_account`](Self::write_owner_for_account) picks
	/// one, under the server key as version 1 otherwise, and unchanged when
	/// encryption is off.
	///
	/// # Errors
	/// Only when the CSPRNG or the AEAD fails; never a fallback to plaintext.
	pub fn encode_for_account(&self, account: &str, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
		match self.write_owner_for_account(account) {
			None => Ok(plaintext.to_vec()),
			Some(owner) => self.seal_for(&owner, plaintext),
		}
	}

	/// Seal `plaintext` under the key `owner` holds, whatever the enabled
	/// flag says: version 1 for the server key, which is what a release
	/// without tenant keys reads, and version 2 for a tenant key.
	///
	/// # Errors
	/// When `owner` is a retired key (never a target), has no loaded key,
	/// or the CSPRNG or the AEAD fails.
	pub fn seal_for(&self, owner: &KeyOwner, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
		match owner {
			KeyOwner::Server => {
				let key = self.key_of(owner).ok_or_else(|| {
					std::io::Error::other("the server key is not loaded, nothing can be sealed")
				})?;
				envelope::seal_v1(key, &self.inner.rng, plaintext, &[])
			}
			KeyOwner::Tenant(_) => self.seal_v2_for(owner, plaintext, &[]),
			KeyOwner::Retired(_) => Err(std::io::Error::other(
				"a retired key only reads; nothing is sealed with it",
			)),
		}
	}
}
