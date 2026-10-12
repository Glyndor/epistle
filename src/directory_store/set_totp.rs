//! A dynamic account's TOTP secret, and how it is kept at rest.
//!
//! Split out so [`super::AccountStore`] in `mod.rs` stays under the
//! per-file code-line budget.
//!
//! With at-rest encryption on ([`crate::storage::MessageCrypto`]) the
//! secret is written to `accounts.toml` as `enc:v1:<base64>`, the base64
//! of the same envelope message files use. Without it the base32 secret
//! is written as before. A value without the prefix is cleartext from an
//! older version (or from a store without a key): it is still read, and
//! the next write of `accounts.toml` under a key seals it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::storage::MessageCrypto;

/// Prefix of a sealed secret. The version lets the format change later
/// without guessing at what an old value holds.
const SEALED_PREFIX: &str = "enc:v1:";

/// What the directory gets for a secret it cannot decrypt (no key, wrong
/// key, tampered value). `!` is not base32, so every code is rejected and
/// the primary password fails closed instead of skipping TOTP.
const UNREADABLE_SECRET: &str = "!unreadable";

/// The on-disk form of `secret`: sealed under `crypto` when encryption is
/// on, unchanged otherwise or when it is already sealed.
fn seal(crypto: &MessageCrypto, secret: &str) -> Result<String, super::StoreError> {
	if secret.starts_with(SEALED_PREFIX) {
		return Ok(secret.to_string());
	}
	let envelope = crypto.encode(secret.as_bytes())?;
	if !envelope.starts_with(crate::storage::MAGIC) {
		// Encryption is off: `encode` handed the cleartext back.
		return Ok(secret.to_string());
	}
	Ok(format!("{SEALED_PREFIX}{}", BASE64.encode(envelope)))
}

/// The base32 secret for a stored value, or [`UNREADABLE_SECRET`] when a
/// sealed value cannot be opened.
pub(super) fn open(crypto: &MessageCrypto, stored: &str) -> String {
	let Some(encoded) = stored.strip_prefix(SEALED_PREFIX) else {
		return stored.to_string();
	};
	let opened = BASE64
		.decode(encoded)
		.ok()
		// A sealed value must carry the envelope; without it `decode` would
		// hand back the bytes unchanged as if they were cleartext.
		.filter(|envelope| envelope.starts_with(crate::storage::MAGIC))
		.and_then(|envelope| crypto.decode(&envelope).ok())
		.and_then(|plain| String::from_utf8(plain).ok());
	opened.unwrap_or_else(|| {
		tracing::warn!(
			target: "epistle::auth",
			event = "totp.secret.unreadable",
			"a stored TOTP secret cannot be decrypted; that account's password login fails until the key is restored"
		);
		UNREADABLE_SECRET.to_string()
	})
}

impl super::AccountStore {
	/// Set or clear a dynamic account's base32 TOTP secret (RFC 6238).
	pub fn set_totp(&self, name: &str, secret: Option<String>) -> Result<(), super::StoreError> {
		let stored = secret
			.map(|secret| seal(&self.crypto, &secret))
			.transpose()?;
		let mut dynamic = self.dynamic.write().expect("store lock");
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| super::StoreError::NotFound(name.to_string()))?;
		account.totp_secret = stored;
		self.persist(&dynamic)?;
		Ok(())
	}

	/// Attach the at-rest encryption handle that protects the TOTP secret.
	pub fn with_crypto(mut self, crypto: MessageCrypto) -> Self {
		self.crypto = crypto;
		self.handle.replace(self.build_directory());
		self
	}

	/// The rows as they go to disk: every cleartext TOTP secret sealed when
	/// encryption is on, so a value from an older version does not outlive
	/// the next write.
	pub(super) fn sealed_for_disk(
		&self,
		dynamic: &[super::DynamicAccount],
	) -> Result<Vec<super::DynamicAccount>, super::StoreError> {
		dynamic
			.iter()
			.map(|account| {
				let mut account = account.clone();
				if let Some(secret) = &account.totp_secret {
					account.totp_secret = Some(seal(&self.crypto, secret)?);
				}
				Ok(account)
			})
			.collect()
	}
}

#[cfg(test)]
#[path = "totp_at_rest_tests.rs"]
mod tests;
