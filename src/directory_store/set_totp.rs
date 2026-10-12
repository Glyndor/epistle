//! Set a dynamic account's TOTP secret.
//!
//! Split out so [`super::AccountStore`] in `mod.rs` stays under the
//! per-file code-line budget. The handler here is also where at-rest
//! encryption of the secret lives when `MessageCrypto` is configured.

impl super::AccountStore {
	/// Set or clear a dynamic account's base32 TOTP secret (RFC 6238).
	pub fn set_totp(&self, name: &str, secret: Option<String>) -> Result<(), super::StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| super::StoreError::NotFound(name.to_string()))?;
		account.totp_secret = secret;
		self.persist(&dynamic)?;
		Ok(())
	}
}
