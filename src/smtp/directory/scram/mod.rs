//! SCRAM credential storage and lookup.

use super::{Address, Directory, Proof, Resolution};

impl Directory {
	/// Attach SCRAM credentials (account name → stored credentials).
	pub fn with_scram(
		mut self,
		scram: impl IntoIterator<Item = (String, crate::smtp::scram::ScramStored)>,
	) -> Self {
		self.scram = scram
			.into_iter()
			.map(|(name, stored)| (name.to_ascii_lowercase(), stored))
			.collect();
		self
	}

	/// Resolve a login to its SCRAM credentials, or `None` when the identity is
	/// unknown or has no SCRAM credentials.
	pub fn scram_credentials(&self, login: &str) -> Option<crate::smtp::scram::ScramCredentials> {
		#[cfg(test)]
		self.record_scram_lookup();
		let account = if login.contains('@') {
			let address = Address::parse(login).ok()?;
			match self.resolve(&address) {
				Resolution::Account(account) => account,
				_ => return None,
			}
		} else {
			login.to_ascii_lowercase()
		};
		self.scram.get(&account)?.to_credentials()
	}

	/// Both final rounds require the original secrets and current account rules.
	pub(crate) fn scram_credentials_current(
		&self,
		account: &str,
		original: &Self,
		protocol: crate::config::Protocol,
	) -> bool {
		use crate::util::constant_time::eq;

		let Some((_, original_hash)) = original.credentials(account) else {
			return false;
		};
		let Some((_, current_hash)) = self.credentials(account) else {
			return false;
		};
		let Some(original) = original
			.scram
			.get(account)
			.and_then(|stored| stored.to_credentials())
		else {
			return false;
		};
		let Some(current) = self
			.scram
			.get(account)
			.and_then(|stored| stored.to_credentials())
		else {
			return false;
		};
		// Every verifier component and the password hash must remain the same.
		eq(original_hash.as_bytes(), current_hash.as_bytes())
			& eq(&original.stored_key, &current.stored_key)
			& eq(&original.server_key, &current.server_key)
			& eq(&original.salt, &current.salt)
			& (original.iterations == current.iterations)
			& self.admit_login(account, protocol, Proof::Scram)
	}
}

#[cfg(test)]
mod tests;
