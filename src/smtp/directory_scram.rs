//! SCRAM credential storage and lookup.

use super::{Address, Directory, Resolution};

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
}

#[cfg(test)]
#[path = "directory_test_counter.rs"]
mod test_counter;
