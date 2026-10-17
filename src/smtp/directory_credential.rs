//! Which credential a session authenticated with.

use super::Directory;

impl Directory {
	/// The stored PHC hash of `account`'s app password labelled `label`,
	/// which names the credential (see [`crate::evidence::bindings`]).
	pub fn app_password_hash(&self, account: &str, label: &str) -> Option<String> {
		self.app_passwords
			.get(&account.to_ascii_lowercase())?
			.iter()
			.find(|entry| entry.label == label)
			.map(|entry| entry.hash.clone())
	}
}
