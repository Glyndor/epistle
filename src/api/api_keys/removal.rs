//! Revoking a key on behalf of another key.

use super::issue::Caller;
use super::{ApiKey, ApiKeyFile, ApiKeyStore};

impl ApiKeyStore {
	/// Remove the key `label` when `within` says it is one the caller may
	/// revoke, and return it. The caller must still be in the file with the
	/// same secret, and `within` is asked about the key as it is in the file
	/// now, all under the file's lock. A key that is not there and one that
	/// `within` refuses are the same `NotFound`.
	pub fn remove_by(
		&mut self,
		label: &str,
		by: &Caller,
		within: impl Fn(&ApiKey) -> bool,
	) -> std::io::Result<ApiKey> {
		let mut removed = None;
		let new_state = crate::storage::locked::edit(
			&self.path,
			|text| {
				toml::from_str::<ApiKeyFile>(text)
					.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
			},
			|state| {
				toml::to_string_pretty(state)
					.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
			},
			ApiKeyFile::default,
			|state: &mut ApiKeyFile| -> std::io::Result<()> {
				if !state.keys.iter().any(|held| {
					held.label == by.label() && held.hash.eq_ignore_ascii_case(by.hash())
				}) {
					return Err(std::io::Error::new(
						std::io::ErrorKind::PermissionDenied,
						"the key that asked is no longer valid",
					));
				}
				let Some(at) = state
					.keys
					.iter()
					.position(|held| held.label == label && within(held))
				else {
					return Err(std::io::Error::new(
						std::io::ErrorKind::NotFound,
						format!("no such API key \"{label}\""),
					));
				};
				removed = Some(state.keys.remove(at));
				Ok(())
			},
		)
		.map_err(|error| match error {
			crate::storage::locked::EditError::Mutate(inner) => inner,
			other => other.into(),
		})?;
		self.keys = new_state.keys;
		removed.ok_or_else(|| std::io::Error::other("the key was not removed"))
	}
}
