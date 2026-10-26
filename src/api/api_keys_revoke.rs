//! Retiring the keys bound to an account when the account goes away.

use super::{ApiKey, ApiKeyFile, ApiKeyStore};

fn is_bound_to(key: &ApiKey, name: &str) -> bool {
	key.account
		.as_deref()
		.is_some_and(|own| own.eq_ignore_ascii_case(name))
}

impl ApiKeyStore {
	/// Drop every key bound to the account `name` and return how many went.
	/// A key names its account, so it goes when the account does. One locked rewrite of the file; the running
	/// server picks it up through its file watcher. A missing file or no
	/// match writes nothing.
	pub fn revoke_bound_to(&mut self, name: &str) -> std::io::Result<usize> {
		// Leave the operator's file alone when nothing is bound to the name.
		match std::fs::read_to_string(&self.path) {
			Ok(text) => {
				let file: ApiKeyFile = toml::from_str(&text)
					.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
				if !file.keys.iter().any(|key| is_bound_to(key, name)) {
					return Ok(0);
				}
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
			Err(error) => return Err(error),
		}
		let mut revoked = 0;
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
				let before = state.keys.len();
				state.keys.retain(|key| !is_bound_to(key, name));
				revoked = before - state.keys.len();
				Ok(())
			},
		)?;
		self.keys = new_state.keys;
		Ok(revoked)
	}
}
