//! Revoking a key on behalf of another key.

use super::issue::{Caller, Reach};
use super::{ApiKey, ApiKeyFile, ApiKeyStore};

pub(super) fn no_longer_valid() -> std::io::Error {
	std::io::Error::new(
		std::io::ErrorKind::PermissionDenied,
		"the key that asked is no longer valid",
	)
}

/// What the key that asks reaches now, as `keys` holds it. An error when it is
/// gone, may no longer make or revoke keys, or the client is no longer inside
/// the network the file declares for it.
pub(super) fn maker_in(keys: &[ApiKey], caller: &Caller) -> std::io::Result<Reach> {
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs());
	keys.iter()
		.find(|held| held.label == caller.label() && held.hash.eq_ignore_ascii_case(caller.hash()))
		.filter(|held| held.admits_network(caller.client_ip()))
		.and_then(|held| Reach::of_maker(held, now))
		.ok_or_else(no_longer_valid)
}

impl ApiKeyStore {
	/// Remove the key `label` when `within` says it is one the caller may
	/// revoke, and return it. The caller must still be in the file with the
	/// same secret and still be allowed to revoke, and `within` is asked, of
	/// what the caller reaches now and of the key as the file holds it, all
	/// under the file's lock. A key that is not there and one that `within`
	/// refuses are the same `NotFound`.
	pub fn remove_by(
		&mut self,
		label: &str,
		by: &Caller,
		within: impl Fn(&Reach, &ApiKey) -> bool,
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
				let own = maker_in(&state.keys, by)?;
				let Some(at) = state
					.keys
					.iter()
					.position(|held| held.label == label && within(&own, held))
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
