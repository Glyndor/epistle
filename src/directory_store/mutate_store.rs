//! The locked read-mutate-write path for `AccountStore`'s dynamic set.
//!
//! Sits in a sibling so `mod.rs` stays under the per-file code-line
//! budget. Every mutator on [`super::AccountStore`] (`add`,
//! `set_password_hash`, `remove`, `set_disabled`, `replace_account`,
//! every `super::mutators` entry point) routes through the
//! [`crate::storage::locked::edit`] helper so a sibling CLI process
//! and the running server cannot lose each other's writes; the
//! closure re-reads the on-disk state under the sibling `flock` and
//! applies the mutation to that fresh state.

use crate::storage::locked::{EditError, edit};

use super::{AccountStore, DynamicFile, StoreError};

/// Format the on-disk bytes for `accounts.toml`, sealing every
/// cleartext TOTP secret under at-rest encryption on the way out.
/// Lives at module scope so the `Fn` signature it satisfies can
/// capture `&AccountStore` without a separate lifetime parameter
/// on each callsite.
pub(super) fn serialize_dynamic_file(
	store: &AccountStore,
	state: &DynamicFile,
) -> std::io::Result<String> {
	let sealed = store
		.sealed_for_disk(&state.accounts)
		.map_err(|error| std::io::Error::other(error.to_string()))?;
	toml::to_string_pretty(&DynamicFile { accounts: sealed })
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))
}

impl AccountStore {
	/// Run `mutate` under the cross-process lock on
	/// `accounts.toml` with the latest on-disk state rehydrated into
	/// `state`. Returns the post-mutation state so the caller can
	/// replace its in-memory mirror without re-reading the file.
	/// The closure's return type is the shared `StoreError` so a
	/// validation failure under the lock surfaces a typed error
	/// rather than a string.
	pub(super) fn mutate_store<F>(&self, mutate: F) -> Result<DynamicFile, StoreError>
	where
		F: FnOnce(&mut DynamicFile) -> Result<(), StoreError>,
	{
		edit(
			&self.path,
			|text| {
				toml::from_str::<DynamicFile>(text).map_err(|error| {
					std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
				})
			},
			|state| serialize_dynamic_file(self, state),
			DynamicFile::default,
			mutate,
		)
		.map_err(|error| match error {
			EditError::Io(io) => StoreError::Io(io),
			EditError::Mutate(store) => store,
		})
	}

	/// Replace the in-memory dynamic-account mirror with the
	/// post-write state and rebuild the directory handle so the next
	/// authentication or resolution call sees the change without
	/// going through the file watcher.
	pub(super) fn refresh_after_write(&self, new_state: DynamicFile) {
		*self.dynamic.write().expect("store lock") = new_state.accounts;
		self.handle.replace(self.build_directory());
	}
}
