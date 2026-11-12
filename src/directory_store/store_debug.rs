//! `Debug` for [`AccountStore`].

use super::AccountStore;

/// Manual Debug so the `ScramUpgrader` trait object can sit in the
/// `Directory` struct (which derives Debug) without forcing every
/// implementor to depend on the store's internals.
impl std::fmt::Debug for AccountStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AccountStore")
			.field("path", &self.path)
			.field("domains", &self.domains)
			.field(
				"dynamic_count",
				&self.dynamic.read().map(|g| g.len()).unwrap_or(0),
			)
			.finish_non_exhaustive()
	}
}
