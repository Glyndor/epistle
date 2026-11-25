//! The ban store the ban routes manage.

use std::sync::Arc;

use crate::antispam::bans::operator::BanAdmin;

use super::ApiState;

impl ApiState {
	/// Manage the bans and the allow list through `store`. Must be set
	/// before the state is shared. Without it the ban routes answer that bans
	/// are not manageable, as `epistle ban` does without a `[database]`.
	pub fn with_ban_admin(mut self, store: Arc<dyn BanAdmin>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.ban_admin = Some(store);
		}
		self
	}

	/// The ban store, when the server has one.
	pub(crate) fn ban_admin(&self) -> Option<&Arc<dyn BanAdmin>> {
		self.inner.ban_admin.as_ref()
	}
}
