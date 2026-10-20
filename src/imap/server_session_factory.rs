//! Build the per-connection IMAP session with every listener-level
//! option applied. Kept apart from the rest of the accept loop so the
//! file-size budget for [`super`] stays under the hard limit.

use std::sync::Arc;

use super::*;

impl Server {
	/// Build a session with this server's quota, OAuth and channel-binding.
	pub(super) fn new_session(&self) -> Session {
		let mut session = Session::new(
			&self.hostname,
			self.data_dir.clone(),
			self.directory.current(),
		)
		.with_quota_limit(self.quota_bytes)
		.with_crypto(self.crypto.clone())
		.with_oauth(self.oauth.clone())
		.with_retention_days(self.retention_days)
		.with_auth_protocol(self.auth_protocol)
		.with_scram_enabled(self.scram_enabled)
		.with_append_limit(self.append_limit);
		if let Some(counter) = &self.per_account_counter {
			session = session.with_per_account_counter(Arc::clone(counter));
		}
		if let Some(cbind) = &self.cbind_data {
			session = session.with_channel_binding(cbind.current());
		}
		if let Some(queue) = &self.training {
			session = session.with_training(queue.clone());
		}
		session
	}
}
