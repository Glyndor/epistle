//! Test-only helpers that put a [`Session`] in a state the protocol would
//! otherwise reach through the AUTH machinery.

use std::sync::Arc;

use super::Session;

impl Session {
	/// Test-only setter: attach a directory to the session. The
	/// production code wires the directory through `with_directory`
	/// at session-construction time.
	pub fn set_directory_for_test(&mut self, directory: Arc<crate::smtp::directory::Directory>) {
		self.directory = directory;
	}

	/// Mark this session as authenticated as `account` without going through
	/// the SASL flow. Test-only: production code sets the field through the
	/// AUTH command machinery.
	pub fn mark_authenticated_for_test(&mut self, account: &str) {
		self.authenticated = Some(account.to_string());
		self.auth_app_password_label = None;
	}

	/// Mark this session as authenticated as `account` via the app
	/// password labelled `label`. Test-only.
	pub fn mark_authenticated_with_app_password_for_test(&mut self, account: &str, label: &str) {
		self.authenticated = Some(account.to_string());
		self.auth_app_password_label = Some(label.to_string());
	}
}
