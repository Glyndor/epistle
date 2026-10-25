//! The class of an authenticated submission (see
//! [`crate::evidence::submission`]).

use super::Server;
use crate::evidence::ClassSources;
use crate::evidence::submission::{Prepared, prepare};
use crate::smtp::reply::Reply;
use crate::smtp::session::{AcceptedMessage, Session};

impl Server {
	/// Decide the class of `message` from the credential that authenticated
	/// `session` and from `account`, strip the client's class header, write
	/// the identification headers, and apply the marketing rules. A refusal
	/// is the reply to send. `pub(crate)` because the API tests compare this
	/// path against the two that submit through the API.
	pub(crate) fn prepare_submission(
		&self,
		session: &Session,
		account: &str,
		message: &mut AcceptedMessage,
	) -> Result<Prepared, Reply> {
		let sources = match &self.class_bindings {
			Some(bindings) => ClassSources {
				explicit: None,
				credential: session
					.auth_app_password_label()
					.and_then(|label| self.directory.current().app_password_hash(account, label))
					.and_then(|hash| {
						bindings.credential(&crate::evidence::bindings::app_password_key(&hash))
					}),
				account: bindings.account(account),
			},
			None => ClassSources::default(),
		};
		let prepared = prepare(
			message,
			sources,
			self.data_dir.as_deref(),
			&self.identification,
			Some(&self.directory.current()),
		)
		.map_err(|refusal| refusal.smtp_reply())?;
		if !prepared.suppressed.is_empty() {
			tracing::info!(
				account = %crate::log_id::account(account),
				dropped = prepared.suppressed.len(),
				"marketing submission: suppressed recipients dropped"
			);
		}
		Ok(prepared)
	}
}
