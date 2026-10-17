//! The outbound path for mail the API submits (`POST /api/v1/send`, JMAP
//! `EmailSubmission/set`). The server hands it the same routing sink SMTP
//! submission uses, so API mail is DKIM-signed, delivered locally to local
//! recipients and queued for the rest, under the id the caller gets back.

use std::sync::Arc;

use super::ApiState;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError, Submission};
use crate::storage::save_sent;

impl ApiState {
	/// Route submissions through `sink`. Must be set before the state is
	/// shared; without it, submissions go straight to the spool.
	pub fn with_outbound(mut self, sink: Arc<dyn MessageSink>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.outbound = Some(sink);
		}
		self
	}

	/// Submit `message` for `account` and return the id of its submission:
	/// the queue id of whatever part leaves the server. A message whose
	/// recipients are all local is delivered at once and queues nothing
	/// under that id. `extra` is the caller-supplied correlation map; the
	/// delivery log and the delivery webhooks copy it onto every record
	/// they emit, but the message itself is never tagged with it.
	pub fn submit(
		&self,
		account: &str,
		message: AcceptedMessage,
		submission: &Submission,
	) -> Result<uuid::Uuid, SinkError> {
		let id = uuid::Uuid::now_v7();
		match &self.inner.outbound {
			Some(sink) => sink.submit(message, id, account, submission)?,
			None => self.inner.spool.submit(message, id, account, submission)?,
		}
		Ok(id)
	}

	/// Save a copy of `data` into `account`'s `Sent` folder when the
	/// per-request override and the account-wide setting admit it.
	/// The default is "on"; the request may opt out with
	/// `request_override = Some(false)`. The credential override
	/// (app password) does not apply on `/api/v1/send` because the
	/// API authenticates with API keys, not app passwords. Failures
	/// are logged and ignored: the outbound submit already returned
	/// success, and a failed Sent copy must not flip it.
	pub fn save_sent_copy(&self, account: &str, data: &[u8], request_override: Option<bool>) {
		if let Some(value) = request_override
			&& !value
		{
			return;
		}
		if request_override.is_none()
			&& !self
				.inner
				.store
				.handle()
				.current()
				.save_sent_for(account)
				.unwrap_or(true)
		{
			return;
		}
		let Some(message_id) = save_sent::first_message_id(data) else {
			tracing::warn!(
				account = %crate::log_id::account(account),
				"save_sent: API message has no Message-ID; skipping copy"
			);
			return;
		};
		let crypto = self.inner.spool.crypto().clone();
		// Reverse dedup: if the same Message-ID already lives in
		// Sent (the client appended first), skip the copy.
		if save_sent::lookup_sent_uid(self.inner.spool.data_dir(), account, &message_id)
			.ok()
			.flatten()
			.is_some()
		{
			tracing::debug!(
				account = %crate::log_id::account(account),
				"save_sent: API message already in Sent; skipping"
			);
			return;
		}
		match save_sent::store_copy(
			self.inner.spool.data_dir(),
			account,
			data,
			&message_id,
			&crypto,
			self.quota_for_account(account),
		) {
			Ok(_uid) => {
				tracing::debug!(
					account = %crate::log_id::account(account),
					"save_sent: API copy stored in Sent"
				);
			}
			Err(error) => {
				tracing::warn!(
					account = %crate::log_id::account(account),
					%error,
					"save_sent: API copy could not be stored; the message is still sent"
				);
			}
		}
	}
}
