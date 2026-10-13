//! The outbound path for mail the API submits (`POST /api/v1/send`, JMAP
//! `EmailSubmission/set`). The server hands it the same routing sink SMTP
//! submission uses, so API mail is DKIM-signed, delivered locally to local
//! recipients and queued for the rest, under the id the caller gets back.

use std::sync::Arc;

use super::ApiState;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

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
	/// under that id.
	pub fn submit(&self, account: &str, message: AcceptedMessage) -> Result<uuid::Uuid, SinkError> {
		let id = uuid::Uuid::now_v7();
		match &self.inner.outbound {
			Some(sink) => sink.submit(message, id, account)?,
			None => self.inner.spool.submit(message, id, account)?,
		}
		Ok(id)
	}
}
