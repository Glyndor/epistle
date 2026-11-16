//! The sink that holds an account's submission instead of delivering it.

use std::sync::Arc;

use super::UndoStore;
use super::frame::Held;
use super::policy::UndoPolicy;
use crate::directory_store::DirectoryHandle;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError, Submission};

/// Wraps the sink a submission ends in. A submission by an account whose
/// delay is above zero is written to the [`UndoStore`] and waits there; the
/// release (see [`super::Releaser`]) later hands it to the wrapped sink,
/// under the same id. Everything else passes straight through: mail from
/// elsewhere (`deliver`), the reports the server writes (`deliver_report`),
/// a submission whose delay is zero and one whose class demands evidence.
pub struct UndoSink {
	inner: Arc<dyn MessageSink>,
	store: Arc<UndoStore>,
	policy: UndoPolicy,
	directory: DirectoryHandle,
}

impl UndoSink {
	/// Hold submissions in `store` as `policy` says, delivering through
	/// `inner` when they are released.
	pub fn new(
		inner: Arc<dyn MessageSink>,
		store: Arc<UndoStore>,
		policy: UndoPolicy,
		directory: DirectoryHandle,
	) -> Self {
		Self {
			inner,
			store,
			policy,
			directory,
		}
	}

	/// The seconds `account`'s submission is held now: what the API tells the
	/// sender it may still cancel for.
	pub fn delay_for(&self, account: &str) -> u32 {
		self.policy.delay_for(&self.directory.current(), account)
	}
}

impl MessageSink for UndoSink {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.inner.deliver(message)
	}

	fn deliver_report(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.inner.deliver_report(message)
	}

	fn submit(
		&self,
		message: AcceptedMessage,
		queue_id: uuid::Uuid,
		account: &str,
		submission: &Submission,
	) -> Result<(), SinkError> {
		let delay = self.delay_for(account);
		// Mail whose evidence is mandatory has its acceptance recorded over
		// the bytes at the moment it is queued: it is never held.
		if delay == 0 || message.recipients.is_empty() || submission.class.evidence_mandatory() {
			return self.inner.submit(message, queue_id, account, submission);
		}
		let now = crate::storage::delivery_log::now_epoch();
		let held = Held {
			id: queue_id,
			account: account.to_string(),
			accepted_at: now,
			release_at: now.saturating_add(u64::from(delay)),
			message,
			submission: submission.clone(),
		};
		self.store
			.hold(&held)
			.map_err(|error| SinkError::Unavailable(error.to_string()))
	}
}
