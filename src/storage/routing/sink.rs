use super::*;

impl MessageSink for SplitDelivery {
	/// Mail from elsewhere: whatever `TLS-Required` it carries is not ours
	/// to honour, so it never reaches a copy we store or forward.
	fn deliver(&self, mut message: AcceptedMessage) -> Result<(), SinkError> {
		message.data = crate::queue::tls_required::strip(message.data);
		self.route_classed(
			message,
			uuid::Uuid::now_v7(),
			None,
			&BTreeMap::new(),
			(crate::evidence::MailClass::Personal, None),
			None,
		)
	}

	/// A report the server wrote: once it is in a local mailbox, a later step
	/// (a redirect, a vacation reply) that fails is logged and not returned,
	/// because the caller would send the report again and fill the mailbox
	/// with copies.
	fn deliver_report(&self, mut message: AcceptedMessage) -> Result<(), SinkError> {
		message.data = crate::queue::tls_required::strip(message.data);
		let mut done = None;
		let routed = self.route_reporting(
			message,
			(uuid::Uuid::now_v7(), None, &BTreeMap::new()),
			(crate::evidence::MailClass::Personal, None),
			None,
			&mut done,
		);
		match (routed, done) {
			(Err(error), Some(_)) => {
				tracing::warn!(%error, "a report reached a mailbox and a later step failed; not repeated");
				Ok(())
			}
			(routed, _) => routed,
		}
	}

	/// Mail one of our accounts sends: only the server's own inspection may
	/// speak in the attachment warning header, so whatever the sender wrote
	/// there is dropped before any copy is stored, queued or signed.
	fn submit(
		&self,
		mut message: AcceptedMessage,
		queue_id: uuid::Uuid,
		account: &str,
		submission: &crate::smtp::sink::Submission,
	) -> Result<(), SinkError> {
		crate::smtp::trace::strip_headers_in_place(
			&mut message.data,
			&[crate::antispam::attachments::policy::WARNING_HEADER],
		);
		match self.evidence_for(account, &message, submission.class)? {
			Some(retention) => {
				self.route_with_evidence(message, queue_id, account, submission, retention)
			}
			None => self.route_classed(
				message,
				queue_id,
				Some(account),
				&submission.extra,
				(submission.class, None),
				None,
			),
		}
	}
}
