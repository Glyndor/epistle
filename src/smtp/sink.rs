//! Destination for messages accepted by the SMTP server.

use super::session::AcceptedMessage;

/// Receives accepted messages. The real implementation will be the storage
/// layer; tests and early milestones use the in-memory sink.
pub trait MessageSink: Send + Sync {
	/// Persist an accepted message. Returning an error makes the server
	/// answer with a transient failure so the client retries later.
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError>;

	/// Take a report the server wrote itself (a failure or delay notice).
	/// Unlike mail from elsewhere it is never retried by a sender: a sink that
	/// can tell must not fail it once part of the work is done, so that a
	/// retry by the caller does not repeat that part.
	fn deliver_report(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.deliver(message)
	}

	/// Take a message that `account`, one of this server's own accounts,
	/// submitted (SMTP after AUTH, `/api/v1/send`, JMAP
	/// `EmailSubmission/set`), where [`MessageSink::deliver`] takes mail
	/// that arrived from elsewhere. The outbound queue entry (if the message
	/// leaves the server) is stored under `queue_id`, so the submitter can
	/// hand that id back to its client. A sink that never queues has nothing
	/// to name and delivers as usual; a sink that queues, or that treats
	/// submissions differently, overrides this.
	///
	/// `submission` carries what the server decided about it: the class it
	/// granted and the caller-supplied correlation map the API may attach
	/// (see `POST /api/v1/send`). The spool stores both on the envelope; the
	/// map is never written into the message itself.
	fn submit(
		&self,
		message: AcceptedMessage,
		queue_id: uuid::Uuid,
		account: &str,
		submission: &Submission,
	) -> Result<(), SinkError> {
		let _ = (queue_id, account);
		// A sink that does not keep evidence must not take mail whose
		// evidence is mandatory: it would be sent, with nothing to show.
		if submission.class.evidence_mandatory() {
			return Err(SinkError::EvidenceUnavailable(
				"this sink keeps no evidence".into(),
			));
		}
		self.deliver(message)
	}
}

/// What the server decided about a submission, besides the message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Submission {
	/// The caller-supplied correlation map (API only; empty for SMTP).
	pub extra: std::collections::BTreeMap<String, String>,
	/// The class the server granted.
	pub class: crate::evidence::MailClass,
}

impl Submission {
	/// A submission of `class` with no correlation map.
	pub fn of_class(class: crate::evidence::MailClass) -> Self {
		Submission {
			extra: std::collections::BTreeMap::new(),
			class,
		}
	}
}

/// Why a delivery could not be accepted.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
	/// Storage is unavailable right now (transient): disk full, network
	/// error talking to the spool, mutex poisoned. The caller should answer
	/// with a 4xx so the client retries later.
	#[error("storage unavailable: {0}")]
	Unavailable(String),
	/// The antivirus found this signature in a submitted message. Permanent:
	/// the same message is refused again however often it is retried.
	#[error("virus detected ({0})")]
	VirusDetected(String),
	/// The attachment policy refused a submitted message; the reason codes,
	/// comma separated. Permanent like a virus.
	#[error("attachment type not accepted ({0})")]
	AttachmentRefused(String),
	/// The content scan could not run now (busy, or clamd failing with
	/// `clamd_on_error = "defer"`). Temporary: the client retries and
	/// nothing passes unscanned.
	#[error("content scan unavailable")]
	ScanUnavailable,
	/// The message is over what clamd can take, and `clamd_on_error =
	/// "defer"` lets nothing pass unscanned. Permanent: a retry is just as
	/// large.
	#[error("message too large for the content scan")]
	ScanTooLarge,
	/// Transactional mail whose evidence cannot be recorded, or that is held
	/// while the evidence does not verify. Transient: the client retries.
	#[error("evidence unavailable: {0}")]
	EvidenceUnavailable(String),
	/// The message has more header fields than a Sieve filter reads, so
	/// some could not be seen by the recipient's rules. Permanent.
	#[error("too many header fields")]
	TooManyHeaderFields,
	/// A local recipient no longer exists (its account or domain was
	/// removed). Permanent for a report the server wrote to it: trying again
	/// finds the same. Inbound mail is still answered with a retry.
	#[error("recipient gone: {0}")]
	Gone(String),
}

impl SinkError {
	/// The SMTP reply that refuses the message for this reason.
	pub fn smtp_reply(&self) -> crate::smtp::reply::Reply {
		use crate::smtp::reply::Reply;
		match self {
			SinkError::Unavailable(_) | SinkError::Gone(_) => {
				Reply::single(451, "4.3.0 temporary storage failure, try again")
			}
			SinkError::EvidenceUnavailable(_) => Reply::single(
				451,
				"4.3.0 transactional mail cannot be recorded as evidence right now, try again later",
			),
			SinkError::VirusDetected(signature) => Reply::single(
				554,
				&format!("5.7.1 message rejected: virus detected ({signature})"),
			),
			SinkError::AttachmentRefused(_) => {
				Reply::single(550, "5.7.1 attachment type not accepted")
			}
			SinkError::ScanUnavailable => {
				Reply::single(451, "4.7.1 content scan unavailable, try again later")
			}
			SinkError::ScanTooLarge => {
				Reply::single(552, "5.3.4 message too large for the content scan")
			}
			SinkError::TooManyHeaderFields => {
				Reply::single(554, "5.6.0 too many header fields in this message")
			}
		}
	}
}

/// In-memory sink: collects messages, for tests and early development.
#[derive(Debug, Default)]
pub struct MemorySink {
	messages: std::sync::Mutex<Vec<AcceptedMessage>>,
}

impl MemorySink {
	/// Create an empty sink.
	pub fn new() -> Self {
		Self::default()
	}

	/// Messages delivered so far.
	pub fn messages(&self) -> Vec<AcceptedMessage> {
		self.messages.lock().expect("sink mutex poisoned").clone()
	}
}

impl MessageSink for MemorySink {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.messages
			.lock()
			.map_err(|_| SinkError::Unavailable("sink mutex poisoned".into()))?
			.push(message);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn memory_sink_collects_messages() {
		let sink = MemorySink::new();
		let message = AcceptedMessage {
			reverse_path: "a@example.org".into(),
			recipients: vec!["b@example.org".into()],
			data: b"hello\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: false,
			no_dsn: Vec::new(),
		};
		sink.deliver(message.clone()).expect("delivery succeeds");
		assert_eq!(sink.messages(), vec![message]);
	}

	#[test]
	fn a_sink_that_keeps_no_evidence_refuses_transactional_mail() {
		let sink = MemorySink::new();
		let message = AcceptedMessage {
			reverse_path: "a@example.org".into(),
			recipients: vec!["b@example.org".into()],
			data: b"hello\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: false,
			no_dsn: Vec::new(),
		};
		let refused = sink.submit(
			message.clone(),
			uuid::Uuid::now_v7(),
			"a",
			&Submission::of_class(crate::evidence::MailClass::Transactional),
		);
		assert!(matches!(refused, Err(SinkError::EvidenceUnavailable(_))));
		assert!(sink.messages().is_empty(), "the message was taken anyway");
		sink.submit(message, uuid::Uuid::now_v7(), "a", &Submission::default())
			.expect("personal mail is taken");
		assert_eq!(sink.messages().len(), 1);
	}
}
