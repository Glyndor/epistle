//! Destination for messages accepted by the SMTP server.

use super::session::AcceptedMessage;

/// Receives accepted messages. The real implementation will be the storage
/// layer; tests and early milestones use the in-memory sink.
pub trait MessageSink: Send + Sync {
	/// Persist an accepted message. Returning an error makes the server
	/// answer with a transient failure so the client retries later.
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError>;

	/// Take a message that `account`, one of this server's own accounts,
	/// submitted (SMTP after AUTH, `/api/v1/send`, JMAP
	/// `EmailSubmission/set`), where [`MessageSink::deliver`] takes mail
	/// that arrived from elsewhere. The outbound queue entry (if the message
	/// leaves the server) is stored under `queue_id`, so the submitter can
	/// hand that id back to its client. A sink that never queues has nothing
	/// to name and delivers as usual; a sink that queues, or that treats
	/// submissions differently, overrides this.
	///
	/// `extra` is the caller-supplied correlation map the API may attach to
	/// a submission (see `POST /api/v1/send`); the spool stores it on the
	/// envelope so the delivery log and webhooks can copy it onto every
	/// record they emit, but it is never written into the message itself.
	/// The SMTP submission path passes an empty map.
	fn submit(
		&self,
		message: AcceptedMessage,
		queue_id: uuid::Uuid,
		account: &str,
		extra: &std::collections::BTreeMap<String, String>,
	) -> Result<(), SinkError> {
		let _ = (queue_id, account, extra);
		self.deliver(message)
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
}

impl SinkError {
	/// The SMTP reply that refuses the message for this reason.
	pub fn smtp_reply(&self) -> crate::smtp::reply::Reply {
		use crate::smtp::reply::Reply;
		match self {
			SinkError::Unavailable(_) => {
				Reply::single(451, "4.3.0 temporary storage failure, try again")
			}
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
}
