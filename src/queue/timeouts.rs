//! How long the outbound SMTP client waits at each step of a conversation.
//!
//! The values are the minimums RFC 5321 section 4.5.3.2 asks a client to
//! wait, so a slow but working server is never cut off early, and a server
//! that accepts the connection and then says nothing holds a delivery slot
//! for a bounded time instead of forever. A timeout is a transient failure
//! of that conversation: its recipients are retried on their schedule, and
//! a connect that times out moves on to the next exchanger.

use std::future::Future;
use std::time::Duration;

use super::client::DeliveryError;

/// Opening the TCP connection to one exchanger (or smarthost, or proxy).
pub const CONNECT: Duration = Duration::from_secs(30);
/// The 220 greeting (RFC 5321 section 4.5.3.2.1).
pub const GREETING: Duration = Duration::from_secs(5 * 60);
/// The reply to EHLO, MAIL, AUTH and STARTTLS: the MAIL wait of section
/// 4.5.3.2.2, which the RFC sets no shorter for the others.
pub const COMMAND: Duration = Duration::from_secs(5 * 60);
/// The reply to each RCPT (section 4.5.3.2.3).
pub const RCPT: Duration = Duration::from_secs(5 * 60);
/// The 354 reply to DATA (section 4.5.3.2.4).
pub const DATA_INIT: Duration = Duration::from_secs(2 * 60);
/// Writing each block of the message (section 4.5.3.2.5).
pub const DATA_BLOCK: Duration = Duration::from_secs(3 * 60);
/// The reply to the final dot (section 4.5.3.2.6).
pub const DATA_END: Duration = Duration::from_secs(10 * 60);
/// One whole delivery attempt for the recipients of one domain, every
/// exchanger and every step together. Each step has its own limit, but a
/// remote that answers each one just in time (or a domain whose every
/// exchanger stalls until its limit) could otherwise hold a conversation
/// slot for hours.
pub const ATTEMPT: Duration = Duration::from_secs(60 * 60);
/// The STARTTLS handshake.
pub const TLS_HANDSHAKE: Duration = Duration::from_secs(60);
/// The reply to QUIT. The outcome of every recipient is known by then, so
/// there is nothing to wait for beyond a polite moment.
pub const QUIT: Duration = Duration::from_secs(30);
/// Size of one block written during DATA: each one gets [`DATA_BLOCK`].
pub const DATA_BLOCK_BYTES: usize = 64 * 1024;

/// One step of a conversation, with how long it may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
	/// Opening the connection.
	Connect,
	/// Waiting for the greeting.
	Greeting,
	/// EHLO, MAIL, AUTH, STARTTLS.
	Command,
	/// One RCPT.
	Rcpt,
	/// DATA, until the 354.
	DataInit,
	/// Writing one block of the message.
	DataBlock,
	/// The reply to the final dot.
	DataEnd,
	/// The STARTTLS handshake.
	TlsHandshake,
	/// QUIT.
	Quit,
}

impl Phase {
	/// How long this step may take.
	pub fn limit(self) -> Duration {
		match self {
			Phase::Connect => CONNECT,
			Phase::Greeting => GREETING,
			Phase::Command => COMMAND,
			Phase::Rcpt => RCPT,
			Phase::DataInit => DATA_INIT,
			Phase::DataBlock => DATA_BLOCK,
			Phase::DataEnd => DATA_END,
			Phase::TlsHandshake => TLS_HANDSHAKE,
			Phase::Quit => QUIT,
		}
	}

	/// What the client was waiting for, for the deferral reason.
	pub fn what(self) -> &'static str {
		match self {
			Phase::Connect => "the connection",
			Phase::Greeting => "the greeting",
			Phase::Command => "a command reply",
			Phase::Rcpt => "the RCPT reply",
			Phase::DataInit => "the DATA reply",
			Phase::DataBlock => "the message data to be read",
			Phase::DataEnd => "the reply to the message",
			Phase::TlsHandshake => "the TLS handshake",
			Phase::Quit => "the QUIT reply",
		}
	}

	/// The transient error of a step that ran out of time.
	pub fn timed_out(self) -> DeliveryError {
		DeliveryError::Transient(format!(
			"timed out after {}s waiting for {}",
			self.limit().as_secs(),
			self.what()
		))
	}
}

/// Run `step`, failing it transiently when it takes longer than `phase`
/// allows.
pub async fn within<T>(
	phase: Phase,
	step: impl Future<Output = Result<T, DeliveryError>>,
) -> Result<T, DeliveryError> {
	match tokio::time::timeout(phase.limit(), step).await {
		Ok(result) => result,
		Err(_) => Err(phase.timed_out()),
	}
}
