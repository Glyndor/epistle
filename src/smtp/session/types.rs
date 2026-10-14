//! SMTP session value types: connection state, accepted messages, actions.

use super::Reply;
use crate::smtp::memory_budget::Reservation;

/// Where the session is in the SMTP dialogue.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum State {
	/// Connection open, no HELO/EHLO yet.
	Connected,
	/// Greeted; ready for a mail transaction.
	Greeted,
	/// MAIL FROM accepted; collecting recipients.
	ReceivingRecipients {
		reverse_path: String,
		require_tls: bool,
	},
	/// Recipients accepted; collecting message data via DATA or BDAT.
	ReceivingData {
		reverse_path: String,
		recipients: Vec<String>,
		/// Recipients that requested no failure DSN (`NOTIFY=NEVER`/no FAILURE).
		no_dsn: Vec<String>,
		size: usize,
		body: Vec<u8>,
		require_tls: bool,
		/// Whether a BDAT chunk has begun (RFC 3030): once true, DATA and RCPT
		/// are no longer valid in this transaction.
		chunking: bool,
		/// The octets of this in-flight body held against the shared memory
		/// budget. Dropping the state drops the reservation, so every way
		/// out of `ReceivingData` (a reply, `RSET`, `EHLO`, a disconnect, a
		/// panic) hands them back; an accepted body moves it to the session
		/// for the length of its delivery.
		reserved: Reservation,
		/// Set by `data_line` when a memory-budget reservation fails. The
		/// body stops growing but the in-flight session still has to read
		/// to the closing `.`; the final 4xx reply is produced at
		/// finalise so the reply is on the wire once per message.
		budget_exhausted: bool,
	},
}

/// A message accepted by the session, ready for delivery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptedMessage {
	/// Envelope sender (`MAIL FROM`). Empty string denotes a bounce
	/// (null reverse-path).
	pub reverse_path: String,
	/// Envelope recipients accepted during the transaction (`RCPT TO`).
	pub recipients: Vec<String>,
	/// Raw RFC 5322 message bytes collected via DATA or BDAT.
	pub data: Vec<u8>,
	/// The sender requested REQUIRETLS (RFC 8689): onward delivery must use
	/// verified TLS.
	pub require_tls: bool,
	/// Routing hint set by inbound screening: deliver local copies into this
	/// mailbox (e.g. `Rejects`) instead of INBOX. `None` leaves routing to
	/// the delivery rules.
	pub mailbox: Option<String>,
	/// Trusted SMTP verification: a reporting-domain DKIM signature without
	/// `l=` covers the complete TLS-RPT body. Never derived from mail headers.
	pub tlsrpt_verified: bool,
	/// Trusted SMTP verification of this message's envelope sender: the
	/// session logged in (and so owns it), or on this hop SPF passed for its
	/// domain or a DKIM signature passed for a domain aligned with it. Set
	/// by the server from its own checks of this message, never derived
	/// from mail headers, which the sender writes. Auto-replies are sent
	/// only when it is true.
	pub sender_verified: bool,
	/// Recipients that asked to suppress failure DSNs (`NOTIFY=NEVER`, or a
	/// `NOTIFY` without `FAILURE`, RFC 3461): no bounce is generated for them.
	pub no_dsn: Vec<String>,
}

/// What the network layer must do after a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
	/// Send the reply and keep reading commands.
	Continue(Reply),
	/// Send the reply and switch to reading data lines.
	CollectData(Reply),
	/// Read exactly `size` raw bytes (a BDAT chunk, RFC 3030) with no reply
	/// first, then feed them to `Session::bdat_chunk`.
	CollectChunk {
		/// Octet count of the BDAT chunk the network layer should read.
		size: usize,
		/// Whether this is the final chunk of the message.
		last: bool,
	},
	/// Read exactly `size` raw bytes (a BDAT chunk) and throw them away,
	/// then send the reply. A refused chunk is still message data and must
	/// never be parsed as commands (RFC 3030), nor held in memory.
	DiscardChunk {
		/// Octet count of the BDAT chunk to read and discard.
		size: usize,
		/// The reply sent once the chunk is consumed.
		reply: Reply,
	},
	/// Send the reply, hand the message to delivery, keep reading commands.
	Deliver(Reply, AcceptedMessage),
	/// Send the reply, then upgrade the connection to TLS (RFC 3207).
	UpgradeTls(Reply),
	/// Send the 334 challenge and read one authentication response line.
	CollectAuthResponse(Reply),
	/// Send the reply and close the connection.
	Close(Reply),
}
