//! SMTP session value types: connection state, accepted messages, actions.

use super::Reply;

/// Where the session is in the SMTP dialogue.
#[derive(Debug, Clone, PartialEq, Eq)]
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
	/// DATA accepted; collecting message lines.
	ReceivingData {
		reverse_path: String,
		recipients: Vec<String>,
		/// Recipients that requested no failure DSN (`NOTIFY=NEVER`/no FAILURE).
		no_dsn: Vec<String>,
		size: usize,
		body: Vec<u8>,
		require_tls: bool,
	},
}

/// A message accepted by the session, ready for delivery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptedMessage {
	pub reverse_path: String,
	pub recipients: Vec<String>,
	pub data: Vec<u8>,
	/// The sender requested REQUIRETLS (RFC 8689): onward delivery must use
	/// verified TLS.
	pub require_tls: bool,
	/// Routing hint set by inbound screening: deliver local copies into this
	/// mailbox (e.g. `Rejects`) instead of INBOX. `None` leaves routing to
	/// the delivery rules.
	pub mailbox: Option<String>,
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
	/// Send the reply, hand the message to delivery, keep reading commands.
	Deliver(Reply, AcceptedMessage),
	/// Send the reply, then upgrade the connection to TLS (RFC 3207).
	UpgradeTls(Reply),
	/// Send the 334 challenge and read one authentication response line.
	CollectAuthResponse(Reply),
	/// Send the reply and close the connection.
	Close(Reply),
}
