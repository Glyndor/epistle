//! Per-connection SMTP session state machine.
//!
//! The session is sans-IO: it consumes parsed commands and data lines and
//! produces replies plus completed messages. The network layer owns sockets
//! and feeds this machine, which keeps the protocol logic fully unit-testable.

use std::sync::Arc;

pub use super::address::Address;
pub use super::directory::{Directory, Resolution};
pub use super::diskspace::DiskGuard;
pub use super::memory_budget::{MemoryBudget, Reservation};
pub use super::reply::Reply;

mod author;
mod bdat;
pub mod cap;
mod finalise;
mod junk;
mod login;
mod oauth;
mod scram;
mod time;
use time::unix_now;

mod builder;
mod data;
mod envelope;
mod limits;
#[cfg(test)]
mod test_hooks;
pub use limits::*;

mod auth_dispatch;
mod transaction_policy;
mod types;
pub use junk::DEFAULT_JUNK_COMMAND_LIMIT;
use transaction_policy::TransactionPolicy;
use types::State;
pub use types::{AcceptedMessage, Action};

/// SMTP session state machine.
#[derive(Debug)]
pub struct Session {
	hostname: String,
	/// Per-instance message-size cap, read by `mail_from` (SIZE parameter),
	/// `data_line` (running size) and the EHLO advertisement. Default is
	/// [`MAX_MESSAGE_SIZE`]; raised or lowered by
	/// [`Session::with_max_message_size`].
	max_message_size: usize,
	/// Recipients one transaction may name, advertised as `LIMITS RCPTMAX`
	/// and enforced at `RCPT TO`. Default is [`DEFAULT_MAX_RECIPIENTS`];
	/// changed by [`Session::with_max_recipients`].
	max_recipients: usize,
	state: State,
	/// Whether STARTTLS can be offered (configured, not yet active).
	tls_available: bool,
	/// Whether the connection is already inside TLS.
	tls_active: bool,
	authenticated: Option<String>,
	/// The label of the app password that authenticated this session,
	/// when the credential was a secondary one. `None` for primary
	/// passwords and EXTERNAL authentication. Stored so the submission
	/// path can look up the credential's `save_sent` override.
	auth_app_password_label: Option<String>,
	/// Failed authentication attempts on this connection.
	auth_failures: u8,
	/// Domain the client announced in HELO/EHLO, for trace headers.
	helo_domain: Option<String>,
	/// Whether the client greeted with EHLO (ESMTP) rather than HELO.
	esmtp: bool,
	/// Recipient resolution; an empty directory rejects everything (fail closed).
	directory: Arc<Directory>,
	/// In-flight SCRAM exchange, between the challenge rounds.
	pending_scram: Option<scram::PendingScram>,
	/// AUTH LOGIN exchange: idle / awaiting username / awaiting password.
	pending_login: Option<Option<String>>,
	/// Test-injected SCRAM server nonce; `None` generates a fresh random one.
	scram_nonce: Option<String>,
	oauth: Option<Arc<crate::oauth::OauthVerifier>>,
	/// `tls-server-end-point` channel-binding data (the server certificate
	/// hash) when the connection is TLS; enables SCRAM-SHA-256-PLUS.
	cbind_data: Option<Vec<u8>>,
	/// All MAIL-FROM-time policy state this session consults: per-account
	/// submission rate limit, per-client-IP and per-sender inbound rate
	/// limits, and the shared disk-space guard. Identity by default; every
	/// check short-circuits when nothing is wired in.
	policy: TransactionPolicy,
	/// Per-tenant aggregate submission limits (accounts, storage, rate).
	/// On top of `send_limiter`; an empty value is the identity and every
	/// check short-circuits.
	tenant_limits: Option<std::sync::Arc<crate::api::TenantLimits>>,
	/// Verified TLS client-certificate identity (email SAN), enabling SASL
	/// EXTERNAL. Set by the network layer after a client-cert handshake.
	client_identity: Option<String>,
	/// Awaiting the EXTERNAL response line after a `334` challenge.
	pending_external: bool,
	/// The client's peer IP, set by the network layer; used to enforce an app
	/// password's CIDR allowlist during authentication.
	peer_ip: Option<std::net::IpAddr>,
	/// Per-account rolling 24h new-recipient cap (plan 4.10). The
	/// fields it carries (correspondent store, daily limit, metrics
	/// handle) live in `cap::Cap`; the SMTP path reads them through
	/// `cap::check_or_reply` at end-of-DATA. Empty by default.
	cap: cap::Cap,
	/// The authentication protocol this session's listener serves;
	/// tagged on every password attempt through this session so a
	/// per-account `allowed_protocols` can admit or reject it.
	auth_protocol: crate::config::Protocol,
	/// Which identification and reputation headers the mail this session
	/// generates gets (the mailbox-full notice it builds at end-of-DATA).
	identification: crate::smtp::identification::Policy,
	/// Shared metrics handle. Optional: with no metrics wired the inbound
	/// rate-limit rejection still returns the 450 reply, the counter just
	/// does not move. Server sets this to its own `Arc<Metrics>` so the
	/// every-listener metric lands in the same registry.
	metrics: Option<std::sync::Arc<crate::metrics::Metrics>>,
	/// Whether SCRAM-SHA-256 / SCRAM-SHA-256-PLUS are enabled on this
	/// listener (the `[auth] scram` knob). `true` keeps the historical
	/// behaviour: both mechanisms advertised and accounted for in the
	/// capability lines. `false` hides them on the wire and refuses an
	/// explicit `AUTH` against them. Plaintext PLAIN / LOGIN are still
	/// advertised regardless, so a SCRAM-less listener still accepts the
	/// password.
	scram_enabled: bool,
	/// Shared byte budget every DATA / BDAT reservation draws from. When
	/// set, a reservation that would push the in-flight total past the
	/// cap is rejected with `452 4.3.1` (DATA: at end-of-DATA; BDAT: on
	/// the offending chunk) and the in-flight bytes are released on
	/// every path that drops the body. `None` (the default) leaves the
	/// historical unbounded behaviour in place.
	memory_budget: Option<Arc<MemoryBudget>>,
	/// The octets of the BDAT chunk being read, charged as they arrive. They
	/// join the body in `bdat_chunk`, or go back with the session if the
	/// client never sends the rest of the chunk.
	chunk_reservation: Reservation,
	/// The claim for the body last accepted, held while the connection
	/// loop delivers it: the body is still in memory until then.
	delivery_reservation: Reservation,
	/// Commands without progress and refusals sent so far, and how many
	/// are allowed; see the `junk` module.
	junk: junk::JunkCount,
}

impl Session {
	/// Create a session for a freshly accepted plaintext connection.
	pub fn new(hostname: &str) -> Self {
		Session {
			hostname: hostname.to_string(),
			max_message_size: MAX_MESSAGE_SIZE,
			max_recipients: DEFAULT_MAX_RECIPIENTS,
			state: State::Connected,
			tls_available: false,
			tls_active: false,
			authenticated: None,
			auth_app_password_label: None,
			auth_failures: 0,
			helo_domain: None,
			esmtp: false,
			directory: Arc::new(Directory::default()),
			pending_scram: None,
			pending_login: None,
			scram_nonce: None,
			oauth: None,
			cbind_data: None,
			policy: TransactionPolicy::default(),
			tenant_limits: None,
			client_identity: None,
			pending_external: false,
			peer_ip: None,
			cap: cap::Cap::empty(),
			auth_protocol: crate::config::Protocol::Submission,
			identification: crate::smtp::identification::Policy::default(),
			metrics: None,
			scram_enabled: true,
			memory_budget: None,
			chunk_reservation: Reservation::none(),
			delivery_reservation: Reservation::none(),
			junk: junk::JunkCount::default(),
		}
	}

	/// How many recipients one transaction may name.
	pub fn max_recipients(&self) -> usize {
		self.max_recipients
	}

	/// The per-instance message-size cap. Useful for tests and for
	/// reflecting the value back on EHLO.
	pub fn max_message_size(&self) -> usize {
		self.max_message_size
	}

	/// The submission-limit charge of the message last handed to the
	/// server (`Action::Deliver`). The server keeps it once the message is
	/// accepted and refunds it on any later refusal.
	pub fn take_submission_charge(&mut self) -> Option<crate::smtp::submission_budget::Charge> {
		self.policy.take_charge()
	}

	/// The DSNs for recipients the last accepted message did not fit for;
	/// the server sends them once that message is delivered.
	pub fn take_quota_reports(&mut self) -> Vec<AcceptedMessage> {
		self.policy.take_quota_reports()
	}

	/// The authenticated account, if AUTH succeeded.
	pub fn authenticated(&self) -> Option<&str> {
		self.authenticated.as_deref()
	}

	/// The label of the app password that authenticated this session,
	/// or `None` for a primary-password login (or EXTERNAL).
	pub fn auth_app_password_label(&self) -> Option<&str> {
		self.auth_app_password_label.as_deref()
	}

	/// Whether a mail transaction is open (`MAIL FROM` accepted, not yet
	/// ended by the message or `RSET`).
	pub fn in_transaction(&self) -> bool {
		matches!(
			self.state,
			State::ReceivingRecipients { .. } | State::ReceivingData { .. }
		)
	}

	/// The domain announced by the client in HELO/EHLO.
	pub fn helo_domain(&self) -> Option<&str> {
		self.helo_domain.as_deref()
	}

	/// Whether the client greeted with EHLO (ESMTP) rather than plain HELO.
	pub fn esmtp(&self) -> bool {
		self.esmtp
	}

	/// Whether the connection is inside TLS.
	pub fn tls_active(&self) -> bool {
		self.tls_active
	}

	/// Called once the TLS handshake completed. Per RFC 3207 the server forgets
	/// everything learned before the upgrade; the client must greet again.
	pub fn tls_started(&mut self) {
		self.state = State::Connected;
		self.tls_available = false;
		self.tls_active = true;
		self.helo_domain = None;
		self.esmtp = false;
	}
}

#[cfg(test)]
mod tests;
