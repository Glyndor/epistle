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

/// Maximum accepted message size in bytes. The historical default and
/// the upper bound for the configurable `[server] max_message_size`;
/// raise it on operators who know what they are doing, lower it on
/// operators who want to be conservative.
pub const MAX_MESSAGE_SIZE: usize = 25 * 1024 * 1024;

/// Recipients per transaction a server accepts unless `max_recipients` says
/// otherwise. RFC 5321 §4.5.3.1.8 makes 100 the least a server may offer.
pub const DEFAULT_MAX_RECIPIENTS: usize = 100;

/// The least `max_message_size` may allow: RFC 5321 §4.5.3.1.7 says a server
/// MUST accept message content of at least 64K octets.
pub const MIN_MESSAGE_SIZE: usize = 64 * 1024;

/// Why [`MIN_MESSAGE_SIZE`] cannot be crossed, as `max_message_size` and
/// `epistle limits set max-message-size` word the refusal.
pub const MIN_MESSAGE_SIZE_REASON: &str =
	"RFC 5321 §4.5.3.1.7 requires accepting messages of at least 64K octets";

/// The fewest recipients per transaction `max_recipients` may allow: RFC 5321
/// §4.5.3.1.8 says a server MUST accept at least 100.
pub const MIN_MAX_RECIPIENTS: usize = 100;

/// Why [`MIN_MAX_RECIPIENTS`] cannot be crossed, as `max_recipients` and
/// `epistle limits set max-recipients` word the refusal.
pub const MIN_MAX_RECIPIENTS_REASON: &str =
	"RFC 5321 §4.5.3.1.8 requires accepting at least 100 recipients";

/// The most recipients per transaction `max_recipients` may allow. Every
/// recipient costs a directory lookup, a spool entry and a delivery, so the
/// cap keeps one message from asking for unbounded work.
pub const MAX_MAX_RECIPIENTS: usize = 10_000;

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

	/// Set the per-instance message-size cap. The same value is used by
	/// the `SIZE` extension in EHLO, the running total checked in
	/// `data_line`, the final size check on end-of-DATA, the per-chunk
	/// cap on BDAT, and the `MAIL FROM` SIZE parameter check. The
	/// default is [`MAX_MESSAGE_SIZE`] when this builder is not used.
	pub fn with_max_message_size(mut self, bytes: usize) -> Self {
		self.max_message_size = bytes;
		self
	}

	/// Set how many recipients one transaction may name. `0` keeps
	/// [`DEFAULT_MAX_RECIPIENTS`]; any other value is taken as given, the
	/// configuration having kept it within [`MIN_MAX_RECIPIENTS`] and
	/// [`MAX_MAX_RECIPIENTS`].
	pub fn with_max_recipients(mut self, count: usize) -> Self {
		if count > 0 {
			self.max_recipients = count;
		}
		self
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

	/// Attach the shared byte budget. `None` (the default) keeps the
	/// historical unbounded behaviour. With a budget set, every DATA
	/// line and every BDAT chunk tries to reserve its bytes; the
	/// reservation is released on every path that drops the in-flight
	/// body (success, error, RSET, disconnect, panic).
	pub fn with_memory_budget(mut self, budget: Arc<MemoryBudget>) -> Self {
		self.memory_budget = Some(budget);
		self
	}

	/// Whether this session has a memory budget wired in. Useful for
	/// tests and for assertions.
	pub fn has_memory_budget(&self) -> bool {
		self.memory_budget.is_some()
	}

	/// Tag every password authentication attempt through this session with
	/// `protocol` so the directory's per-account `allowed_protocols` set
	/// can admit or reject it. `Protocol::Submission` is the default and
	/// matches the historical behaviour for SMTP AUTH.
	pub fn with_auth_protocol(mut self, protocol: crate::config::Protocol) -> Self {
		self.auth_protocol = protocol;
		self
	}

	/// Set which identification and reputation headers the mail this
	/// session generates gets.
	pub fn with_identification(mut self, policy: crate::smtp::identification::Policy) -> Self {
		self.identification = policy;
		self
	}

	/// Set the verified TLS client-certificate identity (email), enabling SASL
	/// EXTERNAL for this connection. Called by the network layer once a client
	/// presented a certificate that rustls verified against the trust anchor.
	pub fn set_client_identity(&mut self, identity: Option<String>) {
		self.client_identity = identity;
	}

	/// Set the client's peer IP, used to enforce app-password CIDR allowlists.
	pub fn set_peer_ip(&mut self, ip: Option<std::net::IpAddr>) {
		self.peer_ip = ip;
	}

	/// Attach the shared metrics handle so session-side rejections (the
	/// inbound per-IP / per-sender rate limits) increment the matching
	/// counter. `None` is a fine default for tests that don't care.
	pub fn with_metrics(mut self, metrics: std::sync::Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	/// Attach a shared per-account submission rate limiter.
	pub fn with_send_limiter(
		mut self,
		limiter: std::sync::Arc<super::ratelimit::SendLimiter>,
	) -> Self {
		self.policy = self.policy.with_send_limiter(limiter);
		self
	}

	/// Toggle the `[auth] scram` knob for this listener. `true` keeps the
	/// default behaviour (both SCRAM-SHA-256 and `-PLUS` advertised when
	/// channel binding is available); `false` hides both on the wire and
	/// refuses an explicit `AUTH` against them.
	pub fn with_scram_enabled(mut self, enabled: bool) -> Self {
		self.scram_enabled = enabled;
		self
	}

	/// Set the server-wide default submission rate limit (messages/min).
	/// The per-domain limit on the active directory (set via
	/// [`crate::smtp::directory::Directory::with_domain_submission_limits`])
	/// takes precedence at check time; this is the fallback when the
	/// account's domain has no entry. `None` together with no per-domain
	/// entry means no limit at all.
	pub fn with_global_submission_rate_limit(mut self, limit: Option<u32>) -> Self {
		self.policy = self.policy.with_global_submission_rate_limit(limit);
		self
	}

	/// Attach a shared per-client-IP inbound rate limiter and its
	/// per-minute cap. Consumed at `MAIL FROM` when the session never
	/// authenticated and a peer IP is known; absent or unknown peer means
	/// the check is skipped.
	pub fn with_inbound_ip_limit(
		mut self,
		limiter: std::sync::Arc<super::ratelimit::SendLimiter>,
		per_min: u32,
	) -> Self {
		self.policy = self.policy.with_inbound_ip_limit(limiter, per_min);
		self
	}

	/// Attach a shared per-envelope-sender inbound rate limiter and its
	/// per-minute cap. Consumed at `MAIL FROM` when the session never
	/// authenticated and the reverse path is non-empty; the null sender
	/// (`<>`) used by bounces is always skipped.
	pub fn with_inbound_sender_limit(
		mut self,
		limiter: std::sync::Arc<super::ratelimit::SendLimiter>,
		per_min: u32,
	) -> Self {
		self.policy = self.policy.with_inbound_sender_limit(limiter, per_min);
		self
	}

	/// Attach per-tenant aggregate limits. On top of the per-account
	/// limiter in [`Self::with_send_limiter`]; the SMTP path checks both
	/// before accepting MAIL FROM. `None` (the default) is the identity and
	/// short-circuits every check.
	pub fn with_tenant_limits(mut self, limits: std::sync::Arc<crate::api::TenantLimits>) -> Self {
		self.policy = self.policy.with_tenant_limits(limits.clone());
		self.tenant_limits = Some(limits);
		self
	}

	/// Provide the `tls-server-end-point` channel-binding data (the server
	/// certificate hash), enabling SCRAM-SHA-256-PLUS. Set by the network layer
	/// once the connection is TLS.
	pub fn with_channel_binding(mut self, cert_hash: Vec<u8>) -> Self {
		self.cbind_data = Some(cert_hash);
		self
	}

	/// Attach a shared disk-space guard for `data_dir`. When set, `MAIL FROM`
	/// is rejected with `452` if the filesystem cannot hold another message,
	/// so the remote retries instead of accepting a message that will
	/// fail to land in the spool.
	pub fn with_disk_guard(mut self, guard: Arc<DiskGuard>) -> Self {
		self.policy = self.policy.with_disk_guard(guard);
		self
	}

	/// Check local recipients against their mailbox quota (see
	/// [`crate::smtp::quota`]).
	pub fn with_quota(mut self, quota: Arc<crate::smtp::quota::MailboxQuota>) -> Self {
		self.policy = self.policy.with_quota(quota);
		self
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

	/// Replace the cap state (correspondent store, daily limit, metrics
	/// handle). Wired by the listener at session-construction time so
	/// the end-of-DATA check has the configured pair in scope.
	pub fn with_cap(mut self, cap: cap::Cap) -> Self {
		self.cap = cap;
		self
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

	/// Test-only setter: attach a directory to the session. The
	/// production code wires the directory through `with_directory`
	/// at session-construction time.
	#[cfg(test)]
	pub fn set_directory_for_test(&mut self, directory: Arc<crate::smtp::directory::Directory>) {
		self.directory = directory;
	}

	/// Mark this session as authenticated as `account` without going through
	/// the SASL flow. Test-only: production code sets the field through the
	/// AUTH command machinery.
	#[cfg(test)]
	pub fn mark_authenticated_for_test(&mut self, account: &str) {
		self.authenticated = Some(account.to_string());
		self.auth_app_password_label = None;
	}

	/// Mark this session as authenticated as `account` via the app
	/// password labelled `label`. Test-only.
	#[cfg(test)]
	pub fn mark_authenticated_with_app_password_for_test(&mut self, account: &str, label: &str) {
		self.authenticated = Some(account.to_string());
		self.auth_app_password_label = Some(label.to_string());
	}

	/// Mark this session as running inside TLS from the start
	/// (implicit-TLS listeners).
	pub fn with_tls_active(mut self) -> Self {
		self.tls_active = true;
		self
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

	/// Set the directory used to resolve recipients.
	pub fn with_directory(mut self, directory: Arc<Directory>) -> Self {
		self.directory = directory;
		self
	}

	/// Offer STARTTLS on this session.
	pub fn with_tls_available(mut self) -> Self {
		self.tls_available = true;
		self
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

	/// The greeting sent when the connection opens.
	pub fn greeting(&self) -> Reply {
		Reply::single(220, &format!("{} ESMTP ready", self.hostname))
	}

	fn greet(&mut self, domain: String, esmtp: bool) -> Action {
		self.state = State::Greeted;
		self.helo_domain = Some(domain);
		self.esmtp = esmtp;
		// Plain HELO (RFC 5321 §4.1.1.1) gets a single-line greeting with no
		// ESMTP extensions; only EHLO advertises capabilities.
		if !esmtp {
			return Action::Continue(Reply::single(250, &self.hostname));
		}
		let size = self.max_message_size;
		let mut lines = vec![
			self.hostname.clone(),
			"PIPELINING".to_string(),
			"ENHANCEDSTATUSCODES".to_string(),
			"8BITMIME".to_string(),
			"SMTPUTF8".to_string(), // RFC 6531: internationalized addresses.
			"CHUNKING".to_string(), // RFC 3030: BDAT length-prefixed message data.
			// RFC 3461: we parse RET/ENVID and NOTIFY/ORCPT parameters.
			"DSN".to_string(),
			format!("SIZE {size}"),
			// RFC 9422: advertise the per-message recipient ceiling we enforce.
			format!("LIMITS RCPTMAX={cap}", cap = self.max_recipients),
		];
		if self.tls_available {
			lines.push("STARTTLS".to_string());
		}
		if self.tls_active && self.authenticated.is_none() {
			lines.push(self.auth_capability());
		}
		// RFC 8689 §3: only advertise REQUIRETLS on a TLS-protected session.
		if self.tls_active {
			lines.push("REQUIRETLS".to_string());
		}
		Action::Continue(Reply::new(250, lines))
	}

	fn start_tls(&mut self) -> Action {
		if !self.tls_available {
			return Action::Continue(Reply::single(454, "4.7.0 TLS not available"));
		}
		match self.state {
			// RFC 3207: STARTTLS requires EHLO first and no open transaction.
			State::Greeted => Action::UpgradeTls(Reply::single(220, "ready to start TLS")),
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	fn mail_from(&mut self, reverse_path: String, size: Option<u64>, require_tls: bool) -> Action {
		match self.state {
			State::Greeted => {
				// RFC 8689 §4.2: REQUIRETLS is only valid once the current
				// hop is already TLS-protected; otherwise the requirement is
				// already violated. Fail closed.
				if require_tls && !self.tls_active {
					return Action::Continue(Reply::single(
						530,
						"5.7.4 REQUIRETLS requires the session to use TLS",
					));
				}
				match (&self.authenticated, Address::parse(&reverse_path)) {
					// Authenticated senders must use one of their own
					// addresses — no spoofing, no null path.
					(Some(account), Ok(address))
						if !self.directory.owns_address(account, &address) =>
					{
						return Action::Continue(Reply::single(
							553,
							"5.7.1 sender address not owned by authenticated user",
						));
					}
					(Some(_), Err(_)) => {
						return Action::Continue(Reply::single(553, "5.1.7 invalid reverse-path"));
					}
					// The null reverse-path (bounces) is legal when
					// unauthenticated; anything else must parse.
					(None, Err(_)) if !reverse_path.is_empty() => {
						return Action::Continue(Reply::single(553, "5.1.7 invalid reverse-path"));
					}
					_ => {}
				}
				// Submission rate limits for authenticated senders: the
				// per-account limit (its domain's override, else the
				// server-wide default) and the tenant aggregate. Nothing is
				// charged here: a sender with no room left is refused before
				// it sends the message, and the message is charged one unit
				// per recipient once it is accepted (`finalise`), so a
				// transaction that ends in RSET or a refusal costs nothing.
				if let Some(account) = self.authenticated.as_deref()
					&& !self
						.policy
						.submission_budget(account, &self.directory)
						.has_room(unix_now())
				{
					return Action::Continue(finalise::rate_limited());
				}
				// Per-IP and per-sender rate limits for unauthenticated sessions.
				// Authenticated sessions are charged against the per-account limiter
				// instead; mixing both for the same envelope would double-charge the
				// authenticated sender's budget.
				if self.authenticated.is_none()
					&& let Some(reply) =
						self.policy
							.check_inbound(&reverse_path, self.peer_ip, unix_now())
				{
					if let Some(metrics) = &self.metrics {
						metrics.rejected(crate::metrics::RejectReason::RateLimit);
					}
					return Action::Continue(reply);
				}
				// SIZE is declared up front: reject oversize without DATA.
				if size.is_some_and(|s| s > self.max_message_size as u64) {
					return Action::Continue(Reply::single(
						552,
						"5.3.4 message exceeds maximum size",
					));
				}
				// Filesystem holding `data_dir` is too full to accept another
				// message. Reject before `DATA` so the remote retries instead
				// of receiving `250 OK` for a payload the spool cannot hold.
				if !self.policy.spool_has_room(self.max_message_size as u64) {
					return Action::Continue(Reply::single(
						452,
						"4.3.1 insufficient system storage; retry later",
					));
				}
				self.state = State::ReceivingRecipients {
					reverse_path,
					require_tls,
				};
				Action::Continue(Reply::ok())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	fn rcpt_to(&mut self, forward_path: String, notify: Option<super::command::Notify>) -> Action {
		// The order is checked before the address is even looked at (RFC
		// 5321 §4.1.4), so a RCPT out of sequence learns nothing about
		// whether a mailbox exists or is full.
		let open = match &self.state {
			State::ReceivingRecipients { .. } => true,
			State::ReceivingData { body, chunking, .. } => body.is_empty() && !*chunking,
			_ => false,
		};
		if !open {
			return Action::Continue(Reply::bad_sequence());
		}
		let Ok(address) = Address::parse(&forward_path) else {
			return Action::Continue(Reply::single(553, "5.1.3 invalid recipient address"));
		};
		match self.directory.resolve(&address) {
			// Foreign domains are relayed only for authenticated users.
			Resolution::NotLocal => {
				if self.authenticated.is_none() {
					return Action::Continue(Reply::single(550, "5.7.1 relaying denied"));
				}
			}
			Resolution::UnknownUser => {
				return Action::Continue(Reply::single(550, "5.1.1 no such user"));
			}
			// A full mailbox refuses this recipient only, temporarily: the
			// owner may make room (RFC 3463 X.2.2).
			Resolution::Account(account)
				if self
					.policy
					.quota()
					.is_some_and(|quota| quota.is_full(&self.directory, &account)) =>
			{
				return Action::Continue(Reply::single(452, "4.2.2 mailbox full"));
			}
			// A local account or a multi-target alias is an acceptable recipient.
			Resolution::Account(_) | Resolution::Alias(_) => {}
		}
		let forward_path = address.to_string();
		// Suppress failure DSNs for NOTIFY=NEVER or a NOTIFY without FAILURE (RFC 3461).
		use super::command::Notify;
		let suppresses_dsn = matches!(
			notify,
			Some(Notify::Never | Notify::On { failure: false, .. })
		);
		match &mut self.state {
			State::ReceivingRecipients {
				reverse_path,
				require_tls,
			} => {
				let reverse_path = reverse_path.clone();
				let require_tls = *require_tls;
				let no_dsn = if suppresses_dsn {
					vec![forward_path.clone()]
				} else {
					Vec::new()
				};
				self.state = State::ReceivingData {
					reverse_path,
					recipients: vec![forward_path],
					no_dsn,
					size: 0,
					body: Vec::new(),
					require_tls,
					chunking: false,
					line_check: crate::smtp::line::LineCheck::stored(),
					reserved: Reservation::none(),
					budget_exhausted: false,
				};
				Action::Continue(Reply::ok())
			}
			// More recipients are accepted only before message data starts; once
			// a BDAT chunk has begun (RFC 3030) RCPT is no longer valid.
			State::ReceivingData {
				recipients,
				no_dsn,
				body,
				chunking,
				..
			} if body.is_empty() && !*chunking => {
				if recipients.len() >= self.max_recipients {
					return Action::Continue(Reply::single(452, "4.5.3 too many recipients"));
				}
				if suppresses_dsn {
					no_dsn.push(forward_path.clone());
				}
				recipients.push(forward_path);
				Action::Continue(Reply::ok())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	fn data(&mut self) -> Action {
		match &self.state {
			// DATA and BDAT are mutually exclusive (RFC 3030): refuse DATA once a
			// BDAT chunk has begun, or after any data has been collected.
			State::ReceivingData { body, chunking, .. } if body.is_empty() && !*chunking => {
				Action::CollectData(Reply::start_mail_input())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	/// Feed one data line (CRLF already stripped and enforced upstream).
	/// Returns `None` while more lines are expected.
	pub fn data_line(&mut self, line: &[u8]) -> Option<Action> {
		if line == b"." {
			return Some(finalise::finalise_from_state(self));
		}
		// Dot-unstuffing (RFC 5321 section 4.5.2).
		let State::ReceivingData {
			size,
			body,
			reserved,
			budget_exhausted,
			..
		} = &mut self.state
		else {
			self.reset();
			return Some(Action::Continue(Reply::bad_sequence()));
		};
		let content = line.strip_prefix(b".").unwrap_or(line);
		let delta = content.len() + 2;
		*size += delta;
		if *size > self.max_message_size {
			// Keep the size counter for the final 552 reply, but don't
			// extend the body past the cap.
			return None;
		}
		// Memory-budget reservation: claim the line's bytes, or stop
		// growing the body and flag the message as over-budget. The claim
		// lives in the state and goes back when the state is dropped; the
		// body and the counter stay consistent because we never extend
		// past a failed reservation.
		if let Some(budget) = &self.memory_budget
			&& reserved
				.try_grow(budget, self.peer_ip, delta as u64)
				.is_err()
		{
			*budget_exhausted = true;
			return None;
		}
		body.extend_from_slice(content);
		body.extend_from_slice(b"\r\n");
		None
	}

	/// Drop any in-progress transaction, keeping the greeting. The body
	/// and any announced chunk are dropped with it, and so is their claim
	/// on the memory budget.
	fn reset(&mut self) {
		self.chunk_reservation = Reservation::none();
		if self.state != State::Connected {
			self.state = State::Greeted;
		}
	}

	/// The budget claim of the body accepted last, for the connection loop
	/// to hold until that body's delivery is over.
	pub fn take_delivery_reservation(&mut self) -> Reservation {
		std::mem::take(&mut self.delivery_reservation)
	}
}

#[cfg(test)]
#[path = "tests_mods.rs"]
mod tests_mods;
