//! Per-connection SMTP session state machine.
//!
//! The session is sans-IO: it consumes parsed commands and data lines and
//! produces replies plus completed messages. The network layer owns sockets
//! and feeds this machine, which keeps the protocol logic fully unit-testable.

use std::sync::Arc;

use super::address::Address;
use super::directory::{Directory, Resolution};
use super::diskspace::DiskGuard;
use super::reply::Reply;

mod bdat;
pub mod cap;
mod finalise;
mod login;
mod oauth;
mod scram;
mod time;
use time::unix_now;

/// Maximum accepted message size in bytes until quotas exist.
pub const MAX_MESSAGE_SIZE: usize = 25 * 1024 * 1024;

/// Maximum number of accepted recipients per transaction (RFC 5321 minimum).
pub const MAX_RECIPIENTS: usize = 100;

mod auth_dispatch;
mod transaction_policy;
#[path = "types.rs"]
mod types;
use transaction_policy::TransactionPolicy;
use types::State;
pub use types::{AcceptedMessage, Action};

/// SMTP session state machine.
#[derive(Debug)]
pub struct Session {
	hostname: String,
	state: State,
	/// Whether STARTTLS can be offered (configured, not yet active).
	tls_available: bool,
	/// Whether the connection is already inside TLS.
	tls_active: bool,
	authenticated: Option<String>,
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
	/// Shared metrics handle. Optional: with no metrics wired the inbound
	/// rate-limit rejection still returns the 450 reply, the counter just
	/// does not move. Server sets this to its own `Arc<Metrics>` so the
	/// every-listener metric lands in the same registry.
	metrics: Option<std::sync::Arc<crate::metrics::Metrics>>,
}

impl Session {
	/// Create a session for a freshly accepted plaintext connection.
	pub fn new(hostname: &str) -> Self {
		Session {
			hostname: hostname.to_string(),
			state: State::Connected,
			tls_available: false,
			tls_active: false,
			authenticated: None,
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
			metrics: None,
		}
	}

	/// Tag every password authentication attempt through this session with
	/// `protocol` so the directory's per-account `allowed_protocols` set
	/// can admit or reject it. `Protocol::Submission` is the default and
	/// matches the historical behaviour for SMTP AUTH.
	pub fn with_auth_protocol(mut self, protocol: crate::config::Protocol) -> Self {
		self.auth_protocol = protocol;
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

	/// Mark this session as authenticated as `account` without going through
	/// the SASL flow. Test-only: production code sets the field through the
	/// AUTH command machinery.
	#[cfg(test)]
	pub fn mark_authenticated_for_test(&mut self, account: &str) {
		self.authenticated = Some(account.to_string());
	}

	/// Mark this session as running inside TLS from the start
	/// (implicit-TLS listeners).
	pub fn with_tls_active(mut self) -> Self {
		self.tls_active = true;
		self
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
		let mut lines = vec![
			self.hostname.clone(),
			"PIPELINING".to_string(),
			"ENHANCEDSTATUSCODES".to_string(),
			"8BITMIME".to_string(),
			"SMTPUTF8".to_string(), // RFC 6531: internationalized addresses.
			"CHUNKING".to_string(), // RFC 3030: BDAT length-prefixed message data.
			// RFC 3461: we parse RET/ENVID and NOTIFY/ORCPT parameters.
			"DSN".to_string(),
			format!("SIZE {MAX_MESSAGE_SIZE}"),
			// RFC 9422: advertise the per-message recipient ceiling we enforce.
			format!("LIMITS RCPTMAX={MAX_RECIPIENTS}"),
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
				// Per-account submission rate limit for authenticated senders.
				// Resolution: per-domain override for the account's own
				// domain (looked up by walking the account's addresses, the
				// same way `Directory::quota_for` does), falling back to the
				// server-wide default, falling back to no limit at all.
				if let Some(account) = self.authenticated.clone()
					&& !self.policy.check_authenticated_submission(
						&account,
						&self.directory,
						unix_now(),
					) {
					return Action::Continue(Reply::single(
						450,
						"4.7.1 sending rate limit exceeded; retry later",
					));
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
				if size.is_some_and(|s| s > MAX_MESSAGE_SIZE as u64) {
					return Action::Continue(Reply::single(
						552,
						"5.3.4 message exceeds maximum size",
					));
				}
				// Filesystem holding `data_dir` is too full to accept another
				// message. Reject before `DATA` so the remote retries instead
				// of receiving `250 OK` for a payload the spool cannot hold.
				if !self.policy.spool_has_room(MAX_MESSAGE_SIZE as u64) {
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
				if recipients.len() >= MAX_RECIPIENTS {
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
		let State::ReceivingData { size, body, .. } = &mut self.state else {
			self.reset();
			return Some(Action::Continue(Reply::bad_sequence()));
		};
		let content = line.strip_prefix(b".").unwrap_or(line);
		*size += content.len() + 2;
		if *size <= MAX_MESSAGE_SIZE {
			body.extend_from_slice(content);
			body.extend_from_slice(b"\r\n");
		}
		None
	}

	/// Drop any in-progress transaction, keeping the greeting.
	fn reset(&mut self) {
		if self.state != State::Connected {
			self.state = State::Greeted;
		}
	}
}

#[cfg(test)]
#[path = "../session_tests_basic.rs"]
mod tests_basic;

#[cfg(test)]
#[path = "../session_tests_auth.rs"]
mod tests_auth;

#[cfg(test)]
#[path = "../session_tests_diskspace.rs"]
mod tests_diskspace;
#[cfg(test)]
#[path = "../session_tests_newrecipients.rs"]
mod tests_newrecipients;
#[cfg(test)]
#[path = "../session_tests_oauth.rs"]
mod tests_oauth;
#[cfg(test)]
#[path = "../session_tests_ratelimit.rs"]
mod tests_ratelimit;
#[cfg(test)]
#[path = "../session_tests_scram.rs"]
mod tests_scram;
