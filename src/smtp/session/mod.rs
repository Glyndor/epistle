//! Per-connection SMTP session state machine.
//!
//! The session is sans-IO: it consumes parsed commands and data lines and
//! produces replies plus completed messages. The network layer owns sockets
//! and feeds this machine, which keeps the protocol logic fully unit-testable.

use std::sync::Arc;

use super::address::Address;
use super::command::{Command, ParseError};
use super::directory::{Directory, Resolution};
use super::reply::Reply;

mod bdat;
mod login;
mod oauth;
mod scram;

/// Maximum accepted message size in bytes until quotas exist.
pub const MAX_MESSAGE_SIZE: usize = 25 * 1024 * 1024;

/// Maximum number of accepted recipients per transaction (RFC 5321 minimum).
pub const MAX_RECIPIENTS: usize = 100;

#[path = "types.rs"]
mod types;
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
	/// Shared per-account submission rate limiter (authenticated senders).
	send_limiter: Option<std::sync::Arc<super::ratelimit::SendLimiter>>,
	/// Verified TLS client-certificate identity (email SAN), enabling SASL
	/// EXTERNAL. Set by the network layer after a client-cert handshake.
	client_identity: Option<String>,
	/// Awaiting the EXTERNAL response line after a `334` challenge.
	pending_external: bool,
	/// The client's peer IP, set by the network layer; used to enforce an app
	/// password's CIDR allowlist during authentication.
	peer_ip: Option<std::net::IpAddr>,
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
			send_limiter: None,
			client_identity: None,
			pending_external: false,
			peer_ip: None,
		}
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

	/// Attach a shared per-account submission rate limiter.
	pub fn with_send_limiter(
		mut self,
		limiter: std::sync::Arc<super::ratelimit::SendLimiter>,
	) -> Self {
		self.send_limiter = Some(limiter);
		self
	}

	/// Provide the `tls-server-end-point` channel-binding data (the server
	/// certificate hash), enabling SCRAM-SHA-256-PLUS. Set by the network layer
	/// once the connection is TLS.
	pub fn with_channel_binding(mut self, cert_hash: Vec<u8>) -> Self {
		self.cbind_data = Some(cert_hash);
		self
	}

	/// The authenticated account, if AUTH succeeded.
	pub fn authenticated(&self) -> Option<&str> {
		self.authenticated.as_deref()
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

	/// Feed one command line (CRLF already stripped and enforced upstream).
	pub fn command_line(&mut self, line: &str) -> Action {
		match super::command::parse(line) {
			Ok(command) => self.apply(command),
			Err(ParseError::UnknownCommand) => Action::Continue(Reply::syntax_error()),
			Err(ParseError::LineTooLong) => {
				Action::Continue(Reply::single(500, "5.5.2 line too long"))
			}
			Err(ParseError::InvalidCharacters) => Action::Continue(Reply::syntax_error()),
			Err(ParseError::InvalidArguments) => Action::Continue(Reply::invalid_arguments()),
			Err(ParseError::UnsupportedParameter) => {
				Action::Continue(Reply::single(555, "5.5.4 parameter not implemented"))
			}
		}
	}

	fn apply(&mut self, command: Command) -> Action {
		match command {
			Command::Helo { domain } => self.greet(domain, false),
			Command::Ehlo { domain } => self.greet(domain, true),
			Command::MailFrom {
				reverse_path,
				size,
				require_tls,
				..
			} => self.mail_from(reverse_path, size, require_tls),
			Command::RcptTo {
				forward_path,
				notify,
				..
			} => self.rcpt_to(forward_path, notify),
			Command::Data => self.data(),
			Command::Bdat { size, last } => self.bdat(size, last),
			Command::Rset => {
				self.reset();
				Action::Continue(Reply::ok())
			}
			Command::Noop => Action::Continue(Reply::ok()),
			Command::Quit => Action::Close(Reply::closing()),
			Command::Vrfy => Action::Continue(Reply::vrfy_not_disclosed()),
			Command::StartTls => self.start_tls(),
			Command::Auth { mechanism, initial } => self.auth(&mechanism, initial),
		}
	}

	fn auth(&mut self, mechanism: &str, initial: Option<String>) -> Action {
		if !self.tls_active {
			// Credentials never cross plaintext.
			return Action::Continue(Reply::single(538, "5.7.11 encryption required for auth"));
		}
		if self.authenticated.is_some() {
			return Action::Continue(Reply::bad_sequence());
		}
		if self.state != State::Greeted {
			return Action::Continue(Reply::bad_sequence());
		}
		// Only negotiate a mechanism that is currently advertised (channel
		// binding present for -PLUS, a verifier present for the OAuth ones).
		let unsupported = || Action::Continue(Reply::single(504, "5.5.4 mechanism not supported"));
		let Some(parsed) = crate::sasl::Mechanism::parse(mechanism) else {
			return unsupported();
		};
		if !crate::sasl::is_available(
			parsed,
			self.client_identity.is_some(),
			self.cbind_data.is_some(),
			self.oauth.is_some(),
		) {
			return unsupported();
		}
		use crate::sasl::Mechanism;
		match parsed {
			Mechanism::External => match initial {
				Some(response) => self.verify_external(&response),
				None => {
					self.pending_external = true;
					Action::CollectAuthResponse(Reply::single(334, ""))
				}
			},
			Mechanism::Plain => match initial {
				Some(response) => self.verify_plain(&response),
				None => Action::CollectAuthResponse(Reply::single(334, "")),
			},
			Mechanism::ScramSha256 => self.scram_begin(initial, false),
			Mechanism::ScramSha256Plus => self.scram_begin(initial, true),
			Mechanism::OauthBearer | Mechanism::Xoauth2 => self.oauth_bearer(mechanism, initial),
			Mechanism::Login => match initial {
				// Initial response is the username; prompt for the password.
				Some(user) => self.login_username(&user),
				None => {
					self.pending_login = Some(None);
					Action::CollectAuthResponse(Reply::single(334, "VXNlcm5hbWU6"))
				}
			},
		}
	}

	/// Common AUTH failure: count it, no oracle, close after three.
	fn auth_fail(&mut self) -> Action {
		self.auth_failures += 1;
		let reply = Reply::single(535, "5.7.8 authentication credentials invalid");
		if self.auth_failures >= 3 {
			Action::Close(reply)
		} else {
			Action::Continue(reply)
		}
	}

	/// Feed the response line of a challenged AUTH (server sent 334).
	pub fn auth_line(&mut self, line: &str) -> Action {
		if line == "*" {
			self.pending_scram = None;
			self.pending_login = None;
			self.pending_external = false;
			return Action::Continue(Reply::single(501, "5.7.0 authentication cancelled"));
		}
		// EXTERNAL: the challenged response is the (optional) authzid.
		if std::mem::take(&mut self.pending_external) {
			return self.verify_external(line);
		}
		// AUTH LOGIN's two-step username/password exchange.
		if let Some(state) = self.pending_login.take() {
			return match state {
				None => self.login_username(line),
				Some(user) => self.login_password(&user, line),
			};
		}
		match self.pending_scram.take() {
			Some(scram::PendingScram::ClientFirst(binding)) => {
				self.scram_client_first(line, binding)
			}
			Some(scram::PendingScram::ClientFinal {
				server,
				credentials,
				account,
			}) => self.scram_client_final(line, *server, *credentials, &account),
			None => self.verify_plain(line),
		}
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
				if let Some(account) = self.authenticated.clone()
					&& let Some(limiter) = &self.send_limiter
					&& !limiter.check(&account, unix_now())
				{
					return Action::Continue(Reply::single(
						450,
						"4.7.1 sending rate limit exceeded; retry later",
					));
				}
				// SIZE is declared up front: reject oversize without DATA.
				if size.is_some_and(|s| s > MAX_MESSAGE_SIZE as u64) {
					return Action::Continue(Reply::single(
						552,
						"5.3.4 message exceeds maximum size",
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
		let State::ReceivingData {
			reverse_path,
			recipients,
			no_dsn,
			size,
			body,
			require_tls,
			..
		} = &mut self.state
		else {
			// Programming error in the network layer; fail the transaction.
			self.reset();
			return Some(Action::Continue(Reply::bad_sequence()));
		};

		if line == b"." {
			let message = AcceptedMessage {
				reverse_path: reverse_path.clone(),
				recipients: recipients.clone(),
				no_dsn: no_dsn.clone(),
				data: body.clone(),
				require_tls: *require_tls,
				mailbox: None,
			};
			let oversize = *size > MAX_MESSAGE_SIZE;
			self.state = State::Greeted;
			if oversize {
				return Some(Action::Continue(Reply::single(
					552,
					"message exceeds maximum size",
				)));
			}
			return Some(Action::Deliver(Reply::ok(), message));
		}

		// Dot-unstuffing (RFC 5321 section 4.5.2).
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

/// Current time in epoch seconds (for rate-limit windows).
fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

#[cfg(test)]
#[path = "../session_tests_basic.rs"]
mod tests_basic;

#[cfg(test)]
#[path = "../session_tests_auth.rs"]
mod tests_auth;
#[cfg(test)]
#[path = "../session_tests_oauth.rs"]
mod tests_oauth;
#[cfg(test)]
#[path = "../session_tests_scram.rs"]
mod tests_scram;
