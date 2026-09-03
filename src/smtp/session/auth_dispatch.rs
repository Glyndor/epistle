//! AUTH dispatch: the command-line entry points and the failure
//! helper. The actual credential checks live in the mechanism-specific
//! siblings (`login`, `scram`, `oauth`); this file owns the gating (TLS
//! required, already-authenticated rejected, fresh greeting required)
//! and the per-mechanism routing table.
//!
//! Lifted out of `mod.rs` so the session module stays under the
//! per-file code-line budget.

use crate::smtp::command::{Command, ParseError};
use crate::smtp::session::types::State;
use crate::smtp::session::{Action, Reply, Session, scram};

impl Session {
	/// Feed one command line (CRLF already stripped and enforced upstream).
	pub fn command_line(&mut self, line: &str) -> Action {
		match crate::smtp::command::parse(line) {
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
	pub(super) fn auth_fail(&mut self) -> Action {
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
}
