//! IMAP session state machine (sans-IO).

use super::command::{Command, FetchItem, Line, ParseError, SearchKey, StoreMode, Tagged};
use super::mailbox;
use crate::smtp::directory::hash_gate::Verdict;

mod auth;
mod base_subject;
mod commands;
mod condstore;
mod dispatch;
mod fetch;
mod helpers;
mod list_status;
mod mailboxes;
mod search_fields;
mod search_header;
mod sort_keys;
mod state;
mod thread_references;

pub(crate) use auth::parse_bearer;

pub use state::{DEFAULT_QUOTA_BYTES, Output, PendingLiteral, SavedSearch, Session, State};

/// The size of the non-synchronizing literal a tagged APPEND or REPLACE
/// line announces (RFC 7888 §4): bytes the client has already sent, which
/// a rejection must discard.
fn sent_literal(line: &str) -> Option<usize> {
	super::command::literal_announcement_in_line(line)
		.filter(|literal| !literal.synchronizing)
		.map(|literal| literal.size)
}

impl Session {
	#[cfg(test)]
	fn rev2_enabled(&self) -> bool {
		self.imap4rev2
	}

	/// The greeting sent when the connection opens.
	pub fn greeting(&self) -> Output {
		Output::text(format!(
			"* OK [CAPABILITY {}] {} IMAP4rev2 ready\r\n",
			self.capabilities(),
			self.hostname
		))
	}

	/// Feed one command line (CRLF stripped).
	pub fn command_line(&mut self, line: &str) -> Output {
		let tagged = match super::command::parse_line(line, self.append_limit) {
			Ok(Line::Command(tagged)) => tagged,
			Ok(Line::Login(request)) => {
				return self.login(&request.tag, request.username(), request.password());
			}
			Ok(Line::Authenticate(request)) => {
				return self.auth(&request.tag, &request.mechanism, request.initial);
			}
			Err(ParseError::Malformed) => {
				return Output::text("* BAD malformed command\r\n".to_string());
			}
			Err(ParseError::Unknown(tag)) => {
				return Output::text(format!("{tag} BAD unknown command\r\n"));
			}
			Err(ParseError::BadArguments(tag)) => {
				// RFC 7888 §4: when an APPEND/REPLACE command fails to parse
				// but the line announced a non-synchronizing literal, the
				// payload is already on the wire and must be discarded so it
				// does not arrive as the next command.
				let mut output = Output::text(format!("{tag} BAD invalid arguments\r\n"));
				output.discard_literal = sent_literal(line);
				return output;
			}
			Err(ParseError::TooBig(tag)) => {
				// A non-synchronizing literal above the limit never gets
				// here from the network layer, which closes the connection
				// instead of reading it; the drain covers direct callers.
				let mut output =
					Output::text(format!("{tag} NO [TOOBIG] message exceeds APPENDLIMIT\r\n"));
				output.discard_literal = sent_literal(line);
				return output;
			}
		};
		self.apply_enabling_condstore(tagged)
	}

	fn login(&mut self, tag: &str, username: &str, password: &str) -> Output {
		if !self.tls_active {
			return Output::text(format!("{tag} NO [PRIVACYREQUIRED] STARTTLS first\r\n"));
		}
		let State::NotAuthenticated { login_failures } = &mut self.state else {
			return Output::text(format!("{tag} BAD already authenticated\r\n"));
		};
		let verdict = self.directory.authenticate_verdict(
			username,
			password,
			self.peer_ip,
			self.auth_protocol,
		);
		match verdict {
			Verdict::Admitted { account, .. } => self.auth_success(tag, account, "LOGIN completed"),
			Verdict::Busy => Output::text(format!("{tag} NO [UNAVAILABLE] Try again later\r\n")),
			Verdict::Refused => {
				*login_failures += 1;
				let response = format!("{tag} NO LOGIN failed\r\n");
				if *login_failures >= 3 {
					Output::closing(format!("* BYE too many failures\r\n{response}"))
				} else {
					Output::text(response)
				}
			}
		}
	}

	/// Whether the client has signed in.
	pub fn is_authenticated(&self) -> bool {
		self.account().is_some()
	}

	/// The account the client signed in as, `None` before sign-in.
	pub(crate) fn signed_in_account(&self) -> Option<&str> {
		self.account()
	}

	fn account(&self) -> Option<&str> {
		match &self.state {
			State::NotAuthenticated { .. } => None,
			State::Authenticated { account } | State::Selected { account, .. } => Some(account),
		}
	}

	/// Whether a `$`-using command is acceptable: the saved set exists and
	/// its kind matches `uid_kind`. Empty after a consumed search or a
	/// missing save — the caller answers `NO` to the client.
	fn saved_search_ok(&self, uid_kind: bool) -> bool {
		matches!(self.saved_search, Some(ref s) if s.are_uids == uid_kind)
	}

	fn mailbox_op(
		&mut self,
		tag: &str,
		verb: &str,
		operation: impl FnOnce(&std::path::Path, &str) -> std::io::Result<()>,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		match operation(&self.data_dir, &account) {
			Ok(()) => Output::text(format!("{tag} OK {verb} completed\r\n")),
			Err(error) => Output::text(format!("{tag} NO {error}\r\n")),
		}
	}

	/// ENABLE (RFC 5161): echo only the extensions we support (RFC 7162).
	fn enable(&mut self, tag: &str, capabilities: &[String]) -> Output {
		if self.account().is_none() {
			return Output::text(format!("{tag} BAD ENABLE only after authentication\r\n"));
		}
		// UIDONLY (RFC 9586) must be enabled before a mailbox is selected.
		if capabilities
			.iter()
			.any(|c| c.eq_ignore_ascii_case("UIDONLY"))
			&& matches!(self.state, State::Selected { .. })
		{
			return Output::text(format!("{tag} BAD UIDONLY not allowed when selected\r\n"));
		}
		let enabled: Vec<&str> = capabilities
			.iter()
			.filter_map(|cap| match cap.to_ascii_uppercase().as_str() {
				"IMAP4REV2" => {
					self.imap4rev2 = true;
					Some("IMAP4rev2")
				}
				"CONDSTORE" => Some("CONDSTORE"),
				"QRESYNC" => Some("QRESYNC"),
				"UIDONLY" => {
					self.uidonly = true;
					Some("UIDONLY")
				}
				"UTF8=ACCEPT" => {
					self.utf8_accept = true;
					Some("UTF8=ACCEPT")
				}
				_ => None,
			})
			.collect();
		Output::text(format!(
			"* ENABLED {}\r\n{tag} OK ENABLE completed\r\n",
			enabled.join(" ")
		))
	}

	/// Called by the network layer when an IDLE ends with DONE.
	pub fn idle_done(&mut self) -> Output {
		match self.idle_tag.take() {
			Some(tag) => Output::text(format!("{tag} OK IDLE terminated\r\n")),
			None => Output::text("* BAD not idling\r\n".to_string()),
		}
	}

	/// NOOP (RFC 9051 §7.1.2). The only required reply is the tagged OK,
	/// but NOOP is the client's poll: it carries every change to the
	/// SELECTed mailbox since the client last heard about it, as EXPUNGE,
	/// FETCH FLAGS and EXISTS (see [`Self::sync_selected`]).
	fn noop(&mut self, tag: &str) -> Output {
		let updates = self.sync_selected(true);
		Output::text(format!("{updates}{tag} OK NOOP completed\r\n"))
	}

	/// `(account, mailbox)` for the SELECTed state, or `None` for any
	/// other state. Cloned names release the mutable borrow on
	/// `self.state` so the caller can re-borrow as needed.
	fn selected_pair(&self) -> Option<(String, String)> {
		match &self.state {
			State::Selected {
				account, mailbox, ..
			} => Some((account.clone(), mailbox.clone())),
			_ => None,
		}
	}
}

#[cfg(test)]
pub(crate) mod tests;
