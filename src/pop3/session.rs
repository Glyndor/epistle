//! Sans-IO POP3 session state machine (RFC 1939).
//!
//! The session owns no sockets: it consumes parsed [`Command`]s and returns a
//! [`Response`] the network layer encodes and writes. A [`Backend`] supplies
//! credential verification, the message index taken at login, message bytes
//! on demand, and deletion
//! at QUIT — all injectable, so the protocol is fully unit-testable.

use std::sync::Arc;

use super::bounds::{MAX_MESSAGE_OCTETS, MAX_SESSION_MESSAGES};
use super::command::Command;
use crate::smtp::directory::hash_gate::Verdict;

/// Storage backing a POP3 session. Implementations talk to the real mailbox;
/// tests supply an in-memory fake.
pub trait Backend {
	/// Verify credentials, returning the canonical account name on success.
	/// `peer_ip` is the client address the network layer recorded; passing
	/// `None` skips the ban-store check on the IP (the ban store already
	/// handles `unknown` as "not banned"). The audit log and the per-IP
	/// ban row are keyed on this address.
	fn verify(&self, user: &str, pass: &str, peer_ip: Option<std::net::IpAddr>) -> Option<String>;
	/// Like [`Backend::verify`], but tells a refusal from a sign-in the server
	/// had no room to check. A backend with no such limit keeps the default.
	fn verify_checked(&self, user: &str, pass: &str, peer_ip: Option<std::net::IpAddr>) -> Verdict {
		match self.verify(user, pass, peer_ip) {
			Some(account) => Verdict::Admitted {
				account,
				label: None,
			},
			None => Verdict::Refused,
		}
	}
	/// The index of the account's inbox at login: `(unique-id, octets)` in
	/// arrival order, at most [`MAX_SESSION_MESSAGES`] entries (the newest
	/// when there are more). No message
	/// body is read.
	fn list(&self, account: &str) -> Vec<(String, usize)>;
	/// The bytes of one message of the index, read when a command needs it.
	/// `None` when it is gone, unreadable, or larger than
	/// [`MAX_MESSAGE_OCTETS`].
	fn fetch(&self, account: &str, uid: &str) -> Option<Vec<u8>>;
	/// Permanently remove the given unique-ids (committed at QUIT).
	fn remove(&self, account: &str, uids: &[String]);
}

/// What the session wants written back. Encoding (dot-stuffing, CRLF, the
/// terminating line) is handled by [`Response::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
	/// Empty SASL challenge, awaiting a client response.
	Continuation,
	/// `+OK <text>`
	Ok(String),
	/// `-ERR <text>`
	Err(String),
	/// `+OK <text>` followed by a dot-terminated body.
	Multiline {
		/// Status line text (after `+OK ` and before CRLF).
		status: String,
		/// Raw body bytes. The encoder dot-stuffs any line starting with `.`
		/// and terminates with the `.\r\n` terminator.
		body: Vec<u8>,
	},
	/// `+OK <text>` then close the connection.
	Bye(String),
}

impl Response {
	/// Encode to the exact bytes sent on the wire, including dot-stuffing of
	/// the body and the terminating `.` line for multiline responses.
	pub fn encode(&self) -> Vec<u8> {
		self.wire().flatten().collect()
	}

	/// The bytes of [`Response::encode`] in pieces of bounded size, so a large
	/// message is never held a second time in full.
	pub fn wire(&self) -> super::wire::Wire<'_> {
		super::wire::Wire::new(self)
	}

	/// Whether the connection should close after sending this response.
	pub fn is_final(&self) -> bool {
		matches!(self, Response::Bye(_))
	}

	/// Whether this is the reply for a message that cannot be read.
	pub fn is_unavailable(&self) -> bool {
		matches!(self, Response::Err(text) if text.starts_with("[SYS/PERM]"))
	}

	/// Whether this is the client's own protocol error (a bad command, a
	/// failed sign-in, an unknown message), the only kind the abuse guard
	/// counts. A `[SYS/...]` reply is a condition of the server or the store.
	pub fn is_client_error(&self) -> bool {
		matches!(self, Response::Err(text) if !text.starts_with("[SYS/"))
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
	Authorization,
	Transaction,
}

struct Message {
	uid: String,
	/// The size announced by the index, in octets.
	size: usize,
	deleted: bool,
}

/// One POP3 connection's protocol state.
pub struct Session<B: Backend> {
	backend: B,
	pending_plain: bool,
	state: State,
	user: Option<String>,
	account: Option<String>,
	messages: Vec<Message>,
	/// The client peer IP, set by the network layer before the command
	/// loop starts. Drives the per-IP ban store check on every
	/// `USER`/`PASS`/`AUTH PLAIN` attempt.
	peer_ip: Option<std::net::IpAddr>,
	/// Shared per-account counter applied after authentication. `None`
	/// keeps the historical behaviour (no per-account cap).
	per_account_counter: Option<Arc<crate::net::per_account_conn::PerAccountCounter>>,
	/// The slot the session holds on [`Session::per_account_counter`].
	/// Dropping the session releases the slot.
	per_account_slot: Option<crate::net::per_account_conn::PerAccountSlot>,
}

impl<B: Backend> Session<B> {
	/// Whether the client has signed in (the TRANSACTION state).
	pub fn is_authenticated(&self) -> bool {
		self.state == State::Transaction
	}

	/// Whether a sign-in is waiting for its password: the client sent
	/// `USER` and the server accepted it, so the replies that follow
	/// belong to that attempt. Accepting a `USER` is not proof that the
	/// client can open the mailbox, because the password that comes next
	/// can still be refused, so it must not clear a streak of failed
	/// sign-ins.
	pub fn sign_in_pending(&self) -> bool {
		self.state == State::Authorization && self.user.is_some()
	}

	/// Start a session in the AUTHORIZATION state.
	pub fn new(backend: B) -> Self {
		Self {
			backend,
			pending_plain: false,
			state: State::Authorization,
			user: None,
			account: None,
			messages: Vec::new(),
			peer_ip: None,
			per_account_counter: None,
			per_account_slot: None,
		}
	}

	/// Set the client peer IP for ban-store enforcement. Called by the
	/// network layer after `accept()`; `None` for in-memory tests.
	pub fn set_peer_ip(&mut self, ip: Option<std::net::IpAddr>) {
		self.peer_ip = ip;
	}

	/// Attach the shared per-account counter this listener enforces.
	pub fn with_per_account_counter(
		mut self,
		counter: Arc<crate::net::per_account_conn::PerAccountCounter>,
	) -> Self {
		self.per_account_counter = Some(counter);
		self
	}

	/// The greeting sent on connect.
	pub fn greeting(&self) -> Response {
		Response::Ok("POP3 ready".to_string())
	}

	/// Consume a client line and return its wire response.
	pub fn handle_line(&mut self, line: &str) -> Response {
		if std::mem::take(&mut self.pending_plain) {
			if line == "*" {
				return Response::Err("authentication cancelled".into());
			}
			return self.auth(Some("PLAIN".into()), Some(line.to_string()));
		}
		match super::command::parse(line) {
			Ok(command) => self.handle(command),
			Err(_) => Response::Err("invalid command".into()),
		}
	}

	/// Drive the session with one parsed command.
	pub fn handle(&mut self, command: Command) -> Response {
		match self.state {
			State::Authorization => self.authorization(command),
			State::Transaction => self.transaction(command),
		}
	}

	fn authorization(&mut self, command: Command) -> Response {
		match command {
			Command::User(name) => {
				self.user = Some(name);
				Response::Ok("send PASS".to_string())
			}
			Command::Pass(pass) => {
				let Some(user) = self.user.clone() else {
					return Response::Err("USER required first".to_string());
				};
				self.login(&user, &pass)
			}
			Command::Auth { mechanism, initial } => self.auth(mechanism, initial),
			Command::Capa => self.capabilities(),
			Command::Quit => Response::Bye("bye".to_string()),
			_ => Response::Err("authenticate first".to_string()),
		}
	}

	fn transaction(&mut self, command: Command) -> Response {
		match command {
			Command::Stat => {
				let (count, octets) = self.totals();
				Response::Ok(format!("{count} {octets}"))
			}
			Command::List(None) => Response::Multiline {
				status: format!("{} messages", self.live_count()),
				body: self.scan_list(|i, m| format!("{} {}\r\n", i + 1, m.size)),
			},
			Command::List(Some(n)) => {
				self.with_message(n, |i, m| Response::Ok(format!("{} {}", i + 1, m.size)))
			}
			Command::Uidl(None) => Response::Multiline {
				status: "unique-id listing".to_string(),
				body: self.scan_list(|i, m| format!("{} {}\r\n", i + 1, m.uid)),
			},
			Command::Uidl(Some(n)) => {
				self.with_message(n, |i, m| Response::Ok(format!("{} {}", i + 1, m.uid)))
			}
			Command::Retr(n) => self.read_message(n, |data| Response::Multiline {
				status: format!("{} octets", data.len()),
				body: data,
			}),
			Command::Top(n, lines) => self.read_message(n, |data| Response::Multiline {
				status: "top".to_string(),
				body: top_of(&data, lines as usize),
			}),
			Command::Dele(n) => self.delete(n),
			Command::Rset => {
				for message in &mut self.messages {
					message.deleted = false;
				}
				Response::Ok(format!("{} messages", self.live_count()))
			}
			Command::Noop => Response::Ok(String::new()),
			Command::Capa => self.capabilities(),
			Command::Quit => {
				let removed: Vec<String> = self
					.messages
					.iter()
					.filter(|m| m.deleted)
					.map(|m| m.uid.clone())
					.collect();
				if let Some(account) = &self.account
					&& !removed.is_empty()
				{
					self.backend.remove(account, &removed);
				}
				Response::Bye("bye".to_string())
			}
			// USER/PASS/AUTH are meaningless after login.
			Command::User(_) | Command::Pass(_) | Command::Auth { .. } => {
				Response::Err("already authenticated".to_string())
			}
		}
	}

	fn capabilities(&self) -> Response {
		Response::Multiline {
			status: "capability list follows".to_string(),
			body: b"USER\r\nUIDL\r\nTOP\r\nSASL PLAIN\r\n".to_vec(),
		}
	}

	/// SASL AUTH (RFC 5034): list mechanisms or start a PLAIN exchange.
	fn auth(&mut self, mechanism: Option<String>, initial: Option<String>) -> Response {
		let Some(mechanism) = mechanism else {
			return Response::Multiline {
				status: "mechanism list follows".to_string(),
				body: b"PLAIN\r\n".to_vec(),
			};
		};
		if mechanism != "PLAIN" {
			return Response::Err("unsupported SASL mechanism".to_string());
		}
		let Some(initial) = initial else {
			self.pending_plain = true;
			return Response::Continuation;
		};
		self.pending_plain = false;
		let verdict = match crate::smtp::auth::parse_plain(&initial) {
			Ok(creds) => self
				.backend
				.verify_checked(&creds.authcid, &creds.password, self.peer_ip),
			Err(_) => Verdict::Refused,
		};
		self.finish_login(verdict)
	}

	/// Verify a USER/PASS login and, on success, open the mailbox.
	fn login(&mut self, user: &str, pass: &str) -> Response {
		let verdict = self.backend.verify_checked(user, pass, self.peer_ip);
		self.finish_login(verdict)
	}

	/// End a login: open the mailbox, refuse with one message whatever was
	/// wrong, or ask to try again when the server had no room to check.
	fn finish_login(&mut self, verdict: Verdict) -> Response {
		match verdict {
			Verdict::Admitted { account, .. } => self.complete_login(account),
			Verdict::Refused => {
				// No oracle: same message whether user or pass was wrong.
				self.user = None;
				Response::Err("authentication failed".to_string())
			}
			Verdict::Busy => {
				self.user = None;
				Response::Err("[SYS/TEMP] try again later".to_string())
			}
		}
	}

	/// Load `account`'s mailbox and enter the transaction state.
	fn complete_login(&mut self, account: String) -> Response {
		// `[server] max_connections_per_account` (default 10 per
		// (account, IP) and 50 in total). Applied after the backend
		// admits the credentials but before the mailbox is loaded so a
		// refused connection does not touch the mail store. The slot
		// lives on the session; dropping the session releases it.
		if let (Some(counter), Some(peer)) = (&self.per_account_counter, self.peer_ip) {
			match counter.try_acquire(&account, peer) {
				Ok(slot) => self.per_account_slot = Some(slot),
				Err(_) => {
					return Response::Err(
						"[IN-USE] Too many concurrent connections for this account".into(),
					);
				}
			}
		}
		let mut index = self.backend.list(&account);
		if index.len() > MAX_SESSION_MESSAGES {
			// The newest stay reachable; the oldest are not listed.
			index.drain(..index.len() - MAX_SESSION_MESSAGES);
		}
		self.messages = index
			.into_iter()
			.map(|(uid, size)| Message {
				uid,
				size,
				deleted: false,
			})
			.collect();
		let count = self.messages.len();
		self.account = Some(account);
		self.state = State::Transaction;
		Response::Ok(format!("mailbox ready, {count} messages"))
	}

	fn totals(&self) -> (usize, usize) {
		self.messages
			.iter()
			.filter(|m| !m.deleted)
			.fold((0, 0), |(c, o), m| (c + 1, o + m.size))
	}

	fn live_count(&self) -> usize {
		self.messages.iter().filter(|m| !m.deleted).count()
	}

	/// Build a multiline body from every live message, 1-based index.
	fn scan_list(&self, format: impl Fn(usize, &Message) -> String) -> Vec<u8> {
		let mut body = Vec::new();
		for (i, message) in self.messages.iter().enumerate() {
			if !message.deleted {
				body.extend_from_slice(format(i, message).as_bytes());
			}
		}
		body
	}

	/// Resolve a 1-based message number to a live message, or `-ERR`.
	fn with_message(&self, number: u32, ok: impl Fn(usize, &Message) -> Response) -> Response {
		match self.live_message(number) {
			Some(index) => ok(index, &self.messages[index]),
			None => Response::Err("no such message".to_string()),
		}
	}

	/// Read message `number` from the backend and answer with `ok`. The
	/// bytes live only for this command.
	fn read_message(&self, number: u32, ok: impl FnOnce(Vec<u8>) -> Response) -> Response {
		let Some(index) = self.live_message(number) else {
			return Response::Err("no such message".to_string());
		};
		let Some(account) = &self.account else {
			return Response::Err("no such message".to_string());
		};
		match self.backend.fetch(account, &self.messages[index].uid) {
			Some(data) if data.len() <= MAX_MESSAGE_OCTETS => ok(data),
			_ => Response::Err("[SYS/PERM] message unavailable".to_string()),
		}
	}

	fn delete(&mut self, number: u32) -> Response {
		match self.live_message(number) {
			Some(index) => {
				self.messages[index].deleted = true;
				Response::Ok(format!("message {number} deleted"))
			}
			None => Response::Err("no such message".to_string()),
		}
	}

	/// The slice index for a 1-based message number that is in range and not
	/// already deleted.
	fn live_message(&self, number: u32) -> Option<usize> {
		let index = (number as usize).checked_sub(1)?;
		self.messages
			.get(index)
			.filter(|m| !m.deleted)
			.map(|_| index)
	}
}

/// The headers plus the first `lines` lines of the body, per the TOP command.
/// Headers and body are split on the first blank line.
fn top_of(data: &[u8], lines: usize) -> Vec<u8> {
	let text = data;
	let split = find_header_end(text);
	let (headers, body) = text.split_at(split);
	let mut out = headers.to_vec();
	for line in body.split_inclusive(|&b| b == b'\n').take(lines) {
		out.extend_from_slice(line);
	}
	out
}

/// Index just past the header/body separator (the blank line), or the end.
fn find_header_end(data: &[u8]) -> usize {
	if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
		return pos + 4;
	}
	if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
		return pos + 2;
	}
	data.len()
}

#[cfg(test)]
#[path = "session_tests_continuation.rs"]
mod continuation_tests;

#[cfg(test)]
mod header_count_tests {
	use super::top_of;
	use crate::util::header_block::{cases, field_count};

	#[test]
	fn the_field_count_is_never_below_the_headers_top_shows() {
		for raw in cases::messages() {
			let headers = top_of(&raw, 0);
			assert!(field_count(&raw) >= cases::fields_in(&headers), "{raw:?}");
		}
	}
}
