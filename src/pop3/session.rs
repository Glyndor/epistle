//! Sans-IO POP3 session state machine (RFC 1939).
//!
//! The session owns no sockets: it consumes parsed [`Command`]s and returns a
//! [`Response`] the network layer encodes and writes. A [`Backend`] supplies
//! credential verification, the message snapshot taken at login, and deletion
//! at QUIT — all injectable, so the protocol is fully unit-testable.

use super::command::Command;

/// Storage backing a POP3 session. Implementations talk to the real mailbox;
/// tests supply an in-memory fake.
pub trait Backend {
	/// Verify credentials, returning the canonical account name on success.
	fn verify(&self, user: &str, pass: &str) -> Option<String>;
	/// The messages in the account's inbox at login: `(unique-id, bytes)`.
	fn load(&self, account: &str) -> Vec<(String, Vec<u8>)>;
	/// Permanently remove the given unique-ids (committed at QUIT).
	fn remove(&self, account: &str, uids: &[String]);
}

/// What the session wants written back. Encoding (dot-stuffing, CRLF, the
/// terminating line) is handled by [`Response::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
	/// `+OK <text>`
	Ok(String),
	/// `-ERR <text>`
	Err(String),
	/// `+OK <text>` followed by a dot-terminated body.
	Multiline { status: String, body: Vec<u8> },
	/// `+OK <text>` then close the connection.
	Bye(String),
}

impl Response {
	/// Encode to the exact bytes sent on the wire, including dot-stuffing of
	/// the body and the terminating `.` line for multiline responses.
	pub fn encode(&self) -> Vec<u8> {
		match self {
			Response::Ok(text) | Response::Bye(text) => format!("+OK {text}\r\n").into_bytes(),
			Response::Err(text) => format!("-ERR {text}\r\n").into_bytes(),
			Response::Multiline { status, body } => {
				let mut out = format!("+OK {status}\r\n").into_bytes();
				out.extend_from_slice(&dot_stuff(body));
				out.extend_from_slice(b".\r\n");
				out
			}
		}
	}

	/// Whether the connection should close after sending this response.
	pub fn is_final(&self) -> bool {
		matches!(self, Response::Bye(_))
	}
}

/// Byte-stuff a message body: any line starting with `.` gets an extra `.`,
/// and bare LF is normalized to CRLF so the terminator is unambiguous.
fn dot_stuff(body: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(body.len() + 16);
	let mut at_line_start = true;
	let mut prev = 0u8;
	for &byte in body {
		if at_line_start && byte == b'.' {
			out.push(b'.');
		}
		if byte == b'\n' && prev != b'\r' {
			out.push(b'\r');
		}
		out.push(byte);
		at_line_start = byte == b'\n';
		prev = byte;
	}
	out
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
	Authorization,
	Transaction,
}

struct Message {
	uid: String,
	data: Vec<u8>,
	deleted: bool,
}

/// One POP3 connection's protocol state.
pub struct Session<B: Backend> {
	backend: B,
	state: State,
	user: Option<String>,
	account: Option<String>,
	messages: Vec<Message>,
}

impl<B: Backend> Session<B> {
	/// Start a session in the AUTHORIZATION state.
	pub fn new(backend: B) -> Self {
		Self {
			backend,
			state: State::Authorization,
			user: None,
			account: None,
			messages: Vec::new(),
		}
	}

	/// The greeting sent on connect.
	pub fn greeting(&self) -> Response {
		Response::Ok("POP3 ready".to_string())
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
				match self.backend.verify(&user, &pass) {
					Some(account) => {
						self.messages = self
							.backend
							.load(&account)
							.into_iter()
							.map(|(uid, data)| Message {
								uid,
								data,
								deleted: false,
							})
							.collect();
						let count = self.messages.len();
						self.account = Some(account);
						self.state = State::Transaction;
						Response::Ok(format!("mailbox ready, {count} messages"))
					}
					None => {
						// No oracle: same message whether user or pass was wrong.
						self.user = None;
						Response::Err("authentication failed".to_string())
					}
				}
			}
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
				body: self.scan_list(|i, m| format!("{} {}\r\n", i + 1, m.data.len())),
			},
			Command::List(Some(n)) => self.with_message(n, |i, m| {
				Response::Ok(format!("{} {}", i + 1, m.data.len()))
			}),
			Command::Uidl(None) => Response::Multiline {
				status: "unique-id listing".to_string(),
				body: self.scan_list(|i, m| format!("{} {}\r\n", i + 1, m.uid)),
			},
			Command::Uidl(Some(n)) => {
				self.with_message(n, |i, m| Response::Ok(format!("{} {}", i + 1, m.uid)))
			}
			Command::Retr(n) => self.with_message(n, |_, m| Response::Multiline {
				status: format!("{} octets", m.data.len()),
				body: m.data.clone(),
			}),
			Command::Top(n, lines) => self.with_message(n, |_, m| Response::Multiline {
				status: "top".to_string(),
				body: top_of(&m.data, lines as usize),
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
			// USER/PASS are meaningless after login.
			Command::User(_) | Command::Pass(_) => {
				Response::Err("already authenticated".to_string())
			}
		}
	}

	fn capabilities(&self) -> Response {
		Response::Multiline {
			status: "capability list follows".to_string(),
			body: b"USER\r\nUIDL\r\nTOP\r\n".to_vec(),
		}
	}

	fn totals(&self) -> (usize, usize) {
		self.messages
			.iter()
			.filter(|m| !m.deleted)
			.fold((0, 0), |(c, o), m| (c + 1, o + m.data.len()))
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
