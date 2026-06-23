//! Sans-IO ManageSieve session state machine (RFC 5804).
//!
//! The session owns no socket: it consumes parsed [`Command`]s and returns a
//! [`Response`] the network layer encodes and writes. A [`Backend`] supplies
//! credential verification and the per-account script store, so the protocol is
//! fully unit-testable. SASL is refused on a cleartext link (fail closed).

use super::command::Command;
use super::store::{ScriptStore, StoreError};

/// The Sieve extensions advertised in the `SIEVE` capability — only those the
/// interpreter actually honors at delivery time. A client checks this list
/// before `require`-ing an extension, so it must match the interpreter:
/// fileinto/envelope (RFC 5228), vacation (RFC 5230), imap4flags (RFC 5232),
/// relational (RFC 5231), variables (RFC 5229), reject/ereject (RFC 5429),
/// copy (RFC 3894), body (RFC 5173), date (RFC 5260) and the
/// `i;ascii-numeric` comparator (RFC 4790).
pub const SIEVE_EXTENSIONS: &str = "fileinto envelope vacation imap4flags relational \
variables reject ereject copy body date comparator-i;ascii-numeric";

/// Storage and authentication backing a session.
pub trait Backend {
	/// Verify SASL PLAIN credentials, returning the canonical account name.
	fn verify(&self, authcid: &str, password: &str) -> Option<String>;
	/// The script store for an authenticated account.
	fn store(&self, account: &str) -> ScriptStore;
}

/// What the session wants written back; [`Response::encode`] renders the bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
	/// `OK`, optionally with a human message.
	Ok(Option<String>),
	/// `NO`, optionally with a human message.
	No(Option<String>),
	/// `NO (CODE) "message"` — a coded failure (e.g. `QUOTA`).
	NoCode(&'static str, String),
	/// `BYE "message"` then close.
	Bye(String),
	/// Raw lines (already encoded) followed by a final `OK`.
	Lines { lines: Vec<String>, ok: String },
	/// A script body returned as a literal, followed by `OK` (GETSCRIPT).
	Script(String),
	/// Send `OK` then upgrade the connection to TLS (STARTTLS).
	StartTls,
}

impl Response {
	/// Encode to the exact bytes sent on the wire.
	pub fn encode(&self) -> Vec<u8> {
		match self {
			Response::Ok(msg) => line("OK", msg.as_deref()),
			Response::No(msg) => line("NO", msg.as_deref()),
			Response::NoCode(code, msg) => format!("NO ({code}) {}\r\n", quoted(msg)).into_bytes(),
			Response::Bye(msg) => format!("BYE {}\r\n", quoted(msg)).into_bytes(),
			Response::Lines { lines, ok } => {
				let mut out = String::new();
				for entry in lines {
					out.push_str(entry);
					out.push_str("\r\n");
				}
				out.push_str(&format!("OK {}\r\n", quoted(ok)));
				out.into_bytes()
			}
			Response::Script(content) => {
				let mut out = format!("{{{}}}\r\n", content.len()).into_bytes();
				out.extend_from_slice(content.as_bytes());
				out.extend_from_slice(b"\r\nOK\r\n");
				out
			}
			Response::StartTls => b"OK \"Begin TLS negotiation now.\"\r\n".to_vec(),
		}
	}

	/// Whether the connection should close after this response.
	pub fn is_final(&self) -> bool {
		matches!(self, Response::Bye(_))
	}

	/// Whether the network layer must upgrade to TLS after sending this.
	pub fn starts_tls(&self) -> bool {
		matches!(self, Response::StartTls)
	}
}

/// One ManageSieve connection's protocol state.
pub struct Session<B: Backend> {
	backend: B,
	tls: bool,
	account: Option<String>,
}

impl<B: Backend> Session<B> {
	/// Start an unauthenticated session. `tls` is `true` once the transport is
	/// encrypted (set again by the network layer after STARTTLS).
	pub fn new(backend: B, tls: bool) -> Self {
		Self {
			backend,
			tls,
			account: None,
		}
	}

	/// Mark the transport as encrypted (called after a STARTTLS upgrade).
	pub fn set_tls(&mut self) {
		self.tls = true;
	}

	/// The capability banner sent on connect and after STARTTLS.
	pub fn greeting(&self) -> Response {
		Response::Lines {
			lines: self.capabilities(),
			ok: "ManageSieve ready.".to_string(),
		}
	}

	/// Drive the session with one parsed command.
	pub fn handle(&mut self, command: Command) -> Response {
		match command {
			Command::Capability => Response::Lines {
				lines: self.capabilities(),
				ok: "Capabilities follow.".to_string(),
			},
			Command::Logout => Response::Bye("Goodbye.".to_string()),
			Command::Noop(tag) => Response::Ok(tag),
			Command::StartTls if self.tls => Response::No(Some("Already using TLS.".to_string())),
			Command::StartTls => Response::StartTls,
			Command::Authenticate { mechanism, initial } => self.authenticate(&mechanism, initial),
			Command::Unauthenticate if self.account.is_some() => {
				self.account = None;
				Response::Ok(None)
			}
			Command::Unauthenticate => Response::No(Some("Not authenticated.".to_string())),
			other => self.script_command(other),
		}
	}

	/// Commands that require an authenticated session.
	fn script_command(&mut self, command: Command) -> Response {
		let Some(account) = self.account.clone() else {
			return Response::No(Some("Authenticate first.".to_string()));
		};
		let store = self.backend.store(&account);
		match command {
			Command::ListScripts => match store.list() {
				Ok(scripts) => Response::Lines {
					lines: scripts
						.iter()
						.map(|s| {
							if s.active {
								format!("{} ACTIVE", quoted(&s.name))
							} else {
								quoted(&s.name)
							}
						})
						.collect(),
					ok: "Listed.".to_string(),
				},
				Err(error) => store_error(error),
			},
			Command::GetScript(name) => match store.get(&name) {
				Ok(content) => Response::Script(content),
				Err(error) => store_error(error),
			},
			Command::PutScript { name, content } => result(store.put(&name, &content)),
			Command::CheckScript { content } => result(ScriptStore::validate(&content)),
			Command::SetActive(name) => {
				let target = (!name.is_empty()).then_some(name);
				result(store.set_active(target.as_deref()))
			}
			Command::DeleteScript(name) => result(store.delete(&name)),
			Command::RenameScript { from, to } => result(store.rename(&from, &to)),
			Command::HaveSpace { .. } => Response::Ok(None),
			_ => Response::No(Some("Unsupported command.".to_string())),
		}
	}

	/// Handle `AUTHENTICATE`. Only SASL PLAIN over TLS is accepted.
	fn authenticate(&mut self, mechanism: &str, initial: Option<String>) -> Response {
		if self.account.is_some() {
			return Response::No(Some("Already authenticated.".to_string()));
		}
		if !self.tls {
			return Response::NoCode("ENCRYPT-NEEDED", "TLS is required first.".to_string());
		}
		if !mechanism.eq_ignore_ascii_case("PLAIN") {
			return Response::No(Some("Only SASL PLAIN is supported.".to_string()));
		}
		let account = initial
			.and_then(|encoded| crate::smtp::auth::parse_plain(&encoded).ok())
			.and_then(|creds| self.backend.verify(&creds.authcid, &creds.password));
		match account {
			Some(account) => {
				self.account = Some(account);
				Response::Ok(Some("Authenticated.".to_string()))
			}
			None => Response::No(Some("Authentication failed.".to_string())),
		}
	}

	/// The capability lines for the current transport state.
	fn capabilities(&self) -> Vec<String> {
		let mut lines = vec![
			format!("{} {}", quoted("IMPLEMENTATION"), quoted("epistle")),
			format!("{} {}", quoted("SIEVE"), quoted(SIEVE_EXTENSIONS)),
			format!("{} {}", quoted("VERSION"), quoted("1.0")),
		];
		if self.tls {
			lines.push(format!("{} {}", quoted("SASL"), quoted("PLAIN")));
		} else {
			lines.push(quoted("STARTTLS"));
		}
		lines
	}
}

/// Map a store result to an `OK`/`NO` response.
fn result(outcome: Result<(), StoreError>) -> Response {
	match outcome {
		Ok(()) => Response::Ok(None),
		Err(error) => store_error(error),
	}
}

/// Map a [`StoreError`] to the appropriate ManageSieve failure response.
fn store_error(error: StoreError) -> Response {
	match error {
		StoreError::InvalidName => Response::No(Some("Invalid script name.".to_string())),
		StoreError::NoSuchScript => Response::NoCode("NONEXISTENT", "No such script.".to_string()),
		StoreError::AlreadyExists => {
			Response::NoCode("ALREADYEXISTS", "Script already exists.".to_string())
		}
		StoreError::ActiveScript => {
			Response::NoCode("ACTIVE", "Cannot delete the active script.".to_string())
		}
		StoreError::InvalidScript(reason) => {
			Response::No(Some(format!("Script does not parse: {reason}")))
		}
		StoreError::Io => Response::No(Some("Storage error.".to_string())),
	}
}

/// Render `OK`/`NO` with an optional quoted message.
fn line(status: &str, message: Option<&str>) -> Vec<u8> {
	match message {
		Some(message) => format!("{status} {}\r\n", quoted(message)).into_bytes(),
		None => format!("{status}\r\n").into_bytes(),
	}
}

/// A ManageSieve quoted string with `"` and `\` escaped.
fn quoted(value: &str) -> String {
	let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
	format!("\"{escaped}\"")
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
