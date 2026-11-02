//! A minimal IMAP client: just the commands a one-way copy needs, over
//! implicit TLS, STARTTLS or (only when the operator insists) plaintext.
//!
//! Every response goes through [`super::wire`], so lines, literals and
//! waits are bounded. Credentials are written to the socket and nowhere
//! else: no command line that carries one is logged, kept, or put in an
//! error message.

use tokio::io::BufReader;
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use super::metadata::{Budget, MAX_NAME_BYTES};
use super::parse::{self, Fetched, Kind, ListEntry, Listed, Status};
use super::transport::{Endpoint, Io, Security, handshake, resolve};
use super::wire::{Limits, Response, WireError};

mod commands;
mod io;
mod quote;
use quote::{quote, quote_mailbox};
pub(crate) use quote::{sanitize, size_fits, uid_set};

/// Why talking to the server failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClientError {
	/// Reading a response failed or broke a limit.
	#[error(transparent)]
	Wire(#[from] WireError),
	/// The TLS handshake failed (including certificate checks).
	#[error("TLS: {0}")]
	Tls(String),
	/// The server refused STARTTLS or does not offer it.
	#[error("the server does not offer STARTTLS; refusing to send the password in clear")]
	NoStartTls,
	/// Login was refused.
	#[error("login refused by the server: {0}")]
	Auth(String),
	/// A command was answered with NO or BAD.
	#[error("{command} refused by the server: {text}")]
	Refused {
		/// The command name.
		command: &'static str,
		/// The server's explanation, sanitized.
		text: String,
	},
	/// The server ended the session.
	#[error("the server closed the session: {0}")]
	Bye(String),
	/// The server broke the protocol.
	#[error("protocol error: {0}")]
	Protocol(String),
	/// A body differs from the size the server declared for it.
	#[error(
		"the server declared {declared} bytes for message UID {uid} and sent {actual}; refusing it"
	)]
	SizeMismatch {
		/// The message.
		uid: u32,
		/// RFC822.SIZE from the listing.
		declared: u64,
		/// Octets received.
		actual: u64,
	},
	/// The bodies of one batch outgrew what the batch may hold.
	#[error("the server sent more than {budget} bytes for one batch; refusing it")]
	BatchTooLarge {
		/// The most one batch may hold.
		budget: u64,
	},
	/// One command used all of its time allowance.
	#[error("IMAP command {command} timed out; saved progress is retained, run again to resume")]
	CommandTimeout { command: &'static str },
	/// Metadata exceeded a bound independent of the server's message count.
	#[error(
		"IMAP {scope} metadata exceeds {limit} bytes; saved progress is retained, reduce the selected folders and run again to resume"
	)]
	Metadata { scope: &'static str, limit: usize },
	/// A name or credential cannot be sent safely.
	#[error("{0}")]
	Unsendable(&'static str),
}

/// A logged-out or logged-in session with one server.
pub(crate) struct Client {
	conn: BufReader<Box<dyn Io>>,
	limits: Limits,
	tag: u32,
	capabilities: Vec<String>,
	deadline: Option<(tokio::time::Instant, &'static str)>,
	read_literal: usize,
	pub(super) metadata: Budget,
	response_budget: usize,
}

/// What EXAMINE reported about a mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Examined {
	/// Number of messages.
	pub(crate) exists: u32,
	/// UIDVALIDITY, `0` when the server sent none.
	pub(crate) uid_validity: u32,
	/// The first UID not yet assigned, zero when omitted.
	pub(crate) uid_next: u32,
}

impl Client {
	/// Connect, read the greeting, and secure the session as `endpoint`
	/// asks. No credential has been sent when this returns.
	pub(crate) async fn connect(endpoint: &Endpoint, limits: Limits) -> Result<Self, ClientError> {
		let address = match endpoint.address {
			Some(address) => address,
			None => resolve(&endpoint.host, endpoint.port, limits).await?,
		};
		let tcp = tokio::time::timeout(limits.idle, TcpStream::connect(address))
			.await
			.map_err(|_| WireError::Timeout)?
			.map_err(WireError::Io)?;
		let stream: Box<dyn Io> = match endpoint.security {
			Security::Tls => Box::new(handshake(Box::new(tcp), endpoint, limits).await?),
			Security::StartTls | Security::Plaintext => Box::new(tcp),
		};
		let mut client = Client {
			conn: BufReader::new(stream),
			limits,
			tag: 0,
			capabilities: Vec::new(),
			deadline: None,
			read_literal: MAX_NAME_BYTES.min(limits.literal),
			metadata: Budget::default(),
			response_budget: 128 * 1024 * 1024,
		};
		client.greeting().await?;
		if endpoint.security == Security::StartTls {
			client.starttls(endpoint).await?;
		}
		client.refresh_capabilities().await?;
		Ok(client)
	}

	/// Whether the server announced `name` (uppercase).
	pub(crate) fn has(&self, name: &str) -> bool {
		self.capabilities.iter().any(|cap| cap == name)
	}

	async fn greeting(&mut self) -> Result<(), ClientError> {
		let greeting = self.read().await?;
		match parse::kind(&greeting) {
			Kind::UntaggedStatus {
				status: Status::Ok,
				text,
			} => {
				self.note_code(&text);
				Ok(())
			}
			Kind::UntaggedStatus {
				status: Status::Bye,
				text,
			} => Err(ClientError::Bye(sanitize(&text))),
			_ => Err(ClientError::Protocol("unexpected greeting".into())),
		}
	}

	/// Remember a CAPABILITY response code.
	fn note_code(&mut self, text: &[u8]) {
		let code = parse::response_code(text);
		if code
			.first()
			.is_some_and(|word| word.eq_ignore_ascii_case("CAPABILITY"))
		{
			self.capabilities = parse::capabilities(code.iter().map(String::as_str));
		}
	}

	async fn starttls(&mut self, endpoint: &Endpoint) -> Result<(), ClientError> {
		self.refresh_capabilities().await?;
		if !self.has("STARTTLS") {
			return Err(ClientError::NoStartTls);
		}
		self.command("STARTTLS", b"STARTTLS", |_| Ok(()))
			.await
			.map_err(|_| ClientError::NoStartTls)?;
		// Anything the server sent after its OK and before the handshake
		// would be plaintext injected into the TLS session (CVE-2011-0411
		// shape). Refuse it rather than read it.
		if !self.conn.buffer().is_empty() {
			return Err(ClientError::Protocol(
				"the server sent data after accepting STARTTLS".into(),
			));
		}
		let plain = std::mem::replace(&mut self.conn, BufReader::new(Box::new(tokio::io::empty())));
		let tls = handshake(plain.into_inner(), endpoint, self.limits).await?;
		self.conn = BufReader::new(Box::new(tls));
		// Capabilities learnt before TLS are not trusted (RFC 9051 §6.2.1).
		self.capabilities.clear();
		Ok(())
	}

	async fn refresh_capabilities(&mut self) -> Result<(), ClientError> {
		let mut found = None;
		self.command("CAPABILITY", b"CAPABILITY", |response| {
			let words = parse::data_words(&response);
			if words
				.first()
				.is_some_and(|word| word.eq_ignore_ascii_case("CAPABILITY"))
			{
				found = Some(parse::capabilities(words.iter().map(String::as_str)));
			}
			Ok(())
		})
		.await?;
		self.capabilities = found.unwrap_or_default();
		Ok(())
	}

	/// Authenticate as `user` with `password`: AUTHENTICATE PLAIN when the
	/// server offers it, LOGIN otherwise.
	pub(crate) async fn login(&mut self, user: &str, password: &str) -> Result<(), ClientError> {
		if [user, password]
			.iter()
			.any(|value| value.bytes().any(|b| matches!(b, b'\0' | b'\r' | b'\n')))
		{
			return Err(ClientError::Unsendable(
				"the user name or password contains a NUL or line break",
			));
		}
		let result = if self.has("AUTH=PLAIN") {
			self.authenticate_plain(user, password).await
		} else if self.has("LOGINDISABLED") {
			return Err(ClientError::Auth(
				"the server disables LOGIN and offers no PLAIN".into(),
			));
		} else {
			let mut line = Zeroizing::new(b"LOGIN ".to_vec());
			line.extend_from_slice(&quote(user.as_bytes()));
			line.push(b' ');
			line.extend_from_slice(&quote(password.as_bytes()));
			self.command("LOGIN", &line, |_| Ok(())).await
		};
		match result {
			Ok(()) => self.refresh_capabilities().await,
			Err(ClientError::Refused { text, .. }) => Err(ClientError::Auth(text)),
			Err(error) => Err(error),
		}
	}

	async fn authenticate_plain(&mut self, user: &str, password: &str) -> Result<(), ClientError> {
		use base64::Engine;
		let mut raw = Zeroizing::new(Vec::with_capacity(user.len() + password.len() + 2));
		raw.push(0);
		raw.extend_from_slice(user.as_bytes());
		raw.push(0);
		raw.extend_from_slice(password.as_bytes());
		let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*raw));
		if self.has("SASL-IR") {
			let mut line = Zeroizing::new(b"AUTHENTICATE PLAIN ".to_vec());
			line.extend_from_slice(encoded.as_bytes());
			return self.command("AUTHENTICATE", &line, |_| Ok(())).await;
		}
		let tag = self.next_tag("AUTHENTICATE");
		self.send(&tag, b"AUTHENTICATE PLAIN").await?;
		let response = self.read().await?;
		if parse::kind(&response) != Kind::Continuation {
			return self.finish_unexpected(&tag, "AUTHENTICATE", response).await;
		}
		let mut line = Zeroizing::new(encoded.as_bytes().to_vec());
		line.extend_from_slice(b"\r\n");
		self.write(&line).await?;
		self.collect(&tag, "AUTHENTICATE", |_| Ok(())).await
	}

	/// Handle a first response that was not the continuation expected.
	async fn finish_unexpected(
		&mut self,
		tag: &[u8],
		command: &'static str,
		response: Response,
	) -> Result<(), ClientError> {
		match parse::kind(&response) {
			Kind::Tagged { tag: got, text, .. } if got == tag => Err(ClientError::Refused {
				command,
				text: sanitize(&text),
			}),
			_ => Err(ClientError::Protocol(format!(
				"unexpected answer to {command}"
			))),
		}
	}

	/// Say goodbye; errors are ignored, the work is already done.
	pub(crate) async fn logout(mut self) {
		let _ = self.command("LOGOUT", b"LOGOUT", |_| Ok(())).await;
	}
}

/// The most mailboxes one account may list.
pub(crate) const MAX_MAILBOXES: usize = 10_000;

#[cfg(test)]
mod tests;
