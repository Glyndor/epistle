//! A minimal IMAP client: just the commands a one-way copy needs, over
//! implicit TLS, STARTTLS or (only when the operator insists) plaintext.
//!
//! Every response goes through [`super::wire`], so lines, literals and
//! waits are bounded. Credentials are written to the socket and nowhere
//! else: no command line that carries one is logged, kept, or put in an
//! error message.

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use super::parse::{self, Fetched, Kind, ListEntry, Listed, Status};
use super::transport::{Endpoint, Io, Security, handshake, resolve};
use super::wire::{Limits, Response, WireError, read_response};

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
}

/// What EXAMINE reported about a mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Examined {
	/// Number of messages.
	pub(crate) exists: u32,
	/// UIDVALIDITY, `0` when the server sent none.
	pub(crate) uid_validity: u32,
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
		let tag = self.next_tag();
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

	/// Every mailbox with its special-use attributes: asked for with
	/// `RETURN (SPECIAL-USE)` when the server has LIST-EXTENDED (RFC 6154
	/// only promises them then), through XLIST on servers that predate
	/// SPECIAL-USE, plain LIST otherwise.
	pub(crate) async fn list(&mut self) -> Result<Vec<ListEntry>, ClientError> {
		let line: &[u8] = if self.has("SPECIAL-USE") && self.has("LIST-EXTENDED") {
			b"LIST \"\" \"*\" RETURN (SPECIAL-USE)"
		} else if self.has("XLIST") && !self.has("SPECIAL-USE") {
			b"XLIST \"\" \"*\""
		} else {
			b"LIST \"\" \"*\""
		};
		let mut entries = Vec::new();
		self.command("LIST", line, |response| {
			if let Some(entry) = parse::list_entry(&response)
				.map_err(|error| ClientError::Protocol(error.to_string()))?
			{
				if entries.len() >= MAX_MAILBOXES {
					return Err(ClientError::Protocol("too many mailboxes".into()));
				}
				entries.push(entry);
			}
			Ok(())
		})
		.await?;
		Ok(entries)
	}

	/// The personal namespace prefix, when the server has NAMESPACE.
	pub(crate) async fn namespace(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
		if !self.has("NAMESPACE") {
			return Ok(None);
		}
		let mut prefix = None;
		self.command("NAMESPACE", b"NAMESPACE", |response| {
			if prefix.is_none() {
				prefix = parse::personal_namespace(&response);
			}
			Ok(())
		})
		.await?;
		Ok(prefix)
	}

	/// Open `name` read-only.
	pub(crate) async fn examine(&mut self, name: &[u8]) -> Result<Examined, ClientError> {
		let mut line = b"EXAMINE ".to_vec();
		line.extend_from_slice(&quote_mailbox(name)?);
		let mut examined = Examined {
			exists: 0,
			uid_validity: 0,
		};
		self.command("EXAMINE", &line, |response| {
			let words = parse::data_words(&response);
			match words.as_slice() {
				[count, word, ..] if word.eq_ignore_ascii_case("EXISTS") => {
					examined.exists = count.parse().unwrap_or(0);
				}
				_ => {}
			}
			if let Kind::UntaggedStatus { text, .. } = parse::kind(&response)
				&& let [code, value, ..] = parse::response_code(&text).as_slice()
				&& code.eq_ignore_ascii_case("UIDVALIDITY")
			{
				examined.uid_validity = value.parse().unwrap_or(0);
			}
			Ok(())
		})
		.await?;
		Ok(examined)
	}

	/// The UID and size of every message with a UID of `from` or more, at
	/// most `cap` of them.
	pub(crate) async fn list_uids(
		&mut self,
		from: u32,
		cap: usize,
	) -> Result<Vec<Listed>, ClientError> {
		let line = format!("UID FETCH {from}:* (UID RFC822.SIZE)");
		let mut listed = Vec::new();
		self.command("FETCH", line.as_bytes(), |response| {
			if let Some(item) =
				parse::listed(response).map_err(|error| ClientError::Protocol(error.to_string()))?
			{
				if listed.len() >= cap {
					return Err(ClientError::Protocol(
						"the server listed more messages than the mailbox holds".into(),
					));
				}
				if item.uid >= from {
					listed.push(item);
				}
			}
			Ok(())
		})
		.await?;
		listed.sort_by_key(|item| item.uid);
		listed.dedup_by_key(|item| item.uid);
		Ok(listed)
	}

	/// Fetch flags, INTERNALDATE, size and body of every message in `batch`
	/// without setting `\Seen`.
	///
	/// The sizes in `batch` are what the server declared when listing, and
	/// nothing the server declares is trusted for memory: every body that
	/// arrives is checked against its declared size ([`size_fits`]), and the
	/// bodies held for the batch may total at most `budget` octets. Either
	/// failure ends the fetch before more is buffered.
	pub(crate) async fn fetch(
		&mut self,
		batch: &[Listed],
		budget: u64,
	) -> Result<Vec<Fetched>, ClientError> {
		let uids: Vec<u32> = batch.iter().map(|item| item.uid).collect();
		let line = format!(
			"UID FETCH {} (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[])",
			uid_set(&uids)
		);
		let mut fetched: Vec<Fetched> = Vec::with_capacity(uids.len());
		let mut held = 0u64;
		let mut responses = 0usize;
		let most_responses = uids.len().saturating_mul(4).saturating_add(64);
		self.command("FETCH", line.as_bytes(), |response| {
			responses += 1;
			if responses > most_responses {
				return Err(ClientError::Protocol(
					"the server sent far more responses than messages asked for".into(),
				));
			}
			let Some(item) =
				parse::fetch(response).map_err(|error| ClientError::Protocol(error.to_string()))?
			else {
				return Ok(());
			};
			let (Some(body), Ok(at)) = (&item.body, uids.binary_search(&item.uid)) else {
				return Ok(());
			};
			let declared = batch[at].size;
			let actual = body.len() as u64;
			if !size_fits(declared, actual) {
				return Err(ClientError::SizeMismatch {
					uid: item.uid,
					declared,
					actual,
				});
			}
			held = held.saturating_add(actual);
			if held > budget || fetched.len() >= uids.len() {
				return Err(ClientError::BatchTooLarge { budget });
			}
			fetched.push(item);
			Ok(())
		})
		.await?;
		Ok(fetched)
	}

	/// Say goodbye; errors are ignored, the work is already done.
	pub(crate) async fn logout(mut self) {
		let _ = self.command("LOGOUT", b"LOGOUT", |_| Ok(())).await;
	}

	fn next_tag(&mut self) -> Vec<u8> {
		self.tag += 1;
		format!("M{}", self.tag).into_bytes()
	}

	/// Send `line` under a fresh tag and hand every untagged data response
	/// to `on_data` until the tagged completion.
	async fn command(
		&mut self,
		name: &'static str,
		line: &[u8],
		on_data: impl FnMut(Response) -> Result<(), ClientError>,
	) -> Result<(), ClientError> {
		let tag = self.next_tag();
		self.send(&tag, line).await?;
		self.collect(&tag, name, on_data).await
	}

	async fn collect(
		&mut self,
		tag: &[u8],
		name: &'static str,
		mut on_data: impl FnMut(Response) -> Result<(), ClientError>,
	) -> Result<(), ClientError> {
		loop {
			let response = self.read().await?;
			match parse::kind(&response) {
				Kind::Tagged {
					tag: got,
					status,
					text,
				} if got == tag => {
					return match status {
						Status::Ok => {
							self.note_code(&text);
							Ok(())
						}
						_ => Err(ClientError::Refused {
							command: name,
							text: sanitize(&text),
						}),
					};
				}
				Kind::Tagged { .. } => {
					return Err(ClientError::Protocol("answer to an unknown tag".into()));
				}
				Kind::UntaggedStatus {
					status: Status::Bye,
					text,
				} => return Err(ClientError::Bye(sanitize(&text))),
				Kind::UntaggedStatus { .. } | Kind::Data => on_data(response)?,
				Kind::Continuation => {
					return Err(ClientError::Protocol(format!(
						"unexpected continuation during {name}"
					)));
				}
			}
		}
	}

	async fn send(&mut self, tag: &[u8], line: &[u8]) -> Result<(), ClientError> {
		let mut full = Zeroizing::new(Vec::with_capacity(tag.len() + line.len() + 3));
		full.extend_from_slice(tag);
		full.push(b' ');
		full.extend_from_slice(line);
		full.extend_from_slice(b"\r\n");
		self.write(&full).await
	}

	async fn write(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
		let stream = self.conn.get_mut();
		tokio::time::timeout(self.limits.idle, async {
			stream.write_all(bytes).await?;
			stream.flush().await
		})
		.await
		.map_err(|_| WireError::Timeout)?
		.map_err(WireError::Io)?;
		Ok(())
	}

	async fn read(&mut self) -> Result<Response, ClientError> {
		Ok(read_response(&mut self.conn, &self.limits).await?)
	}
}

/// The most mailboxes one account may list.
pub(crate) const MAX_MAILBOXES: usize = 10_000;

/// `value` as an IMAP quoted string.
fn quote(value: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(value.len() + 2);
	out.push(b'"');
	for &byte in value {
		if matches!(byte, b'"' | b'\\') {
			out.push(b'\\');
		}
		out.push(byte);
	}
	out.push(b'"');
	out
}

/// A mailbox name as a quoted string, refusing what a quoted string
/// cannot carry.
fn quote_mailbox(name: &[u8]) -> Result<Vec<u8>, ClientError> {
	if name.iter().any(|&b| matches!(b, b'\0' | b'\r' | b'\n')) {
		return Err(ClientError::Unsendable(
			"the mailbox name contains a NUL or line break",
		));
	}
	Ok(quote(name))
}

/// Whether a body of `actual` octets is close enough to the `declared`
/// RFC822.SIZE: servers count line endings or trailing octets slightly
/// differently, so a tenth plus 4 KiB more is tolerated, nothing beyond.
pub(crate) fn size_fits(declared: u64, actual: u64) -> bool {
	actual <= declared.saturating_add(declared / 10).saturating_add(4096)
}

/// A compact UID set for sorted `uids`: runs become `a:b`.
pub(crate) fn uid_set(uids: &[u32]) -> String {
	let mut out = String::new();
	let mut at = 0;
	while at < uids.len() {
		let start = uids[at];
		let mut end = start;
		while at + 1 < uids.len() && uids[at + 1] == end + 1 {
			at += 1;
			end = uids[at];
		}
		if !out.is_empty() {
			out.push(',');
		}
		if start == end {
			out.push_str(&start.to_string());
		} else {
			out.push_str(&format!("{start}:{end}"));
		}
		at += 1;
	}
	out
}

/// Server text made safe to print: printable ASCII only, at most 200
/// characters.
pub(crate) fn sanitize(text: &[u8]) -> String {
	text.iter()
		.take(200)
		.map(|&b| {
			if (0x20..0x7f).contains(&b) {
				char::from(b)
			} else {
				'?'
			}
		})
		.collect()
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
