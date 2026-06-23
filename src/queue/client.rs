//! Minimal SMTP client for outbound delivery.
//!
//! Speaks just enough ESMTP to hand a message to a remote server: EHLO,
//! opportunistic STARTTLS, MAIL, RCPT, DATA. Strict about replies; any
//! unexpected code aborts the attempt.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::dane::policy::DaneOutcome;
use crate::dane::tlsa::TlsaRecord;
use crate::dane::verify::verify_chain;

/// Whether the attempt may be retried later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
	/// 4xx or connection trouble: retry later.
	Transient(String),
	/// 5xx: the remote refused permanently.
	Permanent(String),
}

impl DeliveryError {
	fn from_reply(code: u16, line: &str) -> Self {
		if code >= 500 {
			DeliveryError::Permanent(format!("{code} {line}"))
		} else {
			DeliveryError::Transient(format!("{code} {line}"))
		}
	}
}

/// One outbound delivery attempt over an established stream.
///
/// `server_name` is the MX hostname used for TLS verification when the remote
/// offers STARTTLS. `tlsa` are the DNSSEC-validated TLSA records for this MX (an
/// empty slice means none): when present they make STARTTLS mandatory and the
/// presented certificate is authenticated against them (RFC 7672). TLS is
/// otherwise opportunistic: a remote without STARTTLS and no TLSA still gets the
/// mail. Fail closed: a TLSA mismatch, or DANE-mandated STARTTLS the remote does
/// not offer, returns a transient error so the message is retried, never sent in
/// the clear.
#[allow(clippy::too_many_arguments)]
pub async fn deliver<S>(
	stream: S,
	server_name: &str,
	ehlo_hostname: &str,
	reverse_path: &str,
	recipients: &[String],
	data: &[u8],
	require_tls: bool,
	auth: Option<(&str, &str)>,
	tlsa: &[TlsaRecord],
) -> Result<(), DeliveryError>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let mut conn = Conn::new(Box::new(stream));
	conn.expect(220).await?;

	conn.command(&format!("EHLO {ehlo_hostname}"), 250).await?;
	let offers_starttls = conn.last_reply_contains("STARTTLS");
	// DANE presence makes STARTTLS mandatory (RFC 7672 §2.2): never downgrade.
	if (require_tls || !tlsa.is_empty()) && !offers_starttls {
		return Err(DeliveryError::Transient(
			"TLS required (MTA-STS/DANE) but remote offers no STARTTLS".into(),
		));
	}

	let mut tls_active = false;
	if offers_starttls {
		conn.command("STARTTLS", 220).await?;
		let inner = conn.into_inner();
		let (tls, peer_chain) = tls_connect(inner, server_name).await?;
		// DANE: authenticate the presented chain against validated TLSA records.
		// With none, this is a no-op (opportunistic); a mismatch fails closed.
		match verify_chain(tlsa, &peer_chain) {
			DaneOutcome::Authenticated | DaneOutcome::NoRecords => {}
			DaneOutcome::Mismatch => {
				return Err(DeliveryError::Transient(format!(
					"DANE: no TLSA record matches the certificate of {server_name}"
				)));
			}
		}
		conn = Conn::new(Box::new(tls));
		conn.command(&format!("EHLO {ehlo_hostname}"), 250).await?;
		tls_active = true;
	}

	// Relay (submission) AUTH: only over TLS, never in plaintext (fail closed).
	if let Some((username, password)) = auth {
		if !tls_active {
			return Err(DeliveryError::Permanent(
				"relay AUTH requested but smarthost offered no STARTTLS".into(),
			));
		}
		use base64::Engine;
		let token =
			base64::engine::general_purpose::STANDARD.encode(format!("\0{username}\0{password}"));
		conn.command(&format!("AUTH PLAIN {token}"), 235).await?;
	}

	conn.command(&format!("MAIL FROM:<{reverse_path}>"), 250)
		.await?;
	for recipient in recipients {
		conn.command(&format!("RCPT TO:<{recipient}>"), 250).await?;
	}
	conn.command("DATA", 354).await?;
	conn.send_data(data).await?;
	conn.expect(250).await?;
	let _ = conn.command("QUIT", 221).await;
	Ok(())
}

/// Complete a STARTTLS handshake, returning the encrypted stream and the DER
/// certificate chain the peer presented (leaf first), for DANE authentication.
async fn tls_connect(
	stream: Box<dyn Stream>,
	server_name: &str,
) -> Result<
	(
		tokio_rustls::client::TlsStream<Box<dyn Stream>>,
		Vec<Vec<u8>>,
	),
	DeliveryError,
> {
	let mut roots = RootCertStore::empty();
	roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let name = ServerName::try_from(server_name.to_string())
		.map_err(|_| DeliveryError::Transient(format!("invalid TLS name {server_name}")))?;
	let tls = TlsConnector::from(Arc::new(config))
		.connect(name, stream)
		.await
		.map_err(|error| DeliveryError::Transient(format!("TLS handshake failed: {error}")))?;
	let peer_chain = tls
		.get_ref()
		.1
		.peer_certificates()
		.map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
		.unwrap_or_default();
	Ok((tls, peer_chain))
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Buffered SMTP conversation state.
struct Conn {
	stream: Box<dyn Stream>,
	buffer: Vec<u8>,
	last_reply: String,
}

impl Conn {
	fn new(stream: Box<dyn Stream>) -> Self {
		Conn {
			stream,
			buffer: Vec::new(),
			last_reply: String::new(),
		}
	}

	fn into_inner(self) -> Box<dyn Stream> {
		self.stream
	}

	fn last_reply_contains(&self, needle: &str) -> bool {
		self.last_reply.contains(needle)
	}

	async fn command(&mut self, line: &str, expected: u16) -> Result<(), DeliveryError> {
		self.stream
			.write_all(format!("{line}\r\n").as_bytes())
			.await
			.map_err(io_transient)?;
		self.stream.flush().await.map_err(io_transient)?;
		self.expect(expected).await
	}

	/// Send message data with dot-stuffing and the final terminator.
	async fn send_data(&mut self, data: &[u8]) -> Result<(), DeliveryError> {
		let mut wire = Vec::with_capacity(data.len() + 16);
		for line in data.split_inclusive(|&b| b == b'\n') {
			if line.first() == Some(&b'.') {
				wire.push(b'.');
			}
			wire.extend_from_slice(line);
		}
		if !wire.ends_with(b"\r\n") {
			wire.extend_from_slice(b"\r\n");
		}
		wire.extend_from_slice(b".\r\n");
		self.stream.write_all(&wire).await.map_err(io_transient)?;
		self.stream.flush().await.map_err(io_transient)
	}

	/// Read one (possibly multiline) reply and require `expected`.
	async fn expect(&mut self, expected: u16) -> Result<(), DeliveryError> {
		let reply = self.read_reply().await?;
		let code: u16 = reply
			.get(..3)
			.and_then(|head| head.parse().ok())
			.ok_or_else(|| DeliveryError::Transient(format!("malformed reply: {reply}")))?;
		self.last_reply = reply;
		if code != expected {
			return Err(DeliveryError::from_reply(code, &self.last_reply));
		}
		Ok(())
	}

	async fn read_reply(&mut self) -> Result<String, DeliveryError> {
		loop {
			if let Some(reply) = complete_reply(&self.buffer) {
				let text = String::from_utf8_lossy(&self.buffer[..reply]).to_string();
				self.buffer.drain(..reply);
				return Ok(text);
			}
			if self.buffer.len() > 64 * 1024 {
				return Err(DeliveryError::Transient("oversized reply".into()));
			}
			let mut chunk = [0u8; 4096];
			let read = self.stream.read(&mut chunk).await.map_err(io_transient)?;
			if read == 0 {
				return Err(DeliveryError::Transient(
					"connection closed mid-reply".into(),
				));
			}
			self.buffer.extend_from_slice(&chunk[..read]);
		}
	}
}

fn io_transient(error: std::io::Error) -> DeliveryError {
	DeliveryError::Transient(error.to_string())
}

/// Length of a complete reply in `buffer` (through the final CRLF of its
/// last line), or `None` if more bytes are needed.
fn complete_reply(buffer: &[u8]) -> Option<usize> {
	let mut offset = 0;
	loop {
		let rest = &buffer[offset..];
		let line_end = rest.windows(2).position(|w| w == b"\r\n")? + 2;
		let line = &rest[..line_end];
		// A line like `250-...` continues; `250 ...` (or bare code) ends.
		let continues = line.len() >= 4 && line[3] == b'-';
		offset += line_end;
		if !continues {
			return Some(offset);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn detects_complete_single_line_reply() {
		assert_eq!(complete_reply(b"250 ok\r\n"), Some(8));
		assert_eq!(complete_reply(b"250 ok"), None);
	}

	#[test]
	fn detects_multiline_reply() {
		let reply = b"250-a\r\n250-b\r\n250 c\r\n";
		assert_eq!(complete_reply(reply), Some(reply.len()));
		assert_eq!(complete_reply(b"250-a\r\n"), None);
	}

	#[tokio::test]
	async fn delivers_to_own_server() {
		use crate::smtp::directory::Directory;
		use crate::smtp::server::Server;
		use crate::smtp::sink::{MemorySink, MessageSink};

		let sink = Arc::new(MemorySink::new());
		let directory = crate::directory_store::DirectoryHandle::new(Directory::new(
			["example.org".to_string()],
			[("bob@example.org".to_string(), "bob".to_string())],
		));
		let server = Server::new("mx.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(directory);

		let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream, None).await });

		deliver(
			client_stream,
			"mx.example.org",
			"mail.sender.example",
			"alice@sender.example",
			&["bob@example.org".to_string()],
			b"Subject: hi\r\n\r\n.leading dot\r\nbody\r\n",
			false,
			None,
			&[],
		)
		.await
		.expect("delivery succeeds");

		task.abort();
		let messages = sink.messages();
		assert_eq!(messages.len(), 1);
		assert_eq!(messages[0].reverse_path, "alice@sender.example");
		let data = String::from_utf8(messages[0].data.clone()).expect("ascii");
		// Dot-stuffing round-trips.
		assert!(data.ends_with(".leading dot\r\nbody\r\n"), "{data}");
	}

	#[tokio::test]
	async fn permanent_rejection_is_permanent() {
		use crate::smtp::directory::Directory;
		use crate::smtp::server::Server;
		use crate::smtp::sink::{MemorySink, MessageSink};

		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mx.example.org", sink as Arc<dyn MessageSink>).with_directory(
			crate::directory_store::DirectoryHandle::new(Directory::new(
				["example.org".to_string()],
				[],
			)),
		);

		let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream, None).await });

		let result = deliver(
			client_stream,
			"mx.example.org",
			"mail.sender.example",
			"alice@sender.example",
			&["unknown@example.org".to_string()],
			b"body\r\n",
			false,
			None,
			&[],
		)
		.await;

		task.abort();
		assert!(matches!(result, Err(DeliveryError::Permanent(_))));
	}

	/// Drive `deliver` against a canned server response (writes are discarded).
	async fn deliver_against(greeting: &'static [u8]) -> Result<(), DeliveryError> {
		let stream = tokio::io::join(greeting, tokio::io::sink());
		deliver(
			stream,
			"mx.example.org",
			"mail.sender.example",
			"alice@sender.example",
			&["bob@example.org".to_string()],
			b"body\r\n",
			false,
			None,
			&[],
		)
		.await
	}

	#[tokio::test]
	async fn malformed_greeting_is_transient() {
		let result = deliver_against(b"not-a-code\r\n").await;
		assert!(
			matches!(result, Err(DeliveryError::Transient(_))),
			"{result:?}"
		);
	}

	#[tokio::test]
	async fn relay_auth_without_tls_is_permanent() {
		// Greeting then an EHLO reply offering no STARTTLS.
		let canned: &[u8] = b"220 mx ready\r\n250-mx.example.org\r\n250 SIZE 0\r\n";
		let stream = tokio::io::join(canned, tokio::io::sink());
		let result = deliver(
			stream,
			"mx.example.org",
			"mail.sender.example",
			"alice@sender.example",
			&["bob@example.org".to_string()],
			b"body\r\n",
			false,
			Some(("user", "pass")),
			&[],
		)
		.await;
		// AUTH credentials must never cross plaintext: fail closed.
		assert!(
			matches!(result, Err(DeliveryError::Permanent(_))),
			"{result:?}"
		);
	}

	#[tokio::test]
	async fn connection_closed_before_greeting_is_transient() {
		let result = deliver_against(b"").await;
		assert!(
			matches!(result, Err(DeliveryError::Transient(_))),
			"{result:?}"
		);
	}

	#[tokio::test]
	async fn oversized_reply_is_transient() {
		// 70 KiB with no CRLF: the reply never completes and trips the cap.
		const HUGE: &[u8] = &[b'a'; 70 * 1024];
		let result = deliver_against(HUGE).await;
		assert!(
			matches!(result, Err(DeliveryError::Transient(_))),
			"{result:?}"
		);
	}
}
