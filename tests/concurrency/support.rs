//! Shared fixtures; protocol reads come from the hostile SMTP harness.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use epistle::directory_store::DirectoryHandle;
use epistle::smtp::server::{Server, TlsMode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

use super::wire;

pub const SEED: u64 = 0x1426_cc01_5eed_0064;
pub const DEADLINE: Duration = Duration::from_secs(60);
pub const TASKS: usize = 64;
pub type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Printed before any fallible setup, and therefore captured on every panic.
pub fn seed(case: &str) {
	eprintln!("concurrency case={case} seed={SEED:#018x}");
}

pub fn next(state: &mut u64) -> u64 {
	*state ^= *state << 13;
	*state ^= *state >> 7;
	*state ^= *state << 17;
	*state
}

pub struct Listener {
	pub addr: SocketAddr,
	_guard: wire::AbortOnDrop,
}

impl Listener {
	pub async fn start(server: Server) -> Self {
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind SMTP");
		let addr = listener.local_addr().expect("SMTP address");
		let server = server
			.with_max_connections(128)
			.with_max_connections_per_ip(128);
		let task = tokio::spawn(Arc::new(server).serve(listener));
		Self {
			addr,
			_guard: wire::AbortOnDrop(task.abort_handle()),
		}
	}

	pub async fn connect(&self) -> TcpStream {
		connect(self.addr).await
	}
}

pub async fn connect(addr: SocketAddr) -> TcpStream {
	let mut stream = tokio::time::timeout(DEADLINE, TcpStream::connect(addr))
		.await
		.expect("connect deadline")
		.expect("SMTP connection");
	stream.set_nodelay(true).expect("TCP_NODELAY");
	wire::expect(&mut stream, "220 mx.epistle.test ESMTP ready\r\n").await;
	wire::ehlo(&mut stream).await;
	stream
}

pub struct Tls {
	pub acceptor: epistle::tls::ReloadableAcceptor,
	connector: TlsConnector,
}

impl Tls {
	pub fn new() -> Self {
		epistle::tls::ensure_crypto_provider();
		let cert = rcgen::generate_simple_self_signed(vec!["mx.epistle.test".into()])
			.expect("test certificate");
		let acceptor = epistle::tls::acceptor_from_pem(
			cert.cert.pem().as_bytes(),
			cert.signing_key.serialize_pem().as_bytes(),
		)
		.expect("TLS acceptor");
		let mut roots = RootCertStore::empty();
		roots
			.add(cert.cert.der().clone())
			.expect("trust test certificate");
		let config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		Self {
			acceptor: epistle::tls::ReloadableAcceptor::new(acceptor),
			connector: TlsConnector::from(Arc::new(config)),
		}
	}

	pub fn server(&self, server: Server) -> Server {
		server.with_tls(self.acceptor.clone(), TlsMode::Opportunistic)
	}

	pub async fn connect(&self, listener: &Listener) -> TlsStream {
		let mut tcp = listener.connect().await;
		wire::send(&mut tcp, b"STARTTLS\r\n").await;
		wire::expect(&mut tcp, "220 ready to start TLS\r\n").await;
		let mut stream = tokio::time::timeout(
			DEADLINE,
			self.connector.connect(
				ServerName::try_from("mx.epistle.test").expect("server name"),
				tcp,
			),
		)
		.await
		.expect("TLS deadline")
		.expect("TLS handshake");
		wire::ehlo(&mut stream).await;
		stream
	}
}

pub fn directory() -> DirectoryHandle {
	DirectoryHandle::new(wire::directory())
}

pub async fn login(stream: &mut TlsStream, password: &str) {
	let credentials =
		base64::engine::general_purpose::STANDARD.encode(format!("\0tester\0{password}"));
	wire::send(stream, format!("AUTH PLAIN {credentials}\r\n").as_bytes()).await;
	wire::expect(stream, "235 2.7.0 authentication successful\r\n").await;
}

pub async fn data<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, authenticated: bool) {
	let sender = if authenticated {
		"tester@epistle.test"
	} else {
		"sender@remote.test"
	};
	wire::send(stream, format!("MAIL FROM:<{sender}>\r\n").as_bytes()).await;
	wire::expect(stream, wire::OK).await;
	wire::send(stream, b"RCPT TO:<tester@epistle.test>\r\n").await;
	wire::expect(stream, wire::OK).await;
	wire::send(stream, b"DATA\r\n").await;
	wire::expect(stream, "354 start mail input, end with <CRLF>.<CRLF>\r\n").await;
}

/// Short legal lines, fixed width ids, no dot stuffing or header rewriting needed.
pub fn message(id: usize, lines: usize, authenticated: bool) -> Vec<u8> {
	let sender = if authenticated {
		"tester@epistle.test"
	} else {
		"sender@remote.test"
	};
	let mut raw = format!(
		"From: {sender}\r\nTo: tester@epistle.test\r\nMessage-ID: <cc-{id:04}@epistle.test>\r\nDate: Fri, 30 Oct 2026 12:00:00 +0000\r\nSubject: concurrency {id:04}\r\n\r\n"
	).into_bytes();
	for n in 0..lines {
		raw.extend_from_slice(format!("{id:04}:{n:06}:{}\r\n", "x".repeat(110)).as_bytes());
	}
	raw
}

/// Compare the entire submitted suffix, including its body, independently of trace fields.
pub fn inventory(
	messages: Vec<Vec<u8>>,
	lines: usize,
	authenticated: bool,
) -> BTreeMap<usize, usize> {
	let mut counts = BTreeMap::new();
	for raw in messages {
		let text = std::str::from_utf8(&raw).expect("stored message UTF-8");
		let id = text
			.split("Message-ID: <cc-")
			.nth(1)
			.expect("stored Message-ID")
			.split('@')
			.next()
			.expect("id")
			.parse::<usize>()
			.expect("numeric id");
		let expected = message(id, lines, authenticated);
		assert!(
			raw.ends_with(&expected),
			"seed={SEED:#x} incomplete or altered message {id}"
		);
		*counts.entry(id).or_default() += 1;
	}
	counts
}

pub fn mailbox(root: &Path) -> Vec<Vec<u8>> {
	std::fs::read_dir(root.join("accounts/tester/new"))
		.expect("read mailbox")
		.map(|entry| entry.expect("mailbox entry").path())
		.filter(|path| path.extension().is_some_and(|ext| ext == "eml"))
		.map(|path| std::fs::read(path).expect("read complete message"))
		.collect()
}
