//! Bounded raw-wire clients and a fresh production listener per test.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use epistle::directory_store::DirectoryHandle;
use epistle::imap::server::{Server, TlsMode};
use epistle::smtp::directory::Directory;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

pub const IO_DEADLINE: Duration = Duration::from_secs(15);
pub const SHORT: Duration = Duration::from_secs(2);
/// A password minted when the test starts, so no credential sits in the source.
pub struct Password;

pub static PASSWORD: Password = Password;

impl Password {
	fn minted() -> &'static str {
		static VALUE: std::sync::LazyLock<String> =
			std::sync::LazyLock::new(|| format!("Fx1!{}", uuid::Uuid::new_v4().simple()));
		VALUE.as_str()
	}
}

impl std::ops::Deref for Password {
	type Target = str;

	fn deref(&self) -> &str {
		Self::minted()
	}
}

impl std::fmt::Display for Password {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(Self::minted())
	}
}
pub const PROTOCOL: &str = "* BYE protocol error\r\n";
pub const TOO_LONG: &str = "* BYE line too long\r\n";
pub type Tls = tokio_rustls::client::TlsStream<TcpStream>;

pub struct AbortOnDrop(pub tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
	fn drop(&mut self) {
		self.0.abort();
	}
}

pub struct Harness {
	pub addr: SocketAddr,
	pub data: tempfile::TempDir,
	connector: TlsConnector,
	_task: AbortOnDrop,
}

impl Harness {
	pub async fn start(configure: impl FnOnce(Server) -> Server) -> Self {
		epistle::tls::ensure_crypto_provider();
		let cert = rcgen::generate_simple_self_signed(vec!["mail.epistle.test".into()])
			.expect("self-signed certificate");
		let acceptor = epistle::tls::acceptor_from_pem(
			cert.cert.pem().as_bytes(),
			cert.signing_key.serialize_pem().as_bytes(),
		)
		.expect("TLS acceptor");
		let mut roots = RootCertStore::empty();
		roots
			.add(cert.cert.der().clone())
			.expect("trust certificate");
		let config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		// Hash once, then give each listener an independent directory and store.
		static HASH: OnceLock<String> = OnceLock::new();
		let hash = HASH.get_or_init(|| {
			epistle::smtp::auth::hash_password(&PASSWORD).expect("fixture password hash")
		});
		let directory = Directory::new(
			["epistle.test".to_string()],
			[("tester@epistle.test".to_string(), "tester".to_string())],
		)
		.with_password_hashes([("tester".to_string(), hash.clone())]);
		let data = tempfile::tempdir().expect("isolated mail store");
		let server = configure(Server::new(
			"mail.epistle.test",
			data.path().to_path_buf(),
			DirectoryHandle::new(directory),
			acceptor,
			TlsMode::StartTls,
		));
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind IMAP");
		let addr = listener.local_addr().expect("listener address");
		let task = tokio::spawn(Arc::new(server).serve(listener));
		Self {
			addr,
			data,
			connector: TlsConnector::from(Arc::new(config)),
			_task: AbortOnDrop(task.abort_handle()),
		}
	}

	pub async fn connect(&self) -> TcpStream {
		let mut client = timeout(IO_DEADLINE, TcpStream::connect(self.addr))
			.await
			.expect("connect deadline")
			.expect("connect IMAP");
		client.set_nodelay(true).expect("disable Nagle");
		let greeting = line(&mut client).await.expect("greeting").expect("open");
		assert!(greeting.starts_with("* OK [CAPABILITY "), "{greeting:?}");
		assert!(greeting.contains(" LOGINDISABLED]"), "{greeting:?}");
		assert!(greeting.ends_with(" mail.epistle.test IMAP4rev2 ready\r\n"));
		client
	}

	pub async fn try_upgrade(&self, tcp: TcpStream) -> io::Result<Tls> {
		let name = ServerName::try_from("mail.epistle.test").expect("server name");
		timeout(IO_DEADLINE, self.connector.connect(name, tcp))
			.await
			.expect("TLS deadline")
	}

	pub async fn encrypted(&self) -> Tls {
		let mut client = self.connect().await;
		send(&mut client, b"T STARTTLS\r\n").await;
		expect(&mut client, "T OK begin TLS now\r\n").await;
		self.try_upgrade(client).await.expect("TLS handshake")
	}

	pub async fn authenticated(&self) -> Tls {
		let mut client = self.encrypted().await;
		send(
			&mut client,
			format!("L LOGIN tester {PASSWORD}\r\n").as_bytes(),
		)
		.await;
		expect(&mut client, "L OK LOGIN completed\r\n").await;
		client
	}

	/// Probe the same listener with a new connection after every attack.
	pub async fn healthy(&self) {
		let mut client = self.connect().await;
		noop(&mut client).await;
		logout(&mut client).await;
	}
}

pub async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) {
	timeout(IO_DEADLINE, stream.write_all(bytes))
		.await
		.expect("write deadline")
		.expect("write IMAP");
}

/// Preserve CRLF and leave the next reply untouched, including across TLS.
pub async fn line<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Option<String>> {
	timeout(IO_DEADLINE, async {
		let mut bytes = Vec::new();
		loop {
			let mut byte = [0];
			match stream.read(&mut byte).await {
				Ok(0) if bytes.is_empty() => return Ok(None),
				Ok(0) => panic!("closed mid-reply: {bytes:?}"),
				Ok(_) => bytes.push(byte[0]),
				Err(e) => return Err(e),
			}
			assert!(bytes.len() <= 4096, "unbounded reply");
			if bytes.ends_with(b"\r\n") {
				return Ok(Some(String::from_utf8(bytes).expect("UTF-8 reply")));
			}
		}
	})
	.await
	.expect("reply deadline")
}

pub async fn expect<S: AsyncRead + Unpin>(stream: &mut S, expected: &str) {
	assert_eq!(
		line(stream).await.expect("read reply").as_deref(),
		Some(expected)
	);
}

pub fn is_close(error: &io::Error) -> bool {
	matches!(
		error.kind(),
		io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
	)
}

pub async fn closed<S: AsyncRead + Unpin>(stream: &mut S) {
	match line(stream).await {
		Ok(None) => {}
		Err(e) if is_close(&e) => {}
		other => panic!("expected connection close, got {other:?}"),
	}
}

/// Timeout paths may lose their BYE when its shared write deadline expired.
pub async fn timed_out<S: AsyncRead + Unpin>(stream: &mut S) {
	match line(stream).await {
		Ok(None) => {}
		Err(e) if is_close(&e) => {}
		Ok(Some(reply)) => {
			assert_eq!(reply, "* BYE idle timeout\r\n");
			closed(stream).await;
		}
		other => panic!("expected timeout close, got {other:?}"),
	}
}

pub async fn noop<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
	send(stream, b"N NOOP\r\n").await;
	expect(stream, "N OK NOOP completed\r\n").await;
}

pub async fn logout<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
	send(stream, b"Q LOGOUT\r\n").await;
	expect(stream, "* BYE logging out\r\n").await;
	expect(stream, "Q OK LOGOUT completed\r\n").await;
	closed(stream).await;
}

/// Collect only a bounded SELECT response; other commands use exact lines.
pub async fn select_inbox<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> String {
	send(stream, b"S SELECT INBOX\r\n").await;
	let mut response = String::new();
	for _ in 0..20 {
		let reply = line(stream)
			.await
			.expect("SELECT reply")
			.expect("SELECT open");
		let done = reply == "S OK [READ-WRITE] SELECT completed\r\n";
		assert!(done || reply.starts_with("* "), "{reply:?}");
		response.push_str(&reply);
		if done {
			return response;
		}
	}
	panic!("unbounded SELECT response");
}
