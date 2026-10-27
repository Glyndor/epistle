//! Shared bounded I/O and TLS fixtures for both hostile protocol targets.

use std::io;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use epistle::directory_store::DirectoryHandle;
use epistle::smtp::directory::Directory;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

pub const IO_DEADLINE: Duration = Duration::from_secs(15);
pub const SHORT: Duration = Duration::from_secs(2);
pub const PASSWORD: &str = "HostileFixture37!Valid";
pub type Tls = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

pub struct AbortOnDrop(pub tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
	fn drop(&mut self) {
		self.0.abort();
	}
}

pub fn fixtures() -> (tokio_rustls::TlsAcceptor, TlsConnector, DirectoryHandle) {
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
	static HASH: OnceLock<String> = OnceLock::new();
	let hash = HASH.get_or_init(|| {
		epistle::smtp::auth::hash_password(PASSWORD).expect("fixture password hash")
	});
	let directory = Directory::new(
		["epistle.test".to_string()],
		[
			("tester@epistle.test".to_string(), "tester".to_string()),
			("victim@epistle.test".to_string(), "victim".to_string()),
		],
	)
	.with_password_hashes([
		("tester".to_string(), hash.clone()),
		("victim".to_string(), hash.clone()),
	]);
	(
		acceptor,
		TlsConnector::from(Arc::new(config)),
		DirectoryHandle::new(directory),
	)
}

pub async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) {
	timeout(IO_DEADLINE, stream.write_all(bytes))
		.await
		.expect("write deadline")
		.expect("write command");
}

/// Preserve CRLF and never consume bytes belonging to the next reply.
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
		other => panic!("expected close, got {other:?}"),
	}
}

pub async fn flood<S: AsyncWrite + Unpin>(stream: &mut S, command: &[u8]) {
	match timeout(IO_DEADLINE, stream.write_all(&command.repeat(5000))).await {
		Ok(Ok(())) => {}
		Ok(Err(e)) if is_close(&e) || e.kind() == io::ErrorKind::BrokenPipe => {}
		other => panic!("flood stalled or failed: {other:?}"),
	}
}

/// Advance hard-coded authenticated idle clocks only after real socket setup.
pub async fn elapse_idle(seconds: u64) {
	sleep(Duration::from_millis(50)).await;
	tokio::time::pause();
	tokio::time::advance(Duration::from_secs(seconds)).await;
	tokio::task::yield_now().await;
	tokio::time::resume();
}
