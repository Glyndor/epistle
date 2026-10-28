//! A failed accept (out of descriptors, a connection aborted before it
//! was taken, no buffer space) must never end a listener: every listener
//! keeps accepting afterwards, and the failures are counted.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::scripted::{Scripted, failing_then_connecting};
use crate::directory_store::DirectoryHandle;
use crate::smtp::directory::Directory;

const ERRORS: [i32; 4] = [
	libc::EMFILE,
	libc::ECONNABORTED,
	libc::ENFILE,
	libc::ENOBUFS,
];

/// Longer than any backoff, shorter than any protocol timeout.
const PATIENCE: Duration = Duration::from_secs(30);

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(["example.org".to_string()], []))
}

fn failed_accepts() -> u64 {
	crate::metrics::Metrics::new()
		.snapshot()
		.get("accept_failed")
		.copied()
		.unwrap_or(0)
}

/// The client end receives `needle` after the listener has failed four
/// times, and each failure was counted.
async fn served_after_failures(client: &mut DuplexStream, needle: &str, before: u64, what: &str) {
	let mut got = String::new();
	let mut chunk = [0u8; 1024];
	let read = tokio::time::timeout(PATIENCE, async {
		while !got.contains(needle) {
			let n = client.read(&mut chunk).await.expect("read");
			if n == 0 {
				break;
			}
			got.push_str(&String::from_utf8_lossy(&chunk[..n]));
		}
	})
	.await;
	assert!(
		read.is_ok() && got.contains(needle),
		"{what}: the listener stopped after a failed accept"
	);
	assert!(
		failed_accepts() >= before + ERRORS.len() as u64,
		"{what}: failed accepts are not counted"
	);
}

fn listener() -> (Scripted, DuplexStream, u64) {
	let before = failed_accepts();
	let (listener, client) = failing_then_connecting(&ERRORS);
	(listener, client, before)
}

#[tokio::test(start_paused = true)]
async fn smtp_keeps_accepting() {
	let (listener, mut client, before) = listener();
	let server = Arc::new(
		crate::smtp::server::Server::new(
			"mail.example.org",
			Arc::new(crate::smtp::sink::MemorySink::new())
				as Arc<dyn crate::smtp::sink::MessageSink>,
		)
		.with_directory(directory()),
	);
	tokio::spawn(server.serve_on(listener));
	served_after_failures(&mut client, "220 ", before, "SMTP").await;
}

#[tokio::test(start_paused = true)]
async fn imap_keeps_accepting() {
	let (listener, mut client, before) = listener();
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Arc::new(crate::imap::server::Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		crate::imap::server::TlsMode::StartTls,
	));
	tokio::spawn(server.serve_on(listener));
	served_after_failures(&mut client, "* OK", before, "IMAP").await;
}

#[tokio::test(start_paused = true)]
async fn managesieve_keeps_accepting() {
	let (listener, mut client, before) = listener();
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Arc::new(crate::managesieve::server::Server::new(
		dir.path().to_path_buf(),
		directory(),
		acceptor,
	));
	tokio::spawn(server.serve_on(listener));
	served_after_failures(&mut client, "OK", before, "ManageSieve").await;
}

#[tokio::test(start_paused = true)]
async fn pop3_keeps_accepting() {
	let (listener, client, before) = listener();
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Arc::new(crate::pop3::server::Server::new(
		dir.path().to_path_buf(),
		directory(),
		acceptor,
	));
	tokio::spawn(server.serve_on(listener));
	let mut roots = tokio_rustls::rustls::RootCertStore::empty();
	roots.add(cert).expect("trust");
	crate::tls::ensure_crypto_provider();
	let config = tokio_rustls::rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	let handshake = tokio::time::timeout(
		PATIENCE,
		tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, client),
	)
	.await;
	let Ok(Ok(mut tls)) = handshake else {
		panic!("POP3: the listener stopped after a failed accept");
	};
	let mut greeting = [0u8; 64];
	let n = tls.read(&mut greeting).await.expect("greeting");
	assert!(greeting[..n].starts_with(b"+OK"));
	assert!(failed_accepts() >= before + ERRORS.len() as u64);
}

#[tokio::test(start_paused = true)]
async fn http_keeps_accepting() {
	let (listener, mut client, before) = listener();
	let router = axum::Router::new().route("/", axum::routing::get(|| async { "up" }));
	tokio::spawn(crate::net::http_serve::serve_on(listener, router));
	client
		.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		.await
		.expect("request");
	served_after_failures(&mut client, "up", before, "HTTP").await;
}

/// How long `Accepting::next` takes to hand out the connection behind
/// `errors`, on the paused clock.
async fn time_to_accept(errors: &[i32]) -> Duration {
	let (listener, _client) = failing_then_connecting(errors);
	let mut accepting = super::Accepting::new(listener);
	let start = tokio::time::Instant::now();
	accepting.next().await;
	start.elapsed()
}

#[tokio::test(start_paused = true)]
async fn running_out_of_descriptors_backs_off_doubling_to_a_second() {
	// 10 + 20 + 40 + 80 + 160 + 320 + 640 + 1000 + 1000 ms.
	assert_eq!(
		time_to_accept(&[libc::EMFILE; 9]).await,
		Duration::from_millis(3270)
	);
}

#[tokio::test(start_paused = true)]
async fn an_aborted_connection_is_skipped_at_once() {
	assert_eq!(
		time_to_accept(&[libc::ECONNABORTED; 5]).await,
		Duration::ZERO
	);
}
