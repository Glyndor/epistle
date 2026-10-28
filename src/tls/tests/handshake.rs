//! A client that opens a TLS listener, or asks for STARTTLS, and then
//! never completes the handshake must not hold the connection forever:
//! every listener gives up after the handshake timeout.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::directory_store::DirectoryHandle;
use crate::smtp::directory::Directory;
use crate::smtp::sink::{MemorySink, MessageSink};

/// Longer than any handshake timeout, shorter than every idle timeout.
const PATIENCE: Duration = Duration::from_secs(120);

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(["example.org".to_string()], []))
}

/// Read until `needle` arrives.
async fn read_until(client: &mut DuplexStream, needle: &str) {
	let mut got = String::new();
	let mut chunk = [0u8; 1024];
	while !got.contains(needle) {
		let n = client.read(&mut chunk).await.expect("read");
		assert!(n > 0, "closed before {needle:?}: {got:?}");
		got.push_str(&String::from_utf8_lossy(&chunk[..n]));
	}
}

/// The server task gives up on the stalled handshake within `PATIENCE`.
async fn gives_up<T: std::fmt::Debug>(task: tokio::task::JoinHandle<T>, what: &str) {
	let ended = tokio::time::timeout(PATIENCE, task).await;
	assert!(
		ended.is_ok(),
		"{what}: a stalled TLS handshake was never cut off"
	);
}

fn smtp(mode: crate::smtp::server::TlsMode) -> crate::smtp::server::Server {
	let (acceptor, _cert) = super::test_support::acceptor_and_cert();
	crate::smtp::server::Server::new(
		"mail.example.org",
		Arc::new(MemorySink::new()) as Arc<dyn MessageSink>,
	)
	.with_directory(directory())
	.with_tls(super::ReloadableAcceptor::new(acceptor), mode)
}

#[tokio::test(start_paused = true)]
async fn smtp_implicit_tls() {
	let server = smtp(crate::smtp::server::TlsMode::Implicit);
	let (_client, stream) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move { server.handle(stream, None).await });
	gives_up(task, "submissions").await;
}

#[tokio::test(start_paused = true)]
async fn smtp_starttls() {
	let server = smtp(crate::smtp::server::TlsMode::Opportunistic);
	let (mut client, stream) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move { server.handle(stream, None).await });
	read_until(&mut client, "220 ").await;
	client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	read_until(&mut client, "250 ").await;
	client.write_all(b"STARTTLS\r\n").await.expect("starttls");
	read_until(&mut client, "220 ").await;
	gives_up(task, "SMTP STARTTLS").await;
}

fn imap(mode: crate::imap::server::TlsMode) -> (crate::imap::server::Server, tempfile::TempDir) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, _cert) = super::test_support::acceptor_and_cert();
	let server = crate::imap::server::Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		mode,
	);
	(server, dir)
}

#[tokio::test(start_paused = true)]
async fn imap_implicit_tls() {
	let (server, _dir) = imap(crate::imap::server::TlsMode::Implicit);
	let (_client, stream) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move { server.handle(stream, None).await });
	gives_up(task, "imaps").await;
}

#[tokio::test(start_paused = true)]
async fn imap_starttls() {
	let (server, _dir) = imap(crate::imap::server::TlsMode::StartTls);
	let (mut client, stream) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move { server.handle(stream, None).await });
	read_until(&mut client, "* OK").await;
	client
		.write_all(b"a1 STARTTLS\r\n")
		.await
		.expect("starttls");
	read_until(&mut client, "a1 OK").await;
	gives_up(task, "IMAP STARTTLS").await;
}

#[tokio::test(start_paused = true)]
async fn managesieve_starttls() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, _cert) = super::test_support::acceptor_and_cert();
	let server =
		crate::managesieve::server::Server::new(dir.path().to_path_buf(), directory(), acceptor);
	let (mut client, stream) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move { server.handle_stream(stream).await });
	read_until(&mut client, "OK").await;
	client.write_all(b"STARTTLS\r\n").await.expect("starttls");
	read_until(&mut client, "OK").await;
	gives_up(task, "ManageSieve STARTTLS").await;
}

#[tokio::test(start_paused = true)]
async fn pop3_implicit_tls() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, _cert) = super::test_support::acceptor_and_cert();
	let server = Arc::new(crate::pop3::server::Server::new(
		dir.path().to_path_buf(),
		directory(),
		acceptor,
	));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(server.serve(listener));
	let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
	let mut byte = [0u8; 1];
	let closed = tokio::time::timeout(PATIENCE, client.read(&mut byte)).await;
	assert!(
		matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
		"pop3s: a stalled TLS handshake was never cut off"
	);
}
