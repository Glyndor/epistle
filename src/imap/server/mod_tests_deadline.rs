//! The pre-authentication deadline covers every read of the session, counts
//! from its start, and is not extended by traffic. Every test runs on tokio's
//! paused clock.

use super::tests::{directory, read_until};
use super::*;
use crate::test_fixtures as fixtures;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const PREAUTH: Duration = Duration::from_secs(4);
const IDLE: Duration = Duration::from_secs(30);

fn start_server(
	mode: TlsMode,
) -> (
	tokio::io::DuplexStream,
	tokio::task::JoinHandle<std::io::Result<()>>,
	tempfile::TempDir,
	CertificateDer<'static>,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		mode,
	)
	.with_preauth_timeout(PREAUTH)
	.with_read_timeout(IDLE);
	let (client, stream) = tokio::io::duplex(8192);
	let task = tokio::spawn(async move { server.handle(stream, None).await });
	(client, task, dir, cert)
}

/// Complete the TLS handshake on `client`.
async fn handshake(
	client: tokio::io::DuplexStream,
	cert: CertificateDer<'static>,
) -> tokio_rustls::client::TlsStream<tokio::io::DuplexStream> {
	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));
	let name = ServerName::try_from("mail.example.org").expect("name");
	connector.connect(name, client).await.expect("handshake")
}

/// Complete the handshake of an implicit-TLS server and read its greeting.
async fn sign_in_screen(
	client: tokio::io::DuplexStream,
	cert: CertificateDer<'static>,
) -> impl AsyncRead + AsyncWrite + Unpin {
	let mut tls = handshake(client, cert).await;
	read_until(&mut tls, "IMAP4rev2 ready").await;
	tls
}

async fn greeting(client: &mut tokio::io::DuplexStream) {
	let mut buf = [0; 4096];
	assert!(client.read(&mut buf).await.expect("greeting") > 0);
}

/// Send `chunk` once a second until the server hangs up, then return the
/// seconds the connection lived and everything the server said.
async fn drip_until_closed<S: AsyncRead + AsyncWrite + Unpin>(
	client: &mut S,
	start: Instant,
	chunk: &[u8],
) -> (u64, String) {
	for _ in 0..30 {
		if client.write_all(chunk).await.is_err() {
			break;
		}
		tokio::time::sleep(Duration::from_secs(1)).await;
	}
	let mut reply = Vec::new();
	let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply)).await;
	(
		start.elapsed().as_secs(),
		String::from_utf8_lossy(&reply).into_owned(),
	)
}

#[tokio::test(start_paused = true)]
async fn a_silent_client_is_cut_at_the_deadline() {
	let (mut client, task, _dir, _cert) = start_server(TlsMode::StartTls);
	greeting(&mut client).await;
	let start = Instant::now();
	let mut reply = Vec::new();
	client.read_to_end(&mut reply).await.expect("closed");
	assert_eq!(start.elapsed(), PREAUTH);
	assert_eq!(reply, b"* BYE idle timeout\r\n");
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_dripped_command_line_does_not_extend_the_deadline() {
	let (mut client, task, _dir, _cert) = start_server(TlsMode::StartTls);
	greeting(&mut client).await;
	let start = Instant::now();
	let (lived, reply) = drip_until_closed(&mut client, start, b"N").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert!(reply.ends_with("* BYE idle timeout\r\n"), "{reply}");
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_stream_of_commands_does_not_extend_the_deadline() {
	let (mut client, task, _dir, _cert) = start_server(TlsMode::StartTls);
	greeting(&mut client).await;
	let start = Instant::now();
	let (lived, reply) = drip_until_closed(&mut client, start, b"a1 NOOP\r\n").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert!(reply.ends_with("* BYE idle timeout\r\n"), "{reply}");
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_signed_in_literal_has_a_deadline_that_drip_does_not_extend() {
	let (client, task, dir, cert) = start_server(TlsMode::Implicit);
	let _ = dir;
	let mut tls = sign_in_screen(client, cert).await;
	tls.write_all(format!("a1 LOGIN alice {}\r\n", fixtures::password()).as_bytes())
		.await
		.expect("login");
	read_until(&mut tls, "a1 OK").await;
	let start = Instant::now();
	tls.write_all(b"a2 APPEND INBOX {1000}\r\n")
		.await
		.expect("append");
	read_until(&mut tls, "+ ").await;
	let (lived, reply) = drip_until_closed(&mut tls, start, b"x").await;
	assert!(lived <= IDLE.as_secs() + 1, "lived {lived}s");
	assert!(reply.ends_with("* BYE read timeout\r\n"), "{reply}");
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_dripped_discarded_literal_does_not_extend_the_deadline() {
	let (mut client, task, _dir, _cert) = start_server(TlsMode::StartTls);
	greeting(&mut client).await;
	let start = Instant::now();
	client
		.write_all(b"a1 APPEND INBOX {1024+}\r\n")
		.await
		.expect("append");
	let (lived, reply) = drip_until_closed(&mut client, start, b"x").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert!(reply.ends_with("* BYE read timeout\r\n"), "{reply}");
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_dripped_sasl_response_does_not_extend_the_deadline() {
	let (client, task, _dir, cert) = start_server(TlsMode::Implicit);
	let mut tls = sign_in_screen(client, cert).await;
	let start = Instant::now();
	tls.write_all(b"a1 AUTHENTICATE PLAIN\r\n")
		.await
		.expect("authenticate");
	read_until(&mut tls, "+").await;
	let (lived, _) = drip_until_closed(&mut tls, start, b"x").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_stalled_tls_handshake_is_cut_at_the_deadline() {
	let (mut client, task, _dir, _cert) = start_server(TlsMode::Implicit);
	let start = Instant::now();
	let mut reply = Vec::new();
	let _ = client.read_to_end(&mut reply).await;
	assert_eq!(start.elapsed(), PREAUTH);
	assert!(task.await.expect("server task").is_err());
}

#[tokio::test(start_paused = true)]
async fn a_signed_in_session_is_not_held_to_the_pre_auth_deadline() {
	let (client, task, _dir, cert) = start_server(TlsMode::Implicit);
	let mut tls = sign_in_screen(client, cert).await;
	tls.write_all(format!("a1 LOGIN alice {}\r\n", fixtures::password()).as_bytes())
		.await
		.expect("login");
	read_until(&mut tls, "a1 OK").await;
	tokio::time::sleep(PREAUTH * 3).await;
	tls.write_all(b"a2 NOOP\r\n").await.expect("noop");
	read_until(&mut tls, "a2 OK").await;
	task.abort();
}

#[tokio::test(start_paused = true)]
async fn starttls_without_a_client_hello_is_cut_at_the_deadline_of_the_session() {
	let (mut client, task, _dir, _cert) = start_server(TlsMode::StartTls);
	greeting(&mut client).await;
	let start = Instant::now();
	tokio::time::sleep(PREAUTH - Duration::from_secs(2)).await;
	client
		.write_all(b"a1 STARTTLS\r\n")
		.await
		.expect("starttls");
	let mut said = Vec::new();
	let _ = client.read_to_end(&mut said).await;
	assert_eq!(
		start.elapsed(),
		PREAUTH,
		"the handshake gets what is left of the session deadline, not a window of its own"
	);
	assert!(String::from_utf8_lossy(&said).contains("a1 OK"));
	assert!(task.await.expect("server task").is_err());
}

#[tokio::test(start_paused = true)]
async fn the_deadline_does_not_restart_after_the_starttls_handshake() {
	let (mut client, task, _dir, cert) = start_server(TlsMode::StartTls);
	greeting(&mut client).await;
	let start = Instant::now();
	tokio::time::sleep(Duration::from_secs(2)).await;
	client
		.write_all(b"a1 STARTTLS\r\n")
		.await
		.expect("starttls");
	read_until(&mut client, "a1 OK").await;
	let mut tls = handshake(client, cert).await;
	let (lived, reply) = drip_until_closed(&mut tls, start, b"x").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert!(reply.ends_with("* BYE idle timeout\r\n"), "{reply}");
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn audit_preauth_deadline_also_bounds_blocked_output() {
	let (mut client, task, _dir, _cert) = start_server(TlsMode::StartTls);
	greeting(&mut client).await;
	client
		.write_all("a CAPABILITY\r\n".repeat(200).as_bytes())
		.await
		.expect("write");
	for _ in 0..100 {
		tokio::task::yield_now().await;
	}
	tokio::time::advance(PREAUTH * 3).await;
	for _ in 0..100 {
		tokio::task::yield_now().await;
	}
	let ended = task.is_finished();
	task.abort();
	let _ = task.await;
	assert!(
		ended,
		"preauth session remains alive after 3 deadlines while output is blocked"
	);
}

#[tokio::test(start_paused = true)]
async fn the_tail_of_a_rejected_command_with_a_chained_literal_keeps_the_deadline() {
	let (client, task, _dir, cert) = start_server(TlsMode::Implicit);
	let mut tls = sign_in_screen(client, cert).await;
	let start = Instant::now();
	tls.write_all(b"a1 APPEND INBOX {1+}\r\na {100000+}\r\n")
		.await
		.expect("append");
	let (lived, reply) = drip_until_closed(&mut tls, start, b"x").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert!(reply.ends_with("* BYE read timeout\r\n"), "{reply}");
	task.await.expect("server task").expect("server result");
}

/// Build a plaintext IMAP listener that speaks on the test-supplied
/// transport. The listener is built without the directory's password
/// hashes because none of the audit paths reach authentication: a
/// preauth command that should be rejected is enough to drive the
/// discard helpers under test.
fn start_audit_server() -> (tempfile::TempDir, crate::imap::server::Server) {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[],
	));
	let (tls, _) = crate::tls::test_support::acceptor_and_cert();
	let server = crate::imap::server::Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory,
		tls,
		TlsMode::StartTls,
	)
	.with_preauth_timeout(PREAUTH)
	.with_read_timeout(IDLE)
	.with_append_limit(1024);
	(dir, server)
}

#[tokio::test(start_paused = true)]
async fn audit_discard_timeout_write_is_bounded() {
	let (_dir, server) = start_audit_server();
	let (mut client, stream, ctl) = crate::net::tests::audit_support::Gate::pair();
	let task = tokio::spawn(async move { server.handle(stream, None).await });
	crate::net::tests::audit_support::greeting(&mut client).await;
	client
		.write_all(b"a APPEND INBOX {1+}\r\n")
		.await
		.expect("announcement");
	let mut reply = [0u8; 1024];
	let n = client.read(&mut reply).await.expect("reject");
	assert_eq!(&reply[..n], b"a NO not authenticated\r\n");
	ctl.block(1);
	tokio::time::advance(PREAUTH).await;
	crate::net::tests::audit_support::settle().await;
	let ended = task.is_finished();
	if !ended {
		task.abort();
	}
	let _ = task.await;
	assert!(
		ended,
		"discard timeout BYE write holds the transport beyond the deadline"
	);
	assert!(ctl.was_dropped());
}

#[tokio::test(start_paused = true)]
async fn audit_discard_timeout_flush_is_bounded() {
	let (_dir, server) = start_audit_server();
	let (mut client, stream, ctl) = crate::net::tests::audit_support::Gate::pair();
	let task = tokio::spawn(async move { server.handle(stream, None).await });
	crate::net::tests::audit_support::greeting(&mut client).await;
	client
		.write_all(b"a APPEND INBOX {1+}\r\n")
		.await
		.expect("announcement");
	let mut reply = [0u8; 1024];
	let n = client.read(&mut reply).await.expect("reject");
	assert_eq!(&reply[..n], b"a NO not authenticated\r\n");
	crate::net::tests::audit_support::settle().await;
	ctl.block(2);
	tokio::time::advance(PREAUTH).await;
	crate::net::tests::audit_support::settle().await;
	let ended = task.is_finished();
	if !ended {
		task.abort();
	}
	let _ = task.await;
	assert!(
		ended,
		"discard timeout BYE flush holds the transport beyond the deadline"
	);
	assert!(ctl.was_dropped());
}

#[tokio::test(start_paused = true)]
async fn audit_rejected_tail_write_and_flush_are_bounded() {
	for mode in [1u8, 2u8] {
		let (_dir, server) = start_audit_server();
		let (mut client, stream, ctl) = crate::net::tests::audit_support::Gate::pair();
		let task = tokio::spawn(async move { server.handle(stream, None).await });
		crate::net::tests::audit_support::greeting(&mut client).await;
		client
			.write_all(b"a APPEND INBOX {1+}\r\nx")
			.await
			.expect("announcement");
		let mut reply = [0u8; 1024];
		let n = client.read(&mut reply).await.expect("reject");
		assert_eq!(&reply[..n], b"a NO not authenticated\r\n");
		crate::net::tests::audit_support::settle().await;
		ctl.block(mode);
		client.write_all(b" {2048+}\r\n").await.expect("tail");
		crate::net::tests::audit_support::cut(task, ctl, PREAUTH).await;
	}
}
