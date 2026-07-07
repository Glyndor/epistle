//! IMAP server connection-loop tests.

use super::*;
use std::collections::HashMap;

use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)])),
	)
}

/// Read from `tls` until `needle` appears in the accumulated output.
async fn read_until(tls: &mut (impl AsyncRead + Unpin), needle: &str) -> String {
	let mut got = String::new();
	let mut chunk = [0u8; 4096];
	while !got.contains(needle) {
		let n = tls.read(&mut chunk).await.expect("read");
		assert!(n > 0, "closed waiting for {needle:?}: {got}");
		got.push_str(&String::from_utf8_lossy(&chunk[..n]));
	}
	got
}

#[test]
fn detects_bad_responses() {
	assert!(is_bad_response(b"a1 BAD invalid arguments\r\n"));
	assert!(is_bad_response(b"* BAD malformed command\r\n"));
	// Successful and NO responses are not abuse signals.
	assert!(!is_bad_response(b"a1 OK LOGIN completed\r\n"));
	assert!(!is_bad_response(b"a1 NO LOGIN failed\r\n"));
}

#[tokio::test]
async fn starttls_upgrade_then_login() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		TlsMode::StartTls,
	);

	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	// Plaintext greeting advertises STARTTLS.
	let mut chunk = [0u8; 1024];
	let read = client.read(&mut chunk).await.expect("greeting");
	let greeting = String::from_utf8_lossy(&chunk[..read]).to_string();
	assert!(greeting.contains("STARTTLS"), "{greeting}");

	client
		.write_all(b"a1 STARTTLS\r\n")
		.await
		.expect("starttls");
	let read = client.read(&mut chunk).await.expect("ok");
	assert!(String::from_utf8_lossy(&chunk[..read]).contains("a1 OK"));

	// Handshake over the same stream.
	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));
	let name = ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector.connect(name, client).await.expect("handshake");

	tls.write_all(b"a2 LOGIN alice secret\r\n")
		.await
		.expect("login");
	let read = tls.read(&mut chunk).await.expect("response");
	let response = String::from_utf8_lossy(&chunk[..read]).to_string();
	assert!(response.contains("a2 OK"), "{response}");
	tls.write_all(b"a3 LOGOUT\r\n").await.expect("logout");
	let _ = tls.read(&mut chunk).await;
	task.abort();
}

#[tokio::test]
async fn full_read_session_over_tls() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("dirs");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: b@x.example\r\nSubject: hi\r\n\r\nhello\r\n",
	)
	.expect("write");

	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		TlsMode::Implicit,
	);

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));
	let name = ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector.connect(name, client).await.expect("handshake");

	let greeting = read_until(&mut tls, "IMAP4rev2 ready").await;
	assert!(greeting.starts_with("* OK"), "{greeting}");

	tls.write_all(b"a1 LOGIN alice secret\r\n")
		.await
		.expect("login");
	read_until(&mut tls, "a1 OK").await;

	tls.write_all(b"a2 SELECT INBOX\r\n").await.expect("select");
	let select = read_until(&mut tls, "a2 OK").await;
	assert!(select.contains("* 1 EXISTS"), "{select}");

	tls.write_all(b"a3 FETCH 1 (BODY[])\r\n")
		.await
		.expect("fetch");
	let fetch = read_until(&mut tls, "a3 OK").await;
	assert!(fetch.contains("Subject: hi"), "{fetch}");

	tls.write_all(b"a4 LOGOUT\r\n").await.expect("logout");
	read_until(&mut tls, "a4 OK").await;
	task.abort();
}

/// A StartTLS-mode server (greets in plaintext) plus a connected client.
fn plaintext_server() -> (
	tokio::io::DuplexStream,
	tokio::task::JoinHandle<std::io::Result<()>>,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		TlsMode::StartTls,
	);
	let (client, server_stream) = tokio::io::duplex(256 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	(client, task)
}

async fn read_chunk(client: &mut tokio::io::DuplexStream) -> String {
	let mut chunk = [0u8; 4096];
	let read = client.read(&mut chunk).await.expect("read");
	String::from_utf8_lossy(&chunk[..read]).to_string()
}

#[tokio::test]
async fn non_ascii_command_is_bad() {
	let (mut client, task) = plaintext_server();
	assert!(read_chunk(&mut client).await.starts_with("* OK"));
	client.write_all(&[0xff, 0xfe]).await.expect("write");
	client.write_all(b"\r\n").await.expect("write");
	assert!(read_chunk(&mut client).await.contains("BAD non-ASCII"));
	drop(client);
	let _ = task.await;
}

#[tokio::test]
async fn overlong_line_closes_with_bye() {
	let (mut client, task) = plaintext_server();
	let _ = read_chunk(&mut client).await;
	let huge = vec![b'A'; 200 * 1024];
	client.write_all(&huge).await.expect("write");
	client.write_all(b"\r\n").await.expect("write");
	assert!(read_chunk(&mut client).await.contains("BYE line too long"));
	let _ = task.await;
}

#[tokio::test]
async fn repeated_bad_commands_close_with_bye() {
	let (mut client, task) = plaintext_server();
	let _ = read_chunk(&mut client).await;
	let mut seen = String::new();
	for _ in 0..30 {
		let _ = client.write_all(b"a BOGUSCMD\r\n").await;
	}
	loop {
		let mut chunk = [0u8; 4096];
		let read = client.read(&mut chunk).await.expect("read");
		if read == 0 {
			break;
		}
		seen.push_str(&String::from_utf8_lossy(&chunk[..read]));
	}
	assert!(seen.contains("BYE too many errors"), "{seen}");
	let _ = task.await;
}

#[tokio::test]
async fn eof_ends_the_connection() {
	let (mut client, task) = plaintext_server();
	let _ = read_chunk(&mut client).await;
	drop(client);
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn append_with_literal_stores_a_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		TlsMode::Implicit,
	);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));
	let name = ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector.connect(name, client).await.expect("handshake");

	read_until(&mut tls, "IMAP4rev2 ready").await;
	tls.write_all(b"a1 LOGIN alice secret\r\n")
		.await
		.expect("login");
	read_until(&mut tls, "a1 OK").await;

	// APPEND with a literal: the server sends a continuation, reads the bytes.
	let body = b"From: c@x.example\r\nSubject: appended\r\n\r\nhi\r\n";
	tls.write_all(format!("a2 APPEND INBOX {{{}}}\r\n", body.len()).as_bytes())
		.await
		.expect("append cmd");
	read_until(&mut tls, "+").await;
	tls.write_all(body).await.expect("literal");
	tls.write_all(b"\r\n").await.expect("crlf");
	read_until(&mut tls, "a2 OK").await;

	// The appended message is now in INBOX.
	tls.write_all(b"a3 SELECT INBOX\r\n").await.expect("select");
	let select = read_until(&mut tls, "a3 OK").await;
	assert!(select.contains("* 1 EXISTS"), "{select}");

	tls.write_all(b"a4 LOGOUT\r\n").await.expect("logout");
	read_until(&mut tls, "a4 OK").await;
	task.abort();
}

#[tokio::test]
async fn authenticate_login_over_tls_drives_continuation() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;

	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		TlsMode::Implicit,
	);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));
	let name = ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector.connect(name, client).await.expect("handshake");

	read_until(&mut tls, "IMAP4rev2 ready").await;
	// AUTHENTICATE LOGIN exchanges username and password via continuations.
	tls.write_all(b"a1 AUTHENTICATE LOGIN\r\n")
		.await
		.expect("auth");
	read_until(&mut tls, "+").await;
	tls.write_all(format!("{}\r\n", B64.encode("alice")).as_bytes())
		.await
		.expect("user");
	read_until(&mut tls, "+").await;
	tls.write_all(format!("{}\r\n", B64.encode("secret")).as_bytes())
		.await
		.expect("pass");
	read_until(&mut tls, "a1 OK").await;

	// The authenticated session can select INBOX.
	tls.write_all(b"a2 SELECT INBOX\r\n").await.expect("select");
	read_until(&mut tls, "a2 OK").await;
	tls.write_all(b"a3 LOGOUT\r\n").await.expect("logout");
	read_until(&mut tls, "a3 OK").await;
	task.abort();
}

#[tokio::test]
async fn idle_then_done_resumes_command_mode() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		TlsMode::Implicit,
	);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));
	let name = ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector.connect(name, client).await.expect("handshake");

	read_until(&mut tls, "IMAP4rev2 ready").await;
	tls.write_all(b"a1 LOGIN alice secret\r\n")
		.await
		.expect("login");
	read_until(&mut tls, "a1 OK").await;
	tls.write_all(b"a2 SELECT INBOX\r\n").await.expect("select");
	read_until(&mut tls, "a2 OK").await;

	// Enter IDLE, then end it with DONE — the command tag completes.
	tls.write_all(b"a3 IDLE\r\n").await.expect("idle");
	read_until(&mut tls, "+ ").await;
	tls.write_all(b"DONE\r\n").await.expect("done");
	read_until(&mut tls, "a3 OK").await;

	// Command mode resumed: a NOOP is accepted.
	tls.write_all(b"a4 NOOP\r\n").await.expect("noop");
	read_until(&mut tls, "a4 OK").await;
	tls.write_all(b"a5 LOGOUT\r\n").await.expect("logout");
	read_until(&mut tls, "a5 OK").await;
	task.abort();
}

#[tokio::test(start_paused = true)]
async fn idle_poll_pushes_exists_on_new_mail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("dirs");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		TlsMode::Implicit,
	);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));
	let name = ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector.connect(name, client).await.expect("handshake");

	read_until(&mut tls, "IMAP4rev2 ready").await;
	tls.write_all(b"a1 LOGIN alice secret\r\n")
		.await
		.expect("login");
	read_until(&mut tls, "a1 OK").await;
	tls.write_all(b"a2 SELECT INBOX\r\n").await.expect("select");
	read_until(&mut tls, "a2 OK").await;

	tls.write_all(b"a3 IDLE\r\n").await.expect("idle");
	read_until(&mut tls, "+ ").await;

	// New mail arrives while idling; the poll interval (paused clock) fires and
	// the server pushes an unsolicited EXISTS.
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: c@x.example\r\nSubject: new\r\n\r\nhi\r\n",
	)
	.expect("write");
	let pushed = read_until(&mut tls, "EXISTS").await;
	assert!(pushed.contains("* 1 EXISTS"), "{pushed}");

	tls.write_all(b"DONE\r\n").await.expect("done");
	read_until(&mut tls, "a3 OK").await;
	task.abort();
}

#[tokio::test(start_paused = true)]
async fn idle_read_timeout_sends_bye() {
	let (mut client, task) = plaintext_server();
	assert!(read_chunk(&mut client).await.starts_with("* OK"));
	// Send nothing: the read timeout (paused clock) fires and the server closes.
	let mut seen = String::new();
	loop {
		let mut chunk = [0u8; 4096];
		let n = client.read(&mut chunk).await.expect("read");
		if n == 0 {
			break;
		}
		seen.push_str(&String::from_utf8_lossy(&chunk[..n]));
	}
	assert!(seen.contains("BYE idle timeout"), "{seen}");
	let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn idle_times_out_during_idle() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		TlsMode::Implicit,
	);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));
	let name = ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector.connect(name, client).await.expect("handshake");

	read_until(&mut tls, "IMAP4rev2 ready").await;
	tls.write_all(b"a1 LOGIN alice secret\r\n")
		.await
		.expect("login");
	read_until(&mut tls, "a1 OK").await;
	tls.write_all(b"a2 SELECT INBOX\r\n").await.expect("select");
	read_until(&mut tls, "a2 OK").await;
	tls.write_all(b"a3 IDLE\r\n").await.expect("idle");
	read_until(&mut tls, "+ ").await;
	// Stay silent: the idle timeout (paused clock) fires and the server closes.
	read_until(&mut tls, "BYE idle timeout").await;
	task.abort();
}
