//! IMAP server tests for literal-bearing command framing.

use super::*;
use std::collections::HashMap;
use std::time::Duration;

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

/// RFC 7888 §4: when the server rejects a non-synchronizing literal it must
/// consume the literal bytes. Otherwise the payload arrives as the next
/// command line and is parsed as a real command.
#[tokio::test]
async fn rejected_non_sync_literal_is_discarded() {
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

	// APPEND to a mailbox that does not exist (TRYCREATE). Use the non-sync
	// {N+} form, so the client sends the bytes regardless. The literal
	// payload is crafted to look like `x LOGOUT\r\n`; if the server fails
	// to discard, that line is parsed as a tagged command.
	let inner = b"x LOGOUT\r\n";
	let header = format!("a2 APPEND Missing {{{}+}}\r\n", inner.len());
	tls.write_all(header.as_bytes())
		.await
		.expect("append header");
	tls.write_all(inner).await.expect("append payload");

	// The rejected APPEND returns a tagged NO. The literal bytes must not be
	// parsed as a real command, so no `x OK` ever appears.
	let reply = read_until(&mut tls, "a2 NO").await;
	assert!(
		reply.contains("a2 NO"),
		"rejected APPEND must produce a tagged NO: {reply}"
	);
	assert!(
		!reply.contains("x OK"),
		"x LOGOUT must NOT be executed as a tagged command: {reply}"
	);

	// Session continues: a real command works.
	tls.write_all(b"a3 NOOP\r\n").await.expect("noop");
	read_until(&mut tls, "a3 OK").await;

	tls.write_all(b"a4 LOGOUT\r\n").await.expect("logout");
	let _ = read_until(&mut tls, "a4 OK").await;
	task.abort();
}

/// APPEND must not store the message before the trailing CRLF has been
/// validated. A literal followed by garbage instead of CRLF must produce
/// BAD and leave the mailbox empty (RFC 9051 §6.3.2: the literal is
/// followed by CRLF, or by another literal for MULTIAPPEND).
#[tokio::test(start_paused = true)]
async fn append_literal_with_bad_trailer_does_not_store() {
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

	// Send a 6-byte literal followed by a CRLF line ("BB\r\n"): the trailer
	// is the two non-CRLF bytes "BB", then the line decoder sees an empty
	// line. The server must reject the APPEND with BAD without storing.
	// We then send a STATUS query and expect MESSAGES 0.
	tls.write_all(b"a2 APPEND INBOX {6}\r\n")
		.await
		.expect("append header");
	read_until(&mut tls, "+").await;
	tls.write_all(b"AAAAAABB\r\n")
		.await
		.expect("literal+garbage+crlf");

	// Read whatever the server sends next for up to 5 seconds. The tagged
	// response for `a2` must be BAD, never OK.
	let mut chunk = [0u8; 4096];
	let mut seen = String::new();
	let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
	while !seen.contains("a2 ") && tokio::time::Instant::now() < deadline {
		match tokio::time::timeout(Duration::from_millis(200), tls.read(&mut chunk)).await {
			Ok(Ok(0)) => break,
			Ok(Ok(n)) => seen.push_str(&String::from_utf8_lossy(&chunk[..n])),
			Ok(Err(_)) => break,
			Err(_) => break,
		}
	}
	assert!(
		seen.contains("a2 BAD"),
		"APPEND with non-CRLF trailer must be BAD, saw: {seen}"
	);
	assert!(
		!seen.contains("a2 OK"),
		"rejected APPEND must NOT be OK, saw: {seen}"
	);

	// The mailbox must remain empty: STATUS returns MESSAGES 0.
	tls.write_all(b"a3 STATUS INBOX (MESSAGES)\r\n")
		.await
		.expect("status");
	let status = read_until(&mut tls, "a3 OK").await;
	assert!(
		status.contains("MESSAGES 0"),
		"the rejected APPEND must not store a message: {status}"
	);

	tls.write_all(b"a4 LOGOUT\r\n").await.expect("logout");
	let _ = read_until(&mut tls, "a4 OK").await;
	task.abort();
}

/// APPEND with a literal that the client never finishes sending must
/// drop the connection when the read deadline passes (RFC 9051 §5.4
/// spirit: a single read may not stall forever).
#[tokio::test(start_paused = true)]
async fn append_literal_read_timeout_drops_connection() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory(),
		acceptor,
		TlsMode::Implicit,
	)
	.with_read_timeout(Duration::from_secs(2));
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

	// Announce a literal of 1024 bytes but only send a few, then stall.
	// The server should close the connection after the configured deadline.
	tls.write_all(b"a2 APPEND INBOX {1024}\r\n")
		.await
		.expect("append header");
	let _ = read_until(&mut tls, "+").await;
	tls.write_all(b"only-a-few-by")
		.await
		.expect("partial literal");

	// The literal read is bounded by 2s. Tokio's paused clock advances
	// when nothing else is pending, so the timeout fires deterministically.
	let mut seen = String::new();
	loop {
		let mut chunk = [0u8; 4096];
		match tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk)).await {
			Ok(Ok(0)) => break,
			Ok(Ok(n)) => seen.push_str(&String::from_utf8_lossy(&chunk[..n])),
			Ok(Err(_)) => break,
			Err(_) => panic!("server did not close within 5s; partial reply: {seen}"),
		}
	}
	assert!(
		seen.contains("BYE") && seen.contains("timeout"),
		"expected a BYE timeout response, saw: {seen}"
	);
	let _ = task.await;
}
