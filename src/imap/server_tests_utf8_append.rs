//! APPEND with the RFC 6855 §4 `UTF8 (~{n})` data item, over a real
//! connection so the literal framing and its `)` trailer are exercised.

use super::*;
use crate::test_fixtures as fixtures;
use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const MESSAGE: &[u8] = "Subject: Grüße\r\nFrom: jörg@example.org\r\n\r\nHallo\r\n".as_bytes();

async fn read_until(tls: &mut (impl AsyncRead + Unpin), needle: &str) -> String {
	let mut got = String::new();
	let mut chunk = [0u8; 4096];
	// Stop at end of stream: the caller's assertion then shows what the
	// server sent before it closed.
	while !got.contains(needle) {
		match tls.read(&mut chunk).await {
			Ok(n) if n > 0 => got.push_str(&String::from_utf8_lossy(&chunk[..n])),
			_ => break,
		}
	}
	got
}

/// Log in as alice over implicit TLS and return the client stream.
async fn logged_in(
	data_dir: &std::path::Path,
) -> tokio_rustls::client::TlsStream<tokio::io::DuplexStream> {
	std::fs::create_dir_all(data_dir.join("accounts/alice/new")).expect("dirs");
	let directory = DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash(fixtures::password()),
		)])),
	);
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		data_dir.to_path_buf(),
		directory,
		acceptor,
		TlsMode::Implicit,
	);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	tokio::spawn(async move { server.handle(server_stream, None).await });
	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let name = ServerName::try_from("mail.example.org").expect("name");
	let mut tls = TlsConnector::from(Arc::new(config))
		.connect(name, client)
		.await
		.expect("handshake");
	read_until(&mut tls, "IMAP4rev2 ready").await;
	tls.write_all(format!("a1 LOGIN alice {}\r\n", fixtures::password()).as_bytes())
		.await
		.expect("login");
	read_until(&mut tls, "a1 OK").await;
	tls
}

/// The message files in alice's inbox (the index sits beside them).
fn stored_messages(data_dir: &std::path::Path) -> Vec<Vec<u8>> {
	std::fs::read_dir(data_dir.join("accounts/alice/new"))
		.expect("inbox")
		.map(|entry| entry.expect("entry").path())
		.filter(|path| path.extension().is_some_and(|ext| ext == "eml"))
		.map(|path| std::fs::read(path).expect("message"))
		.collect()
}

#[tokio::test]
async fn utf8_append_after_enable_stores_the_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut tls = logged_in(dir.path()).await;
	tls.write_all(b"e1 ENABLE UTF8=ACCEPT\r\n")
		.await
		.expect("enable");
	read_until(&mut tls, "e1 OK").await;

	let header = format!("a2 APPEND INBOX (\\Seen) UTF8 (~{{{}}}\r\n", MESSAGE.len());
	tls.write_all(header.as_bytes()).await.expect("append");
	let continuation = read_until(&mut tls, "\r\n").await;
	assert!(continuation.starts_with("+ "), "{continuation}");
	tls.write_all(MESSAGE).await.expect("payload");
	tls.write_all(b")\r\n").await.expect("trailer");
	let reply = read_until(&mut tls, "a2 ").await;
	let reply = read_until_line_end(&mut tls, reply).await;
	assert!(reply.contains("a2 OK [APPENDUID "), "{reply}");

	// The `)` was consumed with the literal: the next command is clean.
	tls.write_all(b"n1 NOOP\r\n").await.expect("noop");
	let after = read_until(&mut tls, "n1 OK").await;
	assert!(!after.contains("BAD"), "{after}");
	let stored = stored_messages(dir.path());
	assert_eq!(stored.len(), 1, "one message stored");
	assert!(
		stored[0] == MESSAGE,
		"stored message differs: {} bytes, expected {}",
		stored[0].len(),
		MESSAGE.len()
	);
}

#[tokio::test]
async fn utf8_append_without_enable_is_refused_and_drained() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut tls = logged_in(dir.path()).await;
	// Non-synchronizing, so the payload is on the wire whatever the answer.
	let payload = b"x LOGOUT\r\n";
	let header = format!("a2 APPEND INBOX UTF8 (~{{{}+}}\r\n", payload.len());
	tls.write_all(header.as_bytes()).await.expect("append");
	tls.write_all(payload).await.expect("payload");
	tls.write_all(b")\r\n").await.expect("trailer");
	tls.write_all(b"n1 NOOP\r\n").await.expect("noop");
	let reply = read_until(&mut tls, "n1 OK").await;
	assert!(
		reply.starts_with("a2 BAD UTF8 APPEND requires ENABLE UTF8=ACCEPT\r\n"),
		"{reply}"
	);
	// The payload and its `)` were drained, not run as a command.
	assert!(!reply.contains("x OK"), "{reply}");
	assert!(!reply.contains("BYE"), "{reply}");
	assert_eq!(stored_messages(dir.path()).len(), 0);
}

async fn read_until_line_end(tls: &mut (impl AsyncRead + Unpin), mut got: String) -> String {
	let mut chunk = [0u8; 4096];
	while !got.ends_with("\r\n") {
		match tls.read(&mut chunk).await {
			Ok(n) if n > 0 => got.push_str(&String::from_utf8_lossy(&chunk[..n])),
			_ => break,
		}
	}
	got
}
