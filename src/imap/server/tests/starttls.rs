//! STARTTLS state tests (RFC 9051 section 6.2.1, RFC 2595 section 3.1):
//! commands pipelined behind STARTTLS are discarded, never run in
//! plaintext or inside TLS.

use super::*;
use crate::test_fixtures as fixtures;
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
			crate::smtp::auth::tests::base::hash(fixtures::password()),
		)])),
	)
}

/// Read until a line starting with `tag` arrives; return everything read.
async fn read_tagged(stream: &mut (impl AsyncRead + Unpin), tag: &str) -> String {
	let mut got = String::new();
	let mut chunk = [0u8; 4096];
	loop {
		let n = stream.read(&mut chunk).await.expect("read");
		assert!(n > 0, "closed waiting for {tag:?}: {got}");
		got.push_str(&String::from_utf8_lossy(&chunk[..n]));
		let tagged = got
			.split("\r\n")
			.any(|line| line.starts_with(&format!("{tag} ")));
		if tagged && got.ends_with("\r\n") {
			return got;
		}
	}
}

#[tokio::test]
async fn commands_pipelined_behind_starttls_are_discarded() {
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
	read_tagged(&mut client, "*").await;

	// One write: STARTTLS, then a LOGIN and a NOOP that must die with the
	// plaintext session.
	let injected = format!(
		"a1 STARTTLS\r\nb1 LOGIN alice {}\r\nb2 NOOP\r\n",
		fixtures::password()
	);
	client
		.write_all(injected.as_bytes())
		.await
		.expect("starttls with injected commands");
	let plaintext = read_tagged(&mut client, "a1").await;
	assert!(plaintext.starts_with("a1 OK"), "{plaintext:?}");
	assert_eq!(
		plaintext.matches("\r\n").count(),
		1,
		"only the STARTTLS reply travels in plaintext: {plaintext:?}"
	);

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

	tls.write_all(b"c1 CAPABILITY\r\n")
		.await
		.expect("capability");
	let capability = read_tagged(&mut tls, "c1").await;
	assert!(
		capability.starts_with("* CAPABILITY "),
		"the first bytes inside TLS answer c1: {capability:?}"
	);
	assert!(!capability.contains("STARTTLS"), "{capability:?}");

	// The injected LOGIN did not authenticate the TLS session.
	tls.write_all(b"c2 SELECT INBOX\r\n").await.expect("select");
	let select = read_tagged(&mut tls, "c2").await;
	assert!(
		!select.contains("c2 OK") && !select.contains("b1 ") && !select.contains("b2 "),
		"{select:?}"
	);
	task.abort();
}
