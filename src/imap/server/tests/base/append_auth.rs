//! IMAP server APPEND literal and AUTHENTICATE-over-TLS connection tests.

use super::*;

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
	tls.write_all(format!("a1 LOGIN alice {}\r\n", fixtures::password()).as_bytes())
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
	tls.write_all(format!("{}\r\n", B64.encode(fixtures::password())).as_bytes())
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
