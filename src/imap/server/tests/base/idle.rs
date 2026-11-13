//! IMAP server IDLE connection tests.

use super::*;

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
	tls.write_all(format!("a1 LOGIN alice {}\r\n", fixtures::password()).as_bytes())
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
	tls.write_all(format!("a1 LOGIN alice {}\r\n", fixtures::password()).as_bytes())
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
	tls.write_all(format!("a1 LOGIN alice {}\r\n", fixtures::password()).as_bytes())
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
