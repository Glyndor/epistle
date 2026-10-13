//! STARTTLS state tests (RFC 5804 section 2.2): commands pipelined behind
//! STARTTLS are discarded, and the capabilities re-issued inside TLS are
//! the only bytes the server sends first.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use super::*;
use crate::test_fixtures as fixtures;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(std::collections::HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash(fixtures::password()),
		)])),
	)
}

/// Read until a line starting with `OK`, `NO` or `BYE` ends the response.
async fn read_response(stream: &mut (impl AsyncRead + Unpin)) -> String {
	let mut got = String::new();
	let mut chunk = [0u8; 4096];
	loop {
		let n = stream.read(&mut chunk).await.expect("read");
		assert!(n > 0, "closed after {got:?}");
		got.push_str(&String::from_utf8_lossy(&chunk[..n]));
		let done = got.ends_with("\r\n")
			&& got
				.trim_end_matches("\r\n")
				.rsplit("\r\n")
				.next()
				.is_some_and(|line| ["OK", "NO", "BYE"].iter().any(|k| line.starts_with(k)));
		if done {
			return got;
		}
	}
}

#[tokio::test]
async fn commands_pipelined_behind_starttls_are_discarded() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.path().to_path_buf(), directory(), acceptor);
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle_stream(server_stream).await });
	assert!(read_response(&mut client).await.contains("\"STARTTLS\""));

	// One write: STARTTLS, then an AUTHENTICATE and a NOOP that must die
	// with the plaintext session.
	let plain = B64.encode(format!("\0alice\0{}", fixtures::password()));
	let injected = format!("STARTTLS\r\nAUTHENTICATE \"PLAIN\" \"{plain}\"\r\nNOOP \"x\"\r\n");
	client
		.write_all(injected.as_bytes())
		.await
		.expect("starttls with injected commands");
	let plaintext = read_response(&mut client).await;
	assert_eq!(
		plaintext, "OK \"Begin TLS negotiation now.\"\r\n",
		"only the STARTTLS reply travels in plaintext"
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

	// RFC 5804 section 2.2: fresh capabilities, now with SASL and without
	// STARTTLS, and nothing in front of them.
	let capabilities = read_response(&mut tls).await;
	assert!(
		capabilities.starts_with("\"IMPLEMENTATION\""),
		"{capabilities:?}"
	);
	assert!(
		capabilities.contains("\"SASL\" \"PLAIN\""),
		"{capabilities:?}"
	);
	assert!(!capabilities.contains("STARTTLS"), "{capabilities:?}");

	// The injected AUTHENTICATE did not log the TLS session in.
	tls.write_all(b"LISTSCRIPTS\r\n")
		.await
		.expect("listscripts");
	assert_eq!(
		read_response(&mut tls).await,
		"NO \"Authenticate first.\"\r\n"
	);
	task.abort();
}
