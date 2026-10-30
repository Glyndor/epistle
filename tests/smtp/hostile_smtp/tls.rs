//! STARTTLS boundary injection and the available per-connection AUTH guard.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use epistle::smtp::server::{Server, TlsMode};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use super::harness::*;
use crate::common::TLS_PROBE_IO_TIMEOUT;

pub(super) struct Tls {
	acceptor: epistle::tls::ReloadableAcceptor,
	connector: TlsConnector,
}

impl Tls {
	pub(super) fn new() -> Self {
		epistle::tls::ensure_crypto_provider();
		let cert = rcgen::generate_simple_self_signed(vec!["mx.epistle.test".into()])
			.expect("self-signed certificate");
		let acceptor = epistle::tls::acceptor_from_pem(
			cert.cert.pem().as_bytes(),
			cert.signing_key.serialize_pem().as_bytes(),
		)
		.expect("TLS acceptor");
		let mut roots = RootCertStore::empty();
		roots
			.add(cert.cert.der().clone())
			.expect("trust certificate");
		let config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		Self {
			acceptor: epistle::tls::ReloadableAcceptor::new(acceptor),
			connector: TlsConnector::from(Arc::new(config)),
		}
	}

	pub(super) fn server(&self, server: Server) -> Server {
		server.with_tls(self.acceptor.clone(), TlsMode::Opportunistic)
	}

	async fn upgrade(&self, tcp: TcpStream) -> tokio_rustls::client::TlsStream<TcpStream> {
		self.try_upgrade(tcp).await.expect("TLS handshake")
	}

	async fn try_upgrade(
		&self,
		tcp: TcpStream,
	) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
		let name = ServerName::try_from("mx.epistle.test").expect("server name");
		timeout(TLS_PROBE_IO_TIMEOUT, self.connector.connect(name, tcp))
			.await
			.expect("TLS deadline")
	}

	pub(super) async fn connect(
		&self,
		server: &Harness,
	) -> tokio_rustls::client::TlsStream<TcpStream> {
		let mut tcp = server.connect().await;
		ehlo(&mut tcp).await;
		send(&mut tcp, b"STARTTLS\r\n").await;
		expect(&mut tcp, "220 ready to start TLS\r\n").await;
		let mut tls = self.upgrade(tcp).await;
		ehlo(&mut tls).await;
		tls
	}
}

#[tokio::test]
async fn starttls_pipelined_plaintext_is_discarded_or_connection_closes() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let server = Harness::start(|s| tls.server(s)).await;
	// Establish that the certificate and handshake work before attacking them.
	let mut control = tls.connect(&server).await;
	quit(&mut control).await;
	let mut client = server.connect().await;
	ehlo(&mut client).await;
	// A single small write queues the plaintext with STARTTLS. QUIT detects
	// replay of the old decoder even if MAIL/RCPT would fail for another reason.
	send(
		&mut client,
		b"STARTTLS\r\nMAIL FROM:<forged@remote.test>\r\n\
RCPT TO:<tester@epistle.test>\r\nQUIT\r\n",
	)
	.await;
	expect(&mut client, "220 ready to start TLS\r\n").await;
	let mut client = match tls.try_upgrade(client).await {
		Ok(mut client) => {
			ehlo(&mut client).await;
			send(&mut client, b"DATA\r\n").await;
			expect(&mut client, "503 5.5.1 bad sequence of commands\r\n").await;
			client
		}
		Err(error) => {
			// TCP may split the write after STARTTLS: plaintext left in the
			// socket must then fail the TLS handshake, not run as SMTP.
			assert!(
				matches!(
					error.kind(),
					std::io::ErrorKind::InvalidData
						| std::io::ErrorKind::UnexpectedEof
						| std::io::ErrorKind::ConnectionReset
						| std::io::ErrorKind::BrokenPipe
				),
				"unexpected TLS failure: {error:?}"
			);
			assert!(server.sink.messages().is_empty());
			tls.connect(&server).await
		}
	};
	// A valid encrypted transaction also detects a shifted response stream.
	data(&mut client).await;
	send(&mut client, BODY).await;
	expect(&mut client, OK).await;
	quit(&mut client).await;
	let messages = server.sink.messages();
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].reverse_path, "sender@remote.test");
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_bruteforce_third_failure_gets_535_and_connection_closes() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let password: &str = &PASSWORD;
	let directory = directory().with_password_hashes(HashMap::from([(
		"tester".to_string(),
		epistle::smtp::auth::hash_password(password).expect("fixture password hash"),
	)]));
	let server = Harness::with_directory(directory, |s| tls.server(s)).await;
	let mut client = tls.connect(&server).await;
	let credentials =
		base64::engine::general_purpose::STANDARD.encode(format!("\0tester\0{PASSWORD}-wrong"));
	let command = format!("AUTH PLAIN {credentials}\r\n");
	for _ in 0..3 {
		send(&mut client, command.as_bytes()).await;
		expect(
			&mut client,
			"535 5.7.8 authentication credentials invalid\r\n",
		)
		.await;
	}
	closed(&mut client).await;
	assert!(server.sink.messages().is_empty());
	// Without PostgreSQL there is no persistent ban. A fresh authenticated
	// connection proves the shared listener and password verifier still work.
	let mut next = tls.connect(&server).await;
	let credentials =
		base64::engine::general_purpose::STANDARD.encode(format!("\0tester\0{password}"));
	send(
		&mut next,
		format!("AUTH PLAIN {credentials}\r\n").as_bytes(),
	)
	.await;
	expect(&mut next, "235 2.7.0 authentication successful\r\n").await;
	quit(&mut next).await;
	server.healthy().await;
}
