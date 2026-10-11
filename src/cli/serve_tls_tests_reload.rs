use super::*;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

struct Fixture {
	dir: tempfile::TempDir,
	stack: TlsStack,
	replacement: rcgen::CertifiedKey<rcgen::KeyPair>,
	connector: TlsConnector,
}

impl Fixture {
	fn new() -> Self {
		let dir = tempfile::tempdir().expect("directory");
		let initial = rcgen::generate_simple_self_signed(vec!["mail.example.org".into()])
			.expect("initial certificate");
		let replacement = rcgen::generate_simple_self_signed(vec!["mail.example.org".into()])
			.expect("replacement certificate");
		let mut config: Config =
			toml::from_str("hostname = 'mail.example.org'\ndata_dir = '.'").expect("config");
		let tls = crate::config::Tls {
			cert_file: dir.path().join("cert.pem"),
			key_file: dir.path().join("key.pem"),
			client_ca: None,
		};
		std::fs::write(&tls.cert_file, initial.cert.pem()).expect("certificate file");
		std::fs::write(&tls.key_file, initial.signing_key.serialize_pem()).expect("key file");
		config.tls = Some(tls);
		let stack = build_tls(&config, ChallengeStore::new()).expect("TLS stack");
		let mut roots = RootCertStore::empty();
		roots
			.add(initial.cert.der().clone())
			.expect("initial trust");
		roots
			.add(replacement.cert.der().clone())
			.expect("replacement trust");
		let client = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		Self {
			dir,
			stack,
			replacement,
			connector: TlsConnector::from(Arc::new(client)),
		}
	}

	fn renew(&self) {
		let fresh = crate::tls::acceptor_from_pem(
			self.replacement.cert.pem().as_bytes(),
			self.replacement.signing_key.serialize_pem().as_bytes(),
		)
		.expect("renewed acceptor");
		self.stack
			.reloadable_tls
			.as_ref()
			.expect("reload handle")
			.reload(fresh);
	}

	fn directory(&self) -> crate::directory_store::DirectoryHandle {
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[],
		))
	}

	async fn assert_certificate(&self, stream: tokio::io::DuplexStream, protocol: &str) {
		let connection = self
			.connector
			.connect("mail.example.org".try_into().expect("name"), stream)
			.await
			.expect("TLS handshake");
		let presented = &connection
			.get_ref()
			.1
			.peer_certificates()
			.expect("peer certificate")[0];
		assert!(
			presented == self.replacement.cert.der(),
			"{protocol} must present certificate B after ACME reload"
		);
	}
}

async fn read_until(stream: &mut (impl AsyncRead + Unpin), needle: &str) {
	let mut output = String::new();
	let mut buffer = [0; 4096];
	while !output.contains(needle) {
		let read = stream.read(&mut buffer).await.expect("protocol response");
		assert!(read > 0, "protocol closed before TLS upgrade");
		output.push_str(&String::from_utf8_lossy(&buffer[..read]));
	}
}

#[tokio::test]
async fn imaps_presents_renewed_certificate() {
	check_imap(crate::imap::server::TlsMode::Implicit).await;
}

#[tokio::test]
async fn imap_starttls_presents_renewed_certificate() {
	check_imap(crate::imap::server::TlsMode::StartTls).await;
}

async fn check_imap(mode: crate::imap::server::TlsMode) {
	let fixture = Fixture::new();
	let server = crate::imap::server::Server::new(
		"mail.example.org",
		fixture.dir.path().to_path_buf(),
		fixture.directory(),
		fixture
			.stack
			.tls_acceptor
			.clone()
			.expect("listener acceptor"),
		mode,
	);
	let (mut client, stream) = tokio::io::duplex(65536);
	let task = tokio::spawn(async move { server.handle(stream, None).await });
	if matches!(mode, crate::imap::server::TlsMode::StartTls) {
		read_until(&mut client, "\r\n").await;
		fixture.renew();
		client
			.write_all(b"a1 STARTTLS\r\n")
			.await
			.expect("STARTTLS");
		read_until(&mut client, "a1 OK").await;
	} else {
		fixture.renew();
	}
	fixture.assert_certificate(client, "IMAP").await;
	task.abort();
}

#[tokio::test]
async fn managesieve_starttls_presents_renewed_certificate() {
	let fixture = Fixture::new();
	let server = crate::managesieve::server::Server::new(
		fixture.dir.path().to_path_buf(),
		fixture.directory(),
		fixture
			.stack
			.tls_acceptor
			.clone()
			.expect("listener acceptor"),
	);
	let (mut client, stream) = tokio::io::duplex(65536);
	let task = tokio::spawn(async move { server.handle_stream(stream).await });
	read_until(&mut client, "OK").await;
	fixture.renew();
	client.write_all(b"STARTTLS\r\n").await.expect("STARTTLS");
	read_until(&mut client, "OK").await;
	fixture.assert_certificate(client, "ManageSieve").await;
	task.abort();
}

#[tokio::test]
async fn pop3s_acceptor_presents_renewed_certificate() {
	let fixture = Fixture::new();
	let acceptor = fixture.stack.tls_acceptor.clone().expect("POP3S acceptor");
	fixture.renew();
	let (client, stream) = tokio::io::duplex(65536);
	let task = tokio::spawn(async move { acceptor.accept(stream).await });
	fixture.assert_certificate(client, "POP3S").await;
	task.abort();
}
