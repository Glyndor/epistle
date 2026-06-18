//! AUTH over a STARTTLS-upgraded SMTP connection (the CollectAuthResponse loop).

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

fn directory_with_password() -> DirectoryHandle {
	DirectoryHandle::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)])),
	)
}

fn connector(
	cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) -> tokio_rustls::TlsConnector {
	let mut roots = tokio_rustls::rustls::RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = tokio_rustls::rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn reply<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> String {
	let mut buffer = [0u8; 1024];
	let read = reader.read(&mut buffer).await.expect("read");
	String::from_utf8_lossy(&buffer[..read]).to_string()
}

#[tokio::test]
async fn auth_login_over_starttls_authenticates() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;

	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
		.with_directory(directory_with_password())
		.with_tls(
			crate::tls::ReloadableAcceptor::new(acceptor),
			TlsMode::Opportunistic,
		);

	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	assert!(reply(&mut client).await.starts_with("220 "));
	client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = reply(&mut client).await;
	client.write_all(b"STARTTLS\r\n").await.expect("starttls");
	assert!(reply(&mut client).await.starts_with("220 "));

	let server_name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector(cert)
		.connect(server_name, client)
		.await
		.expect("handshake");
	assert!(reply(&mut tls).await.starts_with("220 "));
	tls.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let ehlo = reply(&mut tls).await;
	assert!(ehlo.contains("AUTH"), "{ehlo}");

	// AUTH LOGIN exchanges username then password over the wire.
	tls.write_all(b"AUTH LOGIN\r\n").await.expect("auth");
	assert!(reply(&mut tls).await.starts_with("334 "));
	tls.write_all(format!("{}\r\n", B64.encode("alice")).as_bytes())
		.await
		.expect("user");
	assert!(reply(&mut tls).await.starts_with("334 "));
	tls.write_all(format!("{}\r\n", B64.encode("secret")).as_bytes())
		.await
		.expect("pass");
	assert!(
		reply(&mut tls).await.starts_with("235 "),
		"auth should succeed"
	);

	drop(tls);
	task.abort();
}
