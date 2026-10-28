//! The probe must complete the handshake and stop before any mail transaction.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;

use super::*;

async fn read_line<S: AsyncReadExt + Unpin>(stream: &mut S) -> String {
	let mut line = Vec::new();
	let mut byte = [0u8; 1];
	while !line.ends_with(b"\r\n") {
		if stream.read_exact(&mut byte).await.is_err() {
			break;
		}
		line.push(byte[0]);
	}
	String::from_utf8_lossy(&line).trim_end().to_string()
}

/// Plain-text server: answers each expected command with the paired reply and
/// returns every command line it received.
async fn scripted<S: AsyncReadExt + AsyncWriteExt + Unpin>(
	mut stream: S,
	replies: &[&str],
) -> Vec<String> {
	let _ = stream.write_all(b"220 smarthost ready\r\n").await;
	let mut seen = Vec::new();
	for reply in replies {
		let line = read_line(&mut stream).await;
		if line.is_empty() {
			break;
		}
		seen.push(line);
		let _ = stream.write_all(reply.as_bytes()).await;
	}
	seen
}

#[tokio::test]
async fn plain_probe_greets_ehlos_and_quits_without_a_transaction() {
	let (client, server) = tokio::io::duplex(8192);
	let task = tokio::spawn(scripted(server, &["250 smarthost\r\n", "221 bye\r\n"]));
	let mut steps = Vec::new();
	probe(
		client,
		"smarthost",
		"mail.example.org",
		false,
		None,
		&mut steps,
	)
	.await
	.unwrap();
	assert_eq!(steps, ["connect", "EHLO", "QUIT"]);
	assert_eq!(
		task.await.unwrap(),
		["EHLO mail.example.org", "QUIT"],
		"the probe must send nothing but EHLO and QUIT"
	);
}

#[tokio::test]
async fn starttls_is_refused_when_the_smarthost_does_not_offer_it() {
	let (client, server) = tokio::io::duplex(8192);
	let task = tokio::spawn(scripted(server, &["250 smarthost\r\n"]));
	let mut steps = Vec::new();
	let error = probe(
		client,
		"smarthost",
		"mail.example.org",
		true,
		None,
		&mut steps,
	)
	.await
	.unwrap_err();
	assert_eq!(
		error,
		DeliveryError::Permanent("smarthost does not offer STARTTLS".into())
	);
	assert_eq!(steps, ["connect", "EHLO"]);
	assert_eq!(task.await.unwrap(), ["EHLO mail.example.org"]);
}

#[tokio::test]
async fn auth_without_starttls_never_reaches_the_wire() {
	let (client, server) = tokio::io::duplex(8192);
	let task = tokio::spawn(scripted(server, &["250 smarthost\r\n"]));
	let mut steps = Vec::new();
	let error = probe(
		client,
		"smarthost",
		"mail.example.org",
		false,
		Some(("user", "secret-value")),
		&mut steps,
	)
	.await
	.unwrap_err();
	assert_eq!(
		error,
		DeliveryError::Permanent("relay AUTH requires STARTTLS".into())
	);
	let seen = task.await.unwrap();
	assert!(
		seen.iter().all(|line| !line.starts_with("AUTH")),
		"credentials must not be sent without TLS"
	);
}

fn acceptor() -> TlsAcceptor {
	let certified = rcgen::generate_simple_self_signed(vec!["smarthost".to_string()]).unwrap();
	let leaf = certified.cert.der().clone();
	let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
	crate::tls::ensure_crypto_provider();
	let config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![leaf], key)
		.unwrap();
	TlsAcceptor::from(Arc::new(config))
}

/// STARTTLS server that authenticates the client and records every command.
async fn tls_server<S>(acceptor: TlsAcceptor, mut plain: S) -> Vec<String>
where
	S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
	let mut seen = Vec::new();
	let _ = plain.write_all(b"220 smarthost ready\r\n").await;
	seen.push(read_line(&mut plain).await);
	let _ = plain.write_all(b"250-smarthost\r\n250 STARTTLS\r\n").await;
	seen.push(read_line(&mut plain).await);
	let _ = plain.write_all(b"220 go\r\n").await;
	let Ok(mut tls) = acceptor.accept(plain).await else {
		return seen;
	};
	seen.push(read_line(&mut tls).await);
	let _ = tls.write_all(b"250 smarthost\r\n").await;
	let auth = read_line(&mut tls).await;
	seen.push(auth.split(' ').take(2).collect::<Vec<_>>().join(" "));
	let _ = tls.write_all(b"235 ok\r\n").await;
	seen.push(read_line(&mut tls).await);
	let _ = tls.write_all(b"221 bye\r\n").await;
	seen
}

#[tokio::test]
async fn starttls_and_auth_complete_and_still_send_no_mail() {
	let (client, server) = tokio::io::duplex(65536);
	let task = tokio::spawn(tls_server(acceptor(), server));
	let mut steps = Vec::new();
	// A self-signed certificate cannot pass web PKI, so this run skips only
	// that check; the command sequence is what is under test.
	probe_with(
		client,
		"smarthost",
		"mail.example.org",
		true,
		Some(("user", "pw")),
		false,
		&mut steps,
	)
	.await
	.unwrap();
	assert_eq!(steps, ["connect", "EHLO", "STARTTLS", "AUTH", "QUIT"]);
	assert_eq!(
		task.await.unwrap(),
		[
			"EHLO mail.example.org",
			"STARTTLS",
			"EHLO mail.example.org",
			"AUTH PLAIN",
			"QUIT"
		]
	);
}

#[tokio::test]
async fn starttls_authenticates_the_certificate_by_default() {
	let (client, server) = tokio::io::duplex(65536);
	let task = tokio::spawn(tls_server(acceptor(), server));
	let mut steps = Vec::new();
	let error = probe(
		client,
		"smarthost",
		"mail.example.org",
		true,
		None,
		&mut steps,
	)
	.await
	.unwrap_err();
	assert!(
		matches!(&error, DeliveryError::Transient(reason) if reason.starts_with("TLS handshake failed")),
		"a self-signed smarthost certificate must be refused: {error:?}"
	);
	assert_eq!(steps, ["connect", "EHLO"]);
	let _ = task.await;
}
