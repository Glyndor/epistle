//! End-to-end STARTTLS authentication-mode tests for `deliver`.
//!
//! Each runs a mock MTA that offers STARTTLS with a self-signed certificate
//! (not in the webpki roots) and drives `deliver` over a duplex pipe. This
//! exercises the accept-any handshake path used by opportunistic mode and DANE.
//! The mock speaks RFC-5321 STARTTLS (the client sends EHLO straight after the
//! handshake, with no fresh banner), matching a real remote MTA.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;

use crate::config::OutboundTls;
use crate::dane::tlsa::TlsaRecord;
use crate::queue::client::{DeliveryError, deliver};

/// A fresh self-signed certificate (and matching acceptor) for the mock MTA,
/// returning the leaf DER so a TLSA association can be derived from it.
fn acceptor_and_leaf() -> (TlsAcceptor, Vec<u8>) {
	let certified = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
		.expect("generate certificate");
	let leaf = certified.cert.der().clone();
	let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).expect("key der");
	crate::tls::ensure_crypto_provider();
	let config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![leaf.clone()], key)
		.expect("server config");
	(TlsAcceptor::from(Arc::new(config)), leaf.to_vec())
}

/// Read one CRLF-terminated command from `stream`.
async fn read_line<S>(stream: &mut S) -> String
where
	S: AsyncReadExt + Unpin,
{
	let mut line = Vec::new();
	let mut byte = [0u8; 1];
	loop {
		if stream.read_exact(&mut byte).await.is_err() {
			break;
		}
		line.push(byte[0]);
		if line.ends_with(b"\r\n") {
			break;
		}
	}
	String::from_utf8_lossy(&line).to_string()
}

/// Run the mock MTA against `server_stream`: greet, offer STARTTLS, upgrade,
/// then accept the transaction and store nothing (success is the 250s/221).
async fn mock_mta<S>(acceptor: TlsAcceptor, mut plain: S)
where
	S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
	let _ = plain.write_all(b"220 mail.example.org ESMTP\r\n").await;
	let _ = read_line(&mut plain).await; // EHLO
	let _ = plain
		.write_all(b"250-mail.example.org\r\n250 STARTTLS\r\n")
		.await;
	let _ = read_line(&mut plain).await; // STARTTLS
	let _ = plain.write_all(b"220 go ahead\r\n").await;
	let mut tls = match acceptor.accept(plain).await {
		Ok(tls) => tls,
		Err(_) => return,
	};
	// RFC 5321 STARTTLS: the client sends EHLO directly, no fresh banner.
	let _ = read_line(&mut tls).await; // EHLO
	let _ = tls.write_all(b"250 mail.example.org\r\n").await;
	let _ = read_line(&mut tls).await; // MAIL FROM
	let _ = tls.write_all(b"250 ok\r\n").await;
	let _ = read_line(&mut tls).await; // RCPT TO
	let _ = tls.write_all(b"250 ok\r\n").await;
	let _ = read_line(&mut tls).await; // DATA
	let _ = tls.write_all(b"354 send it\r\n").await;
	// Consume message lines until the lone "." terminator.
	loop {
		let line = read_line(&mut tls).await;
		if line == ".\r\n" || line.is_empty() {
			break;
		}
	}
	let _ = tls.write_all(b"250 queued\r\n").await;
	let _ = read_line(&mut tls).await; // QUIT
	let _ = tls.write_all(b"221 bye\r\n").await;
}

/// Drive one delivery against the mock MTA with the given mode and TLSA set,
/// reusing `leaf` so a DANE association can be derived by the caller.
async fn run_with(
	acceptor: TlsAcceptor,
	mode: OutboundTls,
	tlsa: Vec<TlsaRecord>,
) -> Result<(), DeliveryError> {
	let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(mock_mta(acceptor, server_stream));
	let result = deliver(
		client_stream,
		"mail.example.org",
		"mail.sender.example",
		"alice@sender.example",
		&["bob@example.org".to_string()],
		b"Subject: hi\r\n\r\nbody\r\n",
		false,
		None,
		&tlsa,
		mode,
	)
	.await;
	let _ = task.await;
	result
}

#[tokio::test]
async fn strict_mode_rejects_self_signed_starttls() {
	// Default strict, no TLSA, no mandate: the self-signed cert is not in the
	// webpki roots, so the handshake must fail closed (transient → retried).
	let (acceptor, _leaf) = acceptor_and_leaf();
	let result = run_with(acceptor, OutboundTls::Strict, Vec::new()).await;
	assert!(
		matches!(result, Err(DeliveryError::Transient(_))),
		"{result:?}"
	);
}

#[tokio::test]
async fn opportunistic_mode_accepts_self_signed_starttls() {
	// Opportunistic: the accept-any verifier completes the handshake and the
	// mail is delivered (encryption without authentication).
	let (acceptor, _leaf) = acceptor_and_leaf();
	let result = run_with(acceptor, OutboundTls::Opportunistic, Vec::new()).await;
	assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn dane_ee_authenticates_self_signed_in_strict_mode() {
	// A DANE-EE (usage 3) TLSA record for the SHA-256 of the full self-signed
	// leaf. Even in strict mode this must use the accept-any handshake and then
	// authenticate via TLSA, so the self-signed DANE-EE cert is delivered to.
	let (acceptor, leaf) = acceptor_and_leaf();
	let digest = ring::digest::digest(&ring::digest::SHA256, &leaf)
		.as_ref()
		.to_vec();
	let record = TlsaRecord::from_parts(3, 0, 1, digest).expect("tlsa record");
	let result = run_with(acceptor, OutboundTls::Strict, vec![record]).await;
	assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn dane_mismatch_is_transient_even_in_opportunistic_mode() {
	// A TLSA record that does not match the presented cert: the handshake
	// accepts any cert, but verify_chain fails closed (transient), so the
	// message is retried rather than sent to an unauthenticated DANE host.
	let (acceptor, _leaf) = acceptor_and_leaf();
	let bogus = TlsaRecord::from_parts(3, 0, 1, vec![0u8; 32]).expect("tlsa record");
	let result = run_with(acceptor, OutboundTls::Opportunistic, vec![bogus]).await;
	assert!(
		matches!(result, Err(DeliveryError::Transient(_))),
		"{result:?}"
	);
}
