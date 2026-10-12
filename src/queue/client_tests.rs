//! SMTP client tests: reply framing, rejections, TLS decisions.

use super::*;

#[test]
fn detects_complete_single_line_reply() {
	assert_eq!(complete_reply(b"250 ok\r\n"), Some(8));
	assert_eq!(complete_reply(b"250 ok"), None);
}

#[test]
fn detects_multiline_reply() {
	let reply = b"250-a\r\n250-b\r\n250 c\r\n";
	assert_eq!(complete_reply(reply), Some(reply.len()));
	assert_eq!(complete_reply(b"250-a\r\n"), None);
}

#[tokio::test]
async fn delivers_to_own_server() {
	use crate::smtp::directory::Directory;
	use crate::smtp::server::Server;
	use crate::smtp::sink::{MemorySink, MessageSink};

	let sink = Arc::new(MemorySink::new());
	let directory = crate::directory_store::DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let server = Server::new("mx.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory);

	let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	deliver(
		client_stream,
		"mx.example.org",
		"mail.sender.example",
		"alice@sender.example",
		&["bob@example.org".to_string()],
		b"Subject: hi\r\n\r\n.leading dot\r\nbody\r\n",
		false,
		None,
		&[],
		OutboundTls::Strict,
		&mut None,
	)
	.await
	.expect("delivery succeeds");

	task.abort();
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].reverse_path, "alice@sender.example");
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii");
	// Dot-stuffing round-trips.
	assert!(data.ends_with(".leading dot\r\nbody\r\n"), "{data}");
}

#[tokio::test]
async fn permanent_rejection_is_permanent() {
	use crate::smtp::directory::Directory;
	use crate::smtp::server::Server;
	use crate::smtp::sink::{MemorySink, MessageSink};

	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mx.example.org", sink as Arc<dyn MessageSink>).with_directory(
		crate::directory_store::DirectoryHandle::new(Directory::new(
			["example.org".to_string()],
			[],
		)),
	);

	let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let result = deliver(
		client_stream,
		"mx.example.org",
		"mail.sender.example",
		"alice@sender.example",
		&["unknown@example.org".to_string()],
		b"body\r\n",
		false,
		None,
		&[],
		OutboundTls::Strict,
		&mut None,
	)
	.await;

	task.abort();
	assert!(matches!(result, Err(DeliveryError::Permanent(_))));
}

/// Drive `deliver` against a canned server response (writes are discarded).
async fn deliver_against(greeting: &'static [u8]) -> Result<(), DeliveryError> {
	let stream = tokio::io::join(greeting, tokio::io::sink());
	deliver(
		stream,
		"mx.example.org",
		"mail.sender.example",
		"alice@sender.example",
		&["bob@example.org".to_string()],
		b"body\r\n",
		false,
		None,
		&[],
		OutboundTls::Strict,
		&mut None,
	)
	.await
}

#[tokio::test]
async fn malformed_greeting_is_transient() {
	let result = deliver_against(b"not-a-code\r\n").await;
	assert!(
		matches!(result, Err(DeliveryError::Transient(_))),
		"{result:?}"
	);
}

#[tokio::test]
async fn relay_auth_without_tls_is_permanent() {
	// Greeting then an EHLO reply offering no STARTTLS.
	let canned: &[u8] = b"220 mx ready\r\n250-mx.example.org\r\n250 SIZE 0\r\n";
	let stream = tokio::io::join(canned, tokio::io::sink());
	let result = deliver(
		stream,
		"mx.example.org",
		"mail.sender.example",
		"alice@sender.example",
		&["bob@example.org".to_string()],
		b"body\r\n",
		false,
		Some(("user", "pass")),
		&[],
		OutboundTls::Strict,
		&mut None,
	)
	.await;
	// AUTH credentials must never cross plaintext: fail closed.
	assert!(
		matches!(result, Err(DeliveryError::Permanent(_))),
		"{result:?}"
	);
}

#[tokio::test]
async fn connection_closed_before_greeting_is_transient() {
	let result = deliver_against(b"").await;
	assert!(
		matches!(result, Err(DeliveryError::Transient(_))),
		"{result:?}"
	);
}

#[tokio::test]
async fn oversized_reply_is_transient() {
	// 70 KiB with no CRLF: the reply never completes and trips the cap.
	const HUGE: &[u8] = &[b'a'; 70 * 1024];
	let result = deliver_against(HUGE).await;
	assert!(
		matches!(result, Err(DeliveryError::Transient(_))),
		"{result:?}"
	);
}

/// The exact rule that decides PKIX authentication, mirroring `deliver`.
fn authenticate_pkix(require_tls: bool, tlsa_empty: bool, mode: OutboundTls) -> bool {
	require_tls || (tlsa_empty && mode == OutboundTls::Strict)
}

#[test]
fn pkix_authentication_decision() {
	use OutboundTls::{Opportunistic, Strict};
	// Mandated TLS is always strict PKIX, regardless of mode or TLSA.
	assert!(authenticate_pkix(true, true, Opportunistic));
	assert!(authenticate_pkix(true, false, Opportunistic));
	assert!(authenticate_pkix(true, true, Strict));
	// TLSA present (not mandated): never PKIX: DANE authenticates instead,
	// even in strict mode (the DANE-EE self-signed fix).
	assert!(!authenticate_pkix(false, false, Strict));
	assert!(!authenticate_pkix(false, false, Opportunistic));
	// Pure opportunistic (no mandate, no TLSA): mode decides.
	assert!(authenticate_pkix(false, true, Strict));
	assert!(!authenticate_pkix(false, true, Opportunistic));
}

#[test]
fn accept_any_verifier_asserts_and_advertises_schemes() {
	crate::tls::ensure_crypto_provider();
	let verifier = AcceptAnyServerCert::new();
	// Any chain is accepted without PKIX (the leaf can be unparseable here:
	// verify_server_cert never inspects it).
	let leaf = CertificateDer::from(vec![0u8; 8]);
	let verified = verifier.verify_server_cert(
		&leaf,
		&[],
		&ServerName::try_from("mx.example.org").expect("name"),
		&[],
		UnixTime::now(),
	);
	assert!(verified.is_ok());
	// The schemes come from the provider, so the offered set is non-empty and
	// matches what the signature checks can verify.
	assert!(!verifier.supported_verify_schemes().is_empty());
}
