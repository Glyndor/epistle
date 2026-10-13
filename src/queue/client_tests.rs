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
		&TlsaRrset::Absent,
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
		&TlsaRrset::Absent,
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
		&TlsaRrset::Absent,
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
		&TlsaRrset::Absent,
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

#[test]
fn pkix_authentication_decision() {
	use OutboundTls::{Opportunistic, Strict};
	// Mandated TLS without DANE records is strict PKIX in either mode.
	assert!(pkix_required(true, false, Opportunistic));
	assert!(pkix_required(true, false, Strict));
	// Usable TLSA records: never PKIX, DANE authenticates instead, even
	// when MTA-STS enforce or REQUIRETLS mandates TLS.
	assert!(!pkix_required(true, true, Strict));
	assert!(!pkix_required(false, true, Strict));
	assert!(!pkix_required(false, true, Opportunistic));
	// Neither mandate nor DANE: mode decides.
	assert!(pkix_required(false, false, Strict));
	assert!(!pkix_required(false, false, Opportunistic));
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

#[test]
fn a_reply_is_read_by_its_code_and_enhanced_status() {
	let cases: &[(u16, &str, DeliveryError)] = &[
		(
			550,
			"550 5.1.1 no such user\r\n",
			DeliveryError::Permanent("550 5.1.1 no such user".into()),
		),
		// Mailbox full is persistent transient (RFC 3463 X.2.2), whatever
		// the basic code says.
		(
			552,
			"552 5.2.2 mailbox full\r\n",
			DeliveryError::Transient("552 5.2.2 mailbox full".into()),
		),
		// A multiline reply reads as one line, its status code once.
		(
			550,
			"550-5.7.1 rejected by\r\n550 5.7.1 local policy\r\n",
			DeliveryError::Permanent("550 5.7.1 rejected by local policy".into()),
		),
		(
			451,
			"451 4.3.0 try again later\r\n",
			DeliveryError::Transient("451 4.3.0 try again later".into()),
		),
		// No enhanced status: the basic code decides; 552 is a storage
		// allocation problem (RFC 5321 §4.5.3.1.10), retried.
		(
			552,
			"552 too much mail stored\r\n",
			DeliveryError::Transient("552 too much mail stored".into()),
		),
		// An enhanced status whose class contradicts the reply code is
		// ignored (RFC 3463 §2): the basic 550 stands.
		(
			550,
			"550 4.2.2 odd\r\n",
			DeliveryError::Permanent("550 4.2.2 odd".into()),
		),
	];
	for (code, raw, expected) in cases {
		assert_eq!(
			&DeliveryError::from_reply(*code, raw),
			expected,
			"reply {raw:?}"
		);
	}
}
