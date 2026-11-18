use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

fn test_directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
			("b@example.org".to_string(), "bob".to_string()),
		],
	))
}

/// Run one scripted client conversation, returning the full server output.
async fn converse(input: &[u8]) -> (String, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory());

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(input).await.expect("client write");
	client_write.shutdown().await.expect("client shutdown");

	let mut output = Vec::new();
	client_read
		.read_to_end(&mut output)
		.await
		.expect("client read");
	task.await.expect("server task").expect("server result");
	(String::from_utf8(output).expect("ascii output"), sink)
}

#[tokio::test]
async fn greets_on_connect() {
	let (output, _) = converse(b"").await;
	assert!(output.starts_with("220 mail.example.org ESMTP ready\r\n"));
}

#[tokio::test]
async fn full_transaction_is_stored() {
	let script = b"EHLO client.example.org\r\n\
MAIL FROM:<alice@example.org>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";
	let (output, sink) = converse(script).await;
	assert!(
		output.contains("250-mail.example.org"),
		"EHLO reply: {output}"
	);
	assert!(output.contains("354 "), "DATA go-ahead: {output}");
	assert!(
		output.ends_with("221 2.0.0 closing connection\r\n"),
		"{output}"
	);

	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].reverse_path, "alice@example.org");
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii message");
	assert!(
		data.starts_with("Received: from client.example.org ([unknown])\r\n"),
		"{data}"
	);
	assert!(data.contains("with ESMTP;"), "{data}");
	assert!(data.ends_with("Subject: hi\r\n\r\nhello\r\n"), "{data}");
}

#[tokio::test]
async fn bare_lf_closes_connection() {
	let (output, sink) = converse(b"EHLO x.example\nMAIL FROM:<a@b.example>\r\n").await;
	assert!(output.contains("554 5.5.2 bare CR or LF"), "{output}");
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn bare_cr_closes_connection() {
	let (output, _) = converse(b"EHLO x\rexample\r\n").await;
	assert!(output.contains("554 5.5.2 bare CR or LF"), "{output}");
}

#[tokio::test]
async fn nul_byte_closes_connection() {
	let (output, _) = converse(b"EHLO x\0.example\r\n").await;
	assert!(output.contains("554 5.5.2 NUL byte"), "{output}");
}

#[tokio::test]
async fn overlong_line_closes_connection() {
	let mut script = vec![b'x'; 2000];
	script.extend_from_slice(b"\r\n");
	let (output, _) = converse(&script).await;
	assert!(output.contains("500 5.5.2 line too long"), "{output}");
}

#[tokio::test]
async fn out_of_order_commands_are_rejected() {
	let (output, sink) = converse(b"MAIL FROM:<a@example.org>\r\nQUIT\r\n").await;
	assert!(output.contains("503 5.5.1 bad sequence"), "{output}");
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn too_many_errors_closes_connection() {
	// A stream of garbage commands trips the abuse guard.
	let (output, _) = converse(&b"BOGUSCMD\r\n".repeat(25)).await;
	assert!(output.contains("421"), "{output}");
	assert!(output.contains("too many errors"), "{output}");
}

#[tokio::test]
async fn utf8_command_accepted_but_invalid_bytes_rejected() {
	// SMTPUTF8 (RFC 6531): a valid UTF-8 (non-ASCII) EHLO domain is accepted.
	let (output, _) = converse(b"EHLO caf\xC3\xA9.example\r\nQUIT\r\n").await;
	assert!(output.contains("250"), "{output}");
	// Invalid UTF-8 bytes are rejected, never greeted with 250.
	let (output, _) = converse(b"EHLO caf\xFF.example\r\nQUIT\r\n").await;
	assert!(!output.contains("250 caf"), "{output}");
}

#[tokio::test]
async fn eight_bit_data_in_message_body_is_accepted() {
	// 8BITMIME: raw 8-bit content in the DATA phase must be accepted.
	let script = b"EHLO client.example.org\r\n\
MAIL FROM:<a@example.org>\r\n\
RCPT TO:<b@example.org>\r\n\
DATA\r\n\
Subject: test\r\n\
\xFF\xFE binary content\r\n\
.\r\n";
	let (output, sink) = converse(script).await;
	assert!(output.contains("250"), "{output}");
	assert_eq!(sink.messages().len(), 1);
	let data = &sink.messages()[0].data;
	assert!(data.iter().any(|&b| b > 127), "8-bit bytes preserved");
}

#[tokio::test]
async fn starttls_not_offered_without_acceptor() {
	let (output, _) = converse(b"EHLO client.example.org\r\nSTARTTLS\r\nQUIT\r\n").await;
	assert!(!output.contains("250-STARTTLS"), "{output}");
	assert!(output.contains("454 4.7.0 TLS not available"), "{output}");
}

/// Test client TLS connector trusting the given certificate.
pub(super) fn test_connector(
	cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) -> tokio_rustls::TlsConnector {
	let mut roots = tokio_rustls::rustls::RootCertStore::empty();
	roots.add(cert).expect("trust test certificate");
	crate::tls::ensure_crypto_provider();
	let config = tokio_rustls::rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn read_reply<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> String {
	let mut buffer = [0u8; 1024];
	let read = reader.read(&mut buffer).await.expect("read reply");
	String::from_utf8_lossy(&buffer[..read]).to_string()
}

mod dns;
mod tls;
