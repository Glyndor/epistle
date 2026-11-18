//! SMTP server TLS and connection-handling tests.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

#[tokio::test]
async fn starttls_upgrade_and_transaction() {
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_tls(
			crate::tls::ReloadableAcceptor::new(acceptor),
			TlsMode::Opportunistic,
		);

	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	assert!(read_reply(&mut client).await.starts_with("220 "));
	client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let ehlo = read_reply(&mut client).await;
	assert!(ehlo.contains("250 STARTTLS"), "{ehlo}");

	client.write_all(b"STARTTLS\r\n").await.expect("starttls");
	assert!(read_reply(&mut client).await.starts_with("220 "));

	// TLS handshake over the same stream.
	let connector = test_connector(cert);
	let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org")
		.expect("server name");
	let mut tls_client = connector
		.connect(server_name, client)
		.await
		.expect("tls handshake");

	// No banner inside TLS: the client speaks first and the session forgot
	// the plaintext EHLO.
	tls_client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("tls ehlo");
	let tls_ehlo = read_reply(&mut tls_client).await;
	// STARTTLS must not be offered again inside TLS.
	assert!(!tls_ehlo.contains("STARTTLS"), "{tls_ehlo}");

	tls_client
		.write_all(b"MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n")
		.await
		.expect("transaction");
	let mut got = String::new();
	while !got.contains("354 ") {
		got.push_str(&read_reply(&mut tls_client).await);
	}
	tls_client
		.write_all(b"secret\r\n.\r\nQUIT\r\n")
		.await
		.expect("data");
	let mut tail = String::new();
	while !tail.contains("221 ") {
		tail.push_str(&read_reply(&mut tls_client).await);
	}

	drop(tls_client);
	task.abort();
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii message");
	// The trace header records the TLS protocol.
	assert!(data.starts_with("Received: from c.example.org"), "{data}");
	assert!(data.contains("with ESMTPS;"), "{data}");
	assert!(data.ends_with("secret\r\n"), "{data}");
}

#[tokio::test]
async fn implicit_tls_serves_inside_handshake() {
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink as Arc<dyn MessageSink>).with_tls(
		crate::tls::ReloadableAcceptor::new(acceptor),
		TlsMode::Implicit,
	);

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let connector = test_connector(cert);
	let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org")
		.expect("server name");
	let mut tls_client = connector
		.connect(server_name, client)
		.await
		.expect("tls handshake");

	assert!(read_reply(&mut tls_client).await.starts_with("220 "));
	tls_client.write_all(b"QUIT\r\n").await.expect("quit");
	assert!(read_reply(&mut tls_client).await.contains("221 "));
	task.abort();
}

#[tokio::test]
async fn implicit_tls_without_acceptor_errors() {
	let sink = Arc::new(MemorySink::new());
	// Implicit TLS with no acceptor: only `tls_mode` differs from the default.
	let server = Server {
		tls_mode: TlsMode::Implicit,
		..Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
	};
	let (_client, server_stream) = tokio::io::duplex(1024);
	assert!(server.handle(server_stream, None).await.is_err());
}

#[tokio::test]
async fn serve_accepts_tcp_connections() {
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(Server::new(
		"mail.example.org",
		sink as Arc<dyn MessageSink>,
	));
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("local addr");
	let task = tokio::spawn(server.serve(listener));

	let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
	let mut greeting = [0u8; 64];
	let read = client.read(&mut greeting).await.expect("read greeting");
	assert!(String::from_utf8_lossy(&greeting[..read]).starts_with("220 "));

	client.write_all(b"QUIT\r\n").await.expect("write quit");
	let mut rest = Vec::new();
	client.read_to_end(&mut rest).await.expect("read close");
	assert!(String::from_utf8_lossy(&rest).contains("221 "));
	task.abort();
}

#[tokio::test]
async fn pipelined_commands_are_processed_in_order() {
	// RFC 2920: the client sends the whole command group in a single write
	// without waiting for intermediate replies. The server must process each
	// command in order and deliver the message.
	let (output, sink) = converse(
		b"EHLO c.example.org\r\n\
		  MAIL FROM:<alice@example.org>\r\n\
		  RCPT TO:<bob@example.org>\r\n\
		  DATA\r\n\
		  Subject: hi\r\n\r\nhello\r\n.\r\n\
		  QUIT\r\n",
	)
	.await;
	let data_idx = output.find("354 ").expect("DATA accepted");
	let close_idx = output.find("221 ").expect("connection closed");
	assert!(data_idx < close_idx, "replies out of order: {output}");
	assert!(
		output.trim_end().ends_with("221 2.0.0 closing connection"),
		"{output}"
	);
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].reverse_path, "alice@example.org");
	assert_eq!(messages[0].recipients, vec!["bob@example.org".to_string()]);
}
