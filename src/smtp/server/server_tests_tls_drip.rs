//! A TLS handshake dripped one octet at a time holds no message and no
//! reservation, but it holds a connection and a per-IP slot: the whole
//! handshake, implicit or after STARTTLS, is bounded to 30 s.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::tests_data_rate::{pass, test_directory};
use super::*;
use crate::smtp::sink::MemorySink;

fn tls_server(mode: TlsMode) -> (DuplexStream, JoinHandle<std::io::Result<()>>) {
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_tls(crate::tls::ReloadableAcceptor::new(acceptor), mode);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	(client, task)
}

/// Send the start of a 512-octet ClientHello record one octet every 5 s,
/// never finishing it, and return when the server ended the connection.
async fn drip_hello(client: &mut DuplexStream, task: &JoinHandle<std::io::Result<()>>) -> Duration {
	// The server task starts its handshake before the clock moves.
	pass(Duration::ZERO).await;
	let started = Instant::now();
	let record = [
		0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
	];
	for octet in record.iter().cycle().take(40) {
		if task.is_finished() {
			break;
		}
		let _ = client.write_all(&[*octet]).await;
		pass(Duration::from_secs(5)).await;
	}
	started.elapsed()
}

#[tokio::test(start_paused = true)]
async fn a_dripped_implicit_tls_handshake_is_dropped_after_30_seconds() {
	let (mut client, task) = tls_server(TlsMode::Implicit);
	let ended = drip_hello(&mut client, &task).await;
	assert_eq!(
		ended,
		Duration::from_secs(30),
		"the handshake bound ends it"
	);
	let error = task
		.await
		.expect("server task")
		.expect_err("a timed-out handshake");
	assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test(start_paused = true)]
async fn a_dripped_starttls_handshake_is_dropped_after_30_seconds() {
	let (mut client, task) = tls_server(TlsMode::Opportunistic);
	client
		.write_all(b"EHLO client.example.org\r\nSTARTTLS\r\n")
		.await
		.expect("client write");
	let mut seen = Vec::new();
	let mut buffer = [0u8; 1024];
	while !String::from_utf8_lossy(&seen).contains("220 ready to start TLS") {
		let n = client.read(&mut buffer).await.expect("client read");
		assert!(n > 0, "the server closed before the 220");
		seen.extend_from_slice(&buffer[..n]);
	}
	let ended = drip_hello(&mut client, &task).await;
	assert_eq!(
		ended,
		Duration::from_secs(30),
		"the handshake bound ends it"
	);
	let error = task
		.await
		.expect("server task")
		.expect_err("a timed-out handshake");
	assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}
