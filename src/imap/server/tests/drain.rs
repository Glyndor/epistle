//! A drain closes IMAP sessions with `* BYE`, also out of IDLE.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::shutdown::Drain;

/// Read until `needle` appears, at most 5 s.
async fn read_until(stream: &mut (impl AsyncRead + Unpin), needle: &str) -> String {
	let mut got = String::new();
	let mut chunk = [0u8; 4096];
	while !got.contains(needle) {
		let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
			.await
			.unwrap_or_else(|_| panic!("no {needle:?} within 5 s; got {got:?}"))
			.expect("read");
		assert!(n > 0, "closed waiting for {needle:?}: {got}");
		got.push_str(&String::from_utf8_lossy(&chunk[..n]));
	}
	got
}

#[tokio::test]
async fn an_open_session_is_closed_with_bye() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, _) = crate::tls::test_support::acceptor_and_cert();
	let drain = Drain::new();
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory,
		acceptor,
		TlsMode::StartTls,
	)
	.with_drain(Arc::clone(&drain));
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	read_until(&mut client, "* OK").await;
	client.write_all(b"a1 CAPABILITY\r\n").await.unwrap();
	read_until(&mut client, "a1 OK").await;
	drain.begin();
	let bye = read_until(&mut client, "* BYE").await;
	assert!(bye.contains("shutting down"), "{bye}");
	tokio::time::timeout(Duration::from_secs(5), task)
		.await
		.expect("the session ends after the BYE")
		.unwrap()
		.unwrap();
}
