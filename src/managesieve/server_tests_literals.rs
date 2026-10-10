//! ManageSieve server connection-loop tests for literal framing.

use super::*;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(std::collections::HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)])),
	)
}

/// Server whose max-literal cap is small enough to drive a rejection
/// from a tiny payload in the test, without sending megabytes.
fn small_max_literal_server(
	max_literal: usize,
) -> (
	tokio::io::DuplexStream,
	tokio::task::JoinHandle<std::io::Result<()>>,
	tempfile::TempDir,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server =
		Server::new(dir.path().to_path_buf(), directory(), acceptor).with_max_literal(max_literal);
	let (client, server_stream) = tokio::io::duplex(256 * 1024);
	let task = tokio::spawn(async move { server.handle_stream(server_stream).await });
	(client, task, dir)
}

async fn read_chunk(client: &mut tokio::io::DuplexStream) -> String {
	let mut chunk = [0u8; 4096];
	let read = client.read(&mut chunk).await.expect("read");
	String::from_utf8_lossy(&chunk[..read]).to_string()
}

/// A rejected literal under the cap must not execute its embedded LOGOUT.
#[tokio::test]
async fn rejected_putscript_literal_is_discarded() {
	let (mut client, task, _dir) = small_max_literal_server(16);
	let _ = read_chunk(&mut client).await;
	let inner: &[u8] = b"LOGOUT\r\nX";
	let header = format!("PUTSCRIPT \"a\" {{{}+}}\r\n", inner.len());
	client.write_all(header.as_bytes()).await.expect("header");
	client.write_all(inner).await.expect("payload");

	let reply = read_chunk(&mut client).await;
	assert_eq!(
		reply, "NO \"Authenticate first.\"\r\n",
		"rejected PUTSCRIPT must receive only the authentication rejection"
	);
	client.write_all(b"NOOP\r\n").await.expect("noop");
	let reply = read_chunk(&mut client).await;
	assert_eq!(
		reply, "OK\r\n",
		"NOOP must be answered with OK after the rejected literal"
	);

	client.write_all(b"LOGOUT\r\n").await.expect("logout");
	let _ = read_chunk(&mut client).await;
	drop(client);
	task.await.expect("server task").expect("server result");
}

/// When the connection closes before the announced literal size arrives,
/// the partial payload must not be stored as a script: it is discarded
/// and a `NO` is returned. Otherwise a malicious or buggy client could
/// plant a truncated Sieve script on the server.
#[tokio::test]
async fn truncated_literal_at_eof_is_not_stored() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.path().to_path_buf(), directory(), acceptor);
	let (mut client, server_stream) = tokio::io::duplex(256 * 1024);
	let task =
		tokio::spawn(async move { server.handle_preauth_for_test(server_stream, "alice").await });

	// Drain the greeting; the test session starts over TLS by construction.
	let _ = read_chunk(&mut client).await;

	// Announce a 100-byte script and send a short valid-prefix payload
	// ("require \"x\";" — 13 bytes) then close. With the bug the parser
	// accepts the prefix as a complete script (it has a balanced
	// require + semicolon and an identifier), so 13 bytes are stored
	// under "a.sieve". With the fix the server detects truncation and
	// drops the partial literal without calling session.handle.
	let header = b"PUTSCRIPT \"a\" {100+}\r\n";
	client.write_all(header).await.expect("header");
	client
		.write_all(b"require \"x\";")
		.await
		.expect("partial payload");
	drop(client);

	// Give the server a chance to drain and tear down.
	let _ = task.await;

	// The filesystem must not contain a script named "a.sieve".
	let sieve_dir = dir.path().join("accounts/alice/sieve");
	let stored = std::fs::read_dir(&sieve_dir)
		.map(|entries| {
			entries
				.filter_map(|e| e.ok())
				.map(|e| e.file_name().to_string_lossy().into_owned())
				.collect::<Vec<_>>()
		})
		.unwrap_or_default();
	assert!(
		!stored.iter().any(|name| name == "a.sieve"),
		"truncated literal at EOF must not create a script; saw: {stored:?}"
	);
}

/// An unauthenticated client must not be able to hold a connection slot
/// forever. The server enforces a pre-auth read deadline that fires
/// without any traffic on the socket.
#[tokio::test(start_paused = true)]
async fn preauth_read_timeout_drops_connection() {
	use std::time::Duration;

	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.path().to_path_buf(), directory(), acceptor)
		.with_preauth_timeout(Duration::from_secs(2));
	let (mut client, server_stream) = tokio::io::duplex(256 * 1024);
	let task = tokio::spawn(async move { server.handle_stream(server_stream).await });

	// Drain the greeting.
	let _ = read_chunk(&mut client).await;

	// Send nothing. Tokio's paused clock advances once the test is
	// otherwise idle, so the 2-second pre-auth deadline fires without
	// waiting on wall-clock time.
	let mut seen = String::new();
	loop {
		let mut chunk = [0u8; 4096];
		match tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk)).await {
			Ok(Ok(0)) => break,
			Ok(Ok(n)) => seen.push_str(&String::from_utf8_lossy(&chunk[..n])),
			Ok(Err(_)) => break,
			Err(_) => panic!("server did not close within 5s; partial reply: {seen}"),
		}
	}
	assert!(
		seen.contains("BYE") && seen.contains("timeout"),
		"expected a BYE timeout response, saw: {seen}"
	);
	let _ = task.await;
}
