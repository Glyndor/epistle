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
fn small_max_literal_server(max_literal: usize) -> (
	tokio::io::DuplexStream,
	tokio::task::JoinHandle<std::io::Result<()>>,
	tempfile::TempDir,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.path().to_path_buf(), directory(), acceptor)
		.with_max_literal(max_literal);
	let (client, server_stream) = tokio::io::duplex(256 * 1024);
	let task = tokio::spawn(async move { server.handle_stream(server_stream).await });
	(client, task, dir)
}

async fn read_chunk(client: &mut tokio::io::DuplexStream) -> String {
	let mut chunk = [0u8; 4096];
	let read = client.read(&mut chunk).await.expect("read");
	String::from_utf8_lossy(&chunk[..read]).to_string()
}

/// RFC 5804 echoes RFC 7888's framing rule: when the server rejects a
/// non-synchronizing literal (the `{N+}` form), the payload bytes the
/// client already sent must not arrive as the next command line. With a
/// server whose max-literal cap is below the payload size, the rejection
/// fires before the literal is read, leaving the bytes in the stream
/// buffer where they would otherwise look like a tagged command.
#[tokio::test]
async fn rejected_putscript_literal_is_discarded() {
	let (mut client, task, dir) = small_max_literal_server(8);
	let _ = read_chunk(&mut client).await;

	// 10-byte payload that is a valid command ("LOGOUT\r\n" plus padding
	// for the CRLF) — the most damning shape, because the bug would
	// close the connection here.
	let inner: &[u8] = b"LOGOUT\r\nX";
	let header = format!("PUTSCRIPT \"a\" {{{}+}}\r\n", inner.len());
	client.write_all(header.as_bytes()).await.expect("header");
	client.write_all(inner).await.expect("payload");

	// Drain whatever the server sends and assert the rejection. With the
	// bug the literal leaks and the server answers BYE (because LOGOUT
	// closes the connection) before closing the socket. With the fix the
	// server only emits the NO rejection, the literal is discarded, and
	// the connection stays usable.
	let reply = read_chunk(&mut client).await;
	assert!(
		reply.contains("NO"),
		"PUTSCRIPT over the cap must produce a NO: {reply}"
	);
	assert!(
		!reply.contains("BYE"),
		"rejected PUTSCRIPT must not see the literal as LOGOUT: {reply}"
	);

	// The literal bytes must not be parsed as a command: NOOP is
	// answered with OK and the session keeps going.
	client.write_all(b"NOOP\r\n").await.expect("noop");
	let reply = read_chunk(&mut client).await;
	assert!(
		reply.starts_with("OK"),
		"NOOP must be answered with OK, not the leaked payload: {reply}"
	);

	client.write_all(b"LOGOUT\r\n").await.expect("logout");
	let _ = read_chunk(&mut client).await;
	drop(client);
	let _ = task.await;
	let _ = dir;
}