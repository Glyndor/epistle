//! Resource bounds for rejected ManageSieve literals.

use super::*;

fn start_server(
	max_literal: usize,
	timeout: Duration,
) -> (
	tokio::io::DuplexStream,
	tokio::task::JoinHandle<std::io::Result<()>>,
	tempfile::TempDir,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let (tls, _) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.path().to_path_buf(), directory, tls)
		.with_max_literal(max_literal)
		.with_preauth_timeout(timeout);
	let (client, stream) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move { server.handle_stream(stream).await });
	(client, task, dir)
}

async fn greeting(client: &mut tokio::io::DuplexStream) {
	let mut buf = [0; 4096];
	assert!(client.read(&mut buf).await.expect("greeting") > 0);
}

async fn read_closed(client: &mut tokio::io::DuplexStream) -> (bool, String) {
	let mut reply = Vec::new();
	let result = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply)).await;
	(
		matches!(result, Ok(Ok(_))),
		String::from_utf8(reply).expect("response text"),
	)
}

#[tokio::test(start_paused = true)]
async fn above_cap_literal_closes_without_reading_payload() {
	let (mut client, task, _dir) = start_server(8, Duration::from_secs(60));
	greeting(&mut client).await;
	client
		.write_all(b"PUTSCRIPT \"a\" {9+}\r\nx")
		.await
		.expect("announcement");
	let (closed, reply) = read_closed(&mut client).await;
	assert!(
		closed,
		"oversized ManageSieve literal must close without waiting for payload"
	);
	assert_eq!(
		reply, "BYE \"literal too large\"\r\n",
		"oversized ManageSieve literal must receive the exact BYE"
	);
	task.await.expect("server task").expect("server result");
}

#[tokio::test]
async fn discarded_literal_storage_stays_below_one_mib() {
	let size = 8 * 1024 * 1024;
	let mut bytes = vec![b'x'; size - 3];
	bytes.extend_from_slice(b"NOOP\r\n");
	let mut stream = std::io::Cursor::new(bytes);
	let mut decoder = LineDecoder::new();
	decoder.feed(b"xxx");
	let drained = discard::literal(&mut stream, &mut decoder, size, Duration::from_secs(2))
		.await
		.expect("drain");
	assert!(
		drained.peak_storage < 1024 * 1024,
		"discarded ManageSieve bytes must retain less than 1 MiB, retained {} bytes",
		drained.peak_storage
	);
	assert!(
		drained.complete,
		"the entire rejected literal must be consumed"
	);
	// A read can split the next command between the decoder and the stream.
	let mut remainder = Vec::new();
	stream
		.read_to_end(&mut remainder)
		.await
		.expect("command remainder");
	decoder.feed(&remainder);

	let next_line = decoder
		.next_line()
		.expect("valid command")
		.map(|line| String::from_utf8(line).expect("command text"));

	assert_eq!(
		next_line.as_deref(),
		Some("NOOP"),
		"the following ManageSieve command must remain in the decoder"
	);
	assert_eq!(
		stream.position() as usize,
		size - 3 + 6,
		"drain must read exactly the available literal and command bytes"
	);
}

#[tokio::test(start_paused = true)]
async fn discarded_literal_keeps_preauth_read_deadline() {
	let (mut client, task, _dir) = start_server(2048, Duration::from_secs(2));
	greeting(&mut client).await;
	client
		.write_all(b"PUTSCRIPT \"a\" {1024+}\r\nx")
		.await
		.expect("partial literal");
	let (closed, reply) = read_closed(&mut client).await;
	assert!(
		closed,
		"rejected ManageSieve literal must close at the pre-auth read deadline"
	);
	assert_eq!(
		reply, "NO \"Authenticate first.\"\r\nBYE \"read timeout\"\r\n",
		"stalled ManageSieve discard must receive the exact timeout response"
	);
	task.await.expect("server task").expect("server result");
}
