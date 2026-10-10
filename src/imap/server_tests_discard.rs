//! Resource bounds for rejected non-synchronizing IMAP literals.

use super::*;

fn start_server(
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
	let server = Server::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		directory,
		tls,
		TlsMode::StartTls,
	)
	.with_read_timeout(timeout);
	let (client, stream) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move { server.handle(stream, None).await });
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
	let (mut client, task, _dir) = start_server(Duration::from_secs(1800));
	greeting(&mut client).await;
	// The parser's BadArguments path also carries an untrusted size.
	client
		.write_all(b"a2 APPEND Missing {1000000000000+}\r\nx")
		.await
		.expect("announcement");
	let (closed, reply) = read_closed(&mut client).await;
	assert!(
		closed,
		"oversized IMAP literal must close without waiting for payload"
	);
	assert_eq!(
		reply, "* BYE literal too large\r\n",
		"oversized IMAP literal must receive the exact BYE"
	);
	task.await.expect("server task").expect("server result");
}

#[tokio::test]
async fn discarded_literal_storage_stays_below_one_mib() {
	let size = 8 * 1024 * 1024;
	let mut bytes = vec![b'x'; size - 3];
	bytes.extend_from_slice(b"a3 NOOP\r\n");
	let mut stream = std::io::Cursor::new(bytes);
	let mut decoder = LineDecoder::new();
	decoder.feed(b"xxx");
	let drained = discard::literal(&mut stream, &mut decoder, size, Duration::from_secs(2))
		.await
		.expect("drain");
	assert!(
		drained.peak_storage < 1024 * 1024,
		"discarded IMAP bytes must retain less than 1 MiB, retained {} bytes",
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
		Some("a3 NOOP"),
		"the following IMAP command must remain in the decoder"
	);
	assert_eq!(
		stream.position() as usize,
		size - 3 + 9,
		"drain must read exactly the available literal and command bytes"
	);
}

#[tokio::test(start_paused = true)]
async fn discarded_literal_keeps_read_deadline() {
	let (mut client, task, _dir) = start_server(Duration::from_secs(2));
	greeting(&mut client).await;
	client
		.write_all(b"a2 APPEND Missing {1024+}\r\nx")
		.await
		.expect("partial literal");
	let (closed, reply) = read_closed(&mut client).await;
	assert!(
		closed,
		"rejected IMAP literal must close at the read deadline"
	);
	assert_eq!(
		reply, "a2 NO not authenticated\r\n* BYE read timeout\r\n",
		"stalled IMAP discard must receive the exact timeout response"
	);
	task.await.expect("server task").expect("server result");
}
