//! The pre-authentication deadline covers every read of the session, counts
//! from its start, and is not extended by traffic. Every test runs on tokio's
//! paused clock.

use super::*;
use tokio::time::Instant;

const PREAUTH: Duration = Duration::from_secs(4);

fn start_server() -> (
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
		.with_max_literal(4096)
		.with_preauth_timeout(PREAUTH);
	let (client, stream) = tokio::io::duplex(8192);
	let task = tokio::spawn(async move { server.handle_stream(stream).await });
	(client, task, dir)
}

async fn greeting(client: &mut tokio::io::DuplexStream) {
	let mut buf = [0; 4096];
	assert!(client.read(&mut buf).await.expect("greeting") > 0);
}

/// Send `chunk` once a second until the server hangs up, then return the
/// seconds the connection lived and everything the server said.
async fn drip_until_closed(
	client: &mut tokio::io::DuplexStream,
	start: Instant,
	chunk: &[u8],
) -> (u64, String) {
	for _ in 0..30 {
		if client.write_all(chunk).await.is_err() {
			break;
		}
		tokio::time::sleep(Duration::from_secs(1)).await;
	}
	let mut reply = Vec::new();
	let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply)).await;
	(
		start.elapsed().as_secs(),
		String::from_utf8(reply).expect("response text"),
	)
}

#[tokio::test(start_paused = true)]
async fn a_literal_that_never_arrives_is_cut_at_the_deadline() {
	let (mut client, task, _dir) = start_server();
	greeting(&mut client).await;
	let start = Instant::now();
	client.write_all(b"NOOP {5}\r\n").await.expect("noop");
	let mut reply = Vec::new();
	let closed = tokio::time::timeout(
		PREAUTH + Duration::from_secs(1),
		client.read_to_end(&mut reply),
	)
	.await;
	assert!(
		closed.is_ok(),
		"a silent literal must be closed at the deadline"
	);
	assert!(start.elapsed() <= PREAUTH + Duration::from_secs(1));
	assert_eq!(
		String::from_utf8(reply).expect("text"),
		"BYE \"read timeout\"\r\n",
		"the stalled literal gets the exact timeout response"
	);
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_dripped_literal_does_not_extend_the_deadline() {
	let (mut client, task, _dir) = start_server();
	greeting(&mut client).await;
	let start = Instant::now();
	client.write_all(b"NOOP {1000}\r\n").await.expect("noop");
	let (lived, reply) = drip_until_closed(&mut client, start, b"x").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert_eq!(reply, "BYE \"read timeout\"\r\n");
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_dripped_command_line_does_not_extend_the_deadline() {
	let (mut client, task, _dir) = start_server();
	greeting(&mut client).await;
	let start = Instant::now();
	let (lived, reply) = drip_until_closed(&mut client, start, b"N").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert_eq!(reply, "BYE \"Pre-authentication timeout.\"\r\n");
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_stream_of_commands_does_not_extend_the_deadline() {
	let (mut client, task, _dir) = start_server();
	greeting(&mut client).await;
	let start = Instant::now();
	let (lived, reply) = drip_until_closed(&mut client, start, b"NOOP\r\n").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert!(reply.ends_with("BYE \"Pre-authentication timeout.\"\r\n"));
	task.await.expect("server task").expect("server result");
}

#[tokio::test(start_paused = true)]
async fn a_dripped_discarded_literal_does_not_extend_the_deadline() {
	let (mut client, task, _dir) = start_server();
	greeting(&mut client).await;
	let start = Instant::now();
	client
		.write_all(b"PUTSCRIPT \"a\" {1024+}\r\n")
		.await
		.expect("announcement");
	let (lived, reply) = drip_until_closed(&mut client, start, b"x").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert_eq!(
		reply,
		"NO \"Authenticate first.\"\r\nBYE \"read timeout\"\r\n"
	);
	task.await.expect("server task").expect("server result");
}
