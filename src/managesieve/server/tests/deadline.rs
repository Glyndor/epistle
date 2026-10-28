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

const IDLE: u64 = 1800;

/// A session already signed in as `alice`, over the same short pre-auth
/// window, so any use of that window after login shows up at once.
fn start_authed() -> (
	tokio::io::DuplexStream,
	tokio::task::JoinHandle<std::io::Result<()>>,
	tempfile::TempDir,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let (tls, _) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.path().to_path_buf(), directory, tls)
		.with_max_literal(4096)
		.with_preauth_timeout(PREAUTH);
	let (client, stream) = tokio::io::duplex(8192);
	let task = tokio::spawn(async move { server.handle_preauth_for_test(stream, "alice").await });
	(client, task, dir)
}

async fn say(client: &mut tokio::io::DuplexStream, bytes: &[u8]) -> String {
	client.write_all(bytes).await.expect("write");
	let mut buf = [0u8; 4096];
	let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
		.await
		.expect("the server answered")
		.expect("read");
	String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test(start_paused = true)]
async fn a_signed_in_session_is_not_held_to_the_pre_auth_window() {
	let (mut client, task, _dir) = start_authed();
	greeting(&mut client).await;
	for _ in 0..3 {
		tokio::time::sleep(Duration::from_secs(IDLE - 60)).await;
		assert_eq!(say(&mut client, b"NOOP\r\n").await, "OK\r\n");
	}
	drop(client);
	let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn a_signed_in_command_is_cut_after_the_idle_timeout() {
	let (mut client, task, _dir) = start_authed();
	greeting(&mut client).await;
	let start = Instant::now();
	client
		.write_all(b"PUTSCRIPT \"a\" {1000+}\r\n")
		.await
		.expect("announcement");
	let mut buf = [0u8; 64];
	let mut seen = Vec::new();
	for _ in 0..40 {
		if client.write_all(b"x").await.is_err() {
			break;
		}
		tokio::time::sleep(Duration::from_secs(100)).await;
	}
	let _ = tokio::time::timeout(Duration::from_secs(5), async {
		while let Ok(n) = client.read(&mut buf).await {
			if n == 0 {
				break;
			}
			seen.extend_from_slice(&buf[..n]);
		}
	})
	.await;
	let lived = start.elapsed().as_secs();
	assert!(
		(IDLE..=IDLE + 200).contains(&lived),
		"cut at the idle timeout, lived {lived}s"
	);
	assert_eq!(String::from_utf8_lossy(&seen), "BYE \"read timeout\"\r\n");
	let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn idle_time_before_a_command_does_not_shorten_its_literal() {
	let (mut client, task, _dir) = start_authed();
	greeting(&mut client).await;
	tokio::time::sleep(Duration::from_secs(IDLE - 10)).await;
	client
		.write_all(b"PUTSCRIPT \"a\" {7+}\r\n")
		.await
		.expect("announcement");
	tokio::time::sleep(Duration::from_secs(20)).await;
	assert_eq!(say(&mut client, b"keep;\r\n").await, "OK\r\n");
	drop(client);
	let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn signing_out_opens_a_fresh_pre_auth_window() {
	let (mut client, task, _dir) = start_authed();
	greeting(&mut client).await;
	tokio::time::sleep(PREAUTH * 3).await;
	assert_eq!(say(&mut client, b"UNAUTHENTICATE\r\n").await, "OK\r\n");
	tokio::time::sleep(PREAUTH - Duration::from_secs(1)).await;
	let reply = say(&mut client, b"CAPABILITY\r\n").await;
	assert!(
		reply.contains("\"IMPLEMENTATION\""),
		"still served: {reply}"
	);
	let start = Instant::now();
	let mut rest = Vec::new();
	let _ = tokio::time::timeout(Duration::from_secs(20), client.read_to_end(&mut rest)).await;
	assert!(start.elapsed() <= PREAUTH + Duration::from_secs(1));
	assert_eq!(
		String::from_utf8_lossy(&rest),
		"BYE \"Pre-authentication timeout.\"\r\n"
	);
	let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn audit_preauth_deadline_also_bounds_blocked_output() {
	let (mut client, task, _dir) = start_server();
	greeting(&mut client).await;
	client
		.write_all("CAPABILITY\r\n".repeat(200).as_bytes())
		.await
		.expect("write");
	for _ in 0..100 {
		tokio::task::yield_now().await;
	}
	tokio::time::advance(PREAUTH * 3).await;
	for _ in 0..100 {
		tokio::task::yield_now().await;
	}
	let ended = task.is_finished();
	task.abort();
	let _ = task.await;
	assert!(
		ended,
		"preauth session remains alive after 3 deadlines while output is blocked"
	);
}

#[tokio::test(start_paused = true)]
async fn the_tls_handshake_shares_the_pre_auth_deadline() {
	let (mut client, task, _dir) = start_server();
	greeting(&mut client).await;
	let start = Instant::now();
	tokio::time::sleep(PREAUTH - Duration::from_secs(1)).await;
	let reply = say(&mut client, b"STARTTLS\r\n").await;
	assert_eq!(reply, "OK \"Begin TLS negotiation now.\"\r\n");
	let mut rest = Vec::new();
	let _ = tokio::time::timeout(Duration::from_secs(60), client.read_to_end(&mut rest)).await;
	let lived = start.elapsed();
	assert!(
		lived <= PREAUTH + Duration::from_secs(1),
		"a handshake that never starts is cut with the window, lived {lived:?}"
	);
	let _ = task.await;
}

/// Build a ManageSieve listener for the audit tests. The audit path is
/// driven through the in-memory `handle_preauth_for_test`, which adopts
/// the account without a STARTTLS handshake so the test can stall the
/// underlying transport without negotiating TLS first.
fn start_audit_server() -> (tempfile::TempDir, crate::managesieve::server::Server) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let (tls, _) = crate::tls::test_support::acceptor_and_cert();
	let server = crate::managesieve::server::Server::new(dir.path().to_path_buf(), directory, tls)
		.with_max_literal(4096)
		.with_preauth_timeout(PREAUTH);
	(dir, server)
}

#[tokio::test(start_paused = true)]
async fn audit_unauthenticate_slow_flush_gets_a_fresh_window() {
	let (_dir, server) = start_audit_server();
	let (mut client, transport, ctl) = crate::net::tests::audit_support::Gate::pair();
	let task =
		tokio::spawn(async move { server.handle_preauth_for_test(transport, "alice").await });
	crate::net::tests::audit_support::greeting(&mut client).await;
	tokio::time::advance(PREAUTH * 3).await;
	crate::net::tests::audit_support::settle().await;
	ctl.block(2);
	client
		.write_all(b"UNAUTHENTICATE\r\n")
		.await
		.expect("write");
	crate::net::tests::audit_support::settle().await;
	let prematurely_ended = task.is_finished();
	tokio::time::advance(Duration::from_secs(1)).await;
	ctl.release();
	crate::net::tests::audit_support::settle().await;
	if !prematurely_ended {
		let mut reply = [0u8; 64];
		let n = client.read(&mut reply).await.expect("ok");
		assert_eq!(&reply[..n], b"OK\r\n");
		client.write_all(b"LOGOUT\r\n").await.expect("logout");
		let mut rest = Vec::new();
		tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut rest))
			.await
			.expect("bye")
			.expect("bye read");
		assert_eq!(rest, b"BYE \"Goodbye.\"\r\n");
	}
	drop(client);
	let result = task.await.expect("join");
	assert!(
		!prematurely_ended,
		"UNAUTHENTICATE closes on its expired old preauth clock: {result:?}"
	);
	assert!(result.is_ok(), "{result:?}");
}
