//! The sign-in deadline covers every read before authentication, counts from
//! the start of the session, and is not extended by traffic. Every test runs
//! on tokio's paused clock.

use super::*;
use tokio::time::Instant;

const PREAUTH: Duration = Duration::from_secs(4);

fn start() -> (
	tokio::io::DuplexStream,
	tokio::task::JoinHandle<std::io::Result<()>>,
	tempfile::TempDir,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("dirs");
	let password = crate::smtp::auth::tests::base::fixture_password();
	let directory = crate::smtp::directory::Directory::new(
		["example.org".into()],
		[("alice@example.org".into(), "alice".into())],
	)
	.with_password_hashes(std::collections::HashMap::from([(
		"alice".into(),
		crate::smtp::auth::tests::base::hash(password),
	)]));
	let backend = MailboxBackend::new(DirectoryHandle::new(directory), dir.path().into());
	let (client, server) = tokio::io::duplex(8192);
	let clock = SessionClock::start(PREAUTH, TIMEOUT);
	let task = tokio::spawn(run(server, backend, None, clock, None));
	(client, task, dir)
}

async fn read_chunk(client: &mut tokio::io::DuplexStream) -> String {
	let mut chunk = [0u8; 4096];
	let read = client.read(&mut chunk).await.expect("read");
	String::from_utf8_lossy(&chunk[..read]).to_string()
}

/// Send `chunk` once a second until the server hangs up, then return the
/// seconds the connection lived.
async fn drip_until_closed(client: &mut tokio::io::DuplexStream, chunk: &[u8]) -> u64 {
	let start = Instant::now();
	for _ in 0..30 {
		if client.write_all(chunk).await.is_err() {
			break;
		}
		tokio::time::sleep(Duration::from_secs(1)).await;
	}
	let mut rest = Vec::new();
	let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest)).await;
	start.elapsed().as_secs()
}

#[tokio::test(start_paused = true)]
async fn a_silent_client_is_cut_at_the_deadline() {
	let (mut client, task, _dir) = start();
	let _ = read_chunk(&mut client).await;
	let start = Instant::now();
	let mut rest = Vec::new();
	client.read_to_end(&mut rest).await.expect("closed");
	assert_eq!(start.elapsed(), PREAUTH);
	assert!(task.await.expect("server task").is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_dripped_command_line_does_not_extend_the_deadline() {
	let (mut client, task, _dir) = start();
	let _ = read_chunk(&mut client).await;
	let lived = drip_until_closed(&mut client, b"U").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert!(task.await.expect("server task").is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_stream_of_commands_does_not_extend_the_deadline() {
	let (mut client, task, _dir) = start();
	let _ = read_chunk(&mut client).await;
	let lived = drip_until_closed(&mut client, b"NOOP\r\n").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert!(task.await.expect("server task").is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_dripped_sasl_response_does_not_extend_the_deadline() {
	let (mut client, task, _dir) = start();
	let _ = read_chunk(&mut client).await;
	client.write_all(b"AUTH PLAIN\r\n").await.expect("auth");
	let lived = drip_until_closed(&mut client, b"x").await;
	assert!(lived <= PREAUTH.as_secs() + 1, "lived {lived}s");
	assert!(task.await.expect("server task").is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_signed_in_session_is_not_held_to_the_sign_in_deadline() {
	let (mut client, task, _dir) = start();
	let _ = read_chunk(&mut client).await;
	client.write_all(b"USER alice\r\n").await.expect("user");
	assert!(read_chunk(&mut client).await.starts_with("+OK"));
	let pass = format!(
		"PASS {}\r\n",
		crate::smtp::auth::tests::base::fixture_password()
	);
	client.write_all(pass.as_bytes()).await.expect("pass");
	assert!(read_chunk(&mut client).await.starts_with("+OK"));
	tokio::time::sleep(PREAUTH * 20).await;
	client.write_all(b"NOOP\r\n").await.expect("noop");
	assert!(read_chunk(&mut client).await.starts_with("+OK"));
	drop(client);
	assert!(task.await.expect("server task").is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_signed_in_command_line_still_gets_the_idle_timeout() {
	let (mut client, task, _dir) = start();
	let _ = read_chunk(&mut client).await;
	client.write_all(b"USER alice\r\n").await.expect("user");
	let _ = read_chunk(&mut client).await;
	let pass = format!(
		"PASS {}\r\n",
		crate::smtp::auth::tests::base::fixture_password()
	);
	client.write_all(pass.as_bytes()).await.expect("pass");
	let _ = read_chunk(&mut client).await;
	let start = Instant::now();
	let mut rest = Vec::new();
	client.read_to_end(&mut rest).await.expect("closed");
	assert_eq!(start.elapsed(), TIMEOUT);
	assert!(task.await.expect("server task").is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_stalled_tls_handshake_is_cut_at_the_deadline() {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".into()],
		[("alice@example.org".into(), "alice".into())],
	));
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.path().into(), directory, acceptor).with_preauth_timeout(PREAUTH);
	let (mut client, stream) = tokio::io::duplex(8192);
	let task =
		tokio::spawn(async move { server.handle(stream, "203.0.113.9".parse().unwrap()).await });
	let start = Instant::now();
	let mut rest = Vec::new();
	let _ = client.read_to_end(&mut rest).await;
	assert_eq!(start.elapsed(), PREAUTH);
	assert!(task.await.expect("server task").is_err());
}

#[tokio::test(start_paused = true)]
async fn audit_preauth_deadline_also_bounds_blocked_output() {
	let (mut client, task, _dir) = start();
	let _ = read_chunk(&mut client).await;
	client
		.write_all("CAPA\r\n".repeat(200).as_bytes())
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
