use super::*;
use tokio::io::duplex;

fn clock() -> SessionClock {
	SessionClock::start(DEFAULT_PREAUTH_TIMEOUT, TIMEOUT)
}

fn backend() -> MailboxBackend {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	MailboxBackend::new(directory, dir.path().to_path_buf())
}

#[tokio::test]
async fn too_many_errors_closes_connection() {
	let (mut client, server) = duplex(64 * 1024);
	let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
	// Drain the greeting, then spam invalid commands.
	let mut chunk = [0u8; 4096];
	let _ = client.read(&mut chunk).await;
	for _ in 0..25 {
		let _ = client.write_all(b"BOGUS\r\n").await;
	}
	// Read until the connection is closed; the last reply is the abuse error.
	let mut seen = String::new();
	loop {
		let read = client.read(&mut chunk).await.expect("read");
		if read == 0 {
			break;
		}
		seen.push_str(&String::from_utf8_lossy(&chunk[..read]));
	}
	assert!(seen.contains("too many errors"), "{seen}");
	let _ = task.await;
}

async fn read_chunk(client: &mut tokio::io::DuplexStream) -> String {
	let mut chunk = [0u8; 4096];
	let read = client.read(&mut chunk).await.expect("read");
	String::from_utf8_lossy(&chunk[..read]).to_string()
}

#[tokio::test]
async fn quit_after_greeting_closes_cleanly() {
	let (mut client, server) = duplex(64 * 1024);
	let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
	let greeting = read_chunk(&mut client).await;
	assert!(greeting.starts_with("+OK"), "{greeting}");
	client.write_all(b"QUIT\r\n").await.expect("write");
	let bye = read_chunk(&mut client).await;
	assert!(bye.starts_with("+OK"), "{bye}");
	// The server closed: the next read yields EOF.
	let mut chunk = [0u8; 16];
	assert_eq!(client.read(&mut chunk).await.expect("read"), 0);
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn eof_ends_the_session() {
	let (mut client, server) = duplex(64 * 1024);
	let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
	let _ = read_chunk(&mut client).await;
	drop(client); // client hangs up before any command.
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn overlong_line_is_rejected() {
	let (mut client, server) = duplex(256 * 1024);
	let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
	let _ = read_chunk(&mut client).await;
	// A line far longer than the protocol allows.
	let huge = vec![b'A'; 100 * 1024];
	client.write_all(&huge).await.expect("write");
	client.write_all(b"\r\n").await.expect("write");
	let reply = read_chunk(&mut client).await;
	assert!(reply.contains("line too long"), "{reply}");
	let _ = task.await;
}

#[tokio::test]
async fn non_ascii_command_is_rejected() {
	let (mut client, server) = duplex(64 * 1024);
	let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
	let _ = read_chunk(&mut client).await;
	client.write_all(&[0xff, 0xfe]).await.expect("write");
	client.write_all(b"\r\n").await.expect("write");
	let reply = read_chunk(&mut client).await;
	assert!(reply.contains("non-ASCII"), "{reply}");
	// The session stays open after a non-final error; hang up to end it.
	drop(client);
	let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_closes_connection() {
	let (mut client, server) = duplex(64 * 1024);
	let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
	let _ = read_chunk(&mut client).await; // greeting
	// Send nothing: the read timeout (paused clock) fires and closes.
	let mut chunk = [0u8; 16];
	assert_eq!(client.read(&mut chunk).await.expect("read"), 0);
	assert!(task.await.expect("join").is_ok());
}
