//! Command floods, resource caps and clients that keep a connection open.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use epistle::smtp::memory_budget::MemoryBudget;
use epistle::smtp::server::DataRate;
use tokio::io::AsyncWriteExt;
use tokio::time::{Instant, sleep, timeout};

use super::harness::*;
use crate::common::BANNER_READ_DEADLINE;

/// Queue thousands of commands without reading even the first response.
async fn flood(client: &mut tokio::net::TcpStream, command: &[u8]) {
	let payload = command.repeat(5000);
	match timeout(BANNER_READ_DEADLINE, client.write_all(&payload)).await {
		Ok(Ok(())) => {}
		Ok(Err(e))
			if matches!(
				e.kind(),
				io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
			) => {}
		other => panic!("flood write stalled or failed unexpectedly: {other:?}"),
	}
}

#[tokio::test]
async fn pipelined_5000_noops_are_bounded_by_421_or_connection_close() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	flood(&mut client, b"NOOP\r\n").await;
	bounded_flood_replies(
		&mut client,
		OK,
		100,
		"421 4.7.0 too many commands without progress, closing connection\r\n",
	)
	.await;
	assert!(server.sink.messages().is_empty());
	server.healthy().await;
}

#[tokio::test]
async fn pipelined_5000_invalid_commands_are_bounded_by_421_or_connection_close() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	flood(&mut client, b"BOGUS\r\n").await;
	bounded_flood_replies(
		&mut client,
		SYNTAX,
		19,
		"421 4.7.0 too many errors, closing connection\r\n",
	)
	.await;
	server.healthy().await;
}

/// Closing TCP with unread attack bytes can reset the connection before all
/// queued replies arrive. Accept that close, but never an extra normal reply.
async fn bounded_flood_replies(
	client: &mut tokio::net::TcpStream,
	normal: &str,
	limit: usize,
	terminal: &str,
) {
	for count in 0..=limit {
		match line(client).await {
			Ok(None) => return,
			Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return,
			Ok(Some(reply)) if count < limit => assert_eq!(reply, normal),
			Ok(Some(reply)) => {
				assert_eq!(reply, terminal);
				closed(client).await;
				return;
			}
			other => panic!("unexpected flood result: {other:?}"),
		}
	}
}

#[tokio::test]
async fn recipient_101_gets_452_and_only_100_reach_delivery() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	helo(&mut client).await;
	send(&mut client, b"MAIL FROM:<sender@remote.test>\r\n").await;
	expect(&mut client, OK).await;
	for _ in 0..100 {
		send(&mut client, b"RCPT TO:<tester@epistle.test>\r\n").await;
		expect(&mut client, OK).await;
	}
	send(&mut client, b"RCPT TO:<tester@epistle.test>\r\n").await;
	expect(&mut client, "452 4.5.3 too many recipients\r\n").await;
	send(&mut client, b"DATA\r\n").await;
	expect(
		&mut client,
		"354 start mail input, end with <CRLF>.<CRLF>\r\n",
	)
	.await;
	send(&mut client, BODY).await;
	expect(&mut client, OK).await;
	quit(&mut client).await;
	let messages = server.sink.messages();
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].recipients.len(), 100);
	server.healthy().await;
}

#[tokio::test]
async fn repeated_messages_do_not_disable_session_timeout_421() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s.with_max_session_time(SHORT_SESSION)).await;
	let mut client = server.connect().await;
	helo(&mut client).await;
	for _ in 0..3 {
		data(&mut client).await;
		send(&mut client, BODY).await;
		expect(&mut client, OK).await;
	}
	expect(&mut client, TIME_UP).await;
	closed(&mut client).await;
	assert_eq!(server.sink.messages().len(), 3);
	server.healthy().await;
}

/// Keep making progress inside the idle timeout, but below any useful rate.
fn drip(mut writer: tokio::net::tcp::OwnedWriteHalf) -> AbortOnDrop {
	let task = tokio::spawn(async move {
		loop {
			sleep(Duration::from_millis(100)).await;
			if writer.write_all(b"x").await.is_err() {
				break;
			}
		}
	});
	AbortOnDrop(task.abort_handle())
}

#[tokio::test]
async fn slowloris_unterminated_command_gets_421_despite_dripping_bytes() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s.with_max_session_time(SHORT_SESSION)).await;
	let mut client = server.connect().await;
	send(&mut client, b"EHLO ").await;
	let (mut reader, writer) = client.into_split();
	let _drip = drip(writer);
	expect(&mut reader, TIME_UP).await;
	closed(&mut reader).await;
	assert!(server.sink.messages().is_empty());
	server.healthy().await;
}

#[tokio::test]
async fn slowloris_data_gets_421_and_releases_message_memory() {
	if !super::enabled() {
		return;
	}
	let budget = Arc::new(MemoryBudget::with_cap(128 * 1024));
	let server = Harness::start(|s| {
		s.with_max_message_size(64 * 1024)
			.with_memory_budget(Arc::clone(&budget))
			.with_data_rate(DataRate::new(10 * 1024, SHORT_SESSION))
	})
	.await;
	let mut client = server.connect().await;
	helo(&mut client).await;
	data(&mut client).await;
	send(&mut client, b"Subject: incomplete\r\n\r\n").await;
	let (mut reader, writer) = client.into_split();
	let _drip = drip(writer);
	expect(
		&mut reader,
		"421 4.4.2 transfer too slow, closing connection\r\n",
	)
	.await;
	closed(&mut reader).await;
	// EOF follows the session drop; allow its task to finish releasing guards.
	let deadline = Instant::now() + BANNER_READ_DEADLINE;
	while budget.used() != 0 && Instant::now() < deadline {
		tokio::task::yield_now().await;
	}
	assert_eq!(
		budget.used(),
		0,
		"the rejected body's reservation was released"
	);
	assert!(server.sink.messages().is_empty());
	server.healthy().await;
}
