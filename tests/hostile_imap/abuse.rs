//! Floods and slow clients, with explicit bounds and listener recovery.

use std::io;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, timeout};

use super::harness::*;

async fn flood(client: &mut (impl tokio::io::AsyncWrite + Unpin), command: &[u8]) {
	match timeout(IO_DEADLINE, client.write_all(&command.repeat(5000))).await {
		Ok(Ok(())) => {}
		Ok(Err(e)) if is_close(&e) || e.kind() == io::ErrorKind::BrokenPipe => {}
		other => panic!("flood stalled or failed unexpectedly: {other:?}"),
	}
}

#[tokio::test]
async fn pipelined_5000_bad_commands_close_at_twentieth_error() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	flood(&mut client, b"A BOGUS\r\n").await;
	// The twentieth BAD is replaced by BYE. Unread input can cause TCP RST.
	for count in 0..20 {
		match line(&mut client).await {
			Ok(None) => break,
			Err(e) if is_close(&e) => break,
			Ok(Some(reply)) if count < 19 => assert_eq!(reply, "A BAD unknown command\r\n"),
			Ok(Some(reply)) => {
				assert_eq!(reply, "* BYE too many errors\r\n");
				closed(&mut client).await;
			}
			other => panic!("unexpected flood result: {other:?}"),
		}
	}
	server.healthy().await;
}

#[tokio::test]
async fn pipelined_5000_noops_release_slot_at_absolute_preauth_deadline() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT).with_max_connections(1)).await;
	let mut client = server.connect().await;
	flood(&mut client, b"A NOOP\r\n").await;
	// Do not read any attack replies until the listener slot must be free.
	sleep(SHORT + Duration::from_secs(1)).await;
	server.healthy().await;
	timeout(IO_DEADLINE, async {
		for _ in 0..=5000 {
			match line(&mut client).await {
				Ok(None) => return,
				Err(e) if is_close(&e) => return,
				Ok(Some(reply)) if reply == "A OK NOOP completed\r\n" => {}
				Ok(Some(reply)) => {
					assert_eq!(reply, "* BYE idle timeout\r\n");
					closed(&mut client).await;
					return;
				}
				other => panic!("unexpected flood result: {other:?}"),
			}
		}
		panic!("flood did not close within the response count bound");
	})
	.await
	.expect("total flood drain deadline");
}

#[tokio::test]
async fn authenticated_unread_capability_flood_must_release_listener_slot() {
	let server = Harness::start(|s| s.with_read_timeout(SHORT).with_max_connections(1)).await;
	let mut client = server.authenticated().await;
	// Constrain the receive window so thousands of large replies block writes.
	socket2::SockRef::from(client.get_ref().0)
		.set_recv_buffer_size(1024)
		.expect("small receive window");
	flood(&mut client, b"A CAPABILITY\r\n").await;
	sleep(SHORT + Duration::from_secs(1)).await;
	// With a single slot, a greeting proves the attack connection was dropped.
	server.healthy().await;
}

#[tokio::test]
async fn silent_unauthenticated_client_is_closed() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT)).await;
	let mut client = server.connect().await;
	timeout(SHORT + Duration::from_secs(1), timed_out(&mut client))
		.await
		.expect("absolute preauth deadline");
	server.healthy().await;
}

#[tokio::test]
async fn silent_authenticated_client_gets_idle_bye_and_close() {
	let server = Harness::start(|s| s.with_read_timeout(SHORT)).await;
	let mut client = server.authenticated().await;
	timeout(SHORT + Duration::from_secs(1), async {
		expect(&mut client, "* BYE idle timeout\r\n").await;
		closed(&mut client).await;
	})
	.await
	.expect("authenticated idle deadline");
	server.healthy().await;
}

async fn drip_until_close(
	mut client: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
	opening: &[u8],
	octets: &[u8],
) {
	send(&mut client, opening).await;
	let (mut reader, mut writer) = tokio::io::split(client);
	let dripping = async {
		loop {
			sleep(Duration::from_millis(100)).await;
			if writer.write_all(octets).await.is_err() {
				std::future::pending::<()>().await;
			}
		}
	};
	timeout(SHORT + Duration::from_secs(1), async {
		tokio::select! {
			_ = dripping => panic!("drip unexpectedly stopped"),
			_ = timed_out(&mut reader) => {}
		}
	})
	.await
	.expect("slowloris exceeded absolute line deadline");
}

#[tokio::test]
async fn preauth_slowloris_cannot_extend_deadline_with_bytes() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT)).await;
	drip_until_close(server.connect().await, b"A NOOP ", b"x").await;
	server.healthy().await;
}

#[tokio::test]
async fn authenticated_slowloris_cannot_extend_line_deadline_with_bytes() {
	let server = Harness::start(|s| s.with_read_timeout(SHORT)).await;
	drip_until_close(server.authenticated().await, b"A NOOP ", b"x").await;
	server.healthy().await;
}

#[tokio::test]
async fn repeated_rejected_literal_plus_cannot_extend_preauth_deadline() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT)).await;
	let mut client = server.connect().await;
	send(&mut client, b"A APPEND INBOX {1+}\r\nx").await;
	expect(&mut client, "A NO not authenticated\r\n").await;
	drip_until_close(client, b"", b" {1+}\r\nx").await;
	server.healthy().await;
}

#[tokio::test]
async fn authenticated_rejected_literal_chain_must_have_total_deadline() {
	let server = Harness::start(|s| s.with_read_timeout(SHORT)).await;
	let mut client = server.authenticated().await;
	send(&mut client, b"A APPEND Missing {1+}\r\nx").await;
	expect(&mut client, "A NO [TRYCREATE] no such mailbox\r\n").await;
	drip_until_close(client, b"", b" {1+}\r\nx").await;
	server.healthy().await;
}

#[tokio::test]
async fn idle_without_done_closes_after_poll_interval() {
	let server = Harness::start(|s| s.with_read_timeout(SHORT)).await;
	let mut client = server.authenticated().await;
	send(&mut client, b"I IDLE\r\n").await;
	expect(&mut client, "+ idling\r\n").await;
	// Pause only after network setup; real sockets must not race virtual time.
	tokio::time::pause();
	tokio::time::advance(Duration::from_secs(31)).await;
	tokio::task::yield_now().await;
	tokio::time::resume();
	expect(&mut client, "* BYE idle timeout\r\n").await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn idle_without_done_must_honor_short_configured_timeout() {
	let server = Harness::start(|s| s.with_read_timeout(SHORT)).await;
	let mut client = server.authenticated().await;
	send(&mut client, b"I IDLE\r\n").await;
	expect(&mut client, "+ idling\r\n").await;
	timeout(SHORT + Duration::from_secs(1), async {
		expect(&mut client, "* BYE idle timeout\r\n").await;
		closed(&mut client).await;
	})
	.await
	.expect("IDLE ignored configured read timeout");
	server.healthy().await;
}
