//! Slow clients, unread pipelines and listener-slot recovery.

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, timeout};

use super::harness::*;

#[tokio::test]
async fn unread_5000_noop_replies_cannot_hold_the_single_preauth_slot() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT).with_max_connections(1)).await;
	let mut client = server.connect().await;
	flood(&mut client, b"NOOP \"alive\"\r\n").await;
	sleep(SHORT + Duration::from_secs(1)).await;
	server.healthy().await;
	timeout(IO_DEADLINE, async {
		for _ in 0..=5001 {
			match line(&mut client).await {
				Ok(None) => return,
				Err(e) if is_close(&e) => return,
				Ok(Some(reply)) if reply == "OK \"alive\"\r\n" => {}
				Ok(Some(reply)) => {
					assert_eq!(reply, "BYE \"Pre-authentication timeout.\"\r\n");
					closed(&mut client).await;
					return;
				}
				other => panic!("unexpected flood reply: {other:?}"),
			}
		}
		panic!("flood did not close within reply bound");
	})
	.await
	.expect("total flood drain deadline");
}

#[tokio::test]
async fn silent_preauth_client_releases_the_single_slot() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT).with_max_connections(1)).await;
	let mut client = server.connect().await;
	timeout(SHORT + Duration::from_secs(1), timed_out(&mut client))
		.await
		.expect("preauth deadline");
	server.healthy().await;
}

async fn drip(client: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin) {
	let (mut reader, mut writer) = tokio::io::split(client);
	let dripping = async {
		loop {
			sleep(Duration::from_millis(100)).await;
			if writer.write_all(b"x").await.is_err() {
				std::future::pending::<()>().await;
			}
		}
	};
	timeout(SHORT + Duration::from_secs(1), async {
		tokio::select! {
			_ = dripping => panic!("drip stopped"),
			_ = timed_out(&mut reader) => {}
		}
	})
	.await
	.expect("absolute slowloris deadline");
}

#[tokio::test]
async fn dripped_command_cannot_extend_absolute_preauth_deadline() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT)).await;
	let mut client = server.connect().await;
	send(&mut client, b"NOOP \"").await;
	drip(client).await;
	server.healthy().await;
}

#[tokio::test]
async fn dripped_rejected_literal_cannot_extend_absolute_preauth_deadline() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT)).await;
	let mut client = server.connect().await;
	send(&mut client, b"PUTSCRIPT \"bomb\" {64+}\r\n").await;
	expect(&mut client, "NO \"Authenticate first.\"\r\n").await;
	drip(client).await;
	assert!(
		!server
			.data
			.path()
			.join("accounts/tester/sieve/bomb.sieve")
			.exists()
	);
	server.healthy().await;
}

#[tokio::test]
async fn authenticated_idle_client_closes_after_1800_seconds() {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester").await;
	elapse_idle(1801).await;
	// The current loop uses this text for EOF, framing errors and idle alike.
	expect(&mut client, "BYE \"Pre-authentication timeout.\"\r\n").await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn authenticated_partial_line_keeps_its_original_deadline() {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester").await;
	send(&mut client, b"NOOP \"").await;
	elapse_idle(900).await;
	send(&mut client, b"x").await;
	elapse_idle(901).await;
	expect(&mut client, "BYE \"Pre-authentication timeout.\"\r\n").await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn authenticated_partial_literal_keeps_its_original_deadline() {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester").await;
	send(&mut client, b"PUTSCRIPT \"bomb\" {64+}\r\nx").await;
	elapse_idle(900).await;
	send(&mut client, b"x").await;
	elapse_idle(901).await;
	expect(&mut client, "BYE \"read timeout\"\r\n").await;
	closed(&mut client).await;
	assert!(
		!server
			.data
			.path()
			.join("accounts/tester/sieve/bomb.sieve")
			.exists()
	);
	server.healthy().await;
}

#[tokio::test]
#[ignore = "bug: authenticated response writes have no deadline and can retain the listener slot"]
async fn authenticated_unread_getscript_flood_must_return_the_single_slot() {
	let server = Harness::start(|s| s.with_max_connections(1)).await;
	let mut client = server.login("tester").await;
	put(
		&mut client,
		"large",
		&format!("#{}", "x".repeat(256 * 1024)),
	)
	.await;
	expect(&mut client, "OK\r\n").await;
	socket2::SockRef::from(client.get_ref().0)
		.set_recv_buffer_size(1024)
		.expect("receive window");
	flood(&mut client, b"GETSCRIPT \"large\"\r\n").await;
	elapse_idle(1801).await;
	server.healthy().await;
}
