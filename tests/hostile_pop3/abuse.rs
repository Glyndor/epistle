//! Floods, silent clients and partial command deadlines.

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, timeout};

use super::harness::*;

#[tokio::test]
async fn pipelined_5000_bad_commands_close_at_twentieth_error() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	flood(&mut client, b"BOGUS\r\n").await;
	for count in 1..=20 {
		// Unread attack input can make the final close arrive as TCP RST.
		match line(&mut client).await {
			Ok(None) => break,
			Err(e) if is_close(&e) => break,
			Ok(Some(reply)) if count < 20 => assert_eq!(reply, "-ERR invalid command\r\n"),
			Ok(Some(reply)) => {
				assert_eq!(reply, "-ERR too many errors\r\n");
				closed(&mut client).await;
			}
			other => panic!("unexpected flood reply: {other:?}"),
		}
	}
	server.healthy().await;
}

#[tokio::test]
async fn unread_5000_capa_replies_cannot_hold_the_single_preauth_slot() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT).with_max_connections(1)).await;
	let mut client = server.connect().await;
	flood(&mut client, b"CAPA\r\n").await;
	sleep(SHORT + Duration::from_secs(1)).await;
	server.healthy().await;
	// Drain only after proving that the listener slot was returned.
	timeout(IO_DEADLINE, async {
		for _ in 0..=5000 * 6 {
			match line(&mut client).await {
				Ok(None) => return,
				Err(e) if is_close(&e) => return,
				Ok(Some(reply)) => assert!(
					matches!(
						reply.as_str(),
						"+OK capability list follows\r\n"
							| "USER\r\n" | "UIDL\r\n"
							| "TOP\r\n" | "SASL PLAIN\r\n"
							| ".\r\n"
					),
					"{reply:?}"
				),
				other => panic!("unexpected flood reply: {other:?}"),
			}
		}
		panic!("flood did not close within reply bound");
	})
	.await
	.expect("total flood drain deadline");
}

#[tokio::test]
async fn silent_tls_handshake_releases_the_single_slot() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT).with_max_connections(1)).await;
	let mut client = server.tcp().await;
	timeout(SHORT + Duration::from_secs(1), closed(&mut client))
		.await
		.expect("TLS deadline");
	server.healthy().await;
}

#[tokio::test]
async fn silent_encrypted_preauth_client_is_closed() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT)).await;
	let mut client = server.connect().await;
	timeout(SHORT + Duration::from_secs(1), closed(&mut client))
		.await
		.expect("preauth deadline");
	server.healthy().await;
}

#[tokio::test]
async fn dripped_command_cannot_extend_absolute_preauth_deadline() {
	let server = Harness::start(|s| s.with_preauth_timeout(SHORT)).await;
	let mut client = server.connect().await;
	send(&mut client, b"USER ").await;
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
			_ = closed(&mut reader) => {}
		}
	})
	.await
	.expect("absolute slowloris deadline");
	server.healthy().await;
}

#[tokio::test]
async fn authenticated_idle_client_closes_after_600_seconds() {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester", 0).await;
	elapse_idle(601).await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn authenticated_partial_line_keeps_its_original_deadline() {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester", 0).await;
	send(&mut client, b"NOOP ").await;
	elapse_idle(300).await;
	send(&mut client, b"x").await;
	elapse_idle(301).await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn authenticated_unread_retr_flood_must_return_the_single_slot() {
	let server = Harness::start(|s| s.with_max_connections(1)).await;
	server.seed(
		"tester",
		&uuid::Uuid::now_v7().to_string(),
		&vec![b'x'; 256 * 1024],
	);
	let mut client = server.login("tester", 1).await;
	socket2::SockRef::from(client.get_ref().0)
		.set_recv_buffer_size(1024)
		.expect("receive window");
	flood(&mut client, b"RETR 1\r\n").await;
	elapse_idle(601).await;
	server.healthy().await;
}
