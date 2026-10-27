//! Hostile SMTP destinations against the production outbound client.

use epistle::queue::client::DeliveryError;
use epistle::queue::timeouts::{COMMAND, GREETING, Phase};
use tokio::io::AsyncReadExt;

use super::harness::*;

#[tokio::test]
async fn unterminated_megabyte_banner_is_rejected_at_accumulated_reply_cap() {
	let (client, mut peer) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move {
		let payload = vec![b'x'; 1 << 20];
		let _ = tokio::io::AsyncWriteExt::write_all(&mut peer, &payload).await;
	});
	let _guard = AbortOnDrop(task.abort_handle());
	let result = within(delivery(client, "sender@outside.test", &recipient(), BODY)).await;
	assert_eq!(
		result,
		Err(DeliveryError::Transient("oversized reply".into()))
	);
	healthy().await;
}

#[tokio::test]
async fn endless_multiline_banner_is_rejected_at_accumulated_reply_cap() {
	let (client, mut peer) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move {
		// Never terminate the reply, but bound the fixture if the cap regresses.
		for _ in 0..128 * 1024 {
			if tokio::io::AsyncWriteExt::write_all(&mut peer, b"220-more\r\n")
				.await
				.is_err()
			{
				break;
			}
		}
		std::future::pending::<()>().await;
	});
	let _guard = AbortOnDrop(task.abort_handle());
	let result = within(delivery(client, "sender@outside.test", &recipient(), BODY)).await;
	assert_eq!(
		result,
		Err(DeliveryError::Transient("oversized reply".into()))
	);
	healthy().await;
}

#[tokio::test(start_paused = true)]
async fn absent_banner_expires_at_greeting_deadline_and_closes() {
	let (client, mut peer) = tokio::io::duplex(4096);
	let recipients = recipient();
	let began = tokio::time::Instant::now();
	let result = tokio::time::timeout(
		GREETING + std::time::Duration::from_secs(1),
		delivery(client, "sender@outside.test", &recipients, BODY),
	)
	.await
	.expect("greeting watchdog");
	assert_eq!(result, Err(Phase::Greeting.timed_out()));
	assert_eq!(tokio::time::Instant::now() - began, GREETING);
	assert_eq!(
		peer.read_u8().await.expect_err("client closed").kind(),
		std::io::ErrorKind::UnexpectedEof
	);
	healthy().await;
}

#[tokio::test(start_paused = true)]
async fn dripping_banner_bytes_do_not_restart_greeting_deadline() {
	let (client, mut peer) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move {
		loop {
			write(&mut peer, b"2").await;
			tokio::time::sleep(std::time::Duration::from_secs(60)).await;
		}
	});
	let _guard = AbortOnDrop(task.abort_handle());
	let recipients = recipient();
	let began = tokio::time::Instant::now();
	let result = tokio::time::timeout(
		GREETING + std::time::Duration::from_secs(1),
		delivery(client, "sender@outside.test", &recipients, BODY),
	)
	.await
	.expect("drip watchdog");
	assert_eq!(result, Err(Phase::Greeting.timed_out()));
	assert_eq!(tokio::time::Instant::now() - began, GREETING);
}

#[tokio::test(start_paused = true)]
async fn unterminated_ehlo_multiline_expires_at_command_deadline() {
	let (client, mut peer) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move {
		write(&mut peer, b"220 ready\r\n").await;
		assert_eq!(line(&mut peer).await, b"EHLO mail.epistle.test\r\n");
		loop {
			write(&mut peer, b"250-more\r\n").await;
			tokio::time::sleep(std::time::Duration::from_secs(30)).await;
		}
	});
	let _guard = AbortOnDrop(task.abort_handle());
	let recipients = recipient();
	let result = tokio::time::timeout(
		COMMAND + std::time::Duration::from_secs(1),
		delivery(client, "sender@outside.test", &recipients, BODY),
	)
	.await
	.expect("EHLO watchdog");
	assert_eq!(result, Err(Phase::Command.timed_out()));
}

#[tokio::test]
async fn body_header_injection_and_early_dot_remain_inside_one_data_transaction() {
	let body = b"From: sender@outside.test\r\n\r\n.\r\nMAIL FROM:<evil@outside.test>\r\n\
RCPT TO:<second@outside.test>\r\nBcc: second@outside.test\r\n.\n.\r.\r\n";
	let (client, mut peer) = tokio::io::duplex(4096);
	let recipients = recipient();
	let remote = async {
		envelope(&mut peer).await;
		let mut wire = Vec::new();
		loop {
			wire.push(peer.read_u8().await.expect("DATA octet"));
			assert!(wire.len() <= 8192);
			if wire.ends_with(b"\r\n.\r\n") {
				break;
			}
		}
		assert_eq!(
			wire,
			b"From: sender@outside.test\r\n\r\n..\r\nMAIL FROM:<evil@outside.test>\r\n\
RCPT TO:<second@outside.test>\r\nBcc: second@outside.test\r\n..\n..\r..\r\n.\r\n"
		);
		write(&mut peer, b"250 queued\r\n").await;
		assert_eq!(line(&mut peer).await, b"QUIT\r\n");
		write(&mut peer, b"221 bye\r\n").await;
	};
	let (result, ()) = within(async {
		tokio::join!(
			delivery(client, "sender@outside.test", &recipients, body),
			remote
		)
	})
	.await;
	assert_eq!(result, Ok(()));
	healthy().await;
}

/// Observe the unsafe command, allowing a valid MAIL before a bad RCPT.
async fn unsafe_envelope(sender: &str, recipient: &str) {
	let (client, mut peer) = tokio::io::duplex(4096);
	let recipients = vec![recipient.to_string()];
	let bad_sender = sender.chars().any(char::is_control);
	let remote = async {
		write(&mut peer, b"220 ready\r\n").await;
		// A future implementation may validate before sending even EHLO.
		let mut first = [0; 1];
		if peer.read(&mut first).await.expect("first command") == 0 {
			return Vec::new();
		}
		let mut ehlo = vec![first[0]];
		ehlo.extend(line(&mut peer).await);
		assert_eq!(ehlo, b"EHLO mail.epistle.test\r\n");
		write(&mut peer, b"250 ready\r\n").await;
		let mut wire = Vec::new();
		if !bad_sender {
			// MAIL is trusted here; observe RCPT instead of failing early.
			let mut mail = Vec::new();
			while !mail.ends_with(b"\r\n") {
				let mut one = [0; 1];
				if peer.read(&mut one).await.expect("MAIL octet") == 0 {
					return wire;
				}
				mail.push(one[0]);
				assert!(mail.len() < 8192);
			}
			assert_eq!(mail, b"MAIL FROM:<sender@outside.test>\r\n");
			write(&mut peer, b"250 sender ok\r\n").await;
		}
		let mut chunk = [0; 4096];
		let count = peer.read(&mut chunk).await.expect("unsafe command");
		wire.extend_from_slice(&chunk[..count]);
		// Dropping the peer forces completion without waiting on QUIT.
		drop(peer);
		wire
	};
	let (result, wire) =
		within(async { tokio::join!(delivery(client, sender, &recipients, BODY), remote) }).await;
	assert!(result.is_err());
	assert!(wire.is_empty(), "unsafe envelope reached SMTP: {wire:?}");
}

#[tokio::test]
#[ignore = "bug: outbound client interpolates recipient CRLF into RCPT command"]
async fn crlf_recipient_is_rejected_before_rcpt_command() {
	unsafe_envelope(
		"sender@outside.test",
		"victim@outside.test>\r\nRCPT TO:<evil@outside.test",
	)
	.await;
}

#[tokio::test]
#[ignore = "bug: outbound client does not validate recipient NUL"]
async fn nul_recipient_is_rejected_before_rcpt_command() {
	unsafe_envelope("sender@outside.test", "victim\0@outside.test").await;
}

#[tokio::test]
#[ignore = "bug: outbound client interpolates reverse-path CRLF into MAIL command"]
async fn crlf_reverse_path_is_rejected_before_any_mail_command() {
	unsafe_envelope(
		"sender@outside.test>\r\nRCPT TO:<evil@outside.test",
		"victim@outside.test",
	)
	.await;
}

#[tokio::test]
#[ignore = "bug: outbound SMTP parser has no 512-octet per-line reply limit"]
async fn complete_sixteen_kib_banner_is_refused_before_ehlo() {
	let (client, mut peer) = tokio::io::duplex(32768);
	let mut banner = b"220 ".to_vec();
	banner.extend(std::iter::repeat_n(b'x', 16 * 1024));
	banner.extend_from_slice(b"\r\n");
	write(&mut peer, &banner).await;
	let recipients = recipient();
	let remote = async {
		let mut command = [0; 128];
		let count = peer
			.read(&mut command)
			.await
			.expect("read after giant banner");
		assert_eq!(
			count,
			0,
			"giant banner was accepted: {:?}",
			&command[..count]
		);
	};
	let (result, ()) = within(async {
		tokio::join!(
			delivery(client, "sender@outside.test", &recipients, BODY),
			remote
		)
	})
	.await;
	assert!(matches!(result, Err(DeliveryError::Transient(_))));
}
