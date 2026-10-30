//! Silent or backpressured destinations at each remaining SMTP phase.

use epistle::queue::timeouts::Phase;
use tokio::io::{AsyncReadExt, DuplexStream};

use super::harness::*;

/// Keep the returned peer alive, but stop reading or answering at this phase.
async fn stop_at(mut peer: DuplexStream, phase: Phase) -> DuplexStream {
	write(&mut peer, b"220 destination ESMTP\r\n").await;
	assert_eq!(line(&mut peer).await, b"EHLO mail.epistle.test\r\n");
	write(&mut peer, b"250 destination\r\n").await;
	assert_eq!(
		line(&mut peer).await,
		b"MAIL FROM:<sender@outside.test>\r\n"
	);
	write(&mut peer, b"250 sender ok\r\n").await;
	assert_eq!(line(&mut peer).await, b"RCPT TO:<victim@outside.test>\r\n");
	if phase == Phase::Rcpt {
		return peer;
	}
	write(&mut peer, b"250 recipient ok\r\n").await;
	assert_eq!(line(&mut peer).await, b"DATA\r\n");
	if phase == Phase::DataInit {
		return peer;
	}
	write(&mut peer, b"354 send data\r\n").await;
	if phase == Phase::DataBlock {
		return peer;
	}
	let mut captured = Vec::new();
	loop {
		let next = line(&mut peer).await;
		if next == b".\r\n" {
			break;
		}
		captured.extend(next);
		assert!(captured.len() < 8192);
	}
	assert_eq!(captured, BODY);
	if phase == Phase::DataEnd {
		return peer;
	}
	assert_eq!(phase, Phase::Quit);
	write(&mut peer, b"250 accepted\r\n").await;
	assert_eq!(line(&mut peer).await, b"QUIT\r\n");
	peer
}

async fn stalled(phase: Phase) {
	let (client, peer) = tokio::io::duplex(4096);
	let recipients = recipient();
	let data = if phase == Phase::DataBlock {
		// More than one production block and more than the duplex capacity.
		vec![b'x'; 128 * 1024]
	} else {
		BODY.to_vec()
	};
	let began = tokio::time::Instant::now();
	let (result, mut peer) =
		tokio::time::timeout(phase.limit() + std::time::Duration::from_secs(1), async {
			tokio::join!(
				delivery(client, "sender@outside.test", &recipients, &data),
				stop_at(peer, phase)
			)
		})
		.await
		.expect("phase watchdog");
	if phase == Phase::Quit {
		// Acceptance was already final; a silent QUIT must not cause a retry.
		assert_eq!(result, Ok(()));
	} else {
		assert_eq!(result, Err(phase.timed_out()));
	}
	assert_eq!(tokio::time::Instant::now() - began, phase.limit());
	let mut tail = Vec::new();
	within((&mut peer).take(8193).read_to_end(&mut tail))
		.await
		.expect("closed timed-out connection");
	if phase == Phase::DataBlock {
		assert!(!tail.is_empty());
		assert!(tail.len() <= 4096);
		assert!(tail.iter().all(|byte| *byte == b'x'));
	} else {
		assert!(tail.is_empty(), "commands sent after timeout: {tail:?}");
	}
	healthy().await;
}

#[tokio::test(start_paused = true)]
async fn silent_rcpt_expires_and_closes_without_data_or_quit() {
	stalled(Phase::Rcpt).await;
}

#[tokio::test(start_paused = true)]
async fn silent_data_init_expires_without_sending_the_message() {
	stalled(Phase::DataInit).await;
}

#[tokio::test(start_paused = true)]
async fn destination_not_reading_data_hits_block_write_deadline() {
	stalled(Phase::DataBlock).await;
}

#[tokio::test(start_paused = true)]
async fn silent_final_dot_expires_and_closes_without_quit() {
	stalled(Phase::DataEnd).await;
}

#[tokio::test(start_paused = true)]
async fn silent_quit_expires_without_changing_accepted_delivery() {
	stalled(Phase::Quit).await;
}
