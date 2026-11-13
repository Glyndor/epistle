//! Clients that take their time: the deadline covers the whole exchange,
//! not each read, and a slot held by a slow client is the only one it
//! holds.

use std::time::{Duration, Instant};

use super::*;
use crate::dkim::test_support::{GOLDEN, fixed_signer};

const DEADLINE: Duration = Duration::from_millis(300);

fn signer_with_deadline(dir: &std::path::Path) -> Running {
	start(SignerServer::new(Arc::new(fixed_signer(dir))).with_deadline(DEADLINE))
}

fn plain_frame() -> Vec<u8> {
	let block = crate::dkim::HeaderBlock::from_message(GOLDEN[0].0.as_bytes()).expect("block");
	crate::dkim::remote::frame::SignRequest {
		domain: "example.org".into(),
		block,
	}
	.encode()
	.expect("encodes")
}

#[tokio::test]
async fn a_client_that_stalls_halfway_is_cut_off_at_the_deadline() {
	let (events, _guard) = capture();
	let dir = tempfile::tempdir().expect("tempdir");
	let running = signer_with_deadline(dir.path());
	let frame = plain_frame();
	let mut stream = UnixStream::connect(&running.socket).await.expect("connect");
	stream
		.write_all(&frame[..frame.len() / 2])
		.await
		.expect("half");
	let mut answer = Vec::new();
	tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer))
		.await
		.expect("the signer closed the connection")
		.expect("read");
	assert!(answer.is_empty(), "no answer to half a request: {answer:?}");
	let warnings = messages(&events, tracing::Level::WARN);
	assert!(
		warnings
			.iter()
			.any(|line| line.contains("within the deadline")),
		"{warnings:?}"
	);
}

#[tokio::test]
async fn a_client_that_drips_its_request_is_cut_off_before_it_finishes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let running = signer_with_deadline(dir.path());
	let frame = plain_frame();
	let step = Duration::from_millis(20);
	// Every single read finishes well inside the deadline; only the
	// exchange as a whole is too slow.
	assert!(step * u32::try_from(frame.len()).expect("len") > DEADLINE * 4);
	let stream = UnixStream::connect(&running.socket).await.expect("connect");
	let (mut reader, mut writer) = stream.into_split();
	let started = Instant::now();
	let drip = async {
		for byte in &frame {
			if writer.write_all(&[*byte]).await.is_err() {
				return;
			}
			tokio::time::sleep(step).await;
		}
		let _ = writer.shutdown().await;
	};
	let closed = async {
		let mut answer = Vec::new();
		let _ = reader.read_to_end(&mut answer).await;
		answer
	};
	tokio::select! {
		answer = closed => assert!(answer.is_empty(), "{answer:?}"),
		() = drip => panic!("the whole request dripped through before the signer cut it off"),
	}
	assert!(started.elapsed() < step * u32::try_from(frame.len()).expect("len"));

	// The same request sent at once is signed under the same deadline.
	let answer = decode_answer(&raw_exchange(&running.socket, &frame).await);
	assert_eq!(answer, SignResponse::Signed(GOLDEN[0].1.into()));
}

#[tokio::test]
async fn a_busy_signer_closes_the_extra_connection_and_frees_the_slot_after() {
	let (events, _guard) = capture();
	let dir = tempfile::tempdir().expect("tempdir");
	let running = start(
		SignerServer::new(Arc::new(fixed_signer(dir.path())))
			.with_deadline(DEADLINE)
			.with_max_connections(1),
	);
	let mut holder_of_the_slot = UnixStream::connect(&running.socket).await.expect("connect");
	holder_of_the_slot
		.write_all(&[0, 0])
		.await
		.expect("two bytes");

	let client = RemoteSigner::new(&running.socket);
	let raw = GOLDEN[0].0.as_bytes();
	assert!(
		matches!(
			client.sign("example.org", raw).await,
			Err(RemoteError::Unavailable(_))
		),
		"the second connection has no slot"
	);
	assert!(
		messages(&events, tracing::Level::WARN)
			.iter()
			.any(|line| line.contains("every connection slot is busy")),
		"the server says why it closed the connection"
	);

	let mut rest = Vec::new();
	tokio::time::timeout(
		Duration::from_secs(10),
		holder_of_the_slot.read_to_end(&mut rest),
	)
	.await
	.expect("the signer cut the slow connection off")
	.expect("read");
	assert_eq!(
		client.sign("example.org", raw).await.as_deref(),
		Ok(GOLDEN[0].1)
	);
}
