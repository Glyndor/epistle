use super::*;
use tokio::io::AsyncReadExt;

const PREAUTH: Duration = Duration::from_secs(60);
const IDLE: Duration = Duration::from_secs(1800);
/// Longer than the buffer of the duplex pairs below, so a write of it has
/// to wait for the peer to read.
const MESSAGE: &[u8] = b"a message longer than the buffer";

#[tokio::test(start_paused = true)]
async fn before_signing_in_every_step_ends_at_the_same_instant() {
	let mut clock = SessionClock::start(PREAUTH, IDLE);
	let end = clock.preauth_until();
	tokio::time::sleep(Duration::from_secs(40)).await;
	assert_eq!(clock.step(false), end);
	assert_eq!(clock.line(false), end);
	clock.line_done();
	assert_eq!(
		clock.line(false),
		end,
		"a new line does not get a new window"
	);
}

#[tokio::test(start_paused = true)]
async fn after_signing_in_a_line_keeps_its_deadline_until_it_is_complete() {
	let mut clock = SessionClock::start(PREAUTH, IDLE);
	let first = clock.line(true);
	tokio::time::sleep(Duration::from_secs(100)).await;
	assert_eq!(clock.line(true), first, "partial reads do not move it");
	clock.line_done();
	assert_eq!(clock.line(true), Instant::now() + IDLE);
}

#[tokio::test(start_paused = true)]
async fn after_signing_in_each_step_gets_a_fresh_window() {
	let clock = SessionClock::start(PREAUTH, IDLE);
	tokio::time::sleep(Duration::from_secs(500)).await;
	assert_eq!(clock.step(true), Instant::now() + IDLE);
}

#[tokio::test(start_paused = true)]
async fn the_preauth_phase_never_outlasts_the_idle_timeout() {
	let clock = SessionClock::start(IDLE, Duration::from_secs(2));
	assert_eq!(
		clock.preauth_until(),
		Instant::now() + Duration::from_secs(2)
	);
}

#[tokio::test(start_paused = true)]
async fn the_write_stall_is_the_shorter_of_the_window_and_the_idle_timeout() {
	let clock = SessionClock::start(PREAUTH, Duration::from_secs(5));
	assert_eq!(clock.write_stall(), Duration::from_secs(5));
	let clock = SessionClock::start(PREAUTH, IDLE);
	assert_eq!(clock.write_stall(), DEFAULT_WRITE_STALL);
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_stops_accepting_the_response_is_cut() {
	let (_client, mut server) = tokio::io::duplex(16);
	let write = tokio::spawn(async move {
		write_all_progressing(&mut server, MESSAGE, Duration::from_secs(2)).await
	});
	// The peer never reads: the write stalls and the window closes.
	for _ in 0..10 {
		tokio::time::advance(Duration::from_secs(1)).await;
		if write.is_finished() {
			break;
		}
	}
	let error = write
		.await
		.expect("write task")
		.expect_err("a peer that stopped reading is cut");
	assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn a_peer_that_reads_slowly_keeps_its_response() {
	let (mut client, mut server) = tokio::io::duplex(16);
	let reader = tokio::spawn(async move {
		let mut buffer = [0u8; 16];
		let mut total = 0;
		while total < MESSAGE.len() {
			tokio::time::sleep(Duration::from_millis(20)).await;
			match client.read(&mut buffer).await {
				Ok(0) => break,
				Ok(count) => total += count,
				Err(_) => break,
			}
		}
		total
	});
	write_all_progressing(&mut server, MESSAGE, Duration::from_secs(2))
		.await
		.expect("a peer that reads slowly keeps the response");
	assert_eq!(reader.await.expect("reader"), MESSAGE.len());
}
