//! A client that stops reading its replies. The rate floor watches what
//! the server reads, so a reply write the client never lets through must
//! not become the new way to hold a connection and the body the session
//! keeps on the memory budget: inside a message transaction the write is
//! held to the rate window as a read is, every reply write gives up after
//! the 300 s idle timeout, and a client cut for its rate gives its
//! reservation back before the 421 is written.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::tests_data_rate::{GRACE, OPEN, pass, reply_codes, test_directory};
use super::*;
use crate::smtp::sink::MemorySink;

/// How much the server can write before a client that is not reading
/// blocks it.
const PIPE: usize = 8;

/// The idle timeout every read and every reply write is bounded by.
const IDLE: Duration = Duration::from_secs(300);

struct Stalled {
	client: DuplexStream,
	task: JoinHandle<std::io::Result<()>>,
	budget: Arc<MemoryBudget>,
}

/// A connection with an 8-octet pipe each way and a server holding its
/// bodies on `budget`, the opening (greeting, EHLO, MAIL, RCPT) already
/// read, so the pipe is empty.
async fn opened() -> Stalled {
	let budget = Arc::new(MemoryBudget::with_cap(1024 * 1024));
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_memory_budget(Arc::clone(&budget)),
	);
	let (client, server_stream) = tokio::io::duplex(PIPE);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	let mut stalled = Stalled {
		client,
		task,
		budget,
	};
	stalled.converse(OPEN, 4).await;
	stalled
}

impl Stalled {
	/// Write `bytes` while reading the replies they bring, until `replies`
	/// final reply lines have arrived in all.
	async fn converse(&mut self, bytes: &[u8], replies: usize) {
		let (mut read, mut write) = tokio::io::split(&mut self.client);
		let writing = async {
			write.write_all(bytes).await.expect("client write");
		};
		let reading = async {
			let mut seen = Vec::new();
			let mut buffer = [0u8; 64];
			while reply_codes(&String::from_utf8_lossy(&seen)).len() < replies
				|| !seen.ends_with(b"\r\n")
			{
				let n = read.read(&mut buffer).await.expect("client read");
				assert!(n > 0, "the server closed during the opening");
				seen.extend_from_slice(&buffer[..n]);
			}
		};
		tokio::join!(writing, reading);
	}

	/// Write `bytes` without reading anything back.
	async fn write(&mut self, bytes: &[u8]) {
		self.client.write_all(bytes).await.expect("client write");
		for _ in 0..4 {
			tokio::task::yield_now().await;
		}
	}

	/// Take whatever the server has written so far, without waiting.
	async fn read_some(&mut self) {
		let mut buffer = [0u8; PIPE];
		let _ = tokio::time::timeout(Duration::ZERO, self.client.read(&mut buffer)).await;
	}

	/// Let `total` pass in 10 s steps, reading what the server wrote every
	/// `read_every` steps (never when `0`). Returns when the body went back
	/// to the budget and when the connection ended, measured from `started`.
	async fn watch(
		&mut self,
		started: Instant,
		total: Duration,
		read_every: u32,
	) -> (Option<Duration>, Option<Duration>) {
		let (mut freed, mut ended) = (None, None);
		let mut step = 0;
		while started.elapsed() < total {
			pass(Duration::from_secs(10)).await;
			step += 1;
			if read_every > 0 && step % read_every == 0 {
				self.read_some().await;
			}
			if freed.is_none() && self.budget.used() == 0 {
				freed = Some(started.elapsed());
			}
			if ended.is_none() && self.task.is_finished() {
				ended = Some(started.elapsed());
			}
		}
		(freed, ended)
	}
}

/// Whether `at` is the 10 s step in which `due` falls.
fn on_step(at: Option<Duration>, due: Duration) -> bool {
	at.is_some_and(|at| at >= due && at < due + Duration::from_secs(10))
}

#[tokio::test(start_paused = true)]
async fn a_client_that_leaves_its_replies_unread_is_cut_when_the_window_runs_out() {
	// The chunk is sent at once, then its 250 is read 8 octets every
	// 250 s: each reply write finishes inside the idle timeout, so only
	// the rate window can end the transaction that holds the chunk.
	let mut stalled = opened().await;
	let started = Instant::now();
	stalled.write(b"BDAT 4096\r\n").await;
	stalled.write(&[b'x'; 4096]).await;
	assert_eq!(
		stalled.budget.used(),
		4096,
		"the chunk is held while its reply is unread"
	);
	let (freed, ended) = stalled.watch(started, Duration::from_secs(3000), 25).await;
	assert!(
		on_step(freed, GRACE),
		"the chunk goes back when the window runs out, not at {freed:?}"
	);
	assert!(
		on_step(ended, GRACE),
		"the connection ends when the window runs out, not at {ended:?}"
	);
}

#[tokio::test(start_paused = true)]
async fn a_cut_client_gives_its_reservation_back_before_the_421_is_written() {
	// The chunk is dripped and nothing is ever read: the 421 cannot be
	// written. The reservation must not wait for it, and the write itself
	// gives up after the idle timeout.
	let mut stalled = opened().await;
	let started = Instant::now();
	stalled.write(b"BDAT 4096\r\n").await;
	stalled.write(&[b'x'; 100]).await;
	assert_eq!(
		stalled.budget.used(),
		100,
		"the octets of the chunk that arrived are held"
	);
	let (freed, ended) = stalled.watch(started, Duration::from_secs(900), 0).await;
	assert!(
		on_step(freed, GRACE),
		"the reservation goes back at the cut, not at {freed:?}"
	);
	assert!(
		on_step(ended, GRACE + IDLE),
		"the unread 421 is given up after the idle timeout, not at {ended:?}"
	);
}

#[tokio::test(start_paused = true)]
async fn the_body_behind_an_unread_250_goes_back_after_the_idle_timeout() {
	// A delivered message keeps its body on the budget until its 250 is
	// written; a client that never reads it must not keep it there.
	let mut stalled = opened().await;
	stalled.converse(b"DATA\r\n", 1).await;
	stalled.write(b"Subject: held\r\n\r\nbody\r\n.\r\n").await;
	let started = Instant::now();
	assert!(
		stalled.budget.used() > 0,
		"the body is held while its 250 is unread"
	);
	let (freed, ended) = stalled.watch(started, Duration::from_secs(900), 0).await;
	assert!(
		on_step(freed, IDLE),
		"the body goes back after the idle timeout, not at {freed:?}"
	);
	assert!(
		on_step(ended, IDLE),
		"the connection ends after the idle timeout, not at {ended:?}"
	);
}

#[tokio::test(start_paused = true)]
async fn an_unread_reply_to_a_garbled_line_is_held_to_the_window_too() {
	// The chunk's 250 is read; the 500 to a non-UTF-8 line between chunks
	// is then left unread, a few octets every 250 s.
	let mut stalled = opened().await;
	let started = Instant::now();
	let chunk = [b"BDAT 4096\r\n".as_slice(), &[b'x'; 4096]].concat();
	stalled.converse(&chunk, 1).await;
	stalled.write(b"\xff\r\n").await;
	let (freed, ended) = stalled.watch(started, Duration::from_secs(3000), 25).await;
	assert!(
		on_step(freed, GRACE),
		"the chunk goes back when the window runs out, not at {freed:?}"
	);
	assert!(
		on_step(ended, GRACE),
		"the connection ends when the window runs out, not at {ended:?}"
	);
}
