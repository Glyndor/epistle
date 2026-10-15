//! The minimum transfer rate for a DATA body: after the grace period the
//! average rate since the 354 must stay at or above the floor, or the
//! client is answered `421 4.4.2` and the connection is closed. Every test
//! runs on tokio's paused clock, so the minutes below are virtual.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::*;
use crate::smtp::sink::MemorySink;

/// The exact line a client below the floor gets before the close.
pub(super) const TOO_SLOW: &str = "421 4.4.2 transfer too slow, closing connection\r\n";

/// The default grace period: no client is judged before it.
pub(super) const GRACE: Duration = Duration::from_secs(120);

/// The default floor, in bytes per second.
pub(super) const FLOOR: usize = 10 * 1024;

pub(super) const OPEN: &[u8] = b"EHLO client.example.org\r\nMAIL FROM:<a@example.net>\r\n\
RCPT TO:<bob@example.org>\r\n";

pub(super) fn test_directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	))
}

/// A server with the built-in rate floor and an in-memory sink.
pub(super) fn default_server() -> (Arc<Server>, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory());
	(Arc::new(server), sink)
}

/// One client connection driven by the test, the server running in its
/// own task.
pub(super) struct Client {
	read: ReadHalf<DuplexStream>,
	write: WriteHalf<DuplexStream>,
	seen: Vec<u8>,
	task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl Client {
	pub(super) fn connect(server: &Arc<Server>) -> Self {
		let (client, server_stream) = tokio::io::duplex(64 * 1024);
		let server = Arc::clone(server);
		let task = tokio::spawn(async move { server.handle(server_stream, None).await });
		Client {
			task: Some(task),
			..Self::over(client)
		}
	}

	/// The client end of a connection a listener accepts on its own.
	fn over(stream: DuplexStream) -> Self {
		let (read, write) = tokio::io::split(stream);
		Client {
			read,
			write,
			seen: Vec::new(),
			task: None,
		}
	}

	/// Send `bytes` and let the server task read them before the clock
	/// moves on: the rate is measured on what the server has read.
	pub(super) async fn send(&mut self, bytes: &[u8]) {
		self.write
			.write_all(bytes)
			.await
			.expect("the connection is still open");
		for _ in 0..4 {
			tokio::task::yield_now().await;
		}
	}

	/// Read until the server has written `needle` (in the whole output).
	pub(super) async fn wait_for(&mut self, needle: &str) {
		let mut buffer = [0u8; 4096];
		while !String::from_utf8_lossy(&self.seen).contains(needle) {
			let read = self.read.read(&mut buffer).await.expect("client read");
			assert!(read > 0, "the server closed before writing {needle:?}");
			self.seen.extend_from_slice(&buffer[..read]);
		}
	}

	/// Read to the close and return everything the server wrote.
	pub(super) async fn finish(mut self) -> String {
		self.read
			.read_to_end(&mut self.seen)
			.await
			.expect("client read");
		if let Some(task) = self.task {
			task.await.expect("server task").expect("server result");
		}
		String::from_utf8(self.seen).expect("ascii output")
	}
}

/// The code of every final reply line the server wrote, in order.
pub(super) fn reply_codes(output: &str) -> Vec<&str> {
	output
		.split("\r\n")
		.filter(|line| line.len() >= 4 && line.as_bytes()[3] == b' ')
		.map(|line| &line[..3])
		.collect()
}

/// `bytes` of body as 512-byte lines (510 octets and CRLF).
pub(super) fn body(bytes: usize) -> Vec<u8> {
	assert_eq!(bytes % 512, 0, "whole lines only");
	let mut lines = Vec::with_capacity(bytes);
	for _ in 0..bytes / 512 {
		lines.extend_from_slice(&[b'x'; 510]);
		lines.extend_from_slice(b"\r\n");
	}
	lines
}

/// Let `time` pass on the paused clock, then let the server task act on
/// any deadline that came due before the client does anything else.
pub(super) async fn pass(time: Duration) {
	tokio::time::advance(time).await;
	for _ in 0..4 {
		tokio::task::yield_now().await;
	}
}

/// Assert the 421 came exactly when the grace ran out.
pub(super) fn assert_cut_at_grace(started: Instant) {
	let elapsed = started.elapsed();
	assert!(
		elapsed >= GRACE && elapsed < GRACE + Duration::from_millis(5),
		"the client is cut when the grace runs out, not at {elapsed:?}"
	);
}

/// Open a transaction and enter DATA; returns the instant of the 354.
async fn enter_data(client: &mut Client) -> Instant {
	client.send(OPEN).await;
	client.send(b"DATA\r\n").await;
	client.wait_for("354 ").await;
	Instant::now()
}

/// 100 octets every 10 seconds (10 bytes/s), from the 354 until 110 s;
/// each read is far inside the 300 s idle timeout.
async fn drip_until_grace(client: &mut Client) {
	for _ in 0..12 {
		client.send(&[&[b'x'; 98][..], b"\r\n"].concat()).await;
		pass(Duration::from_secs(10)).await;
	}
}

#[tokio::test(start_paused = true)]
async fn a_slow_data_client_is_cut_with_421_when_the_grace_runs_out() {
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	let started = enter_data(&mut client).await;
	drip_until_grace(&mut client).await;
	let output = client.finish().await;
	assert_cut_at_grace(started);
	assert!(
		output.ends_with(TOO_SLOW),
		"the exact 421 line, then the close"
	);
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "421"]
	);
	assert!(sink.messages().is_empty(), "nothing is delivered");
}

#[tokio::test(start_paused = true)]
async fn a_data_client_exactly_at_the_floor_is_not_cut() {
	// 10 KiB at the start of every second for 200 s: at each whole second
	// the average is exactly the floor, never under it.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	enter_data(&mut client).await;
	let second = body(FLOOR);
	for _ in 0..200 {
		client.send(&second).await;
		pass(Duration::from_secs(1)).await;
	}
	client.send(b".\r\nQUIT\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "221"],
		"a client at the floor delivers"
	);
	assert!(
		sink.messages()[0].data.ends_with(&second.repeat(200)),
		"the whole body is delivered"
	);
}

#[tokio::test(start_paused = true)]
async fn a_fast_data_client_is_never_cut_even_when_it_pauses() {
	// 3 MiB at once, then 290 s of silence: the average over the whole
	// body (about 10.6 KiB/s) stays above the floor.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	enter_data(&mut client).await;
	client.send(&body(3 * 1024 * 1024)).await;
	pass(Duration::from_secs(290)).await;
	client.send(b".\r\nQUIT\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "221"]
	);
	assert_eq!(sink.messages().len(), 1);
}

/// A listener whose connections arrive when the test sends them, all from
/// one peer address.
struct Arrivals {
	next: tokio::sync::Mutex<mpsc::UnboundedReceiver<DuplexStream>>,
	peer: SocketAddr,
}

impl crate::net::accept::Accept for Arrivals {
	type Stream = DuplexStream;

	async fn accept(&self) -> std::io::Result<(DuplexStream, SocketAddr)> {
		match self.next.lock().await.recv().await {
			Some(stream) => Ok((stream, self.peer)),
			None => std::future::pending().await,
		}
	}
}

#[tokio::test(start_paused = true)]
async fn the_budget_and_the_per_ip_slot_come_back_after_the_cut() {
	// One connection per client and a budget for one message: the next
	// message fits only if the cut client gave both back.
	let budget = Arc::new(MemoryBudget::with_cap(4096));
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_max_message_size(4096)
			.with_memory_budget(Arc::clone(&budget))
			.with_max_connections_per_ip(1),
	);
	let (arrive, next) = mpsc::unbounded_channel();
	let listener = Arrivals {
		next: tokio::sync::Mutex::new(next),
		peer: "203.0.113.7:4000".parse().expect("peer"),
	};
	let serving = tokio::spawn(Arc::clone(&server).serve_on(listener));

	let (slow, stream) = tokio::io::duplex(64 * 1024);
	arrive.send(stream).expect("first connection");
	let mut slow = Client::over(slow);
	let started = enter_data(&mut slow).await;
	drip_until_grace(&mut slow).await;
	let output = slow.finish().await;
	assert_cut_at_grace(started);
	assert!(output.ends_with(TOO_SLOW), "the slow client is cut");
	assert_eq!(budget.used(), 0, "the cut body went back to the budget");

	let (next_client, stream) = tokio::io::duplex(64 * 1024);
	arrive.send(stream).expect("second connection");
	let mut next_client = Client::over(next_client);
	let mut message = OPEN.to_vec();
	message.extend_from_slice(b"DATA\r\nSubject: hi\r\n\r\n");
	for _ in 0..30 {
		message.extend_from_slice(&[&[b'y'; 98][..], b"\r\n"].concat());
	}
	message.extend_from_slice(b".\r\nQUIT\r\n");
	next_client.send(&message).await;
	let output = next_client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "221"],
		"the same address connects again and its message fits the budget"
	);
	assert_eq!(sink.messages().len(), 1);
	serving.abort();
}

#[tokio::test(start_paused = true)]
async fn octets_past_the_size_cap_buy_no_time() {
	// Past `max_message_size` the body stops growing but DATA is still read
	// to the dot while the reservation is held. 3 MiB would cover 307 s at
	// the floor; only the first 4 KiB count, so the grace decides.
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_max_message_size(4096),
	);
	let mut client = Client::connect(&server);
	let started = enter_data(&mut client).await;
	client.send(&body(3 * 1024 * 1024)).await;
	let output = client.finish().await;
	assert_cut_at_grace(started);
	assert!(output.ends_with(TOO_SLOW), "the exact 421 line");
	assert!(sink.messages().is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_window_ends_with_the_transaction() {
	// A delivered message closes its window: 250 s idle between two
	// messages is the command phase, judged only by the idle timeout.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	enter_data(&mut client).await;
	client.send(b"Subject: one\r\n\r\nbody\r\n.\r\n").await;
	pass(Duration::from_secs(250)).await;
	client
		.send(&OPEN[b"EHLO client.example.org\r\n".len()..])
		.await;
	client
		.send(b"DATA\r\nSubject: two\r\n\r\nbody\r\n.\r\nQUIT\r\n")
		.await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		[
			"220", "250", "250", "250", "354", "250", "250", "250", "354", "250", "221"
		],
		"both messages are delivered"
	);
	assert_eq!(sink.messages().len(), 2);
}
