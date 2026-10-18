//! The minimum transfer rate for BDAT (RFC 3030): one window for the whole
//! transaction, from the first chunk to the LAST one. The time between
//! chunks counts, commands sent in it bring no octets, and the grace is
//! given once, so neither tiny chunks nor slow commands can hold a body
//! reservation past what the octets received so far cover.

use std::time::Duration;

use tokio::time::Instant;

use super::tests_data_rate::{
	Client, FLOOR, OPEN, TOO_SLOW, assert_cut_at_grace, default_server, pass, reply_codes,
	test_directory,
};
use super::*;
use crate::smtp::line::filler;
use crate::smtp::sink::MemorySink;

#[tokio::test(start_paused = true)]
async fn tiny_chunks_each_inside_the_grace_do_not_hold_the_budget() {
	// One octet every 100 s: every chunk arrives at once, so a window per
	// chunk would never cut, and the transaction would hold its body on
	// the budget forever.
	let budget = Arc::new(MemoryBudget::with_cap(8192));
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_memory_budget(Arc::clone(&budget)),
	);
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	let started = Instant::now();
	client.send(b"BDAT 1\r\nx").await;
	pass(Duration::from_secs(100)).await;
	client.send(b"BDAT 1\r\nx").await;
	let output = client.finish().await;
	assert_cut_at_grace(started);
	assert!(output.ends_with(TOO_SLOW), "the exact 421 line");
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "250", "250", "421"]
	);
	assert_eq!(budget.used(), 0, "the held chunks go back to the budget");
	assert!(sink.messages().is_empty());
}

#[tokio::test(start_paused = true)]
async fn slow_commands_between_chunks_count_against_the_transaction() {
	// A NOOP every 50 s keeps the 300 s idle timeout away, but brings no
	// octets: the transaction is judged when its grace runs out.
	let (server, _sink) = default_server();
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	let started = Instant::now();
	client.send(b"BDAT 100\r\n").await;
	client.send(&[b'x'; 100]).await;
	pass(Duration::from_secs(50)).await;
	client.send(b"NOOP\r\n").await;
	pass(Duration::from_secs(50)).await;
	client.send(b"NOOP\r\n").await;
	let output = client.finish().await;
	assert_cut_at_grace(started);
	assert!(output.ends_with(TOO_SLOW), "the exact 421 line");
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "250", "250", "250", "421"]
	);
}

#[tokio::test(start_paused = true)]
async fn a_fast_first_chunk_buys_only_the_time_its_octets_cover() {
	// 2 MiB at once covers 204.8 s at 10 KiB/s; a LAST chunk that never
	// comes is cut then, not one grace after it was announced.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	let started = Instant::now();
	client.send(b"BDAT 2097152\r\n").await;
	client.send(&filler(2 * 1024 * 1024)).await;
	client.send(b"BDAT 4096 LAST\r\n").await;
	let output = client.finish().await;
	let elapsed = started.elapsed();
	let covered = Duration::from_millis(204_800);
	assert!(
		elapsed >= covered && elapsed < covered + Duration::from_millis(5),
		"cut when the octets of the first chunk run out, not at {elapsed:?}"
	);
	assert!(output.ends_with(TOO_SLOW), "the exact 421 line");
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "250", "421"]
	);
	assert!(sink.messages().is_empty(), "nothing is delivered");
}

#[tokio::test(start_paused = true)]
async fn chunks_at_the_floor_with_the_commands_between_them_are_delivered() {
	// A 10 KiB chunk at the start of every second for 200 s: the chunk
	// commands and the waits count, and the average never drops under
	// the floor.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	for _ in 0..199 {
		client.send(format!("BDAT {FLOOR}\r\n").as_bytes()).await;
		client.send(&filler(FLOOR)).await;
		pass(Duration::from_secs(1)).await;
	}
	client
		.send(format!("BDAT {FLOOR} LAST\r\n").as_bytes())
		.await;
	client.send(&filler(FLOOR)).await;
	client.send(b"QUIT\r\n").await;
	let output = client.finish().await;
	let mut expected = vec!["220", "250", "250", "250"];
	expected.extend(std::iter::repeat_n("250", 200));
	expected.push("221");
	assert_eq!(
		reply_codes(&output),
		expected,
		"every chunk and the message"
	);
	assert!(
		sink.messages()[0]
			.data
			.ends_with(&filler(FLOOR).repeat(200))
	);
}

#[tokio::test(start_paused = true)]
async fn a_slow_chunk_read_only_to_be_thrown_away_is_cut_too() {
	// A chunk outside a transaction is read and discarded; a client that
	// drips it still holds a connection and a per-IP slot.
	let (server, _sink) = default_server();
	let mut client = Client::connect(&server);
	client
		.send(b"EHLO client.example.org\r\nBDAT 4096\r\n")
		.await;
	let started = Instant::now();
	for _ in 0..12 {
		client.send(&[b'x'; 100]).await;
		pass(Duration::from_secs(10)).await;
	}
	let output = client.finish().await;
	assert_cut_at_grace(started);
	assert!(output.ends_with(TOO_SLOW));
	assert_eq!(reply_codes(&output), ["220", "250", "421"]);
}
