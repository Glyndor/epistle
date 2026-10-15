//! The minimum transfer rate for BDAT (RFC 3030): every chunk is judged
//! on its own window, from the moment its octets start to be read, so the
//! time spent between chunks in the command phase never counts.

use std::time::Duration;

use tokio::time::Instant;

use super::tests_data_rate::{
	Client, FLOOR, OPEN, TOO_SLOW, assert_cut_at_grace, default_server, pass, reply_codes,
};

/// 100 octets every 10 seconds (10 bytes/s) for 120 s: far under the floor.
async fn drip_until_grace(client: &mut Client) {
	for _ in 0..12 {
		client.send(&[b'x'; 100]).await;
		pass(Duration::from_secs(10)).await;
	}
}

#[tokio::test(start_paused = true)]
async fn a_slow_bdat_chunk_is_cut_on_its_own_window_after_a_fast_one() {
	// 2 MiB at once in the first chunk would carry a window shared by the
	// whole transaction above the floor for minutes; the second chunk is
	// judged alone and cut when its own grace runs out.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	client.send(b"BDAT 2097152\r\n").await;
	client.send(&vec![b'x'; 2 * 1024 * 1024]).await;
	client.wait_for("chunk received").await;
	client.send(b"BDAT 4096 LAST\r\n").await;
	let started = Instant::now();
	drip_until_grace(&mut client).await;
	let output = client.finish().await;
	assert_cut_at_grace(started);
	assert!(
		output.ends_with(TOO_SLOW),
		"the exact 421 line, then the close"
	);
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "250", "421"]
	);
	assert!(sink.messages().is_empty(), "nothing is delivered");
}

#[tokio::test(start_paused = true)]
async fn the_pause_between_bdat_chunks_does_not_count_against_the_rate() {
	// 250 s between two chunks (inside the 300 s idle timeout) is command
	// phase; each chunk then arrives at once and is well above the floor.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	client.send(b"BDAT 100\r\n").await;
	client.send(&[b'x'; 100]).await;
	client.wait_for("chunk received").await;
	pass(Duration::from_secs(250)).await;
	client
		.send(format!("BDAT {FLOOR} LAST\r\n").as_bytes())
		.await;
	client.send(&vec![b'y'; FLOOR]).await;
	client.send(b"QUIT\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "250", "250", "221"],
		"both chunks are taken and the message delivered"
	);
	let body = [vec![b'x'; 100], vec![b'y'; FLOOR]].concat();
	assert!(
		sink.messages()[0].data.ends_with(&body),
		"both chunks make up the body"
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
	drip_until_grace(&mut client).await;
	let output = client.finish().await;
	assert_cut_at_grace(started);
	assert!(output.ends_with(TOO_SLOW));
	assert_eq!(reply_codes(&output), ["220", "250", "421"]);
}
