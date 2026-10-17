//! Legitimate senders the rate floor must not cut: a slow relay with a
//! message at the size cap, a server that sends in bursts with long pauses
//! between them, and a client that pipelines a whole transaction.

use std::time::Duration;

use super::tests_data_rate::{Client, OPEN, body, default_server, pass, reply_codes};

#[tokio::test(start_paused = true)]
async fn a_relay_at_12_kib_per_second_delivers_a_message_at_the_size_cap() {
	// 12 KiB every second for 2133 s: just under the 25 MiB cap, and 20%
	// above the 10 KiB/s floor at every second of the 35 minutes.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	client.send(b"DATA\r\n").await;
	client.wait_for("354 ").await;
	client.send(b"Subject: relay\r\n\r\n").await;
	let second = body(12 * 1024);
	for _ in 0..2133 {
		client.send(&second).await;
		pass(Duration::from_secs(1)).await;
	}
	client.send(b".\r\nQUIT\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "221"],
		"the relay is not cut"
	);
	let data = &sink.messages()[0].data;
	let start = data
		.windows(16)
		.position(|header| header == b"Subject: relay\r\n")
		.expect("the client's header is delivered");
	assert_eq!(
		data.len() - start,
		18 + 2133 * 12 * 1024,
		"the whole message is delivered"
	);
}

#[tokio::test(start_paused = true)]
async fn bursts_with_long_pauses_between_them_are_not_cut() {
	// 1 MiB chunks 100 s apart: each burst covers 102.4 s at the floor,
	// so the 100 s of silence after it never puts the average under it.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	let burst = vec![b'z'; 1024 * 1024];
	for _ in 0..20 {
		client.send(b"BDAT 1048576\r\n").await;
		client.send(&burst).await;
		pass(Duration::from_secs(100)).await;
	}
	client.send(b"BDAT 1048576 LAST\r\n").await;
	client.send(&burst).await;
	client.send(b"QUIT\r\n").await;
	let output = client.finish().await;
	let mut expected = vec!["220", "250", "250", "250"];
	expected.extend(std::iter::repeat_n("250", 21));
	expected.push("221");
	assert_eq!(reply_codes(&output), expected, "every burst is taken");
	assert!(sink.messages()[0].data.ends_with(&burst.repeat(21)));
}

#[tokio::test(start_paused = true)]
async fn a_whole_transaction_pipelined_in_one_write_is_delivered() {
	// RFC 2920 and RFC 3030: every command and chunk in one write, the
	// replies read only at the end.
	let (server, sink) = default_server();
	let mut client = Client::connect(&server);
	let mut pipelined = OPEN.to_vec();
	pipelined.extend_from_slice(b"BDAT 6\r\nhello BDAT 7 LAST\r\nworld\r\nQUIT\r\n");
	client.send(&pipelined).await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "250", "250", "221"]
	);
	assert!(sink.messages()[0].data.ends_with(b"hello world\r\n"));
}
