//! The rate floor as a listener is configured with it: `0` turns it off,
//! and a configured floor and grace replace the built-in ones.

use std::time::Duration;

use tokio::time::Instant;

use super::tests_data_rate::{Client, OPEN, TOO_SLOW, pass, reply_codes, test_directory};
use super::*;
use crate::smtp::sink::MemorySink;

fn server_with(rate: DataRate) -> (Arc<Server>, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_data_rate(rate);
	(Arc::new(server), sink)
}

async fn enter_data(client: &mut Client) -> Instant {
	client.send(OPEN).await;
	client.send(b"DATA\r\n").await;
	client.wait_for("354 ").await;
	Instant::now()
}

#[tokio::test(start_paused = true)]
async fn a_floor_of_zero_never_cuts_a_slow_client() {
	// 100 octets every 10 s for 400 s, far past the grace: with the floor
	// off only the 300 s idle timeout applies, and every read is inside it.
	let (server, sink) = server_with(DataRate::new(0, Duration::from_secs(120)));
	let mut client = Client::connect(&server);
	enter_data(&mut client).await;
	for _ in 0..40 {
		client.send(&[&[b'x'; 98][..], b"\r\n"].concat()).await;
		pass(Duration::from_secs(10)).await;
	}
	client.send(b".\r\nQUIT\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "354", "250", "221"],
		"the slow message is delivered"
	);
	assert_eq!(sink.messages().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_configured_floor_and_grace_replace_the_defaults() {
	// 10 KiB/s is the built-in floor, but this listener asks for 20 KiB/s
	// after 30 s: the client is cut when that grace runs out.
	let (server, _sink) = server_with(DataRate::new(20 * 1024, Duration::from_secs(30)));
	let mut client = Client::connect(&server);
	let started = enter_data(&mut client).await;
	let second = super::tests_data_rate::body(10 * 1024);
	for _ in 0..30 {
		client.send(&second).await;
		pass(Duration::from_secs(1)).await;
	}
	let output = client.finish().await;
	let elapsed = started.elapsed();
	assert!(
		elapsed >= Duration::from_secs(30) && elapsed < Duration::from_millis(30_005),
		"cut when the configured grace runs out, not at {elapsed:?}"
	);
	assert!(output.ends_with(TOO_SLOW), "the exact 421 line");
}
