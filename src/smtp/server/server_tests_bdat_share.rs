//! The octets of a BDAT chunk charged as they arrive: exactly what was
//! read, never rounded to the read buffer, and given back the moment the
//! budget refuses the chunk, while the session goes on. Every test runs on
//! tokio's paused clock.

use std::net::IpAddr;

use super::tests_data_rate::{Client, OPEN, reply_codes, test_directory};
use super::*;
use crate::smtp::sink::MemorySink;

const PEER: [u8; 4] = [203, 0, 113, 20];

fn server_on(budget: &Arc<MemoryBudget>) -> (Arc<Server>, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_memory_budget(Arc::clone(budget));
	(Arc::new(server), sink)
}

/// A message of exactly `len` octets: a header, then lines of 98 octets.
fn message_of(len: usize) -> Vec<u8> {
	let mut message = b"Subject: hi\r\n\r\n".to_vec();
	while message.len() + 100 <= len {
		message.extend_from_slice(&[&[b'y'; 98][..], b"\r\n"].concat());
	}
	message.resize(len - 2, b'z');
	message.extend_from_slice(b"\r\n");
	message
}

#[tokio::test(start_paused = true)]
async fn a_chunk_of_exactly_the_share_fits_and_one_octet_more_does_not() {
	// A share of 10000 is not a multiple of the 4096-octet read buffer: a
	// charge rounded up per read would refuse the first chunk, one rounded
	// down would accept the second.
	let budget = Arc::new(MemoryBudget::with_cap(40_000).with_client_share(10_000));
	let (server, sink) = server_on(&budget);
	let mut client = Client::connect_from(&server, Some(IpAddr::from(PEER)));
	let mut session = OPEN.to_vec();
	session.extend_from_slice(b"BDAT 10000 LAST\r\n");
	session.extend_from_slice(&message_of(10_000));
	session.extend_from_slice(b"MAIL FROM:<a@example.net>\r\nRCPT TO:<bob@example.org>\r\n");
	session.extend_from_slice(b"BDAT 10001 LAST\r\n");
	session.extend_from_slice(&message_of(10_001));
	session.extend_from_slice(b"QUIT\r\n");
	client.send(&session).await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		[
			"220", "250", "250", "250", "250", "250", "250", "452", "221"
		],
		"10000 octets fit the share of 10000, 10001 do not"
	);
	assert_eq!(sink.messages().len(), 1);
	assert_eq!(budget.used(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_refused_chunk_gives_its_octets_back_before_the_session_goes_on() {
	// The budget refuses the chunk after two reads: what those reads were
	// charged is released with the 452, not when the connection ends, and
	// the same session then delivers a message in the room it freed.
	let budget = Arc::new(MemoryBudget::with_cap(8192));
	let (server, sink) = server_on(&budget);
	let mut client = Client::connect_from(&server, Some(IpAddr::from(PEER)));
	client.send(OPEN).await;
	client.send(b"BDAT 12000 LAST\r\n").await;
	for piece in [4096, 4096, 3808] {
		client.send(&vec![b'x'; piece]).await;
	}
	client.wait_for("452 ").await;
	assert_eq!(budget.used(), 0, "the partial chunk went back with the 452");
	let mut message = b"MAIL FROM:<a@example.net>\r\nRCPT TO:<bob@example.org>\r\n".to_vec();
	message.extend_from_slice(b"BDAT 8000 LAST\r\n");
	message.extend_from_slice(&message_of(8000));
	message.extend_from_slice(b"QUIT\r\n");
	client.send(&message).await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		[
			"220", "250", "250", "250", "452", "250", "250", "250", "221"
		],
		"the session goes on and its next message fits"
	);
	assert_eq!(sink.messages().len(), 1);
}
