//! A BDAT chunk is charged to the memory budget as its octets arrive, the
//! way a DATA body is, and not when it is announced. Announcing `BDAT n`
//! costs nothing: a client that announces 25 MiB and drips the body holds
//! only what it sent, so a handful of addresses can no longer keep the
//! whole budget for the length of a grace period.

use std::net::IpAddr;

use super::tests_data_rate::{Client, OPEN, reply_codes, test_directory};
use super::*;
use crate::smtp::memory_budget::DEFAULT_BUDGET_BYTES;
use crate::smtp::sink::MemorySink;

/// The largest chunk a default listener accepts: the message size cap.
const ANNOUNCED: usize = crate::smtp::session::MAX_MESSAGE_SIZE;

fn server_on(budget: &Arc<MemoryBudget>) -> (Arc<Server>, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_memory_budget(Arc::clone(budget));
	(Arc::new(server), sink)
}

#[tokio::test(start_paused = true)]
async fn an_announced_chunk_holds_only_the_octets_that_arrived() {
	let budget = Arc::new(MemoryBudget::with_cap(DEFAULT_BUDGET_BYTES));
	let (server, _sink) = server_on(&budget);
	let mut client = Client::connect(&server);
	client.send(OPEN).await;
	client
		.send(format!("BDAT {ANNOUNCED}\r\n").as_bytes())
		.await;
	client.send(&[b'x'; 4096]).await;
	assert_eq!(
		budget.used(),
		4096,
		"a dripped chunk is charged for what arrived, not what was announced"
	);
	drop(client);
	for _ in 0..4 {
		tokio::task::yield_now().await;
	}
	assert_eq!(budget.used(), 0, "the disconnect hands the octets back");
}

#[tokio::test(start_paused = true)]
async fn four_addresses_announcing_large_chunks_leave_room_for_others() {
	// With the per-client quarter share, 25 + 25 + 14 MiB announced from
	// each of four addresses used to hold the whole default 256 MiB budget
	// for the length of the grace, and every other sender got 452.
	let budget = Arc::new(
		MemoryBudget::with_cap(DEFAULT_BUDGET_BYTES).with_client_share(
			DEFAULT_BUDGET_BYTES / crate::smtp::memory_budget::CLIENT_SHARE_DIVISOR,
		),
	);
	let (server, sink) = server_on(&budget);
	let mut holders = Vec::new();
	for address in 1..=4u8 {
		for announced in [ANNOUNCED, ANNOUNCED, 14 * 1024 * 1024] {
			let peer: IpAddr = [203, 0, 113, address].into();
			let mut client = Client::connect_from(&server, Some(peer));
			client.send(OPEN).await;
			client
				.send(format!("BDAT {announced}\r\n").as_bytes())
				.await;
			client.send(&[b'x'; 512]).await;
			holders.push(client);
		}
	}
	assert_eq!(budget.used(), 12 * 512, "twelve drips hold twelve drips");
	let mut sender = Client::connect_from(&server, Some([198, 51, 100, 9].into()));
	let mut message = OPEN.to_vec();
	message.extend_from_slice(b"BDAT 30 LAST\r\nSubject: hi\r\n\r\nhello there\r\n\r\n");
	message.extend_from_slice(b"QUIT\r\n");
	sender.send(&message).await;
	let output = sender.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "250", "221"],
		"another sender still delivers"
	);
	assert_eq!(sink.messages().len(), 1);
	drop(holders);
	for _ in 0..8 {
		tokio::task::yield_now().await;
	}
	assert_eq!(budget.used(), 0, "every dripped chunk went back");
}

#[tokio::test(start_paused = true)]
async fn a_chunk_refused_while_it_grows_is_read_to_its_end_never_as_commands() {
	// The budget runs out partway through the chunk: the client gets 452
	// once the rest of the chunk is read and thrown away, and none of the
	// octets, which here are all NOOP lines, is answered as a command.
	let budget = Arc::new(MemoryBudget::with_cap(8192));
	let (server, sink) = server_on(&budget);
	let mut client = Client::connect(&server);
	let chunk = b"NOOP\r\n".repeat(3333);
	client.send(OPEN).await;
	client
		.send(format!("BDAT {} LAST\r\n", chunk.len()).as_bytes())
		.await;
	for piece in chunk.chunks(4000) {
		client.send(piece).await;
	}
	client.send(b"QUIT\r\n").await;
	let output = client.finish().await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "452", "221"],
		"one 452 for the chunk, then the QUIT"
	);
	assert!(
		output.contains("452 4.3.1 insufficient system resources; try again later\r\n"),
		"the budget refusal line"
	);
	assert_eq!(budget.used(), 0);
	assert!(sink.messages().is_empty());
}
