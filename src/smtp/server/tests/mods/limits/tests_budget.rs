//! The memory budget across the connection loop: what a client that
//! disconnects or stalls mid-transfer leaves behind, and how long the
//! accepted body stays on the budget. Each leaking path runs many times
//! against one budget before a legitimate message has to fit.

use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::SinkError;

const ROUNDS: usize = 10;

fn test_directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	))
}

/// A sink that records how many budget octets were held while the
/// connection loop handed it a message.
struct BudgetProbe {
	budget: Arc<MemoryBudget>,
	held_at_delivery: Mutex<Vec<u64>>,
}

impl MessageSink for BudgetProbe {
	fn deliver(&self, _message: AcceptedMessage) -> Result<(), SinkError> {
		let held = self.budget.used();
		self.held_at_delivery.lock().expect("probe").push(held);
		Ok(())
	}
}

fn server_with(budget: &Arc<MemoryBudget>) -> (Arc<Server>, Arc<BudgetProbe>) {
	let probe = Arc::new(BudgetProbe {
		budget: Arc::clone(budget),
		held_at_delivery: Mutex::new(Vec::new()),
	});
	let server = Server::new("mail.example.org", probe.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_max_message_size(4096)
		.with_memory_budget(Arc::clone(budget));
	(Arc::new(server), probe)
}

/// Write `input`, then either close the client's write half (a clean
/// disconnect) or keep it open with nothing more to send (a stalled
/// client the server has to time out). Returns what the server wrote.
async fn exchange(server: &Arc<Server>, input: &[u8], close: bool) -> String {
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let server = Arc::clone(server);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(input).await.expect("client write");
	if close {
		client_write.shutdown().await.expect("client shutdown");
	}
	let mut output = Vec::new();
	client_read
		.read_to_end(&mut output)
		.await
		.expect("client read");
	task.await.expect("server task").expect("server result");
	drop(client_write);
	String::from_utf8(output).expect("ascii output")
}

/// The code of every final reply line the server wrote, in order.
fn reply_codes(output: &str) -> Vec<&str> {
	output
		.split("\r\n")
		.filter(|line| line.len() >= 4 && line.as_bytes()[3] == b' ')
		.map(|line| &line[..3])
		.collect()
}

const OPEN: &[u8] = b"EHLO client.example.org\r\nMAIL FROM:<a@example.net>\r\n\
RCPT TO:<bob@example.org>\r\n";

fn legitimate_message() -> Vec<u8> {
	let mut script = OPEN.to_vec();
	script.extend_from_slice(b"DATA\r\nSubject: hi\r\n\r\n");
	for _ in 0..30 {
		script.extend_from_slice(&[b'x'; 98]);
		script.extend_from_slice(b"\r\n");
	}
	script.extend_from_slice(b".\r\nQUIT\r\n");
	script
}

async fn assert_legitimate_message_fits(server: &Arc<Server>, probe: &BudgetProbe) {
	let output = exchange(server, &legitimate_message(), true).await;
	assert!(
		output.contains("354 ") && output.contains("\r\n250 2.0.0 ok\r\n221 "),
		"a legitimate message is accepted once the leaking path is over"
	);
	assert_eq!(probe.held_at_delivery.lock().expect("probe").len(), 1);
}

#[tokio::test]
async fn a_client_that_announces_a_bdat_chunk_and_disconnects_leaves_nothing_held() {
	let budget = Arc::new(MemoryBudget::with_cap(8192));
	let (server, probe) = server_with(&budget);
	for _ in 0..ROUNDS {
		exchange(&server, b"EHLO client.example.org\r\nBDAT 4096\r\n", true).await;
	}
	assert_eq!(budget.used(), 0, "an unread chunk goes back to the budget");
	assert_legitimate_message_fits(&server, &probe).await;
}

#[tokio::test(start_paused = true)]
async fn a_client_that_stalls_inside_a_bdat_chunk_is_timed_out_and_released() {
	let budget = Arc::new(MemoryBudget::with_cap(8192));
	let (server, probe) = server_with(&budget);
	for _ in 0..ROUNDS {
		let mut input = b"EHLO client.example.org\r\nBDAT 4096\r\n".to_vec();
		input.extend_from_slice(&[b'x'; 100]);
		exchange(&server, &input, false).await;
	}
	assert_eq!(
		budget.used(),
		0,
		"a timed-out chunk goes back to the budget"
	);
	assert_legitimate_message_fits(&server, &probe).await;
}

#[tokio::test]
async fn a_client_that_disconnects_mid_data_leaves_nothing_held() {
	let budget = Arc::new(MemoryBudget::with_cap(8192));
	let (server, probe) = server_with(&budget);
	for _ in 0..ROUNDS {
		let mut input = OPEN.to_vec();
		input.extend_from_slice(b"DATA\r\n");
		for _ in 0..30 {
			input.extend_from_slice(&[b'x'; 98]);
			input.extend_from_slice(b"\r\n");
		}
		exchange(&server, &input, true).await;
	}
	assert_eq!(
		budget.used(),
		0,
		"an abandoned body goes back to the budget"
	);
	assert_legitimate_message_fits(&server, &probe).await;
}

#[tokio::test]
async fn the_body_stays_on_the_budget_until_the_delivery_is_over() {
	// Between the final dot and the reply the body is still in memory,
	// stamped and checked (DNS, scanners, Bayes), so it must still count.
	let budget = Arc::new(MemoryBudget::with_cap(8192));
	let (server, probe) = server_with(&budget);
	assert_legitimate_message_fits(&server, &probe).await;
	let held = probe.held_at_delivery.lock().expect("probe")[0];
	assert!(held >= 30 * 100, "the body counted while it was delivered");
	assert_eq!(budget.used(), 0, "and went back once the reply was sent");
}

#[tokio::test]
async fn a_bdat_chunk_refused_for_the_budget_is_consumed_never_run_as_commands() {
	// RFC 3030: the octets after `BDAT n` are message data whatever the
	// reply. A refusal that leaves them unread would parse the message as
	// SMTP commands (a smuggling and desync vector). The budget here is
	// smaller than the chunk, so the chunk is refused.
	let budget = Arc::new(MemoryBudget::with_cap(64));
	let (server, probe) = server_with(&budget);
	let smuggled =
		b"RSET\r\nMAIL FROM:<forged@example.org>\r\nRCPT TO:<bob@example.org>\r\nDATA\r\n";
	let mut input = OPEN.to_vec();
	input.extend_from_slice(format!("BDAT {} LAST\r\n", smuggled.len()).as_bytes());
	input.extend_from_slice(smuggled);
	input.extend_from_slice(b"QUIT\r\n");
	let output = exchange(&server, &input, true).await;
	assert_eq!(
		reply_codes(&output),
		["220", "250", "250", "250", "452", "221"],
		"the refused chunk is read off the wire, never answered as commands"
	);
	assert!(probe.held_at_delivery.lock().expect("probe").is_empty());
	assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn a_delivered_body_goes_back_before_the_next_message_on_the_connection() {
	// The budget fits one body. Two messages in one connection both fit
	// only if the first body is released once its delivery is over.
	let budget = Arc::new(MemoryBudget::with_cap(3500));
	let (server, probe) = server_with(&budget);
	let mut script = legitimate_message();
	script.truncate(script.len() - b"QUIT\r\n".len());
	script.extend_from_slice(&legitimate_message()[b"EHLO client.example.org\r\n".len()..]);
	let output = exchange(&server, &script, true).await;
	assert_eq!(
		reply_codes(&output),
		[
			"220", "250", "250", "250", "354", "250", "250", "250", "354", "250", "221"
		],
		"both messages accepted"
	);
	assert_eq!(probe.held_at_delivery.lock().expect("probe").len(), 2);
}
