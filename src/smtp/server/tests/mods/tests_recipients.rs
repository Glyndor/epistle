//! The recipient cap a listener is given reaches every session it opens:
//! the connection advertises it and `RCPT TO` enforces it on the wire.

use super::tests_data_rate::{Client, reply_codes, test_directory};
use super::*;
use crate::smtp::sink::MemorySink;

fn server_with_cap(cap: usize) -> Arc<Server> {
	let sink = Arc::new(MemorySink::new());
	Arc::new(
		Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_max_recipients(cap),
	)
}

#[tokio::test(start_paused = true)]
async fn a_listener_cap_is_advertised_and_enforced_on_the_wire() {
	let server = server_with_cap(120);
	let mut client = Client::connect(&server);
	let mut commands = b"EHLO client.example.org\r\nMAIL FROM:<a@example.net>\r\n".to_vec();
	commands.extend_from_slice(&b"RCPT TO:<bob@example.org>\r\n".repeat(121));
	commands.extend_from_slice(b"QUIT\r\n");
	client.send(&commands).await;
	let output = client.finish().await;
	let advertised = output.lines().find(|line| line.contains("LIMITS"));
	assert_eq!(
		advertised,
		Some("250 LIMITS RCPTMAX=120"),
		"EHLO advertises the listener cap"
	);
	let codes = reply_codes(&output);
	assert_eq!(codes.len(), 1 + 1 + 1 + 121 + 1, "one reply per command");
	assert!(
		codes[3..123].iter().all(|code| *code == "250"),
		"120 recipients are accepted"
	);
	assert!(
		output.contains("452 4.5.3 too many recipients\r\n"),
		"the 121st is refused"
	);
	assert_eq!(codes[123], "452");
}
