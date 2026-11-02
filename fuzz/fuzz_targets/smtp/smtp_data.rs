#![no_main]

use std::sync::Arc;

use epistle::smtp::directory::Directory;
use epistle::smtp::line::LineDecoder;
use epistle::smtp::session::{Action, Session};
use libfuzzer_sys::fuzz_target;

// The DATA reader as the connection loop drives it: the CRLF line decoder
// fed in network-sized pieces, then the session's dot-unstuffing and end
// detection. Arbitrary bytes must not panic, and where the TCP stream
// happens to be cut (a CR at the end of one read, the LF at the start of
// the next, a dot line split in two) must not change what is accepted.
fuzz_target!(|data: &[u8]| {
	let Some((&cut, body)) = data.split_first() else {
		return;
	};
	let whole = receive(body, body.len().max(1));
	let pieces = receive(body, usize::from(cut % 64) + 1);
	assert_eq!(whole, pieces, "the outcome depends on where reads end");
});

/// What the session decides about `input` arriving in `chunk`-byte reads.
fn receive(input: &[u8], chunk: usize) -> Option<Action> {
	let directory = Arc::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let mut session = Session::new("mx.example.org").with_directory(directory);
	for command in [
		"EHLO client.example.net",
		"MAIL FROM:<alice@example.net>",
		"RCPT TO:<bob@example.org>",
		"DATA",
	] {
		session.command_line(command);
	}
	let mut decoder = LineDecoder::new();
	for piece in input.chunks(chunk) {
		decoder.feed(piece);
		loop {
			match decoder.next_line() {
				Ok(Some(line)) => {
					if let Some(action) = session.data_line(&line) {
						return Some(action);
					}
				}
				Ok(None) => break,
				Err(_) => return None,
			}
		}
	}
	None
}
