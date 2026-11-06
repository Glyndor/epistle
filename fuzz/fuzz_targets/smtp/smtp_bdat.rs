#![no_main]

//! A BDAT chunked message driven through the SMTP session, against the same
//! in-memory directory of two accounts the session target uses.
//!
//! The client sends the chunks of one message: how many there are, how long
//! each one is and which one carries the last flag come from the input, and
//! the octets of each chunk come from the rest of it. The session reads them
//! and hands the message over. What it checks is that it never hands over
//! more than one message, and that the body of the message it hands over is
//! the octets of the chunks that were sent.

#[path = "../shared/accounts.rs"]
mod accounts;

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

use accounts::DOMAIN;

/// The octets of a chunk of `size` octets: CRLF framed lines most of the
/// time, since a chunk that breaks the framing closes the connection, and
/// raw octets the rest.
fn chunk(u: &mut Unstructured, size: usize) -> Vec<u8> {
	if u.int_in_range(0..=7).unwrap_or(0) == 0 {
		let mut raw = u.bytes(size).map(<[u8]>::to_vec).unwrap_or_default();
		raw.resize(size, b'x');
		return raw;
	}
	let mut out: Vec<u8> = b"Subject: chunk\r\n"
		.iter()
		.copied()
		.cycle()
		.take(size)
		.collect();
	if size >= 2 {
		out[size - 2..].copy_from_slice(b"\r\n");
	}
	out
}

/// The chunks a client sends: how many, how long each one is, which one
/// carries the last flag, and the octets of each one.
fn chunks(u: &mut Unstructured) -> Vec<(Vec<u8>, bool)> {
	let count = u.int_in_range(1..=6).unwrap_or(1);
	(0..count)
		.map(|_| {
			let size = u.int_in_range(0..=64).unwrap_or(0);
			let last = u.arbitrary::<bool>().unwrap_or(false);
			(chunk(u, size), last)
		})
		.collect()
}

/// The envelope a client names: a sender of its own, and a recipient the
/// directory knows.
fn envelope(u: &mut Unstructured, accounts: &[accounts::Account]) -> (String, String) {
	let sender = match u.int_in_range(0..=3).unwrap_or(0) {
		0 => "alice@example.net".to_string(),
		1 => "bob@example.net".to_string(),
		2 => format!("{}@{DOMAIN}", accounts[1].name),
		_ => "postmaster@example.net".to_string(),
	};
	let recipient = format!("{}@{DOMAIN}", accounts[0].name);
	(sender, recipient)
}

fuzz_target!(|data: &[u8]| {
	let mut u = Unstructured::new(data);
	let accounts = accounts::accounts();
	let directory = accounts::directory(&accounts);
	let (sender, recipient) = envelope(&mut u, &accounts);
	epistle::fuzzing::smtp_bdat(directory, &sender, &recipient, &chunks(&mut u));
});
