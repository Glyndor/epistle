#![no_main]

use libfuzzer_sys::fuzz_target;

// The message/MIME decoder parses raw attacker-controlled message bytes at
// delivery time and must never panic.
fuzz_target!(|data: &[u8]| {
	let _ = epistle::sieve::message::Message::parse(data);
});
