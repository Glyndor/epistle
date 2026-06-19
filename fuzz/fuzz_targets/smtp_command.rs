#![no_main]

use libfuzzer_sys::fuzz_target;

// The SMTP command parser must never panic on hostile input.
fuzz_target!(|data: &[u8]| {
	if let Ok(line) = std::str::from_utf8(data) {
		let _ = mail::smtp::command::parse(line);
	}
});
