#![no_main]

use libfuzzer_sys::fuzz_target;

// The POP3 command parser takes pre-authentication network input and must
// never panic on hostile bytes.
fuzz_target!(|data: &[u8]| {
	if let Ok(line) = std::str::from_utf8(data) {
		let _ = epistle::pop3::command::parse(line);
	}
});
