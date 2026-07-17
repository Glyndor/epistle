#![no_main]

use libfuzzer_sys::fuzz_target;

// The IMAP command parser takes pre-authentication network input and must
// never panic on hostile bytes.
fuzz_target!(|data: &[u8]| {
	if let Ok(line) = std::str::from_utf8(data) {
		let _ = epistle::imap::command::parse(line);
	}
});
