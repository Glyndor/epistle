#![no_main]

use libfuzzer_sys::fuzz_target;

// Address parsing/validation must never panic on hostile input.
fuzz_target!(|data: &[u8]| {
	if let Ok(raw) = std::str::from_utf8(data) {
		let _ = epistle::smtp::address::Address::parse(raw);
	}
});
