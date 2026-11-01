#![no_main]

use libfuzzer_sys::fuzz_target;

// JWT decoding and claim checks must never panic on hostile tokens.
fuzz_target!(|data: &[u8]| {
	if let Ok(input) = std::str::from_utf8(data) {
		epistle::fuzzing::jwt_decode(input);
	}
});
