#![no_main]

use libfuzzer_sys::fuzz_target;

// This parser must never panic or spend unbounded work on hostile input.
fuzz_target!(|data: &[u8]| {
	if let Ok(input) = std::str::from_utf8(data) {
		epistle::fuzzing::dns_security_records(input);
	}
});
