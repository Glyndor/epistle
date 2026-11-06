#![no_main]

use libfuzzer_sys::fuzz_target;

// The SPF, DMARC and DKIM key records a sending domain publishes, and the
// SPF macros expanded with a sender and HELO name the client chooses. None
// of it may panic, and a parsed record must keep to the ranges it promises.
fuzz_target!(|data: &[u8]| {
	if let Ok(input) = std::str::from_utf8(data) {
		epistle::fuzzing::sender_auth_records(input);
	}
});
