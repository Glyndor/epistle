#![no_main]

use libfuzzer_sys::fuzz_target;

// What a client sends before it is logged in: SASL PLAIN, an OAUTHBEARER or
// XOAUTH2 initial response, and the two SCRAM-SHA-256 client messages. None
// of it may panic, and SCRAM must accept only the proof the password gives,
// over the nonce the server sent.
fuzz_target!(|data: &[u8]| {
	if let Ok(input) = std::str::from_utf8(data) {
		epistle::fuzzing::sasl_exchange(input);
	}
});
