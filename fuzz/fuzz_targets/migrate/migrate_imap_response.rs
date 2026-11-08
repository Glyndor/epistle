#![no_main]

use libfuzzer_sys::fuzz_target;

// The reader and the parsers must never panic, exceed their bounds or spend
// unbounded work on what a hostile source server sends.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::migrate_imap_response(data);
});
