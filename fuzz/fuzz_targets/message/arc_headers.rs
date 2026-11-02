#![no_main]

use libfuzzer_sys::fuzz_target;

// ARC header parsing must never panic on hostile input.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::arc_headers(data);
});
