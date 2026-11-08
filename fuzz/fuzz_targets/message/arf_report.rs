#![no_main]

use libfuzzer_sys::fuzz_target;

// An inbound feedback report must never panic the reader, and the values a
// complaint carries must never add a field to the report built from them.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::arf_report(data);
});
