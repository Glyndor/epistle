#![no_main]

use libfuzzer_sys::fuzz_target;

// Attachment sniffing must never panic on hostile bytes.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::attachment_inspect(data);
});
