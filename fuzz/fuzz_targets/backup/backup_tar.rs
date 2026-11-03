#![no_main]

use libfuzzer_sys::fuzz_target;

// A hostile archive must never panic the reader, pass the decompression
// ceiling or name a destination outside the data directory.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::backup_tar(data);
});
