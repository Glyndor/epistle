#![no_main]

use libfuzzer_sys::fuzz_target;

// The configuration parser must end every text in a value or an error, with
// no panic, no stack overflow and no unbounded work, whatever the file says.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::config_parse(data);
});
