#![no_main]

use libfuzzer_sys::fuzz_target;

// This parser must never panic or spend unbounded work on hostile input.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::rules_match(data);
});
