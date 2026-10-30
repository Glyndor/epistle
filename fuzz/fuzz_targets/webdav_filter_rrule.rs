#![no_main]

use libfuzzer_sys::fuzz_target;

// CalDAV and CardDAV filters and RRULE expansion must never panic or spend unbounded work on hostile text.
fuzz_target!(|data: &[u8]| {
	if let Ok(input) = std::str::from_utf8(data) {
		epistle::fuzzing::webdav_filter_rrule(input);
	}
});
