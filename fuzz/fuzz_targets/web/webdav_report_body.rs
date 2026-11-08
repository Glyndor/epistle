#![no_main]

use libfuzzer_sys::fuzz_target;

// The readers of a REPORT or PROPFIND body that run before any filter must
// never panic, disagree with each other or accept a sync token the change
// log no longer covers.
fuzz_target!(|data: &[u8]| {
	if let Ok(input) = std::str::from_utf8(data) {
		epistle::fuzzing::webdav_report_body(input);
	}
});
