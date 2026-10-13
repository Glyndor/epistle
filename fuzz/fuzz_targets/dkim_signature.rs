#![no_main]

use libfuzzer_sys::fuzz_target;

// A DKIM-Signature header value comes from any sender on the internet:
// the tag-list parser (`b=`, `bh=`, `h=`, `l=`, folded whitespace) and the
// canonicalisation of the same value must never panic.
fuzz_target!(|data: &[u8]| {
	if let Ok(value) = std::str::from_utf8(data) {
		epistle::fuzzing::dkim_signature(value);
	}
});
