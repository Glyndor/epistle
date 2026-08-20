#![no_main]

use libfuzzer_sys::fuzz_target;

// The ManageSieve command parser takes network input plus an optional literal
// payload; neither path may panic on hostile bytes. The first input byte
// selects whether a literal is attached, the second half of the remainder
// becomes that literal.
fuzz_target!(|data: &[u8]| {
	let Some((&selector, rest)) = data.split_first() else {
		return;
	};
	let (line_bytes, literal) = if selector & 1 == 1 && !rest.is_empty() {
		let mid = rest.len() / 2;
		(&rest[..mid], Some(rest[mid..].to_vec()))
	} else {
		(rest, None)
	};
	if let Ok(line) = std::str::from_utf8(line_bytes) {
		let _ = epistle::managesieve::command::parse(line, literal);
	}
});
