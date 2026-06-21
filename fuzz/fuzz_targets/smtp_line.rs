#![no_main]

use libfuzzer_sys::fuzz_target;
use epistle::smtp::line::LineDecoder;

// The CRLF line decoder must handle arbitrary byte streams without panicking,
// draining every line it can (the SMTP-smuggling-hardened path).
fuzz_target!(|data: &[u8]| {
	let mut decoder = LineDecoder::new();
	decoder.feed(data);
	while let Ok(Some(_)) = decoder.next_line() {}
});
