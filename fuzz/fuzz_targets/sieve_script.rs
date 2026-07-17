#![no_main]

use libfuzzer_sys::fuzz_target;

// Sieve scripts arrive from users over ManageSieve; the lexer + parser
// pipeline must never panic on a hostile script.
fuzz_target!(|data: &[u8]| {
	if let Ok(text) = std::str::from_utf8(data) {
		if let Ok(tokens) = epistle::sieve::lexer::tokenize(text) {
			let _ = epistle::sieve::parser::parse(&tokens);
		}
	}
});
