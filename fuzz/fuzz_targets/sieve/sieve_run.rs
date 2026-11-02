#![no_main]

use libfuzzer_sys::fuzz_target;

// A script runs against mail anyone can send. Whatever the script and the
// message are, parsing the one, reading the other and running them together
// must not panic and must stay inside the run's budget (a run that spends
// too much stops; it does not hang or allocate without bound). The input is
// a script and a message separated by the first NUL octet.
fuzz_target!(|data: &[u8]| {
	let (script, message) = match data.iter().position(|b| *b == 0) {
		Some(at) => (&data[..at], &data[at + 1..]),
		None => (data, &b"Subject: x\r\n\r\nbody\r\n"[..]),
	};
	let Ok(script) = std::str::from_utf8(script) else {
		return;
	};
	let Ok(tokens) = epistle::sieve::lexer::tokenize(script) else {
		return;
	};
	let Ok(commands) = epistle::sieve::parser::parse(&tokens) else {
		return;
	};
	let message = epistle::sieve::interp::Message::parse(message);
	let _ = epistle::sieve::interp::evaluate(&commands, &message);
});
