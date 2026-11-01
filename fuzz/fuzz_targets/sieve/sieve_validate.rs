#![no_main]

use libfuzzer_sys::fuzz_target;

// The check every protocol runs before it stores a script or reports one
// valid (size, syntax, extensions, `:matches` keys, sends mail or not) takes
// text a user chose and must never panic or loop.
fuzz_target!(|data: &[u8]| {
	if let Ok(text) = std::str::from_utf8(data) {
		let _ = epistle::managesieve::store::ScriptStore::validate(text);
		let _ = epistle::sieve::analysis::sends_mail(text);
	}
});
