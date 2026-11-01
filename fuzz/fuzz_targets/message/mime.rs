#![no_main]

use libfuzzer_sys::fuzz_target;

// A whole inbound message through every MIME consumer: IMAP FETCH
// structure, JMAP body properties, the DMARC and TLS-RPT report walkers,
// the From field reader and DKIM body canonicalisation. Deep nesting,
// broken boundaries and bad encodings must not panic or overflow the stack.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::mime(data);
});
