#![no_main]

use libfuzzer_sys::fuzz_target;

// The DKIM signer reads its requests from a process that may be
// compromised, and the client reads the signer's answers the same way:
// the frame decoder and the checks before the key holder must never
// panic or allocate past the caps.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::signer_frame(data);
});
