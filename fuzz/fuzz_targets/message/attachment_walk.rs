#![no_main]

use libfuzzer_sys::fuzz_target;

// A message through the attachment inspection: the MIME walk, the zip and
// OLE2 directory readers and the rules on top. Contradictory central
// directories, offsets past the end and deep nesting must not panic, and
// the walk and the listing must keep to their limits.
fuzz_target!(|data: &[u8]| {
	epistle::fuzzing::attachment_walk(data);
});
