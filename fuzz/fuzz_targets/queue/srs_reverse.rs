#![no_main]

//! The SRS rewriter: an address a client sends, and the sender it hides.
//!
//! The rewriter signs a sender into an `SRS0` address of its own domain,
//! and gives the sender back when a bounce comes home. The target drives
//! it with the bytes of a client: an address to reverse, and a sender to
//! sign. What it checks is that the pair the rewriter gives back is the
//! pair it would sign again, and that what it signs it reverses again.

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

/// The alphabet of a name that picks the secret an address is signed with:
/// the name of a hosted domain, and the domain of a sender.
const NAME: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789.-";

/// A name of the shape of a domain, never empty.
fn name(u: &mut Unstructured) -> String {
	let len = u.int_in_range(1..=12).unwrap_or(1);
	let mut out = String::new();
	for _ in 0..len {
		let at = u.choose_index(NAME.len()).unwrap_or(0);
		out.push(NAME[at] as char);
	}
	out
}

/// The local part of a sender, as a client writes it, never empty.
fn local(u: &mut Unstructured) -> String {
	let len = u.int_in_range(1..=24).unwrap_or(1);
	let mut bytes = u.bytes(len).map(<[u8]>::to_vec).unwrap_or_default();
	bytes.resize(len, b'x');
	String::from_utf8_lossy(&bytes).replace(['\r', '\n'], " ")
}

fuzz_target!(|data: &[u8]| {
	let mut u = Unstructured::new(data);
	// The address a client sent, as the bytes arrive.
	let sent = String::from_utf8_lossy(data);
	let local = local(&mut u);
	let domain = name(&mut u);
	let hosted = name(&mut u);
	epistle::fuzzing::srs_reverse(&sent, &local, &domain, &hosted);
});
