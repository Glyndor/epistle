//! External signatures make canonicalization errors observable at the public API.

use super::harness::*;
use epistle::dkim::DkimOutcome::{Fail, Pass};

macro_rules! vector {
	($test:ident, $fixture:literal) => {
		#[test]
		fn $test() {
			case($fixture, Pass, 1);
		}
	};
}

vector!(ed_simple_simple, "ed25519-simple-simple-mixed");
vector!(ed_simple_relaxed, "ed25519-simple-relaxed-mixed");
vector!(ed_relaxed_simple, "ed25519-relaxed-simple-mixed");
vector!(ed_relaxed_relaxed, "ed25519-relaxed-relaxed-mixed");
vector!(rsa_simple_simple, "rsa2048-simple-simple-mixed");
vector!(rsa_simple_relaxed, "rsa2048-simple-relaxed-mixed");
vector!(rsa_relaxed_simple, "rsa2048-relaxed-simple-mixed");
vector!(rsa_relaxed_relaxed, "rsa2048-relaxed-relaxed-mixed");
vector!(rfc6376_relaxed_example, "rfc6376-relaxed");

#[test]
// RFC 6376 sections 3.4.3 and 3.4.4 distinguish CRLF from null input.
fn empty_and_whitespace_only_bodies_use_distinct_external_hashes() {
	for key in ["ed25519", "rsa2048"] {
		for hc in ["simple", "relaxed"] {
			for bc in ["simple", "relaxed"] {
				for shape in ["empty", "blank"] {
					case(&format!("{key}-{hc}-{bc}-{shape}"), Pass, 1);
				}
			}
		}
	}
}

#[test]
// RFC 6376 section 3.4.4 keeps leading WSP as one SP, not zero.
fn relaxed_body_preserves_indentation() {
	let name = "ed25519-relaxed-relaxed-mixed";
	let raw = replace(&message(name), "\t  indented", "indented");
	expect_dkim(raw, Dns::dkim(name), Fail, Some("example.test"), 0);
}

#[test]
fn relaxed_body_accepts_equivalent_tabs_and_trailing_empty_lines() {
	let name = "ed25519-relaxed-relaxed-mixed";
	let raw = replace(&message(name), "\t  indented\ttext \t", " indented text");
	let mut raw = raw;
	raw.extend_from_slice(b"\r\n\r\n");
	expect_dkim(raw, Dns::dkim(name), Pass, Some("example.test"), 1);
}

#[test]
fn simple_body_keeps_tabs_and_spaces_significant() {
	let name = "ed25519-relaxed-simple-mixed";
	let raw = replace(&message(name), "line\t\t two", "line two");
	expect_dkim(raw, Dns::dkim(name), Fail, Some("example.test"), 0);
}

#[test]
fn relaxed_headers_accept_case_and_folding_equivalence() {
	let name = "ed25519-relaxed-relaxed-mixed";
	let raw = replace(
		&message(name),
		"SuBJeCt:  external\tvector\r\n\t folded  ",
		"subject: external vector folded",
	);
	expect_dkim(raw, Dns::dkim(name), Pass, Some("example.test"), 1);
}

#[test]
fn simple_headers_reject_refolding() {
	let name = "ed25519-simple-relaxed-mixed";
	let raw = replace(&message(name), "\r\n\t folded  ", " folded  ");
	expect_dkim(raw, Dns::dkim(name), Fail, Some("example.test"), 1);
}
