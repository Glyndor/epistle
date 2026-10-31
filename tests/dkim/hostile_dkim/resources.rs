//! Bounded resource probes. The ten-signature cap is local policy, not an RFC MUST.

use super::harness::*;
use epistle::dkim::DkimOutcome::{Pass, PermError};

fn eleven() -> Vec<u8> {
	let raw = message("ed25519-relaxed-relaxed-mixed");
	let end = raw.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
	let mut out = raw[..end].repeat(11);
	out.extend_from_slice(&raw[end..]);
	out
}

#[test]
// RFC 6376 section 6.1 allows a verifier to limit signatures evaluated.
fn more_than_ten_signatures_is_rejected_before_dns() {
	expect_dkim(
		eleven(),
		Dns::dkim("ed25519-relaxed-relaxed-mixed"),
		PermError,
		None,
		0,
	);
}

#[test]
fn nine_thousand_headers_verify_within_wall_deadline() {
	let raw = message("headers-9000");
	let text = std::str::from_utf8(&raw)
		.unwrap()
		.split("\r\n\r\n")
		.next()
		.unwrap();
	assert_eq!(
		text.split("\r\n")
			.filter(|line| !line.starts_with([' ', '\t']))
			.count(),
		9000
	);
	expect_dkim(
		raw,
		Dns::dkim("headers-9000"),
		Pass,
		Some("example.test"),
		1,
	);
}
