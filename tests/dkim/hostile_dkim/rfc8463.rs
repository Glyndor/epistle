//! RFC 8463 Appendix A, copied from the existing published-vector unit test.

use super::harness::*;
use epistle::dkim::DkimOutcome::{Fail, Pass};

fn dns() -> Dns {
	Dns::one(
		"brisbane._domainkey.football.example.com",
		&record("rfc8463"),
	)
}

#[test]
fn published_ed25519_signature_passes() {
	expect_dkim(
		message("rfc8463"),
		dns(),
		Pass,
		Some("football.example.com"),
		1,
	);
}

#[test]
fn published_signature_rejects_changed_subject() {
	let raw = replace(&message("rfc8463"), "Is dinner ready?", "Is dinner ready!");
	expect_dkim(raw, dns(), Fail, Some("football.example.com"), 1);
}

#[test]
fn published_signature_rejects_changed_body_before_dns() {
	let raw = replace(&message("rfc8463"), "We lost", "We LOST");
	expect_dkim(raw, dns(), Fail, Some("football.example.com"), 0);
}

#[test]
// RFC 8463 section 3 signs the SHA-256 digest with PureEdDSA Ed25519.
fn published_signature_binds_sha256_digest_and_not_raw_headers() {
	bounded(|| {
		use base64::Engine;
		let decode = |s: &str| {
			base64::engine::general_purpose::STANDARD
				.decode(s)
				.expect("base64")
		};
		let raw = text("rfc8463.eml");
		let value = raw
			.split(" b=")
			.nth(1)
			.expect("b=")
			.split("\r\nFrom:")
			.next()
			.unwrap();
		let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
		let signature = decode(&compact);
		let key = ring::signature::UnparsedPublicKey::new(
			&ring::signature::ED25519,
			decode("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="),
		);
		let input = bytes("rfc8463.input");
		assert!(
			key.verify(
				ring::digest::digest(&ring::digest::SHA256, &input).as_ref(),
				&signature
			)
			.is_ok()
		);
		assert!(key.verify(&input, &signature).is_err());
	});
}
