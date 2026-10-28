//! The signer signs the From field the sender was authorised for, so it
//! refuses a message that carries more than one: with two, it would sign
//! one (the last) while a reader or a check could look at the other.

use super::*;

fn signer() -> Signer {
	let (pem, _record) = generate_key().expect("generate");
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("key.pem");
	std::fs::write(&path, pem).expect("write key");
	Signer::load("sel", &path).expect("load key")
}

#[test]
fn a_message_with_two_from_fields_is_not_signed() {
	let signer = signer();
	for (case, raw) in [
		&b"From: alice@example.org\r\nFrom: bob@example.org\r\nSubject: hi\r\n\r\nbody\r\n"[..],
		b"From: alice@example.org\r\nSubject: hi\r\nfrom : bob@example.org\r\n\r\nbody\r\n",
	]
	.into_iter()
	.enumerate()
	{
		assert_eq!(signer.sign("example.org", raw), None, "case {case}");
	}
}

#[test]
fn a_message_with_one_from_field_is_signed() {
	let raw = b"From: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n";
	let header = signer().sign("example.org", raw).expect("signs");
	let signature = super::super::super::signature::parse(
		header.strip_prefix("DKIM-Signature:").expect("header"),
	)
	.expect("parse signature");
	for name in ["from", "subject"] {
		assert_eq!(
			signature
				.signed_headers
				.iter()
				.filter(|field| *field == name)
				.count(),
			2
		);
	}
}
