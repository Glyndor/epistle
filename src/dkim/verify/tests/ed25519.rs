//! Ed25519 verification against the RFC 8463 Appendix A example.
//!
//! The bytes here come from the RFC, not from this project's signer: the
//! message, the DNS key record and the `b=` signature are the ones the RFC
//! prints. A signer and a verifier that agree on the wrong bytes pass each
//! other's tests and fail at every receiver, so the test that matters is one
//! that takes its input from somewhere else.
//!
//! The RFC's message carries two signatures; only the `ed25519-sha256` one is
//! kept here, because the RSA key of the example is 1024 bits and outside the
//! range this verifier accepts. Dropping it does not change the Ed25519 hash
//! input: the `h=` tag does not cover `DKIM-Signature`, so the other
//! signature's header is not part of what gets hashed.

use super::*;
use std::collections::HashMap;

use crate::dkim::signature::Algorithm;
use crate::dkim::test_support::KeyDns;

/// The RFC 8463 Appendix A example, with the `rsa-sha256` signature removed.
const RFC8463_MESSAGE: &str = concat!(
	"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n",
	" d=football.example.com; i=@football.example.com;\r\n",
	" q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n",
	" subject : date : message-id : from : subject : date;\r\n",
	" bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n",
	" b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r\n",
	" Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r\n",
	"From: Joe SixPack <joe@football.example.com>\r\n",
	"To: Suzie Q <suzie@shopping.example.net>\r\n",
	"Subject: Is dinner ready?\r\n",
	"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n",
	"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n",
	"\r\n",
	"Hi.\r\n",
	"\r\n",
	"We lost the game.  Are you hungry yet?\r\n",
	"\r\n",
	"Joe.\r\n",
	"\r\n",
);

/// The RFC 8463 Appendix A public key record for the `brisbane` selector.
const RFC8463_RECORD: &str = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

/// The bytes the example's signature covers: the headers its `h=` tag lists,
/// relaxed-canonicalized, then the `DKIM-Signature` header with `b=` emptied
/// (RFC 6376 section 3.7).
const RFC8463_HASH_INPUT: &str = concat!(
	"from:Joe SixPack <joe@football.example.com>\r\n",
	"to:Suzie Q <suzie@shopping.example.net>\r\n",
	"subject:Is dinner ready?\r\n",
	"date:Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n",
	"message-id:<20030712040037.46341.5F8J@football.example.com>\r\n",
	"dkim-signature:v=1; a=ed25519-sha256; c=relaxed/relaxed; ",
	"d=football.example.com; i=@football.example.com; q=dns/txt; ",
	"s=brisbane; t=1528637909; h=from : to : subject : date : message-id : ",
	"from : subject : date; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=",
);

/// The DNS the example's key is published in.
fn rfc8463_dns() -> KeyDns {
	let mut records = HashMap::new();
	records.insert(
		"brisbane._domainkey.football.example.com".to_string(),
		vec![RFC8463_RECORD.to_string()],
	);
	KeyDns(records)
}

#[tokio::test]
async fn verifies_the_rfc8463_appendix_a_example() {
	let results = verify_message(&rfc8463_dns(), RFC8463_MESSAGE.as_bytes()).await;
	assert_eq!(results.len(), 1, "{results:?}");
	assert_eq!(results[0].domain.as_deref(), Some("football.example.com"));
	assert_eq!(results[0].outcome, DkimOutcome::Pass, "{results:?}");
}

#[tokio::test]
async fn rejects_the_rfc8463_example_after_a_one_byte_change() {
	// One byte of a signed header changes: the body hash still matches, so
	// it is the signature that has to fail.
	let tampered = RFC8463_MESSAGE.replace("Is dinner ready?", "Is dinner ready!");
	assert_ne!(tampered, RFC8463_MESSAGE);
	let results = verify_message(&rfc8463_dns(), tampered.as_bytes()).await;
	assert_eq!(results.len(), 1, "{results:?}");
	assert_eq!(results[0].outcome, DkimOutcome::Fail, "{results:?}");
}

#[test]
fn the_signature_covers_the_sha256_of_the_header_data() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as BASE64;
	use ring::signature::UnparsedPublicKey;

	let public_key = BASE64
		.decode("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
		.expect("public key");
	let signature = BASE64
		.decode(concat!(
			"/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus",
			"Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==",
		))
		.expect("signature");
	let key = UnparsedPublicKey::new(&ring::signature::ED25519, public_key);

	// RFC 8463 section 3: the signature covers the SHA-256 digest of the
	// header data.
	let digest = Algorithm::Ed25519Sha256.signed_bytes(RFC8463_HASH_INPUT.as_bytes());
	assert!(key.verify(digest.as_ref(), &signature).is_ok());

	// The header data itself is not what it covers.
	assert!(
		key.verify(RFC8463_HASH_INPUT.as_bytes(), &signature)
			.is_err()
	);
}

/// Sign a message with a fresh key, returning the signed message and the DNS
/// that publishes its key.
fn signed_message() -> (Vec<u8>, KeyDns) {
	use std::io::Write;

	let (pem, record) = crate::dkim::generate_key().expect("generate key");
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(pem.as_bytes()).expect("write key");
	let signer = crate::dkim::Signer::load("sel", file.path()).expect("load key");

	let raw =
		b"From: alice@example.org\r\nSubject: hi\r\nTo: bob@elsewhere.example\r\n\r\nHello\r\n";
	let mut signed = signer.sign("example.org", raw).expect("signs").into_bytes();
	signed.extend_from_slice(raw);

	let mut records = HashMap::new();
	records.insert("sel._domainkey.example.org".to_string(), vec![record]);
	(signed, KeyDns(records))
}

#[tokio::test]
async fn a_signed_message_verifies_and_a_changed_byte_does_not() {
	let (signed, dns) = signed_message();

	let results = verify_message(&dns, &signed).await;
	assert_eq!(results.len(), 1, "{results:?}");
	assert_eq!(results[0].outcome, DkimOutcome::Pass, "{results:?}");

	// One byte of a signed header changes.
	let tampered = String::from_utf8(signed.clone())
		.expect("UTF-8 message")
		.replace("Subject: hi", "Subject: ho");
	assert_ne!(tampered.as_bytes(), signed.as_slice());
	let results = verify_message(&dns, tampered.as_bytes()).await;
	assert_eq!(results.len(), 1, "{results:?}");
	assert_eq!(results[0].outcome, DkimOutcome::Fail, "{results:?}");
}
