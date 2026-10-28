
use super::*;

#[test]
fn signature_matches_aws_published_vector() {
	// AWS SigV4 documentation, "Task 3: Calculate the signature", as
	// reproduced by the IAM service example. The constants (secret
	// access key, credential scope, string-to-sign) come straight from
	// the AWS docs so a working test proves this implementation matches
	// theirs, not just our own. A change to the HMAC chain would break
	// this and only this test.
	let string_to_sign = "AWS4-HMAC-SHA256\n\
20150830T123600Z\n\
20150830/us-east-1/iam/aws4_request\n\
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
	let key = signing_key(
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"20150830",
		"us-east-1",
		"iam",
	);
	assert_eq!(
		signature(&key, string_to_sign),
		"5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	);
}

#[test]
fn timestamps_format_utc_at_second_granularity() {
	assert_eq!(
		timestamps(0),
		("19700101T000000Z".to_string(), "19700101".to_string())
	);
	// 1_000_000_000 seconds = 2001-09-09 01:46:40 UTC.
	assert_eq!(
		timestamps(1_000_000_000),
		("20010909T014640Z".to_string(), "20010909".to_string())
	);
}

#[test]
fn sha256_hex_matches_a_known_digest() {
	// SHA-256("") == the documented empty-input digest.
	assert_eq!(
		sha256_hex(b""),
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	);
	// SHA-256("abc") is in every textbook.
	assert_eq!(
		sha256_hex(b"abc"),
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	);
}
