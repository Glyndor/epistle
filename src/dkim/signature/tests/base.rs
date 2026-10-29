use super::*;

const SAMPLE: &str = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; \
s=sel; h=from:to:subject; bh=aGFzaA==; b=c2ln";

#[test]
fn parses_complete_signature() {
	let signature = parse(SAMPLE).expect("valid signature");
	assert_eq!(signature.algorithm, Algorithm::RsaSha256);
	assert_eq!(signature.domain, "example.org");
	assert_eq!(signature.selector, "sel");
	assert_eq!(signature.signed_headers, vec!["from", "to", "subject"]);
	assert_eq!(signature.body_hash, b"hash");
	assert_eq!(signature.signature, b"sig");
	assert_eq!(signature.header_canon, Canon::Relaxed);
	assert_eq!(signature.body_canon, Canon::Relaxed);
}

#[test]
fn defaults_to_simple_canonicalization() {
	let signature =
		parse("v=1; a=ed25519-sha256; d=example.org; s=sel; h=from; bh=aGFzaA==; b=c2ln")
			.expect("valid");
	assert_eq!(signature.algorithm, Algorithm::Ed25519Sha256);
	assert_eq!(signature.header_canon, Canon::Simple);
	assert_eq!(signature.body_canon, Canon::Simple);
}

#[test]
fn strips_folding_whitespace_in_values() {
	let folded = "v=1; a=rsa-sha256; d=example.org; s=sel; h=from : to; \
bh=aGF z aA==; b=c2 ln";
	let signature = parse(folded).expect("valid");
	assert_eq!(signature.body_hash, b"hash");
	assert_eq!(signature.signature, b"sig");
}

#[test]
fn rejects_missing_required_tags() {
	assert!(parse("v=1; a=rsa-sha256; d=example.org; s=sel; bh=aGFzaA==; b=c2ln").is_err());
	assert!(parse("v=1; a=rsa-sha256; s=sel; h=from; bh=aGFzaA==; b=c2ln").is_err());
	assert!(parse("a=rsa-sha256; d=e.org; s=sel; h=from; bh=aGFzaA==; b=c2ln").is_err());
}

#[test]
fn rejects_unsigned_from() {
	assert!(
		parse("v=1; a=rsa-sha256; d=example.org; s=sel; h=to:subject; bh=aGFzaA==; b=c2ln")
			.is_err()
	);
}

#[test]
fn rejects_unsupported_algorithm() {
	assert!(parse("v=1; a=rsa-sha1; d=example.org; s=sel; h=from; bh=aGFzaA==; b=c2ln").is_err());
}

#[test]
fn parses_length_and_expiration() {
	let signature = parse(
		"v=1; a=rsa-sha256; d=example.org; s=sel; h=from; bh=aGFzaA==; b=c2ln; l=100; x=12345",
	)
	.expect("valid");
	assert_eq!(signature.body_length, Some(100));
	assert_eq!(signature.expiration, Some(12345));
}

#[test]
fn rejects_remaining_missing_tags() {
	// Missing a=, s=, bh=, b= each individually.
	assert!(parse("v=1; d=example.org; s=sel; h=from; bh=aGFzaA==; b=c2ln").is_err());
	assert!(parse("v=1; a=rsa-sha256; d=example.org; h=from; bh=aGFzaA==; b=c2ln").is_err());
	assert!(parse("v=1; a=rsa-sha256; d=example.org; s=sel; h=from; b=c2ln").is_err());
	assert!(parse("v=1; a=rsa-sha256; d=example.org; s=sel; h=from; bh=aGFzaA==").is_err());
}

#[test]
fn rejects_malformed_tag_values() {
	// Invalid base64 in bh= and b=.
	assert!(parse("v=1; a=rsa-sha256; d=e.org; s=sel; h=from; bh=@@@; b=c2ln").is_err());
	assert!(parse("v=1; a=rsa-sha256; d=e.org; s=sel; h=from; bh=aGFzaA==; b=@@@").is_err());
	// Unknown canonicalization.
	assert!(
		parse("v=1; a=rsa-sha256; c=weird/relaxed; d=e.org; s=sel; h=from; bh=aGFzaA==; b=c2ln")
			.is_err()
	);
	// Non-numeric l= and x=.
	assert!(parse("v=1; a=rsa-sha256; d=e.org; s=sel; h=from; bh=aGFzaA==; b=c2ln; l=x").is_err());
	assert!(parse("v=1; a=rsa-sha256; d=e.org; s=sel; h=from; bh=aGFzaA==; b=c2ln; x=y").is_err());
}

#[test]
fn a_repeated_tag_makes_the_signature_invalid() {
	let error =
		parse(&format!("{SAMPLE}; i=@example.org; i=@sub.example.org")).expect_err("repeat");
	assert_eq!(error.0, "repeated tag \"i\"");
	let error = parse(&format!("{SAMPLE}; x-one=1; x-one=2")).expect_err("unknown repeat");
	assert_eq!(error.0, "repeated tag \"x-one\"");
}

#[test]
fn a_signature_with_a_hostile_number_of_tags_is_refused_early() {
	let tags: String = (0..10_000).map(|n| format!("x{n}=1; ")).collect();
	let error = parse(&format!("{SAMPLE}; {tags}")).expect_err("too many tags");
	assert_eq!(error.0, "too many tags");
}
