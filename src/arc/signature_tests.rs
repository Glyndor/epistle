//! Tests for ARC-Message-Signature and ARC-Seal parsing.

use super::chain::ChainValidation;
use super::signature::{parse_message_signature, parse_seal};
use crate::dkim::{Algorithm, Canon};

const AMS: &str = "i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=sel; \
h=from:to:subject; bh=aGFzaA==; b=c2ln; t=12345";

const SEAL: &str = "i=1; a=ed25519-sha256; d=example.org; s=sel; cv=none; b=c2ln";

#[test]
fn parses_complete_message_signature() {
	let ams = parse_message_signature(AMS).expect("valid AMS");
	assert_eq!(ams.instance, 1);
	assert_eq!(ams.algorithm, Algorithm::RsaSha256);
	assert_eq!(ams.domain, "example.org");
	assert_eq!(ams.selector, "sel");
	assert_eq!(ams.signed_headers, vec!["from", "to", "subject"]);
	assert_eq!(ams.body_hash, b"hash");
	assert_eq!(ams.signature, b"sig");
	assert_eq!(ams.header_canon, Canon::Relaxed);
	assert_eq!(ams.body_canon, Canon::Relaxed);
	assert_eq!(ams.timestamp, Some(12345));
}

#[test]
fn message_signature_defaults_to_simple_canon() {
	let ams =
		parse_message_signature("i=2; a=rsa-sha256; d=e.org; s=s; h=from; bh=aGFzaA==; b=c2ln")
			.expect("valid");
	assert_eq!(ams.header_canon, Canon::Simple);
	assert_eq!(ams.body_canon, Canon::Simple);
	assert_eq!(ams.timestamp, None);
}

#[test]
fn message_signature_must_cover_from() {
	assert!(
		parse_message_signature(
			"i=1; a=rsa-sha256; d=e.org; s=s; h=to:subject; bh=aGFzaA==; b=c2ln"
		)
		.is_err()
	);
}

#[test]
fn message_signature_must_not_cover_arc_headers() {
	assert!(
		parse_message_signature(
			"i=1; a=rsa-sha256; d=e.org; s=s; h=from:arc-seal; bh=aGFzaA==; b=c2ln"
		)
		.is_err()
	);
}

#[test]
fn message_signature_rejects_missing_tags() {
	// No bh=.
	assert!(parse_message_signature("i=1; a=rsa-sha256; d=e.org; s=s; h=from; b=c2ln").is_err());
	// No i=.
	assert!(
		parse_message_signature("a=rsa-sha256; d=e.org; s=s; h=from; bh=aGFzaA==; b=c2ln").is_err()
	);
}

#[test]
fn parses_complete_seal() {
	let seal = parse_seal(SEAL).expect("valid seal");
	assert_eq!(seal.instance, 1);
	assert_eq!(seal.algorithm, Algorithm::Ed25519Sha256);
	assert_eq!(seal.chain_validation, ChainValidation::None);
	assert_eq!(seal.signature, b"sig");
}

#[test]
fn seal_rejects_body_tags() {
	assert!(parse_seal("i=1; a=rsa-sha256; d=e.org; s=s; cv=pass; h=from; b=c2ln").is_err());
	assert!(parse_seal("i=1; a=rsa-sha256; d=e.org; s=s; cv=pass; bh=aGFzaA==; b=c2ln").is_err());
}

#[test]
fn seal_requires_valid_cv() {
	assert!(parse_seal("i=1; a=rsa-sha256; d=e.org; s=s; b=c2ln").is_err());
	assert!(parse_seal("i=1; a=rsa-sha256; d=e.org; s=s; cv=bogus; b=c2ln").is_err());
}

#[test]
fn instance_out_of_range_rejected() {
	assert!(parse_seal("i=0; a=rsa-sha256; d=e.org; s=s; cv=none; b=c2ln").is_err());
	assert!(parse_seal("i=51; a=rsa-sha256; d=e.org; s=s; cv=none; b=c2ln").is_err());
}

#[test]
fn unsupported_algorithm_rejected() {
	assert!(parse_seal("i=1; a=rsa-sha1; d=e.org; s=s; cv=none; b=c2ln").is_err());
}

#[test]
fn folding_whitespace_stripped_in_values() {
	let ams = parse_message_signature(
		"i=1; a=rsa-sha256; d=e.org; s=s; h=from : to; bh=aGF z aA==; b=c2 ln",
	)
	.expect("valid");
	assert_eq!(ams.body_hash, b"hash");
	assert_eq!(ams.signature, b"sig");
	assert_eq!(ams.signed_headers, vec!["from", "to"]);
}
