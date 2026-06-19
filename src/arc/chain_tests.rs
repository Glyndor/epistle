//! Tests for ARC chain extraction and structural validation.

use super::chain::{ChainError, ChainValidation, MAX_INSTANCE, chain_status, extract, tag};

/// Build a raw message with the given ARC header lines followed by a body.
fn message(headers: &[&str]) -> Vec<u8> {
	let mut raw = String::from("From: a@example.org\r\n");
	for header in headers {
		raw.push_str(header);
		raw.push_str("\r\n");
	}
	raw.push_str("\r\nbody\r\n");
	raw.into_bytes()
}

fn instance(i: u32) -> [String; 3] {
	[
		format!("ARC-Authentication-Results: i={i}; example.org; spf=pass"),
		format!("ARC-Message-Signature: i={i}; a=rsa-sha256; d=example.org; s=s; b=AAAA=="),
		format!("ARC-Seal: i={i}; a=rsa-sha256; d=example.org; s=s; cv=none; b=BBBB=="),
	]
}

#[test]
fn no_arc_headers_is_empty_chain() {
	let raw = message(&[]);
	assert_eq!(extract(&raw), Ok(None));
}

#[test]
fn single_well_formed_instance() {
	let headers = instance(1);
	let raw = message(&[&headers[0], &headers[1], &headers[2]]);
	let chain = extract(&raw).expect("valid").expect("present");
	assert_eq!(chain.len(), 1);
	assert_eq!(chain[0].instance, 1);
	assert_eq!(chain_status(&chain), Some(ChainValidation::None));
}

#[test]
fn two_contiguous_instances_order_by_number() {
	let one = instance(1);
	let two = instance(2);
	// Deliberately interleave the order they appear in the message.
	let raw = message(&[&two[2], &one[0], &two[0], &one[1], &one[2], &two[1]]);
	let chain = extract(&raw).expect("valid").expect("present");
	assert_eq!(chain.len(), 2);
	assert_eq!(chain[0].instance, 1);
	assert_eq!(chain[1].instance, 2);
}

#[test]
fn missing_header_is_incomplete() {
	let headers = instance(1);
	// Drop the ARC-Seal.
	let raw = message(&[&headers[0], &headers[1]]);
	assert_eq!(extract(&raw), Err(ChainError::Incomplete));
}

#[test]
fn gap_in_instances_is_non_contiguous() {
	let one = instance(1);
	let three = instance(3);
	let raw = message(&[&one[0], &one[1], &one[2], &three[0], &three[1], &three[2]]);
	assert_eq!(extract(&raw), Err(ChainError::NonContiguous));
}

#[test]
fn duplicate_header_in_one_instance_rejected() {
	let one = instance(1);
	let raw = message(&[&one[0], &one[0], &one[1], &one[2]]);
	assert_eq!(extract(&raw), Err(ChainError::Duplicate));
}

#[test]
fn instance_over_cap_rejected() {
	let over = MAX_INSTANCE + 1;
	let headers = instance(over);
	let raw = message(&[&headers[0], &headers[1], &headers[2]]);
	assert_eq!(extract(&raw), Err(ChainError::BadInstance));
}

#[test]
fn header_without_instance_is_malformed() {
	let raw = message(&["ARC-Seal: a=rsa-sha256; cv=none; b=BBBB=="]);
	assert_eq!(extract(&raw), Err(ChainError::Malformed));
}

#[test]
fn tag_reads_first_equals_and_preserves_base64_padding() {
	let header = "i=1; a=rsa-sha256; b=AAAABBBB==; cv=pass";
	assert_eq!(tag(header, "i"), Some("1"));
	assert_eq!(tag(header, "b"), Some("AAAABBBB=="));
	assert_eq!(tag(header, "cv"), Some("pass"));
	assert_eq!(tag(header, "missing"), None);
}

#[test]
fn chain_validation_parses_and_renders() {
	assert_eq!(ChainValidation::parse("PASS"), Some(ChainValidation::Pass));
	assert_eq!(ChainValidation::parse("fail"), Some(ChainValidation::Fail));
	assert_eq!(ChainValidation::parse("bogus"), None);
	assert_eq!(ChainValidation::Pass.as_str(), "pass");
}

#[test]
fn folded_header_value_is_unfolded() {
	let raw = message(&[
		"ARC-Authentication-Results: i=1; example.org;\r\n spf=pass",
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.org; s=s; b=AAAA==",
		"ARC-Seal: i=1; a=rsa-sha256; d=example.org; s=s; cv=none; b=BBBB==",
	]);
	let chain = extract(&raw).expect("valid").expect("present");
	assert!(chain[0].auth_results.contains("spf=pass"));
}
