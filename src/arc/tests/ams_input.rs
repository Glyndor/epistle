//! What an ARC-Message-Signature is checked against: the headers it has to
//! cover, how much of the message it reads, and the key record it picks.

use super::ams::{DOMAIN, MESSAGE, MockDns, SELECTOR, dns_for, key, rsa_ams, value_of};
use super::key::{ed25519_record, rsa_key_pair, rsa_record};
use crate::arc::ams::{build, verify};
use crate::arc::signature::parse_message_signature;
use crate::dkim::DkimOutcome;
use std::collections::HashMap;

/// `MESSAGE` with one more header line in front of it.
fn with_header_on_top(line: &str) -> Vec<u8> {
	[line.as_bytes(), MESSAGE].concat()
}

#[tokio::test]
async fn an_extra_from_header_that_h_does_not_cover_is_refused() {
	let key = key();
	let value = value_of(&build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed"));
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_for(&key, false);
	let message = with_header_on_top("From: other@example.net\r\n");
	assert_eq!(
		verify(&dns, &ams, &value, &message).await,
		DkimOutcome::PermError
	);
}

#[tokio::test]
async fn an_unrelated_extra_header_does_not_stop_the_signature_verifying() {
	let key = key();
	let value = value_of(&build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed"));
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_for(&key, false);
	let message = with_header_on_top("X-Note: unrelated\r\n");
	assert_eq!(
		verify(&dns, &ams, &value, &message).await,
		DkimOutcome::Pass
	);
}

#[tokio::test]
async fn a_header_block_past_the_bound_is_not_read() {
	let key = key();
	let value = value_of(&build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed"));
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_for(&key, false);
	let filler = "X-Pad: 0123456789012345678901234567890123456789\r\n".repeat(50_000);
	assert!(filler.len() > 2 * 1024 * 1024);
	let message = with_header_on_top(&filler);
	assert_eq!(
		verify(&dns, &ams, &value, &message).await,
		DkimOutcome::PermError
	);
}

#[tokio::test]
async fn an_rsa_signature_verifies_when_an_ed25519_record_is_published_first() {
	let rsa = rsa_key_pair();
	let value = rsa_ams(&rsa);
	let ams = parse_message_signature(&value).expect("parse");
	let mut txt = HashMap::new();
	txt.insert(
		format!("{SELECTOR}._domainkey.{DOMAIN}"),
		vec![ed25519_record(&[7u8; 32]), rsa_record(&rsa)],
	);
	let dns = MockDns {
		txt,
		temp_fail: false,
	};
	assert_eq!(verify(&dns, &ams, &value, MESSAGE).await, DkimOutcome::Pass);
}
