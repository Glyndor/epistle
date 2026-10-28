//! The budgets a signature has to live inside: the number of names its
//! `h=` tag lists and the work that list may ask for.

use super::*;
use std::time::{Duration, Instant};

use crate::dkim::signature::{Algorithm, Canon, MAX_SIGNED_HEADER_NAMES};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

use super::base::{dns_with_key, empty_dns};

/// The value of an `h=` tag that names `count` headers the message does
/// not carry, after the one every signature must cover.
fn listed_names(count: usize) -> String {
	let mut names = String::from("from");
	for _ in 0..count {
		names.push_str(":z");
	}
	names
}

/// Fold a long tag value into continuation lines of legal length.
fn folded(value: &str) -> String {
	let mut out = String::with_capacity(value.len() + value.len() / 900 + 4);
	let mut line = String::new();
	for byte in value.bytes() {
		line.push(byte as char);
		if line.len() == 900 {
			out.push_str(&line);
			out.push_str("\r\n ");
			line.clear();
		}
	}
	out.push_str(&line);
	out
}

/// Nine thousand short headers and one signature whose `h=` tag names half
/// a million of them. The body hash is the right one, so nothing but the
/// budget keeps the signature from being walked.
fn hostile_message() -> Vec<u8> {
	let body = b"body\r\n";
	let body_hash = BASE64.encode(ring::digest::digest(
		&ring::digest::SHA256,
		&canon::body(Canon::Relaxed, body),
	));
	let mut raw = b"From: alice@example.org\r\n".to_vec();
	raw.extend(std::iter::repeat_n(b"X:0\r\n".as_slice(), 9_000).flatten());
	raw.extend(
		b"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=sel; h="
			.as_slice(),
	);
	raw.extend(folded(&listed_names(500_000)).as_bytes());
	raw.extend(format!("; bh={body_hash}; b=AAAA\r\n\r\n").as_bytes());
	raw.extend_from_slice(body);
	raw
}

#[tokio::test]
async fn a_signature_that_names_half_a_million_headers_is_refused_at_once() {
	let raw = hostile_message();
	assert!(
		raw.len() < MAX_HEADER_BYTES,
		"the hostile message must stay inside the header budget"
	);
	let started = Instant::now();
	let results = verify_message(&empty_dns(), &raw).await;
	let elapsed = started.elapsed();
	assert_eq!(results.len(), 1, "{results:?}");
	assert_eq!(results[0].outcome, DkimOutcome::PermError, "{results:?}");
	assert!(
		elapsed < Duration::from_secs(2),
		"reading the signature took {elapsed:?}: the names are walked one by one \
		 over every header instead of being read from an index"
	);
}

#[test]
fn a_name_count_past_the_budget_is_refused_while_the_tag_is_read() {
	let inside = format!(
		"v=1; a=ed25519-sha256; d=example.org; s=sel; h={}; bh=aGFzaA==; b=c2ln",
		listed_names(MAX_SIGNED_HEADER_NAMES - 1)
	);
	let parsed = crate::dkim::signature::parse(&inside).expect("a list inside the budget");
	assert_eq!(parsed.signed_headers.len(), MAX_SIGNED_HEADER_NAMES);

	let past = format!(
		"v=1; a=ed25519-sha256; d=example.org; s=sel; h={}; bh=aGFzaA==; b=c2ln",
		listed_names(MAX_SIGNED_HEADER_NAMES)
	);
	assert!(
		crate::dkim::signature::parse(&past).is_err(),
		"a list past the budget must be refused"
	);
}

#[tokio::test]
async fn a_repeated_name_is_signed_from_the_bottom_up() {
	let rng = SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
	let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load key");

	let body = b"Hello world\r\n";
	let body_hash = BASE64.encode(ring::digest::digest(
		&ring::digest::SHA256,
		&canon::body(Canon::Relaxed, body),
	));
	let dkim_value = format!(
		" v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=sel; h=from:from; \
		 bh={body_hash}; b="
	);

	// RFC 6376 section 5.4.1: a name listed twice signs the headers of that
	// name from the bottom up, the last one first.
	let mut hash_input = String::new();
	hash_input.push_str(&canon::header(
		Canon::Relaxed,
		"From",
		" second@example.org",
	));
	hash_input.push_str(&canon::header(Canon::Relaxed, "From", " first@example.org"));
	let mut dkim_line = canon::header(Canon::Relaxed, "DKIM-Signature", &dkim_value);
	dkim_line.truncate(dkim_line.len() - 2);
	hash_input.push_str(&dkim_line);

	let signed = Algorithm::Ed25519Sha256.signed_bytes(hash_input.as_bytes());
	let signature = BASE64.encode(key_pair.sign(signed.as_ref()).as_ref());
	let message = format!(
		"From: first@example.org\r\nSubject: hi\r\nFrom: second@example.org\r\n\
		 DKIM-Signature:{dkim_value}{signature}\r\n\r\nHello world\r\n"
	);

	let dns = dns_with_key(&key_pair);
	let results = verify_message(&dns, message.as_bytes()).await;
	assert_eq!(results.len(), 1, "{results:?}");
	assert_eq!(results[0].outcome, DkimOutcome::Pass, "{results:?}");
}

#[test]
fn the_index_holds_every_header_under_its_name() {
	let raw = b"From: first@example.org\r\nSubject: hi\r\nFrom: second@example.org\r\n\r\nbody\r\n";
	let message = Message::split(raw).expect("message");
	let index = HeaderIndex::build(&message);
	assert_eq!(index.positions.get("from"), Some(&vec![0, 2]));
	assert_eq!(index.positions.get("subject"), Some(&vec![1]));
	assert!(!index.positions.contains_key("absent"));
}
