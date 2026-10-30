//! Sign/verify roundtrip tests for ARC-Message-Signature.

use super::super::ams::{build, verify};
use super::super::signature::parse_message_signature;
use super::key::{ed25519_record, rsa_key_pair, rsa_record};
use crate::dkim::signature::Algorithm;
use crate::dkim::{Canon, DkimOutcome, canon};
use crate::spf::{DnsFailure, DnsLookup};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

/// A pinned, boxed future as the `DnsLookup` trait returns.
type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// A DNS mock that serves a fixed TXT map and can simulate a temp failure.
struct MockDns {
	txt: HashMap<String, Vec<String>>,
	temp_fail: bool,
}

impl DnsLookup for MockDns {
	fn txt(&self, name: &str) -> Fut<'_, Vec<String>> {
		let result = if self.temp_fail {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.txt.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}
	fn addresses(&self, _name: &str) -> Fut<'_, Vec<IpAddr>> {
		Box::pin(async move { Ok(Vec::new()) })
	}
	fn mx(&self, _name: &str) -> Fut<'_, Vec<String>> {
		Box::pin(async move { Ok(Vec::new()) })
	}
}

const DOMAIN: &str = "example.org";
const SELECTOR: &str = "arc1";

fn key() -> Ed25519KeyPair {
	let rng = ring::rand::SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
	Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse")
}

fn dns_for(key: &Ed25519KeyPair, temp_fail: bool) -> MockDns {
	let record = format!(
		"v=DKIM1; k=ed25519; p={}",
		BASE64.encode(key.public_key().as_ref())
	);
	dns_with(record, temp_fail)
}

/// A resolver that serves one key record for the selector of the tests.
fn dns_with(record: String, temp_fail: bool) -> MockDns {
	let mut txt = HashMap::new();
	txt.insert(format!("{SELECTOR}._domainkey.{DOMAIN}"), vec![record]);
	MockDns { txt, temp_fail }
}

const MESSAGE: &[u8] =
	b"From: alice@example.org\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nHello ARC\r\n";

/// Extract the header value (after the colon, no trailing CRLF) from a built
/// ARC-Message-Signature line.
fn value_of(line: &str) -> String {
	let after = line.split_once(':').expect("colon").1;
	after.strip_suffix("\r\n").unwrap_or(after).to_string()
}

/// The bytes an AMS covers: the headers its `h=` tag lists, relaxed
/// canonicalized, then the `ARC-Message-Signature` header with `b=` emptied
/// and no trailing CRLF (RFC 6376 section 3.7).
fn ams_input(ams_value: &str) -> String {
	let mut input = String::new();
	input.push_str(&canon::header(Canon::Relaxed, "From", " alice@example.org"));
	input.push_str(&canon::header(Canon::Relaxed, "To", " bob@example.net"));
	input.push_str(&canon::header(Canon::Relaxed, "Subject", " hi"));
	input.push_str(
		canon::header(
			Canon::Relaxed,
			"ARC-Message-Signature",
			&without_signature(ams_value),
		)
		.strip_suffix("\r\n")
		.expect("canonical CRLF"),
	);
	input
}

/// The header value with the `b=` tag emptied, the way the verifier strips
/// it before hashing.
fn without_signature(value: &str) -> String {
	value
		.split(';')
		.map(|tag| {
			let trimmed = tag.trim_start();
			if trimmed.starts_with("b=") {
				let prefix = tag.len() - trimmed.len();
				format!("{}b=", &tag[..prefix])
			} else {
				tag.to_string()
			}
		})
		.collect::<Vec<_>>()
		.join(";")
}

/// The `bh=` tag of the test message: the SHA-256 of its relaxed body.
fn body_hash() -> String {
	let text = std::str::from_utf8(MESSAGE).expect("utf8 message");
	let (_, body) = text.split_once("\r\n\r\n").expect("message sections");
	let canonical = canon::body(Canon::Relaxed, body.as_bytes());
	BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &canonical))
}

/// An ARC-Message-Signature that declares `a=rsa-sha256` and carries an RSA
/// signature over the signed headers themselves, which is what an RSA
/// signature covers: the hash goes inside the PKCS#1 padding.
fn rsa_ams(key: &RsaKeyPair) -> String {
	let value = format!(
		" i=1; a=rsa-sha256; c=relaxed/relaxed; d={DOMAIN}; s={SELECTOR}; h=from:to:subject; bh={}; b=",
		body_hash()
	);
	let input = ams_input(&value);
	let mut signature = vec![0u8; key.public().modulus_len()];
	key.sign(
		&RSA_PKCS1_SHA256,
		&ring::rand::SystemRandom::new(),
		input.as_bytes(),
		&mut signature,
	)
	.expect("sign");
	format!("{value}{}", BASE64.encode(&signature))
}

/// An ARC-Message-Signature that declares `a=rsa-sha256` and carries an
/// Ed25519 signature over the raw signed data, which is the bytes an RSA
/// signature covers. The record publishes the Ed25519 key.
fn ed25519_signature_over_raw_bytes_labelled_as_rsa(key: &Ed25519KeyPair) -> String {
	let value = format!(
		" i=1; a=rsa-sha256; c=relaxed/relaxed; d={DOMAIN}; s={SELECTOR}; h=from:to:subject; bh={}; b=",
		body_hash()
	);
	let input = ams_input(&value);
	let signature = key.sign(input.as_bytes());
	format!("{value}{}", BASE64.encode(signature.as_ref()))
}

#[test]
fn the_ams_signature_covers_the_sha256_of_the_signed_headers() {
	let key = key();
	let line = build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed");
	let value = value_of(&line);

	// RFC 8463 section 3: an Ed25519-SHA256 signature covers the SHA-256
	// digest of the signed data, not the data itself.
	let input = ams_input(&value);
	let expected = key.sign(&Algorithm::Ed25519Sha256.signed_bytes(input.as_bytes()));
	assert_eq!(
		parse_message_signature(&value).expect("parse").signature,
		expected.as_ref()
	);
}

#[tokio::test]
async fn sign_then_verify_passes() {
	let key = key();
	let line = build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed");
	let value = value_of(&line);
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_for(&key, false);
	assert_eq!(verify(&dns, &ams, &value, MESSAGE).await, DkimOutcome::Pass);
}

#[tokio::test]
async fn tampered_body_fails_body_hash() {
	let key = key();
	let line = build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed");
	let value = value_of(&line);
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_for(&key, false);
	let tampered =
		b"From: alice@example.org\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nTAMPERED\r\n";
	assert_eq!(
		verify(&dns, &ams, &value, tampered).await,
		DkimOutcome::Fail
	);
}

#[tokio::test]
async fn tampered_header_fails_signature() {
	let key = key();
	let line = build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed");
	let value = value_of(&line);
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_for(&key, false);
	// Same body (bh passes) but a changed signed header → signature fails.
	let tampered =
		b"From: mallory@example.org\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nHello ARC\r\n";
	assert_eq!(
		verify(&dns, &ams, &value, tampered).await,
		DkimOutcome::Fail
	);
}

#[tokio::test]
async fn missing_key_record_is_permerror() {
	let key = key();
	let line = build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed");
	let value = value_of(&line);
	let ams = parse_message_signature(&value).expect("parse");
	let empty = MockDns {
		txt: HashMap::new(),
		temp_fail: false,
	};
	assert_eq!(
		verify(&empty, &ams, &value, MESSAGE).await,
		DkimOutcome::PermError
	);
}

#[tokio::test]
async fn dns_temp_failure_is_temperror() {
	let key = key();
	let line = build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed");
	let value = value_of(&line);
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_for(&key, true);
	assert_eq!(
		verify(&dns, &ams, &value, MESSAGE).await,
		DkimOutcome::TempError
	);
}

#[test]
fn build_without_from_returns_none() {
	let key = key();
	let no_from = b"To: bob@example.net\r\nSubject: hi\r\n\r\nbody\r\n";
	assert!(build(&key, 1, DOMAIN, SELECTOR, no_from).is_none());
}

#[tokio::test]
async fn an_rsa_signature_verifies_with_the_key_the_record_publishes() {
	let key = rsa_key_pair();
	let value = rsa_ams(&key);
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_with(rsa_record(&key), false);
	assert_eq!(verify(&dns, &ams, &value, MESSAGE).await, DkimOutcome::Pass);
}

#[tokio::test]
async fn an_rsa_signature_is_refused_when_the_record_publishes_an_ed25519_key() {
	let key = rsa_key_pair();
	let value = rsa_ams(&key);
	let ams = parse_message_signature(&value).expect("parse");
	// The record publishes an Ed25519 key for a header that says RSA.
	let dns = dns_with(ed25519_record(&[3u8; 32]), false);
	assert_eq!(
		verify(&dns, &ams, &value, MESSAGE).await,
		DkimOutcome::PermError
	);
}

#[tokio::test]
async fn an_ed25519_signature_is_refused_when_the_record_publishes_an_rsa_key() {
	let key = key();
	let line = build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed");
	let value = value_of(&line);
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_with(rsa_record(&rsa_key_pair()), false);
	assert_eq!(
		verify(&dns, &ams, &value, MESSAGE).await,
		DkimOutcome::PermError
	);
}

#[tokio::test]
async fn a_record_that_claims_an_rsa_key_and_publishes_an_ed25519_one_is_refused() {
	let key = rsa_key_pair();
	let value = rsa_ams(&key);
	let ams = parse_message_signature(&value).expect("parse");
	// The record says k=rsa, but what it publishes is not an RSA key.
	let dns = dns_with(
		format!("v=DKIM1; k=rsa; p={}", BASE64.encode([5u8; 32])),
		false,
	);
	assert_eq!(
		verify(&dns, &ams, &value, MESSAGE).await,
		DkimOutcome::PermError
	);
}

#[tokio::test]
async fn an_ed25519_signature_over_the_raw_data_is_refused_when_the_header_says_rsa() {
	// The header claims RSA, and the signature is an Ed25519 one over the
	// raw signed data, which is the bytes an RSA signature covers. The
	// record publishes the Ed25519 key that made it.
	let key = key();
	let value = ed25519_signature_over_raw_bytes_labelled_as_rsa(&key);
	let ams = parse_message_signature(&value).expect("parse");
	let dns = dns_for(&key, false);
	assert_eq!(
		verify(&dns, &ams, &value, MESSAGE).await,
		DkimOutcome::PermError
	);
}

#[tokio::test]
async fn an_ed25519_signature_is_refused_when_the_record_declares_an_rsa_key() {
	let key = key();
	let line = build(&key, 1, DOMAIN, SELECTOR, MESSAGE).expect("signed");
	let value = value_of(&line);
	let ams = parse_message_signature(&value).expect("parse");
	// The record declares an RSA key, and publishes the Ed25519 one.
	let record = format!(
		"v=DKIM1; k=rsa; p={}",
		BASE64.encode(key.public_key().as_ref())
	);
	let dns = dns_with(record, false);
	assert_eq!(
		verify(&dns, &ams, &value, MESSAGE).await,
		DkimOutcome::PermError
	);
}

#[allow(unused_imports)]
use super::super::ams;
