//! Sign/verify roundtrip tests for ARC-Message-Signature.

use super::ams::{build, verify};
use super::signature::parse_message_signature;
use crate::dkim::DkimOutcome;
use crate::spf::{DnsFailure, DnsLookup};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{Ed25519KeyPair, KeyPair};
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
