//! Tests for ArcSealer: seal a message, then re-validate the chain.

use super::chain::{ChainValidation, extract};
use super::sealer::ArcSealer;
use super::validate::validate;
use crate::spf::{DnsFailure, DnsLookup};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

struct MockDns(HashMap<String, Vec<String>>);

impl DnsLookup for MockDns {
	fn txt(&self, name: &str) -> Fut<'_, Vec<String>> {
		let result = Ok(self.0.get(name).cloned().unwrap_or_default());
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
const MESSAGE: &[u8] =
	b"From: alice@example.org\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nHello ARC\r\n";

/// Generate a key, returning the keypair and a resolver serving its public
/// half — both derived from one pkcs8 so signing and verification agree.
fn key_and_dns() -> (Ed25519KeyPair, MockDns) {
	let rng = ring::rand::SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
	let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
	let record = format!(
		"v=DKIM1; k=ed25519; p={}",
		BASE64.encode(key.public_key().as_ref())
	);
	let mut txt = HashMap::new();
	txt.insert(format!("{SELECTOR}._domainkey.{DOMAIN}"), vec![record]);
	(key, MockDns(txt))
}

fn prepend(headers: &str, message: &[u8]) -> Vec<u8> {
	let mut out = headers.as_bytes().to_vec();
	out.extend_from_slice(message);
	out
}

#[tokio::test]
async fn sealing_a_fresh_message_yields_a_valid_chain() {
	let (key, dns) = key_and_dns();
	let sealer = ArcSealer::new(key, DOMAIN, SELECTOR);
	let headers = sealer
		.seal(MESSAGE, "spf=pass; dkim=pass", &[], ChainValidation::None)
		.expect("sealed");
	let sealed = prepend(&headers, MESSAGE);

	let chain = extract(&sealed).expect("structural").expect("present");
	assert_eq!(chain.len(), 1);
	assert_eq!(chain[0].instance, 1);

	assert_eq!(validate(&dns, &sealed).await, ChainValidation::Pass);
}

#[tokio::test]
async fn second_hop_seals_over_the_first() {
	let (key, dns) = key_and_dns();
	let sealer = ArcSealer::new(key, DOMAIN, SELECTOR);

	// First hop seals a fresh message.
	let first = sealer
		.seal(MESSAGE, "spf=pass", &[], ChainValidation::None)
		.expect("first");
	let after_first = prepend(&first, MESSAGE);

	// Second hop: the prior chain validated, so cv=pass at i=2.
	let prior = extract(&after_first).expect("structural").expect("present");
	let second = sealer
		.seal(MESSAGE, "spf=pass", &prior, ChainValidation::Pass)
		.expect("second");
	let after_second = prepend(&second, &after_first);

	let chain = extract(&after_second)
		.expect("structural")
		.expect("present");
	assert_eq!(chain.len(), 2);

	assert_eq!(validate(&dns, &after_second).await, ChainValidation::Pass);
}

#[test]
fn message_without_from_cannot_be_sealed() {
	let (key, _dns) = key_and_dns();
	let sealer = ArcSealer::new(key, DOMAIN, SELECTOR);
	let no_from = b"To: bob@example.net\r\n\r\nbody\r\n";
	assert!(
		sealer
			.seal(no_from, "spf=none", &[], ChainValidation::None)
			.is_none()
	);
}
