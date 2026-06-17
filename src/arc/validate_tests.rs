//! End-to-end ARC chain validation tests.

use super::chain::ChainValidation;
use super::seal::SealParams;
use super::validate::validate;
use super::{ams, seal};
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
const AAR: &str = "i=1; example.org; spf=pass";
const MESSAGE: &[u8] =
	b"From: alice@example.org\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nHello ARC\r\n";

fn new_key() -> Ed25519KeyPair {
	let rng = ring::rand::SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
	Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse")
}

fn dns_for(key: &Ed25519KeyPair) -> MockDns {
	let record = format!(
		"v=DKIM1; k=ed25519; p={}",
		BASE64.encode(key.public_key().as_ref())
	);
	let mut txt = HashMap::new();
	txt.insert(format!("{SELECTOR}._domainkey.{DOMAIN}"), vec![record]);
	MockDns(txt)
}

fn value_of(line: &str) -> String {
	let after = line.split_once(':').expect("colon").1;
	after.strip_suffix("\r\n").unwrap_or(after).to_string()
}

/// Build a self-consistent single-instance ARC chain over MESSAGE and return
/// the full raw message with the three ARC headers prepended.
fn sealed_message(key: &Ed25519KeyPair, cv: ChainValidation) -> Vec<u8> {
	let ams_line = ams::build(key, 1, DOMAIN, SELECTOR, MESSAGE).expect("ams");
	let ams_value = value_of(&ams_line);
	let params = SealParams {
		instance: 1,
		domain: DOMAIN,
		selector: SELECTOR,
		chain_validation: cv,
	};
	let seal_line = seal::build(key, &params, &[], AAR, &ams_value);

	let mut out = format!("ARC-Authentication-Results: {AAR}\r\n").into_bytes();
	out.extend_from_slice(seal_line.as_bytes());
	out.extend_from_slice(ams_line.as_bytes());
	out.extend_from_slice(MESSAGE);
	out
}

#[tokio::test]
async fn no_arc_headers_is_none() {
	let dns = dns_for(&new_key());
	assert_eq!(validate(&dns, MESSAGE).await, ChainValidation::None);
}

#[tokio::test]
async fn intact_single_instance_chain_passes() {
	let key = new_key();
	let raw = sealed_message(&key, ChainValidation::None);
	let dns = dns_for(&key);
	assert_eq!(validate(&dns, &raw).await, ChainValidation::Pass);
}

#[tokio::test]
async fn tampered_body_fails() {
	let key = new_key();
	let raw = sealed_message(&key, ChainValidation::None);
	// Flip a byte in the body region.
	let mut tampered = raw.clone();
	let last = tampered.len() - 3;
	tampered[last] ^= 0x20;
	let dns = dns_for(&key);
	assert_eq!(validate(&dns, &tampered).await, ChainValidation::Fail);
}

#[tokio::test]
async fn wrong_cv_on_first_instance_fails() {
	let key = new_key();
	// First instance must record cv=none; pass here is inconsistent.
	let raw = sealed_message(&key, ChainValidation::Pass);
	let dns = dns_for(&key);
	assert_eq!(validate(&dns, &raw).await, ChainValidation::Fail);
}

#[tokio::test]
async fn unknown_signing_key_fails() {
	let key = new_key();
	let raw = sealed_message(&key, ChainValidation::None);
	// Resolver serves a different key than the one that signed.
	let dns = dns_for(&new_key());
	assert_eq!(validate(&dns, &raw).await, ChainValidation::Fail);
}
