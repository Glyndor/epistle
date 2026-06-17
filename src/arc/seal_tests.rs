//! Sign/verify roundtrip tests for ARC-Seal.

use super::chain::{ChainValidation, Instance};
use super::seal::{SealParams, build, verify};
use super::signature::parse_seal;
use crate::dkim::DkimOutcome;
use crate::spf::{DnsFailure, DnsLookup};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

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

const AAR: &str = "i=1; example.org; spf=pass";
const AMS: &str = "i=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=arc1; \
h=from; bh=aGFzaA==; b=AAAA==";

fn params(instance: u32, cv: ChainValidation) -> SealParams<'static> {
	SealParams {
		instance,
		domain: DOMAIN,
		selector: SELECTOR,
		chain_validation: cv,
	}
}

/// Header value (after the colon, no trailing CRLF) of a built ARC-Seal line.
fn value_of(line: &str) -> String {
	let after = line.split_once(':').expect("colon").1;
	after.strip_suffix("\r\n").unwrap_or(after).to_string()
}

#[tokio::test]
async fn first_instance_seal_roundtrips() {
	let key = key();
	let line = build(&key, &params(1, ChainValidation::None), &[], AAR, AMS);
	let value = value_of(&line);
	let seal = parse_seal(&value).expect("parse");
	let chain = vec![Instance {
		instance: 1,
		auth_results: AAR.to_string(),
		message_signature: AMS.to_string(),
		seal: value.clone(),
	}];
	let dns = dns_for(&key, false);
	assert_eq!(verify(&dns, &seal, &value, &chain).await, DkimOutcome::Pass);
}

#[tokio::test]
async fn second_instance_seals_prior_chain() {
	let key = key();
	// Instance 1 seal.
	let seal1_line = build(&key, &params(1, ChainValidation::None), &[], AAR, AMS);
	let seal1 = value_of(&seal1_line);
	let inst1 = Instance {
		instance: 1,
		auth_results: AAR.to_string(),
		message_signature: AMS.to_string(),
		seal: seal1,
	};
	// Instance 2 seals over instance 1 plus its own AAR/AMS.
	let aar2 = "i=2; relay.example; arc=pass";
	let ams2 = "i=2; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=arc1; h=from; \
bh=aGFzaA==; b=BBBB==";
	let seal2_line = build(
		&key,
		&params(2, ChainValidation::Pass),
		std::slice::from_ref(&inst1),
		aar2,
		ams2,
	);
	let seal2 = value_of(&seal2_line);
	let parsed = parse_seal(&seal2).expect("parse");
	let chain = vec![
		inst1,
		Instance {
			instance: 2,
			auth_results: aar2.to_string(),
			message_signature: ams2.to_string(),
			seal: seal2.clone(),
		},
	];
	let dns = dns_for(&key, false);
	assert_eq!(
		verify(&dns, &parsed, &seal2, &chain).await,
		DkimOutcome::Pass
	);
}

#[tokio::test]
async fn tampered_auth_results_breaks_seal() {
	let key = key();
	let line = build(&key, &params(1, ChainValidation::None), &[], AAR, AMS);
	let value = value_of(&line);
	let seal = parse_seal(&value).expect("parse");
	// The verifier sees a different AAR than was sealed.
	let chain = vec![Instance {
		instance: 1,
		auth_results: "i=1; evil.example; spf=fail".to_string(),
		message_signature: AMS.to_string(),
		seal: value.clone(),
	}];
	let dns = dns_for(&key, false);
	assert_eq!(verify(&dns, &seal, &value, &chain).await, DkimOutcome::Fail);
}

#[tokio::test]
async fn missing_key_is_permerror() {
	let key = key();
	let line = build(&key, &params(1, ChainValidation::None), &[], AAR, AMS);
	let value = value_of(&line);
	let seal = parse_seal(&value).expect("parse");
	let chain = vec![Instance {
		instance: 1,
		auth_results: AAR.to_string(),
		message_signature: AMS.to_string(),
		seal: value.clone(),
	}];
	let empty = MockDns {
		txt: HashMap::new(),
		temp_fail: false,
	};
	assert_eq!(
		verify(&empty, &seal, &value, &chain).await,
		DkimOutcome::PermError
	);
}

#[tokio::test]
async fn dns_temp_failure_is_temperror() {
	let key = key();
	let line = build(&key, &params(1, ChainValidation::None), &[], AAR, AMS);
	let value = value_of(&line);
	let seal = parse_seal(&value).expect("parse");
	let chain = vec![Instance {
		instance: 1,
		auth_results: AAR.to_string(),
		message_signature: AMS.to_string(),
		seal: value.clone(),
	}];
	let dns = dns_for(&key, true);
	assert_eq!(
		verify(&dns, &seal, &value, &chain).await,
		DkimOutcome::TempError
	);
}
