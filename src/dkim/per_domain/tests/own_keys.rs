//! Domains that each have a key of their own: a message verifies against its
//! own domain's record and against no other domain's.

use std::collections::HashMap;

use super::base::fresh_signer;
use super::*;
use crate::dkim::test_support::KeyDns;
use crate::dkim::{DkimOutcome, verify_message};

/// Three domains, each with a key and the record that key is published as at
/// `<selector>._domainkey.<domain>`.
fn domains() -> (PerDomainSigner, HashMap<String, Vec<String>>) {
	let mut overrides = Vec::new();
	let mut records = HashMap::new();
	for domain in ["b.example", "c.example"] {
		let signer = fresh_signer("own1");
		records.insert(
			format!("own1._domainkey.{domain}"),
			vec![signer.dns_record_value()],
		);
		overrides.push(DomainSigner {
			domain: domain.to_string(),
			signer,
		});
	}
	let default = fresh_signer("s1");
	records.insert(
		"s1._domainkey.a.example".into(),
		vec![default.dns_record_value()],
	);
	(
		PerDomainSigner::new(ReloadableSigner::new(default), overrides),
		records,
	)
}

fn message(domain: &str) -> Vec<u8> {
	format!("From: user@{domain}\r\nTo: x@remote.example\r\nSubject: hi\r\n\r\nbody\r\n")
		.into_bytes()
}

async fn outcome(dns: &KeyDns, signed: &str, raw: &[u8]) -> DkimOutcome {
	let mut full = signed.as_bytes().to_vec();
	full.extend_from_slice(raw);
	verify_message(dns, &full).await[0].outcome
}

#[tokio::test]
async fn each_domain_verifies_with_its_own_record() {
	let (signer, records) = domains();
	let dns = KeyDns(records);
	for domain in ["a.example", "b.example", "c.example"] {
		let raw = message(domain);
		let signed = signer.sign(domain, &raw).expect("signs");
		assert_eq!(
			outcome(&dns, &signed, &raw).await,
			DkimOutcome::Pass,
			"{domain}"
		);
	}
}

#[tokio::test]
async fn one_domains_signature_fails_against_anothers_record() {
	let (signer, mut records) = domains();
	// c.example's record now carries b.example's key: a signature made for
	// c.example with its own key no longer verifies, and b's key would only
	// verify if the two domains shared one.
	let b = records["own1._domainkey.b.example"].clone();
	records.insert("own1._domainkey.c.example".into(), b);
	let dns = KeyDns(records);
	let raw = message("c.example");
	let signed = signer.sign("c.example", &raw).expect("signs");
	assert_eq!(
		outcome(&dns, &signed, &raw).await,
		DkimOutcome::Fail,
		"the key that signed for c.example is not b.example's"
	);
}
