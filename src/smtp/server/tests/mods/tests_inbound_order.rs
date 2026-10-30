//! Signatures covering a field removed at unauthenticated ingress.

use super::tests_auth::directory_with_password;
use super::tests_inbound_headers::{PLAIN, receive};
use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::HashMap;

use crate::arc::chain::ChainValidation;
use crate::arc::seal::{self, SealParams};
use crate::arc::sealer::ArcSealer;
use crate::dkim::test_support::KeyDns;
use crate::dkim::{Algorithm, Canon, DkimOutcome, canon};
use crate::smtp::sink::MemorySink;
use crate::smtp::trace::header_values;

const REMOVED: &str = "X-Spam-Status: prior-verdict\r\n";

fn key() -> Ed25519KeyPair {
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).expect("key");
	Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key pair")
}

fn record(key: &Ed25519KeyPair) -> Vec<String> {
	vec![format!(
		"v=DKIM1; k=ed25519; p={}",
		BASE64.encode(key.public_key().as_ref())
	)]
}

// Build an external signature independently of the production signers' fixed
// header allowlist. Both From and the soon-to-be-removed field must be signed.
fn signature(key: &Ed25519KeyPair, name: &str, preamble: &str) -> String {
	let body = canon::body(Canon::Relaxed, b"body\r\n");
	let hash = BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &body));
	let value = format!(
		" {preamble}; a=ed25519-sha256; c=relaxed/relaxed; s=external; h=from:x-spam-status; bh={hash}; b="
	);
	let mut input = canon::header(Canon::Relaxed, "From", " eve@sender.example");
	input.push_str(&canon::header(
		Canon::Relaxed,
		"X-Spam-Status",
		" prior-verdict",
	));
	let own = canon::header(Canon::Relaxed, name, &value);
	input.push_str(own.strip_suffix("\r\n").expect("canonical CRLF"));
	// An Ed25519-SHA256 signature covers the SHA-256 digest of the signed
	// data (RFC 8463 section 3), not the data itself.
	let signed = Algorithm::Ed25519Sha256.signed_bytes(input.as_bytes());
	format!(
		"{value}{}",
		BASE64.encode(key.sign(signed.as_ref()).as_ref())
	)
}

fn signed_dkim(key: &Ed25519KeyPair) -> String {
	let value = signature(key, "DKIM-Signature", "v=1; d=sender.example");
	format!("DKIM-Signature:{value}\r\n{REMOVED}{PLAIN}")
}

fn signed_arc(key: &Ed25519KeyPair) -> String {
	let ams = signature(key, "ARC-Message-Signature", "i=1; d=prior.example");
	let aar = " i=1; prior.example; dkim=pass";
	let params = SealParams {
		instance: 1,
		domain: "prior.example",
		selector: "external",
		chain_validation: ChainValidation::None,
	};
	let seal = seal::build(key, &params, &[], aar, &ams);
	format!(
		"{seal}ARC-Message-Signature:{ams}\r\nARC-Authentication-Results:{aar}\r\n{REMOVED}{PLAIN}"
	)
}

#[tokio::test]
async fn dkim_verification_uses_original_headers_before_stripping() {
	let external = key();
	let dns = Arc::new(KeyDns(HashMap::from([(
		"external._domainkey.sender.example".into(),
		record(&external),
	)])));
	let original = signed_dkim(&external);
	let results = crate::dkim::verify_message(dns.as_ref(), original.as_bytes()).await;
	assert_eq!(results.len(), 1);
	assert_eq!(results[0].outcome, DkimOutcome::Pass);
	let stripped = original.replace(REMOVED, "");
	let results = crate::dkim::verify_message(dns.as_ref(), stripped.as_bytes()).await;
	assert_eq!(results.len(), 1);
	assert_eq!(results[0].outcome, DkimOutcome::Fail);
	for bdat in [false, true] {
		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mail.example.org", sink.clone())
			.with_directory(directory_with_password())
			.with_spf(dns.clone());
		receive(server, &original, bdat).await;
		let messages = sink.messages();
		assert_eq!(messages.len(), 1);
		let message = &messages[0];
		let results = header_values(&message.data, "Authentication-Results");
		assert_eq!(results.len(), 1);
		assert!(
			results[0].contains("dkim=pass header.d=sender.example"),
			"{results:?}"
		);
		assert!(message.sender_verified);
		assert!(header_values(&message.data, "X-Spam-Status").is_empty());
		assert_eq!(
			header_values(&message.data, "DKIM-Signature"),
			header_values(original.as_bytes(), "DKIM-Signature")
		);
	}
}

#[tokio::test]
async fn arc_verification_uses_original_headers_before_stripping() {
	let external = key();
	let original = signed_arc(&external);
	for bdat in [false, true] {
		let local = key();
		let dns = Arc::new(KeyDns(HashMap::from([
			(
				"external._domainkey.prior.example".into(),
				record(&external),
			),
			("arc._domainkey.mail.example.org".into(), record(&local)),
		])));
		assert_eq!(
			crate::arc::validate::validate(dns.as_ref(), original.as_bytes()).await,
			ChainValidation::Pass
		);
		let stripped = original.replace(REMOVED, "");
		assert_eq!(
			crate::arc::validate::validate(dns.as_ref(), stripped.as_bytes()).await,
			ChainValidation::Fail
		);
		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mail.example.org", sink.clone())
			.with_directory(directory_with_password())
			.with_spf(dns.clone())
			.with_arc_sealer(Arc::new(ArcSealer::new(local, "mail.example.org", "arc")));
		receive(server, &original, bdat).await;
		let messages = sink.messages();
		assert_eq!(messages.len(), 1);
		let data = &messages[0].data;
		let chain = crate::arc::chain::extract(data)
			.expect("chain")
			.expect("present");
		assert_eq!(chain.len(), 2);
		let latest = chain.last().expect("local seal");
		assert_eq!(
			crate::arc::signature::parse_seal(&latest.seal)
				.expect("seal")
				.chain_validation,
			ChainValidation::Pass
		);
		assert_eq!(
			chain[0].message_signature,
			crate::arc::chain::extract(original.as_bytes())
				.expect("chain")
				.expect("present")[0]
				.message_signature
		);
		assert!(header_values(data, "X-Spam-Status").is_empty());
		assert_eq!(
			crate::arc::validate::validate(dns.as_ref(), data).await,
			ChainValidation::Pass
		);
	}
}
