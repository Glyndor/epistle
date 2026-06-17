//! ARC-Seal (AS) signing and verification (RFC 8617 §5.1.2).
//!
//! Unlike the AMS, the seal signs the ARC header *set* — every instance's
//! ARC-Authentication-Results, ARC-Message-Signature and ARC-Seal, in
//! increasing instance order, all relaxed-canonicalized — and never the body.
//! The seal being created or verified is included last with its `b=` emptied.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};

use crate::dkim::{Canon, DkimOutcome, canon, parse_key};
use crate::spf::{DnsFailure, DnsLookup};

use super::ams::strip_b;
use super::chain::{ChainValidation, Instance};
use super::signature::Seal;

/// Build the `ARC-Seal` header line for a new instance, signing the chain so
/// far (`prior`, instances `1..i-1`) plus this instance's freshly built
/// ARC-Authentication-Results and ARC-Message-Signature values.
/// Identity and chain status for a new seal.
pub struct SealParams<'a> {
	pub instance: u32,
	pub domain: &'a str,
	pub selector: &'a str,
	pub chain_validation: ChainValidation,
}

pub fn build(
	key: &Ed25519KeyPair,
	params: &SealParams,
	prior: &[Instance],
	current_auth_results: &str,
	current_message_signature: &str,
) -> String {
	let value = format!(
		" i={}; a=ed25519-sha256; d={}; s={}; cv={}; b=",
		params.instance,
		params.domain,
		params.selector,
		params.chain_validation.as_str(),
	);

	let mut input = String::new();
	for inst in sorted(prior) {
		append_instance(&mut input, &inst.auth_results, &inst.message_signature);
		input.push_str(&canon::header(Canon::Relaxed, "ARC-Seal", &inst.seal));
	}
	// This instance: AAR, AMS, then the seal itself with an empty b= and no
	// trailing CRLF (it terminates the signed input).
	append_instance(&mut input, current_auth_results, current_message_signature);
	input.push_str(&final_seal_line(&value));

	let signature = BASE64.encode(key.sign(input.as_bytes()).as_ref());
	format!("ARC-Seal:{value}{signature}\r\n")
}

/// Verify one ARC-Seal against the chain it covers (instances `1..=i`).
pub async fn verify(
	dns: &dyn DnsLookup,
	seal: &Seal,
	raw_value: &str,
	instances: &[Instance],
) -> DkimOutcome {
	let mut input = String::new();
	for inst in sorted(instances) {
		if inst.instance > seal.instance {
			continue;
		}
		append_instance(&mut input, &inst.auth_results, &inst.message_signature);
		if inst.instance == seal.instance {
			input.push_str(&final_seal_line(&strip_b(raw_value)));
		} else {
			input.push_str(&canon::header(Canon::Relaxed, "ARC-Seal", &inst.seal));
		}
	}

	let key_name = format!("{}._domainkey.{}", seal.selector, seal.domain);
	let texts = match dns.txt(&key_name).await {
		Ok(texts) => texts,
		Err(DnsFailure::Temporary) => return DkimOutcome::TempError,
	};
	let Some(key) = texts.iter().find_map(|text| parse_key(text)) else {
		return DkimOutcome::PermError;
	};

	let public_key = UnparsedPublicKey::new(&ED25519, key);
	match public_key.verify(input.as_bytes(), &seal.signature) {
		Ok(()) => DkimOutcome::Pass,
		Err(_) => DkimOutcome::Fail,
	}
}

/// Append an instance's AAR and AMS canonicalized headers (with CRLF).
fn append_instance(input: &mut String, auth_results: &str, message_signature: &str) {
	input.push_str(&canon::header(
		Canon::Relaxed,
		"ARC-Authentication-Results",
		auth_results,
	));
	input.push_str(&canon::header(
		Canon::Relaxed,
		"ARC-Message-Signature",
		message_signature,
	));
}

/// The terminating ARC-Seal header: relaxed-canonicalized, no trailing CRLF.
fn final_seal_line(value: &str) -> String {
	let mut line = canon::header(Canon::Relaxed, "ARC-Seal", value);
	if line.ends_with("\r\n") {
		line.truncate(line.len() - 2);
	}
	line
}

/// Instances in increasing order, borrowed.
fn sorted(instances: &[Instance]) -> Vec<&Instance> {
	let mut refs: Vec<&Instance> = instances.iter().collect();
	refs.sort_by_key(|inst| inst.instance);
	refs
}
