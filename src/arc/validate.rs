//! Full ARC chain validation (RFC 8617 §5.2).
//!
//! Combines the structural extraction with AMS and seal verification to
//! produce the chain-validation status (`cv`) a downstream sealer would record:
//! `none` for an absent chain, `pass` for an intact one, `fail` otherwise. The
//! result is fail-closed — any malformed part, broken signature, or
//! inconsistent `cv` collapses the whole chain to `fail`.

use crate::dkim::DkimOutcome;
use crate::spf::{DnsFailure, DnsLookup};

use super::chain::{ChainValidation, Instance, extract};
use super::signature::{parse_message_signature, parse_seal};
use super::{ams, seal};

/// Validate the ARC chain on a raw message. A DNS error while reading a key
/// counts as a broken chain, which is what a seal needs to say (RFC 8617
/// section 5.2); [`validate_checked`] tells the two apart.
pub async fn validate(dns: &dyn DnsLookup, raw_message: &[u8]) -> ChainValidation {
	validate_checked(dns, raw_message)
		.await
		.unwrap_or(ChainValidation::Fail)
}

/// Validate the ARC chain on a raw message, and say when the answer is not
/// known because a DNS lookup failed temporarily, so the caller can retry
/// later instead of treating the chain as broken.
pub async fn validate_checked(
	dns: &dyn DnsLookup,
	raw_message: &[u8],
) -> Result<ChainValidation, DnsFailure> {
	let instances = match extract(raw_message) {
		Ok(Some(instances)) => instances,
		// No ARC headers at all: a fresh chain.
		Ok(None) => return Ok(ChainValidation::None),
		// Structurally broken.
		Err(_) => return Ok(ChainValidation::Fail),
	};

	if !cv_values_consistent(&instances) {
		return Ok(ChainValidation::Fail);
	}

	// The most recent ARC-Message-Signature must verify against the message.
	let newest = instances.last().expect("non-empty chain");
	let Ok(ams) = parse_message_signature(&newest.message_signature) else {
		return Ok(ChainValidation::Fail);
	};
	match ams::verify(dns, &ams, &newest.message_signature, raw_message).await {
		DkimOutcome::Pass => {}
		DkimOutcome::TempError => return Err(DnsFailure::Temporary),
		_ => return Ok(ChainValidation::Fail),
	}

	// Every ARC-Seal in the chain must verify.
	for instance in &instances {
		let Ok(parsed) = parse_seal(&instance.seal) else {
			return Ok(ChainValidation::Fail);
		};
		match seal::verify(dns, &parsed, &instance.seal, &instances).await {
			DkimOutcome::Pass => {}
			DkimOutcome::TempError => return Err(DnsFailure::Temporary),
			_ => return Ok(ChainValidation::Fail),
		}
	}

	Ok(ChainValidation::Pass)
}

/// Each seal's recorded `cv` must match its position: `none` on the first
/// instance, `pass` on every later one. Anything else means the chain was
/// already broken when sealed.
fn cv_values_consistent(instances: &[Instance]) -> bool {
	instances.iter().all(|instance| {
		let Ok(seal) = parse_seal(&instance.seal) else {
			return false;
		};
		let expected = if instance.instance == 1 {
			ChainValidation::None
		} else {
			ChainValidation::Pass
		};
		seal.chain_validation == expected
	})
}
