//! ARC sealing (RFC 8617 §5.1): add a new instance to a message's chain.
//!
//! A sealer holds the host's ed25519 key and seals each received message with
//! the next instance: it writes an ARC-Authentication-Results capturing this
//! hop's results, an ARC-Message-Signature over the message, and an ARC-Seal
//! over the whole chain carrying the supplied chain-validation status. Key
//! loading and configuration live in the wiring layer; this is pure given a
//! key, so it is unit-tested by sealing and re-validating.

use ring::signature::Ed25519KeyPair;

use super::ams;
use super::chain::{ChainValidation, Instance, MAX_INSTANCE};
use super::seal::{self, SealParams};

/// Seals messages into a domain's ARC chain.
pub struct ArcSealer {
	key: Ed25519KeyPair,
	domain: String,
	selector: String,
}

impl ArcSealer {
	/// Build a sealer from an already-loaded key.
	pub fn new(
		key: Ed25519KeyPair,
		domain: impl Into<String>,
		selector: impl Into<String>,
	) -> Self {
		Self {
			key,
			domain: domain.into(),
			selector: selector.into(),
		}
	}

	/// Seal `raw_message`, given the chain already present (`prior`), this
	/// hop's authentication results, and the chain-validation status the
	/// verifier computed for `prior`. Returns the three ARC header lines
	/// (newest first) to prepend, or `None` if the message cannot be signed
	/// (no From header) or the chain is already full.
	pub fn seal(
		&self,
		raw_message: &[u8],
		auth_results: &str,
		prior: &[Instance],
		chain_validation: ChainValidation,
	) -> Option<String> {
		let instance = next_instance(prior)?;

		let ams_line = ams::build(
			&self.key,
			instance,
			&self.domain,
			&self.selector,
			raw_message,
		)?;
		let ams_value = header_value(&ams_line)?;

		// authserv-id is the sealing host; the results follow verbatim.
		let aar_value = format!(" i={instance}; {}; {auth_results}", self.domain);

		let params = SealParams {
			instance,
			domain: &self.domain,
			selector: &self.selector,
			chain_validation,
		};
		let seal_line = seal::build(&self.key, &params, prior, &aar_value, &ams_value);

		// Newest instance on top, AAR last (RFC 8617 §5.1 ordering is not
		// significant, but this is the conventional layout).
		Some(format!(
			"{seal_line}{ams_line}ARC-Authentication-Results:{aar_value}\r\n"
		))
	}
}

/// The next instance number for a chain, or `None` if it is already at the cap.
fn next_instance(prior: &[Instance]) -> Option<u32> {
	let highest = prior.iter().map(|inst| inst.instance).max().unwrap_or(0);
	let next = highest + 1;
	(next <= MAX_INSTANCE).then_some(next)
}

/// The value of a built `Name: value\r\n` header line (after the colon, no
/// trailing CRLF).
fn header_value(line: &str) -> Option<String> {
	let after = line.split_once(':')?.1;
	Some(after.strip_suffix("\r\n").unwrap_or(after).to_string())
}
