//! The half of DKIM signing that holds the private key.
//!
//! A [`KeyHolder`] takes a [`HeaderBlock`] and the `d=` domain, writes the
//! tag list itself (algorithm, selector, domain, `h=`, `bh=`), signs, and
//! returns the `DKIM-Signature` fields. It never sees the message, and it
//! picks the selector, so the `s=` it writes always names the key that
//! signed even while a rotation replaces that key. Today the holder runs in
//! the same process as the code that reads the message; the interface is
//! the boundary a signing service takes over (`docs/operations/serve-split.md`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::block::{HeaderBlock, Malformed};
use super::{Signer, rsa_sign};
use crate::dkim::signature::Algorithm;

/// Why a key holder did not sign a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
	/// The block failed [`HeaderBlock::check`].
	#[error("malformed header block: {0}")]
	Malformed(#[from] Malformed),
	/// The tag list cannot be written within the line limits of the field:
	/// a domain, selector or field name longer than a line can hold.
	#[error("the signature field cannot be written for this domain and these names")]
	Unsignable,
}

/// The half of signing that holds the key: sign a header block for `d=`.
pub trait KeyHolder: Send + Sync {
	/// Sign `block` for `domain` and return the complete `DKIM-Signature`
	/// fields to prepend (folded, each ending in CRLF), ed25519 first and
	/// RSA after it when the holder has an RSA key for the domain.
	fn sign_block(&self, domain: &str, block: &HeaderBlock) -> Result<String, Refusal>;
}

/// Sign `raw` for `domain` through `holder`: read the message into a block
/// here, and hand the holder only the block. `None` when the message cannot
/// be read into a block or the holder refuses it, which leaves the message
/// unsigned, as it always has been in that case.
pub(crate) fn sign_message(holder: &dyn KeyHolder, domain: &str, raw: &[u8]) -> Option<String> {
	let block = HeaderBlock::from_message(raw)?;
	holder.sign_block(domain, &block).ok()
}

impl KeyHolder for Signer {
	fn sign_block(&self, domain: &str, block: &HeaderBlock) -> Result<String, Refusal> {
		block.check()?;
		let body_hash = BASE64.encode(block.body_hash);
		// ed25519 first, then the optional RSA signature.
		let mut out = self
			.one_signature(
				"ed25519-sha256",
				&self.selector,
				domain,
				&block.names,
				&body_hash,
				&block.canonical,
				&|input| {
					// RFC 8463 section 3: an Ed25519-SHA256 signature covers the
					// SHA-256 digest of the header data, not the data itself.
					let signed = Algorithm::Ed25519Sha256.signed_bytes(input);
					Some(self.key.sign(signed.as_ref()).as_ref().to_vec())
				},
			)
			.ok_or(Refusal::Unsignable)?;
		if let Some(rsa) = &self.rsa
			&& let Some(line) = self.one_signature(
				"rsa-sha256",
				&rsa.selector,
				domain,
				&block.names,
				&body_hash,
				&block.canonical,
				&|input| rsa_sign(&rsa.key, input),
			) {
			out.push_str(&line);
		}
		Ok(out)
	}
}
