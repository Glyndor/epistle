//! A signer that picks the key of the message's `d=` domain: the domain's
//! `[[dkim.domain]]` override when it has one, the `[dkim]` default
//! otherwise.
//!
//! The default and every override are hot-swappable: the rotation of the
//! `[dkim]` key replaces the default, and each domain's own rotation
//! replaces that domain's override.

use super::rotate::ReloadableSigner;
use super::sign::{HeaderBlock, KeyHolder, Refusal};

/// One per-domain override as the signer keeps it: the lowercase domain
/// name and the signer of that domain, which its rotation replaces.
#[derive(Clone)]
pub struct DomainSigner {
	/// Lowercased hosted domain this override signs for.
	pub domain: String,
	/// The domain's signer, swapped by the domain's rotation.
	pub signer: ReloadableSigner,
}

/// The signer the storage sink uses. It holds the hot-swappable default
/// and the hot-swappable per-domain overrides; signing for a message's `d=`
/// picks the override when one is configured, the default otherwise.
#[derive(Clone)]
pub struct PerDomainSigner {
	default_signer: ReloadableSigner,
	/// One entry per `[[dkim.domain]]`, few enough for a linear search.
	overrides: Vec<DomainSigner>,
}

impl PerDomainSigner {
	/// Build a `PerDomainSigner` from the default signer, which the rotation
	/// task replaces, and the overrides, whose `domain` is lowercase.
	pub fn new(default_signer: ReloadableSigner, overrides: Vec<DomainSigner>) -> Self {
		PerDomainSigner {
			default_signer,
			overrides,
		}
	}

	/// Sign `raw` for `domain`, picking the override when the operator
	/// configured one and falling back to the default signer otherwise.
	/// `domain` is matched case-insensitively, the same way the
	/// validator and the routing layer compare it. The message is read
	/// here and only its header block reaches the key ([`KeyHolder`]).
	pub fn sign(&self, domain: &str, raw: &[u8]) -> Option<String> {
		super::sign::holder::sign_message(self, domain, raw)
	}
}

impl KeyHolder for PerDomainSigner {
	fn sign_block(&self, domain: &str, block: &HeaderBlock) -> Result<String, Refusal> {
		if let Some(override_signer) = self
			.overrides
			.iter()
			.find(|d| d.domain.eq_ignore_ascii_case(domain))
		{
			return override_signer.signer.current().sign_block(domain, block);
		}
		self.default_signer.current().sign_block(domain, block)
	}
}

#[cfg(test)]
mod tests;
