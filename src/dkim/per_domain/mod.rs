//! A signer that picks the key of the message's `d=` domain: the domain's
//! `[[dkim.domain]]` override when it has one, the `[dkim]` default
//! otherwise.
//!
//! The default and every override are hot-swappable: the rotation of the
//! `[dkim]` key replaces the default, and each domain's own rotation
//! replaces that domain's override. The set of overrides is replaced too
//! when the hosted domains change while the server runs.

use std::sync::{Arc, RwLock};

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
	/// Shared by every clone, so replacing it reaches the sink.
	overrides: Arc<RwLock<Vec<DomainSigner>>>,
}

impl PerDomainSigner {
	/// Build a `PerDomainSigner` from the default signer, which the rotation
	/// task replaces, and the overrides, whose `domain` is lowercase.
	pub fn new(default_signer: ReloadableSigner, overrides: Vec<DomainSigner>) -> Self {
		PerDomainSigner {
			default_signer,
			overrides: Arc::new(RwLock::new(overrides)),
		}
	}

	/// The per-domain overrides in effect now.
	pub fn overrides(&self) -> Vec<DomainSigner> {
		self.overrides.read().expect("dkim overrides lock").clone()
	}

	/// Replace the per-domain overrides, for every clone of this signer.
	pub fn replace_overrides(&self, overrides: Vec<DomainSigner>) {
		*self.overrides.write().expect("dkim overrides lock") = overrides;
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
		let chosen = self
			.overrides
			.read()
			.expect("dkim overrides lock")
			.iter()
			.find(|d| d.domain.eq_ignore_ascii_case(domain))
			.map(|d| d.signer.current());
		if let Some(override_signer) = chosen {
			return override_signer.sign_block(domain, block);
		}
		self.default_signer.current().sign_block(domain, block)
	}
}

#[cfg(test)]
mod tests;
