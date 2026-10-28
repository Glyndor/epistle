//! A signer that picks the key of the message's `d=` domain: the domain's
//! `[[dkim.domain]]` override when it has one, the `[dkim]` default
//! otherwise.
//!
//! The default is hot-swappable, because the rotation task replaces it.
//! Overrides are loaded once at startup and never rotated: an override's
//! key lives until the operator replaces it in the configuration and
//! restarts the server.

use std::sync::Arc;

use super::rotate::ReloadableSigner;
use super::sign::Signer;

/// One per-domain override as the signer keeps it: the lowercase domain
/// name and the static `Signer` that signs for it.
#[derive(Clone)]
pub struct DomainSigner {
	/// Lowercased hosted domain this override signs for.
	pub domain: String,
	/// The static `Signer` (loaded once at startup, not rotated).
	pub signer: Arc<Signer>,
}

/// The signer the storage sink uses. It holds the hot-swappable default
/// and the immutable per-domain overrides; signing for a message's `d=`
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
	/// validator and the routing layer compare it.
	pub fn sign(&self, domain: &str, raw: &[u8]) -> Option<String> {
		if let Some(override_signer) = self
			.overrides
			.iter()
			.find(|d| d.domain.eq_ignore_ascii_case(domain))
		{
			return override_signer.signer.sign(domain, raw);
		}
		self.default_signer.current().sign(domain, raw)
	}
}

#[cfg(test)]
mod tests;
