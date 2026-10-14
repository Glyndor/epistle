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
mod tests {
	use super::*;
	use std::io::Write;

	fn fresh_signer(selector: &str) -> Arc<Signer> {
		let (pem, _) = crate::dkim::generate_key().expect("key");
		let mut file = tempfile::NamedTempFile::new().expect("temp file");
		file.write_all(pem.as_bytes()).expect("write");
		let signer = Signer::load(selector, file.path()).expect("load");
		Arc::new(signer)
	}

	#[test]
	fn picks_the_override_for_a_listed_domain() {
		let default = ReloadableSigner::new(fresh_signer("default-sel"));
		let overrides = vec![DomainSigner {
			domain: "example.org".to_string(),
			signer: fresh_signer("per-sel"),
		}];
		let signer = PerDomainSigner::new(default, overrides);
		let raw = b"From: a@example.org\r\nSubject: x\r\n\r\nbody\r\n";
		let header = signer.sign("example.org", raw).expect("signs");
		assert!(
			header.contains("s=per-sel;"),
			"override selector must be the one signed with, got {header}"
		);
	}

	#[test]
	fn falls_back_to_the_default_for_an_unlisted_domain() {
		let default = ReloadableSigner::new(fresh_signer("default-sel"));
		let overrides = vec![DomainSigner {
			domain: "example.org".to_string(),
			signer: fresh_signer("per-sel"),
		}];
		let signer = PerDomainSigner::new(default, overrides);
		let raw = b"From: a@elsewhere.example\r\nSubject: x\r\n\r\nbody\r\n";
		let header = signer.sign("elsewhere.example", raw).expect("signs");
		assert!(
			header.contains("s=default-sel;"),
			"unlisted domain must sign with the default, got {header}"
		);
	}

	#[test]
	fn matches_overrides_case_insensitively() {
		let default = ReloadableSigner::new(fresh_signer("default-sel"));
		let overrides = vec![DomainSigner {
			domain: "example.org".to_string(),
			signer: fresh_signer("per-sel"),
		}];
		let signer = PerDomainSigner::new(default, overrides);
		let raw = b"From: a@example.org\r\nSubject: x\r\n\r\nbody\r\n";
		let header = signer.sign("EXAMPLE.ORG", raw).expect("signs");
		assert!(
			header.contains("s=per-sel;"),
			"override lookup must be case-insensitive, got {header}"
		);
	}

	#[test]
	fn reload_replaces_only_the_default_signer() {
		let default = ReloadableSigner::new(fresh_signer("default-sel"));
		let overrides = vec![DomainSigner {
			domain: "example.org".to_string(),
			signer: fresh_signer("per-sel"),
		}];
		let signer = PerDomainSigner::new(default.clone(), overrides);
		default.reload(fresh_signer("default-2"));
		let raw = b"From: a@example.org\r\nSubject: x\r\n\r\nbody\r\n";
		let listed = signer.sign("example.org", raw).expect("signs");
		assert!(
			listed.contains("s=per-sel;"),
			"per-domain override must be unaffected by default reload, got {listed}"
		);
		let raw = b"From: a@other.example\r\nSubject: x\r\n\r\nbody\r\n";
		let other = signer.sign("other.example", raw).expect("signs");
		assert!(
			other.contains("s=default-2;"),
			"default reload must propagate to the default signer, got {other}"
		);
	}
}
