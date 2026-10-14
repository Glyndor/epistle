//! A signer that picks the right key for the message's `d=` domain, so
//! the relay can host many domains with independent keys without
//! rotating every domain together.
//!
//! The default signer (one key, optional RSA dual) is hot-swappable: the
//! background rotation task replaces it. Per-domain overrides are loaded
//! once at startup: in this release they are not rotated, so a per-domain
//! key lives until the operator replaces it by editing `[dkim.domain]`
//! and restarting.
//!
//! The lookup is `O(n)` over a `Vec` because the number of overrides is
//! small (a single deployment rarely has more than a handful) and the
//! comparison is one lowercase string. A `HashMap` would force a
//! per-call allocation and lock contention on a hot path.

use std::collections::HashMap;
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
	/// Lowercase domain name, in the order the operator listed them.
	overrides: Vec<DomainSigner>,
}

impl PerDomainSigner {
	/// Build a `PerDomainSigner` from a default signer and per-domain
	/// overrides. The overrides are stored in `domain` order; the
	/// default is what the existing rotation task replaces.
	pub fn new(default_signer: ReloadableSigner, overrides: Vec<DomainSigner>) -> Self {
		PerDomainSigner {
			default_signer,
			overrides,
		}
	}

	/// The default signer, for callers that drive rotation (the
	/// rotation task replaces this one, not the overrides).
	pub fn default_signer(&self) -> &ReloadableSigner {
		&self.default_signer
	}

	/// The per-domain overrides, in the order the operator listed them.
	/// Used by `dns-records`, `verify-dns` and `dkim show` to publish a
	/// per-domain TXT record.
	pub fn overrides(&self) -> &[DomainSigner] {
		&self.overrides
	}

	/// Sign `raw` for `domain`, picking the override when the operator
	/// configured one and falling back to the default signer otherwise.
	/// `domain` is matched case-insensitively, the same way the
	/// validator and the routing layer compare it.
	pub fn sign(&self, domain: &str, raw: &[u8]) -> Option<String> {
		let want = domain.to_ascii_lowercase();
		if let Some(override_signer) = self.overrides.iter().find(|d| d.domain == want) {
			return override_signer.signer.sign(domain, raw);
		}
		self.default_signer.current().sign(domain, raw)
	}
}

/// Lowercase the override domains once and group them, so the signer
/// can resolve a `d=` to its override in one pass. The rotation task
/// loads the default and the overrides separately; this helper just
/// normalises the override names so a typo in the operator's input
/// cannot make signing silently fall back to the default.
pub fn lowercase_overrides(raw: &HashMap<String, Arc<Signer>>) -> Vec<DomainSigner> {
	let mut entries: Vec<DomainSigner> = raw
		.iter()
		.map(|(name, signer)| DomainSigner {
			domain: name.to_ascii_lowercase(),
			signer: Arc::clone(signer),
		})
		.collect();
	entries.sort_by(|a, b| a.domain.cmp(&b.domain));
	entries
}

/// Sort and validate a pre-built list of overrides. Used by the
/// startup path: each entry's key is already loaded, only the lookup
/// order has to be fixed.
pub fn sort_overrides(mut entries: Vec<DomainSigner>) -> Vec<DomainSigner> {
	entries.sort_by(|a, b| a.domain.cmp(&b.domain));
	entries
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

	#[test]
	fn lowercase_overrides_keeps_the_loaded_signers() {
		let s1 = fresh_signer("a");
		let s2 = fresh_signer("b");
		let mut raw = HashMap::new();
		raw.insert("Example.Org".to_string(), Arc::clone(&s1));
		raw.insert("elsewhere.example".to_string(), Arc::clone(&s2));
		let lower = lowercase_overrides(&raw);
		assert_eq!(lower.len(), 2);
		for entry in &lower {
			let raw_key = match entry.domain.as_str() {
				"example.org" => &s1,
				"elsewhere.example" => &s2,
				other => panic!("unexpected domain {other}"),
			};
			assert!(
				Arc::ptr_eq(&entry.signer, raw_key),
				"the override must keep the loaded signer for {}",
				entry.domain
			);
		}
	}

	#[test]
	fn sort_overrides_returns_alphabetical_order() {
		let s1 = fresh_signer("a");
		let s2 = fresh_signer("b");
		let unsorted = vec![
			DomainSigner {
				domain: "zeta.example".to_string(),
				signer: Arc::clone(&s1),
			},
			DomainSigner {
				domain: "alpha.example".to_string(),
				signer: Arc::clone(&s2),
			},
		];
		let sorted = sort_overrides(unsorted);
		assert_eq!(sorted[0].domain, "alpha.example");
		assert_eq!(sorted[1].domain, "zeta.example");
	}
}
