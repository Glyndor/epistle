//! DKIM signing configuration.

use std::path::PathBuf;

use serde::Deserialize;

/// The first version of epistle that refuses to start without the dual-signing
/// pair. Before this version the server prints a single-signature warning; at
/// and after this version the configuration is rejected at load time.
pub const DKIM_RSA_REQUIRED_FROM: &str = "0.10";

/// Outbound DKIM signing material.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dkim {
	/// Selector published at `<selector>._domainkey.<domain>`. It signs
	/// every domain that has no `[[dkim.domain]]` override.
	pub selector: String,
	/// ed25519 private key, PKCS#8 PEM, paired with [`Self::selector`].
	pub key_file: PathBuf,
	/// Optional RSA selector for an additional rsa-sha256 signature (RFC 8463).
	#[serde(default)]
	pub rsa_selector: Option<String>,
	/// Optional RSA private key (PKCS#8 PEM) paired with `rsa_selector`.
	#[serde(default)]
	pub rsa_key_file: Option<PathBuf>,
	/// Deprecated. The rotation interval is now fixed at
	/// [`crate::dkim::ROTATE_INTERVAL_DAYS`] days and is no longer
	/// configurable. Retained as an `Option` so existing configs that still
	/// carry the field keep parsing under `deny_unknown_fields`; the value
	/// is ignored and a deprecation warning is logged once at startup when
	/// present. Will be removed in a future release.
	#[serde(default)]
	pub rotate_days: Option<u32>,
	/// Deprecated. The overlap window is now fixed at
	/// [`crate::dkim::ROTATE_OVERLAP_DAYS`] days and is no longer
	/// configurable. Same backward-compatibility rationale as
	/// [`Self::rotate_days`].
	#[serde(default)]
	pub rotate_overlap_days: Option<u32>,
	/// Per-domain overrides: a domain listed here signs with its own
	/// ed25519 (and optional RSA) key, so one hosted domain's key
	/// compromise or DNS mistake does not affect the others. Domains
	/// absent from this list keep using the default `[dkim]` key.
	#[serde(default)]
	pub domain: Vec<DkimDomain>,
}

/// A per-domain DKIM override: signs mail whose `d=` is `name` with
/// these keys, falling back to the configured `[dkim]` keys for every
/// other signing domain.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DkimDomain {
	/// The hosted domain the override signs for, matched against the
	/// message's `d=` without regard to case.
	pub name: String,
	/// Selector published at `<selector>._domainkey.<name>`.
	pub selector: String,
	/// ed25519 private key, PKCS#8 PEM.
	pub key_file: PathBuf,
	/// Optional RSA selector for an additional rsa-sha256 signature on
	/// mail from this domain.
	#[serde(default)]
	pub rsa_selector: Option<String>,
	/// Optional RSA private key (PKCS#8 PEM) paired with
	/// `rsa_selector`. Must be set together with `rsa_selector`, the
	/// same way the configured `[dkim]` block does.
	#[serde(default)]
	pub rsa_key_file: Option<PathBuf>,
}

impl Dkim {
	/// Warning text when only one DKIM signature is going to be produced.
	///
	/// Returns `None` when both `rsa_selector` and `rsa_key_file` are set,
	/// and the exact text of the warning otherwise. The single source of the
	/// message keeps `serve`, `config-check` and `verify-dns` from drifting;
	/// the three call sites are tested through this method instead of through
	/// their respective outputs.
	pub fn single_signature_warning(&self) -> Option<String> {
		if self.rsa_selector.is_some() && self.rsa_key_file.is_some() {
			return None;
		}
		Some(format!(
			"[dkim] signs with one key only. \
			 Receivers that verify RSA alone treat this mail as unsigned. \
			 Generate an RSA key with \"epistle dkim-keygen --rsa\", \
			 publish the TXT record \"epistle dns-records\" prints, \
			 and set rsa_selector and rsa_key_file. \
			 From version {version} the server refuses to start without them.",
			version = DKIM_RSA_REQUIRED_FROM,
		))
	}

	/// The `[[dkim.domain]]` override for `name`, compared without regard
	/// to case the way the signer and the validator compare domains.
	pub fn override_for(&self, name: &str) -> Option<&DkimDomain> {
		self.domain
			.iter()
			.find(|d| d.name.eq_ignore_ascii_case(name))
	}

	/// Selectors that leftover detection (`epistle dkim cleanup` and the
	/// rotation task's report) must never count as unused: the configured
	/// pair, every override's pair, and the selector an override's key file
	/// name carries when it has the `dkim-<selector>.key` shape rotated keys
	/// use. An override is not rotated, so nothing in the rotation state
	/// names it, and its record and key file would otherwise look orphaned.
	pub fn kept_selectors(&self) -> Vec<String> {
		let mut kept = vec![self.selector.clone()];
		kept.extend(self.rsa_selector.clone());
		for entry in &self.domain {
			kept.push(entry.selector.clone());
			kept.extend(entry.rsa_selector.clone());
			for file in std::iter::once(&entry.key_file).chain(entry.rsa_key_file.as_ref()) {
				let selector = file
					.file_name()
					.and_then(|name| name.to_str())
					.and_then(|name| name.strip_prefix("dkim-"))
					.and_then(|name| name.strip_suffix(".key"));
				kept.extend(selector.map(str::to_string));
			}
		}
		kept
	}
}

impl DkimDomain {
	/// The RSA pair is a single switch: a published `_domainkey` TXT
	/// without a loadable key, or a key with no TXT, is the same kind of
	/// half-configured state the configured `[dkim]` block refuses.
	pub fn rsa_pair_is_complete(&self) -> bool {
		(self.rsa_selector.is_some() && self.rsa_key_file.is_some())
			|| (self.rsa_selector.is_none() && self.rsa_key_file.is_none())
	}
}

#[path = "validate_dkim_domain.rs"]
mod validate;

#[cfg(test)]
#[path = "dkim_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "dkim_tests_per_domain.rs"]
mod tests_per_domain;
