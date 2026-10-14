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
	/// Selector published at `<selector>._domainkey.<domain>` for any
	/// signing domain that has no per-domain override. Optional when
	/// every hosted domain has a per-domain override, the way Mox
	/// imports land.
	pub selector: Option<String>,
	/// ed25519 private key, PKCS#8 PEM, used for every signing domain
	/// that has no per-domain override. Paired with [`Self::selector`]:
	/// either both are set or neither is.
	pub key_file: Option<PathBuf>,
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
	/// The hosted domain the override signs for. Lowercased during
	/// config normalisation and matched case-insensitively against the
	/// message's `d=`.
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

	/// The per-domain override for `name` when one is configured, so the
	/// signer and the rotation logic use the same lookup.
	pub fn override_for(&self, name: &str) -> Option<&DkimDomain> {
		self.domain.iter().find(|d| d.name == name)
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

#[cfg(test)]
#[path = "dkim_tests.rs"]
mod tests;
