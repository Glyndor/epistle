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
	/// Selector published at `<selector>._domainkey.<domain>`.
	pub selector: String,
	/// ed25519 private key, PKCS#8 PEM.
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
}

impl Dkim {
	/// Warning text when only one DKIM signature is going to be produced.
	///
	/// Returns `None` when both `rsa_selector` and `rsa_key_file` are set, and
	/// the exact text of the warning otherwise. The single source of the
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
}

#[cfg(test)]
#[path = "dkim_tests.rs"]
mod tests;
