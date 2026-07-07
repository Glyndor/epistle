//! DKIM signing configuration.

use std::path::PathBuf;

use serde::Deserialize;

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
	/// Automatic key rotation interval in days. Requires a `[dns]` provider to
	/// publish the new selector. Absent disables rotation.
	#[serde(default)]
	pub rotate_days: Option<u32>,
	/// Days the previous selector's TXT stays published after a rotation so
	/// in-flight mail still verifies (default 7).
	#[serde(default = "default_overlap_days")]
	pub rotate_overlap_days: u32,
}

/// Default overlap window for a retired DKIM selector.
fn default_overlap_days() -> u32 {
	7
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_dkim_section() {
		let dkim: Dkim = toml::from_str(
			r#"
selector = "mail"
key_file = "/etc/mail/dkim.pem"
"#,
		)
		.expect("parse dkim");
		assert_eq!(dkim.selector, "mail");
	}

	#[test]
	fn rejects_missing_fields_and_unknown_keys() {
		assert!(toml::from_str::<Dkim>(r#"selector = "mail""#).is_err());
		assert!(
			toml::from_str::<Dkim>(
				r#"
selector = "mail"
key_file = "/k.pem"
algorithm = "rsa"
"#
			)
			.is_err()
		);
	}
}
