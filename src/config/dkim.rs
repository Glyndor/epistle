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
		// Deprecated fields default to None when absent.
		assert!(dkim.rotate_days.is_none());
		assert!(dkim.rotate_overlap_days.is_none());
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

	#[test]
	fn deprecated_rotation_fields_still_parse() {
		// Existing configs written before the interval became constant must
		// keep loading: `deny_unknown_fields` would otherwise reject the
		// whole file on upgrade. The values are captured but never read.
		let dkim: Dkim = toml::from_str(
			r#"
selector = "mail"
key_file = "/k.pem"
rotate_days = 30
rotate_overlap_days = 3
"#,
		)
		.expect("deprecated fields parse");
		assert_eq!(dkim.rotate_days, Some(30));
		assert_eq!(dkim.rotate_overlap_days, Some(3));
	}

	#[test]
	fn only_one_deprecated_field_is_enough_to_be_ignored() {
		// Either field set on its own is also tolerated.
		let only_days: Dkim = toml::from_str(
			r#"
selector = "mail"
key_file = "/k.pem"
rotate_days = 30
"#,
		)
		.expect("parse");
		assert_eq!(only_days.rotate_days, Some(30));
		assert!(only_days.rotate_overlap_days.is_none());

		let only_overlap: Dkim = toml::from_str(
			r#"
selector = "mail"
key_file = "/k.pem"
rotate_overlap_days = 21
"#,
		)
		.expect("parse");
		assert!(only_overlap.rotate_days.is_none());
		assert_eq!(only_overlap.rotate_overlap_days, Some(21));
	}
}
