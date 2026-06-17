//! ARC sealing configuration (RFC 8617).

use std::path::PathBuf;

use serde::Deserialize;

/// ARC sealing material. The signing domain is the server hostname; the key is
/// published like a DKIM key at `<selector>._domainkey.<domain>`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arc {
	/// Selector published at `<selector>._domainkey.<domain>`.
	pub selector: String,
	/// ed25519 private key, PKCS#8 PEM (the same format DKIM uses).
	pub key_file: PathBuf,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_arc_section() {
		let arc: Arc = toml::from_str(
			r#"
selector = "arc"
key_file = "/etc/mail/arc.pem"
"#,
		)
		.expect("parse arc");
		assert_eq!(arc.selector, "arc");
	}

	#[test]
	fn rejects_missing_fields_and_unknown_keys() {
		assert!(toml::from_str::<Arc>(r#"selector = "arc""#).is_err());
		assert!(
			toml::from_str::<Arc>(
				r#"
selector = "arc"
key_file = "/k.pem"
domain = "x"
"#
			)
			.is_err()
		);
	}
}
