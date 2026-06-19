//! ACME configuration: automatic TLS certificate issuance settings.

use serde::Deserialize;

/// Default days before expiry to start renewing.
const fn default_renew_before_days() -> u32 {
	30
}

/// Automatic-TLS (ACME) settings. Present enables auto issuance/renewal.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acme {
	/// The CA's ACME directory URL (e.g. Let's Encrypt).
	pub directory_url: String,
	/// Account contact email addresses.
	#[serde(default)]
	pub contacts: Vec<String>,
	/// Domains to obtain certificates for.
	pub domains: Vec<String>,
	/// Days before expiry to begin renewal.
	#[serde(default = "default_renew_before_days")]
	pub renew_before_days: u32,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_with_defaults() {
		let acme: Acme = toml::from_str(
			r#"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
domains = ["mail.example.org"]
"#,
		)
		.expect("parse");
		assert_eq!(acme.renew_before_days, 30);
		assert!(acme.contacts.is_empty());
		assert_eq!(acme.domains, vec!["mail.example.org".to_string()]);
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Acme, _> = toml::from_str(
			"directory_url = \"https://x/dir\"\ndomains = [\"a.example\"]\nsurprise = true\n",
		);
		assert!(result.is_err());
	}
}
