//! Management API configuration.

use serde::Deserialize;

/// Management API settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
	/// argon2id PHC hash of the bearer token.
	pub token_hash: String,
	/// Account names allowed to authenticate to the admin panel. An account
	/// that authenticates but is not listed is a valid user, not an admin;
	/// empty (the default) means no account is a panel admin.
	#[serde(default)]
	pub admins: Vec<String>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_api_section() {
		let api: Api = toml::from_str(r#"token_hash = "$argon2id$x""#).expect("parse");
		assert_eq!(api.token_hash, "$argon2id$x");
		assert!(api.admins.is_empty());
	}

	#[test]
	fn parses_admins_list() {
		let api: Api = toml::from_str(
			r#"token_hash = "$argon2id$x"
admins = ["ops-a1b2"]"#,
		)
		.expect("parse");
		assert_eq!(api.admins, vec!["ops-a1b2".to_string()]);
	}

	#[test]
	fn rejects_unknown_keys() {
		assert!(
			toml::from_str::<Api>(
				r#"token_hash = "x"
port = 1"#
			)
			.is_err()
		);
	}
}
