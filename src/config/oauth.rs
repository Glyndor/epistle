//! OAuth2/OIDC bearer-token verification configuration (OAUTHBEARER/XOAUTH2).

use serde::Deserialize;

/// OAuth verifier material. Tokens are accepted when signed by `public_key`
/// with `algorithm` and issued by `issuer` for `audience`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oauth {
	/// Expected `iss` claim.
	pub issuer: String,
	/// Expected `aud` claim.
	pub audience: String,
	/// Signature algorithm: `ES256` or `RS256`.
	pub algorithm: String,
	/// Base64 public key (SPKI DER for RSA, raw point for EC).
	pub public_key: String,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_oauth_section() {
		let oauth: Oauth = toml::from_str(
			r#"
issuer = "https://idp.example"
audience = "mail"
algorithm = "ES256"
public_key = "BASE64KEY"
"#,
		)
		.expect("parse oauth");
		assert_eq!(oauth.issuer, "https://idp.example");
		assert_eq!(oauth.algorithm, "ES256");
	}

	#[test]
	fn rejects_missing_fields_and_unknown_keys() {
		assert!(toml::from_str::<Oauth>(r#"issuer = "x""#).is_err());
		assert!(
			toml::from_str::<Oauth>(
				r#"
issuer = "x"
audience = "mail"
algorithm = "ES256"
public_key = "k"
extra = "no"
"#
			)
			.is_err()
		);
	}
}
