//! OAuth2/OIDC bearer-token verification configuration (OAUTHBEARER/XOAUTH2).

use serde::Deserialize;

/// OAuth verifier material. Tokens are accepted when signed for `audience` by
/// `issuer` using `algorithm`, with the signing key taken from exactly one
/// source: a static base64 `public_key`, or keys fetched at startup from the
/// OIDC `discovery_url` (`/.well-known/openid-configuration`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oauth {
	/// Expected `iss` claim.
	pub issuer: String,
	/// Expected `aud` claim.
	pub audience: String,
	/// Signature algorithm: `ES256` or `RS256`. With OIDC discovery this is the
	/// fallback for a JWKS key that omits its own `alg`.
	pub algorithm: String,
	/// Base64 public key (PKCS#1 DER for RSA, raw uncompressed point for EC).
	/// Mutually exclusive with `discovery_url`.
	#[serde(default)]
	pub public_key: Option<String>,
	/// OIDC discovery document URL (`https://…/.well-known/openid-configuration`).
	/// Its `jwks_uri` is fetched to obtain the signing keys. Mutually exclusive
	/// with `public_key`.
	#[serde(default)]
	pub discovery_url: Option<String>,
}

/// Why an `[oauth]` section is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OauthConfigError {
	/// Neither `public_key` nor `discovery_url` was set.
	NoKeySource,
	/// Both `public_key` and `discovery_url` were set.
	AmbiguousKeySource,
	/// `discovery_url` is not an `https://` URL.
	InsecureDiscoveryUrl,
}

impl std::fmt::Display for OauthConfigError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let message = match self {
			OauthConfigError::NoKeySource => {
				"exactly one of `public_key` or `discovery_url` must be set (got neither)"
			}
			OauthConfigError::AmbiguousKeySource => {
				"exactly one of `public_key` or `discovery_url` must be set (got both)"
			}
			OauthConfigError::InsecureDiscoveryUrl => "`discovery_url` must be an https:// URL",
		};
		f.write_str(message)
	}
}

impl std::error::Error for OauthConfigError {}

impl Oauth {
	/// Validate that exactly one key source is configured and that, when OIDC
	/// discovery is used, the endpoint is HTTPS. Fails closed.
	pub fn validate(&self) -> Result<(), OauthConfigError> {
		match (&self.public_key, &self.discovery_url) {
			(Some(_), Some(_)) => return Err(OauthConfigError::AmbiguousKeySource),
			(None, None) => return Err(OauthConfigError::NoKeySource),
			_ => {}
		}
		if let Some(url) = &self.discovery_url
			&& !url.starts_with("https://")
		{
			return Err(OauthConfigError::InsecureDiscoveryUrl);
		}
		Ok(())
	}
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
		assert_eq!(oauth.public_key.as_deref(), Some("BASE64KEY"));
		assert!(oauth.discovery_url.is_none());
		oauth.validate().expect("valid static key");
	}

	#[test]
	fn parses_discovery_section() {
		let oauth: Oauth = toml::from_str(
			r#"
issuer = "https://idp.example"
audience = "mail"
algorithm = "RS256"
discovery_url = "https://idp.example/.well-known/openid-configuration"
"#,
		)
		.expect("parse oauth");
		assert!(oauth.public_key.is_none());
		oauth.validate().expect("valid discovery");
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

	#[test]
	fn rejects_both_or_neither_key_source() {
		let neither: Oauth = toml::from_str(
			r#"
issuer = "x"
audience = "mail"
algorithm = "ES256"
"#,
		)
		.expect("parse");
		assert_eq!(neither.validate(), Err(OauthConfigError::NoKeySource));

		let both: Oauth = toml::from_str(
			r#"
issuer = "x"
audience = "mail"
algorithm = "ES256"
public_key = "k"
discovery_url = "https://idp.example/.well-known/openid-configuration"
"#,
		)
		.expect("parse");
		assert_eq!(both.validate(), Err(OauthConfigError::AmbiguousKeySource));
	}

	#[test]
	fn rejects_non_https_discovery_url() {
		let insecure: Oauth = toml::from_str(
			r#"
issuer = "x"
audience = "mail"
algorithm = "RS256"
discovery_url = "http://idp.example/.well-known/openid-configuration"
"#,
		)
		.expect("parse");
		assert_eq!(
			insecure.validate(),
			Err(OauthConfigError::InsecureDiscoveryUrl)
		);
	}
}
