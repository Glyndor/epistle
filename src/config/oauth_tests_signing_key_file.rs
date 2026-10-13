//! `[oauth] signing_key_file`: the signing key read from a file instead of
//! written into the config.

use super::*;

fn oauth(extra: &str) -> Oauth {
	toml::from_str(&format!(
		"issuer = \"https://mail.example\"\naudience = \"mail\"\nalgorithm = \"ES256\"\npublic_key = \"PUB\"\n{extra}"
	))
	.expect("parse")
}

#[test]
fn the_key_is_read_from_the_file_and_trimmed() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("oauth_signing.key");
	std::fs::write(&path, "BASE64PRIV\n").unwrap();
	let oauth = oauth(&format!(
		"signing_key_file = {:?}\n",
		path.display().to_string()
	));
	assert_eq!(oauth.validate(), Ok(()));
	assert_eq!(
		oauth.signing_key_material().unwrap().as_deref(),
		Some("BASE64PRIV")
	);
}

#[test]
fn an_inline_key_still_works_and_no_key_mounts_nothing() {
	assert_eq!(
		oauth("signing_key = \"INLINE\"\n")
			.signing_key_material()
			.unwrap()
			.as_deref(),
		Some("INLINE")
	);
	assert_eq!(oauth("").signing_key_material().unwrap(), None);
}

#[test]
fn a_missing_file_is_an_error_not_a_server_without_tokens() {
	let error = oauth("signing_key_file = \"/nonexistent/oauth_signing.key\"\n")
		.signing_key_material()
		.unwrap_err();
	assert!(
		error.to_string().contains("/nonexistent/oauth_signing.key"),
		"{error}"
	);
}

#[test]
fn both_sources_at_once_are_refused() {
	assert_eq!(
		oauth("signing_key = \"INLINE\"\nsigning_key_file = \"/k\"\n").validate(),
		Err(OauthConfigError::AmbiguousSigningKey)
	);
}

#[test]
fn a_key_file_needs_the_static_public_key_too() {
	let oauth: Oauth = toml::from_str(
		"issuer = \"https://mail.example\"\naudience = \"mail\"\nalgorithm = \"ES256\"\ndiscovery_url = \"https://idp.example/.well-known/openid-configuration\"\nsigning_key_file = \"/k\"\n",
	)
	.unwrap();
	assert_eq!(
		oauth.validate(),
		Err(OauthConfigError::SigningKeyWithoutPublicKey)
	);
}
