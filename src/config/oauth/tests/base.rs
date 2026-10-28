use super::*;

#[test]
fn the_identity_declarations_default_to_off_and_parse() {
	let base = "issuer = \"i\"\naudience = \"a\"\nalgorithm = \"ES256\"\npublic_key = \"K\"\n";
	let off: Oauth = toml::from_str(base).expect("parse");
	assert!(!off.allow_unverified_email);
	assert!(!off.idp_enforces_second_factor);
	let on: Oauth = toml::from_str(&format!(
		"{base}allow_unverified_email = true\nidp_enforces_second_factor = true\n"
	))
	.expect("parse");
	assert!(on.allow_unverified_email);
	assert!(on.idp_enforces_second_factor);
	let verifier = crate::oauth::OauthVerifier::from_jwks("i", "a", vec![]).declared_by(&on);
	assert!(verifier.second_factor_attested());
}

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
fn signing_key_requires_static_public_key() {
	// With a static public_key, signing_key is accepted (a valid authz server).
	let server: Oauth = toml::from_str(
		r#"
issuer = "https://idp.example"
audience = "mail"
algorithm = "ES256"
public_key = "BASE64PUB"
signing_key = "BASE64PRIV"
"#,
	)
	.expect("parse");
	server.validate().expect("valid authz server");

	// signing_key with discovery instead of a static public_key is rejected.
	let bad: Oauth = toml::from_str(
		r#"
issuer = "https://idp.example"
audience = "mail"
algorithm = "ES256"
discovery_url = "https://idp.example/.well-known/openid-configuration"
signing_key = "BASE64PRIV"
"#,
	)
	.expect("parse");
	assert_eq!(
		bad.validate(),
		Err(OauthConfigError::SigningKeyWithoutPublicKey)
	);
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
