use super::*;

/// An `[oauth]` section with a signing key, plus `extra` lines.
fn oauth(extra: &str) -> Oauth {
	toml::from_str(&format!(
		"issuer = \"https://mail.example\"\naudience = \"mail\"\nalgorithm = \"ES256\"\n\
		 public_key = \"K\"\nsigning_key = \"S\"\n{extra}"
	))
	.expect("parse")
}

#[test]
fn defaults_are_an_hour_and_no_refresh_token() {
	let section = oauth("");
	assert_eq!(section.access_token_ttl(), 3600);
	assert_eq!(section.refresh_token_ttl(), None);
	section.validate().expect("defaults are valid");
}

#[test]
fn a_lifetime_inside_its_bounds_is_accepted() {
	let section = oauth("access_token_ttl_secs = 900\nrefresh_token_ttl_secs = 2592000\n");
	section.validate().expect("valid");
	assert_eq!(section.access_token_ttl(), 900);
	assert_eq!(section.refresh_token_ttl(), Some(2_592_000));
}

#[test]
fn the_bounds_themselves_are_accepted() {
	oauth("access_token_ttl_secs = 60\n")
		.validate()
		.expect("min");
	oauth("access_token_ttl_secs = 86400\n")
		.validate()
		.expect("max");
	oauth("access_token_ttl_secs = 3600\nrefresh_token_ttl_secs = 3600\n")
		.validate()
		.expect("refresh min");
	oauth("refresh_token_ttl_secs = 31536000\n")
		.validate()
		.expect("refresh max");
}

#[test]
fn an_access_lifetime_outside_the_bounds_is_refused() {
	for value in [0, 59, 86_401, u64::MAX] {
		let error = oauth(&format!("access_token_ttl_secs = {value}\n"))
			.validate()
			.expect_err("out of range");
		assert_eq!(error, OauthConfigError::AccessLifetimeOutOfRange(value));
		assert!(error.to_string().contains("between 60 and 86400"));
	}
}

#[test]
fn a_refresh_lifetime_outside_the_bounds_is_refused() {
	for value in [0, 3599, 31_536_001] {
		let error = oauth(&format!("refresh_token_ttl_secs = {value}\n"))
			.validate()
			.expect_err("out of range");
		assert_eq!(error, OauthConfigError::RefreshLifetimeOutOfRange(value));
		assert!(error.to_string().contains("between 3600 and 31536000"));
	}
}

#[test]
fn a_refresh_token_may_not_expire_before_its_access_token() {
	let error = oauth("access_token_ttl_secs = 86400\nrefresh_token_ttl_secs = 3600\n")
		.validate()
		.expect_err("shorter");
	assert_eq!(error, OauthConfigError::RefreshShorterThanAccess);
}

#[test]
fn a_lifetime_without_a_signing_key_is_refused() {
	for extra in [
		"access_token_ttl_secs = 900\n",
		"refresh_token_ttl_secs = 7200\n",
	] {
		let section: Oauth = toml::from_str(&format!(
			"issuer = \"i\"\naudience = \"a\"\nalgorithm = \"ES256\"\npublic_key = \"K\"\n{extra}"
		))
		.expect("parse");
		assert_eq!(
			section.validate().expect_err("no signing key"),
			OauthConfigError::LifetimeWithoutSigningKey
		);
	}
}

#[test]
fn a_signing_key_file_also_counts_as_a_signing_key() {
	let section: Oauth = toml::from_str(
		"issuer = \"i\"\naudience = \"a\"\nalgorithm = \"ES256\"\npublic_key = \"K\"\n\
		 signing_key_file = \"/etc/epistle/oauth.key\"\nrefresh_token_ttl_secs = 7200\n",
	)
	.expect("parse");
	section.validate().expect("valid");
}
