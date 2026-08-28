//! Property test: every config struct that holds a secret must keep the secret
//! out of its `Debug` rendering. If anyone re-derives `Debug` on `Config` or
//! replaces a redacted field with `&self.field`, these tests turn red.
//!
//! One struct, one sentinel — a string that cannot appear by accident in any
//! other fixture. Each case asserts both that the sentinel is absent and that
//! a `***` redaction marker is present, so a debug impl that simply removes the
//! field (rather than redacting it) is also caught.

use super::Config;
use crate::config::{Database, Ldap, Oauth, Webhook};

/// The recognition token for every test in this file. It must never appear
/// inside any `format!("{:?}", …)` output of these structs.
const SENTINEL: &str = "SENTINEL-DO-NOT-LEAK-8f3a";

fn assert_redacted(struct_name: &str, field_name: &str, rendered: &str) {
	assert!(
		!rendered.contains(SENTINEL),
		"{struct_name}.{field_name} leaked through Debug: {rendered}"
	);
	assert!(
		rendered.contains("***"),
		"{struct_name}.{field_name} missing redaction marker in Debug: {rendered}"
	);
}

#[test]
fn ldap_bind_password_is_redacted() {
	let ldap: Ldap = toml::from_str(&format!(
		r#"
url = "ldaps://ldap.example.org"
bind_dn = "cn=svc,dc=example,dc=org"
bind_password = "{SENTINEL}"
base_dn = "ou=people,dc=example,dc=org"
user_filter = "(uid=%s)"
"#
	))
	.expect("ldap parses");
	assert_redacted("Ldap", "bind_password", &format!("{ldap:?}"));
}

#[test]
fn oauth_signing_key_is_redacted() {
	let oauth: Oauth = toml::from_str(&format!(
		r#"
issuer = "https://idp.example"
audience = "mail"
algorithm = "ES256"
public_key = "BASE64PUB"
signing_key = "{SENTINEL}"
"#
	))
	.expect("oauth parses");
	assert_redacted("Oauth", "signing_key", &format!("{oauth:?}"));
}

#[test]
fn database_url_is_redacted() {
	let db: Database = toml::from_str(&format!(
		r#"url = "postgres://user:{SENTINEL}@host.example/mail"
max_connections = 5
directory = true"#
	))
	.expect("database parses");
	assert_redacted("Database", "url", &format!("{db:?}"));
}

#[test]
fn webhook_secret_is_redacted() {
	let webhook: Webhook = toml::from_str(&format!(
		r#"
url = "https://hooks.example/mail"
secret = "{SENTINEL}"
"#
	))
	.expect("webhook parses");
	assert_redacted("Webhook", "secret", &format!("{webhook:?}"));
}

#[test]
fn config_srs_secret_is_redacted() {
	let config: Config = toml::from_str(&format!(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
srs_secret = "{SENTINEL}"
"#
	))
	.expect("config parses");
	assert_redacted("Config", "srs_secret", &format!("{config:?}"));
}
