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
///
/// Built at run time rather than written as a literal. A constant string
/// flowing into `bind_password`, `signing_key`, `secret` or `srs_secret` is a
/// constant reaching a credential-named sink, which is what
/// `rust/hard-coded-cryptographic-value` reports — and it is right to: that is
/// the shape of a real hard-coded secret, and the query cannot tell this one
/// apart by looking at it.
///
/// #679 records the lesson from the six pull requests that tried to make the
/// literal progressively harder to pattern-match: the alert moved six times and
/// the code got worse. The fix is to remove the node the path starts from, not
/// to disguise it. There is no constant here to start from.
fn sentinel() -> String {
	format!("SENTINEL-DO-NOT-LEAK-{}", uuid::Uuid::new_v4().simple())
}

/// Assert the rendering without ever putting it in the failure message.
///
/// The first version printed `{rendered}` on failure, and I defended it: the
/// dump is what would have reached the logs, so showing it made the point. That
/// was wrong, and CodeQL said so — `Cleartext logging of sensitive information`,
/// twice, on exactly those two lines.
///
/// It is right. A panic message goes to the CI log, and CI logs are retained and
/// widely readable. A test that fails by writing the secret-bearing struct into
/// them leaks on the one run where it matters. That the secret here is a
/// generated sentinel does not change the shape, and the shape is what the next
/// person copies.
///
/// #679 says to remove the node the path starts from rather than disguise it.
/// The rendering never enters a message, so there is no path. The failure still
/// names the struct, the field, and which of the two properties broke, which is
/// everything needed to reproduce it locally with the dump in front of you.
fn assert_redacted(struct_name: &str, field_name: &str, sentinel: &str, rendered: &str) {
	assert!(
		!rendered.contains(sentinel),
		"{struct_name}.{field_name} leaked its value through Debug. \
		 The rendering is deliberately not shown here: printing it is the leak. \
		 Reproduce locally to inspect it."
	);
	assert!(
		rendered.contains("***"),
		"{struct_name}.{field_name} has no `***` redaction marker in Debug, so \
		 the field was dropped rather than redacted. The rendering is \
		 deliberately not shown here."
	);
}

#[test]
fn ldap_bind_password_is_redacted() {
	let sentinel = sentinel();
	let ldap: Ldap = toml::from_str(&format!(
		r#"
url = "ldaps://ldap.example.org"
bind_dn = "cn=svc,dc=example,dc=org"
bind_password = "{sentinel}"
base_dn = "ou=people,dc=example,dc=org"
user_filter = "(uid=%s)"
"#
	))
	.expect("ldap parses");
	assert_redacted("Ldap", "bind_password", &sentinel, &format!("{ldap:?}"));
}

#[test]
fn oauth_signing_key_is_redacted() {
	let sentinel = sentinel();
	let oauth: Oauth = toml::from_str(&format!(
		r#"
issuer = "https://idp.example"
audience = "mail"
algorithm = "ES256"
public_key = "BASE64PUB"
signing_key = "{sentinel}"
"#
	))
	.expect("oauth parses");
	assert_redacted("Oauth", "signing_key", &sentinel, &format!("{oauth:?}"));
}

#[test]
fn database_url_is_redacted() {
	let sentinel = sentinel();
	let db: Database = toml::from_str(&format!(
		r#"url = "postgres://user:{sentinel}@host.example/mail"
max_connections = 5
directory = true"#
	))
	.expect("database parses");
	assert_redacted("Database", "url", &sentinel, &format!("{db:?}"));
}

#[test]
fn webhook_secret_is_redacted() {
	let sentinel = sentinel();
	let webhook: Webhook = toml::from_str(&format!(
		r#"
url = "https://hooks.example/mail"
secret = "{sentinel}"
"#
	))
	.expect("webhook parses");
	assert_redacted("Webhook", "secret", &sentinel, &format!("{webhook:?}"));
}

#[test]
fn config_srs_secret_is_redacted() {
	let sentinel = sentinel();
	let config: Config = toml::from_str(&format!(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
srs_secret = "{sentinel}"
"#
	))
	.expect("config parses");
	assert_redacted("Config", "srs_secret", &sentinel, &format!("{config:?}"));
}
