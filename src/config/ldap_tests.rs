//! Tests for parsing and validating the `[ldap]` configuration section. No LDAP
//! server is needed: these exercise the pure parse + validation logic.

use super::Ldap;

fn full() -> &'static str {
	r#"
url = "ldaps://dir.example.org"
bind_dn = "cn=service,dc=example,dc=org"
bind_password = "secret"
base_dn = "ou=people,dc=example,dc=org"
user_filter = "(uid=%s)"
account_attribute = "uid"
mail_attribute = "mail"
refresh_secs = 600
tls = true
"#
}

#[test]
fn parses_a_full_section_and_validates() {
	let ldap: Ldap = toml::from_str(full()).expect("parse");
	assert_eq!(ldap.url, "ldaps://dir.example.org");
	assert_eq!(ldap.user_filter, "(uid=%s)");
	assert_eq!(ldap.refresh_secs, 600);
	assert!(ldap.tls);
	assert!(ldap.validate().is_ok());
}

#[test]
fn applies_attribute_and_refresh_defaults() {
	let ldap: Ldap = toml::from_str(
		r#"
url = "ldap://dir.example.org"
bind_dn = "cn=svc"
bind_password = "p"
base_dn = "dc=example,dc=org"
user_filter = "(sAMAccountName=%s)"
"#,
	)
	.expect("parse");
	assert_eq!(ldap.account_attribute, "uid");
	assert_eq!(ldap.mail_attribute, "mail");
	assert_eq!(ldap.refresh_secs, 3600);
	assert!(!ldap.tls);
	assert!(ldap.validate().is_ok());
}

#[test]
fn rejects_unknown_keys() {
	let result: Result<Ldap, _> = toml::from_str(
		r#"
url = "ldap://x"
bind_dn = "a"
bind_password = "b"
base_dn = "c"
user_filter = "(uid=%s)"
surprise = true
"#,
	);
	assert!(result.is_err());
}

#[test]
fn rejects_bad_scheme() {
	let mut ldap: Ldap = toml::from_str(full()).expect("parse");
	ldap.url = "https://dir.example.org".to_string();
	assert!(ldap.validate().is_err());
}

#[test]
fn rejects_filter_without_placeholder() {
	let mut ldap: Ldap = toml::from_str(full()).expect("parse");
	ldap.user_filter = "(uid=fixed)".to_string();
	assert!(ldap.validate().is_err());
}

#[test]
fn rejects_empty_required_fields() {
	for mutate in [
		|l: &mut Ldap| l.bind_dn.clear(),
		|l: &mut Ldap| l.bind_password.clear(),
		|l: &mut Ldap| l.base_dn.clear(),
		|l: &mut Ldap| l.account_attribute.clear(),
		|l: &mut Ldap| l.mail_attribute.clear(),
	] {
		let mut ldap: Ldap = toml::from_str(full()).expect("parse");
		mutate(&mut ldap);
		assert!(ldap.validate().is_err());
	}
}

#[test]
fn rejects_zero_refresh() {
	let mut ldap: Ldap = toml::from_str(full()).expect("parse");
	ldap.refresh_secs = 0;
	assert!(ldap.validate().is_err());
}
