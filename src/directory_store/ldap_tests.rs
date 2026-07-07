//! Unit tests for the pure parts of the LDAP backend: RFC 4515 filter escaping,
//! `%s` substitution and attribute mapping. The live-bind and search-load paths
//! need a real server and are covered by the gated integration tests in
//! `tests/ldap.rs`.

use std::collections::HashMap;

use ldap3::SearchEntry;

use super::{account_name, build_filter, escape_filter, first_value};
use crate::config::Ldap;

fn config() -> Ldap {
	toml::from_str(
		r#"
url = "ldap://dir.example.org"
bind_dn = "cn=svc"
bind_password = "p"
base_dn = "dc=example,dc=org"
user_filter = "(uid=%s)"
account_attribute = "uid"
mail_attribute = "mail"
"#,
	)
	.expect("parse ldap config")
}

fn entry(attrs: &[(&str, &[&str])]) -> SearchEntry {
	let mut map: HashMap<String, Vec<String>> = HashMap::new();
	for (key, values) in attrs {
		map.insert(
			(*key).to_string(),
			values.iter().map(|v| (*v).to_string()).collect(),
		);
	}
	SearchEntry {
		dn: "uid=alice,dc=example,dc=org".to_string(),
		attrs: map,
		bin_attrs: HashMap::new(),
	}
}

#[test]
fn escapes_rfc4515_metacharacters() {
	assert_eq!(escape_filter("a*b"), "a\\2ab");
	assert_eq!(escape_filter("a(b"), "a\\28b");
	assert_eq!(escape_filter("a)b"), "a\\29b");
	assert_eq!(escape_filter("a\\b"), "a\\5cb");
	assert_eq!(escape_filter("a\0b"), "a\\00b");
	// A plain value is unchanged.
	assert_eq!(escape_filter("alice"), "alice");
}

#[test]
fn escaping_neutralizes_a_filter_injection_attempt() {
	// A login crafted to widen the filter to "any user" must be neutralized:
	// every metacharacter is escaped, so the structure stays intact.
	let malicious = "*)(uid=*))(|(uid=*";
	let escaped = escape_filter(malicious);
	assert!(!escaped.contains('*'));
	assert!(!escaped.contains('('));
	assert!(!escaped.contains(')'));
}

#[test]
fn substitutes_every_placeholder_with_the_escaped_login() {
	assert_eq!(build_filter("(uid=%s)", "alice"), "(uid=alice)");
	// Both occurrences are replaced, and the login is escaped.
	assert_eq!(
		build_filter("(|(uid=%s)(mail=%s))", "a*b"),
		"(|(uid=a\\2ab)(mail=a\\2ab))"
	);
}

#[test]
fn maps_account_from_the_configured_attribute() {
	let config = config();
	let entry = entry(&[("uid", &["alice"]), ("mail", &["alice@example.org"])]);
	assert_eq!(account_name(&config, &entry), Some("alice".to_string()));
}

#[test]
fn falls_back_to_mail_when_account_attribute_absent() {
	let config = config();
	let entry = entry(&[("mail", &["bob@example.org"])]);
	assert_eq!(
		account_name(&config, &entry),
		Some("bob@example.org".to_string())
	);
}

#[test]
fn maps_to_none_when_no_usable_attribute() {
	let config = config();
	let entry = entry(&[("cn", &["nobody"])]);
	assert_eq!(account_name(&config, &entry), None);
}

#[test]
fn first_value_skips_empty_and_missing() {
	let entry = entry(&[
		("uid", &[""]),
		("mail", &["x@example.org", "y@example.org"]),
	]);
	assert_eq!(first_value(&entry, "uid"), None);
	assert_eq!(first_value(&entry, "absent"), None);
	assert_eq!(
		first_value(&entry, "mail"),
		Some("x@example.org".to_string())
	);
}
