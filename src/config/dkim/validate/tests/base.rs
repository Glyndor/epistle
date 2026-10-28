//! The exact messages `[[dkim.domain]]` validation gives, so an operator
//! reading the error can find the entry and the rule it broke.

use std::collections::HashMap;

use crate::config::{ConfigError, Dkim};

fn dkim(overrides: &str) -> Dkim {
	toml::from_str(&format!(
		"selector = \"mail\"\nkey_file = \"/etc/mail/dkim.pem\"\n{overrides}"
	))
	.unwrap_or_else(|error| panic!("the [dkim] block parses: {error}"))
}

fn message(dkim: &Dkim, domains: &[&str], aliases: &[&str]) -> Option<String> {
	let domains: Vec<String> = domains.iter().map(|d| (*d).to_string()).collect();
	let aliases: HashMap<String, String> = aliases
		.iter()
		.map(|a| ((*a).to_string(), "example.org".to_string()))
		.collect();
	match dkim.validate(&domains, &aliases) {
		Ok(()) => None,
		Err(ConfigError::Invalid(text)) => Some(text),
		Err(_) => Some("not a ConfigError::Invalid".to_string()),
	}
}

const ORG: &str =
	"[[domain]]\nname = \"example.org\"\nselector = \"ed-a\"\nkey_file = \"/a.pem\"\n";

#[test]
fn a_hosted_domain_and_an_alias_domain_are_accepted() {
	let both = dkim(&format!(
		"{ORG}[[domain]]\nname = \"example.net\"\nselector = \"ed-b\"\nkey_file = \"/b.pem\"\n"
	));
	assert_eq!(message(&both, &["example.org"], &["example.net"]), None);
}

#[test]
fn a_domain_the_server_does_not_host_is_named_exactly() {
	let other =
		dkim("[[domain]]\nname = \"other.example\"\nselector = \"ed-a\"\nkey_file = \"/a.pem\"\n");
	assert_eq!(
		message(&other, &["example.org"], &[]).as_deref(),
		Some(
			"[dkim.domain] name = \"other.example\" is not in [domains] or [domain_aliases]; \
			 per-domain keys can only sign domains the server hosts"
		)
	);
}

#[test]
fn a_domain_listed_twice_in_any_case_is_named_exactly() {
	let twice = dkim(&format!(
		"{ORG}[[domain]]\nname = \"Example.ORG\"\nselector = \"ed-b\"\nkey_file = \"/b.pem\"\n"
	));
	assert_eq!(
		message(&twice, &["example.org"], &[]).as_deref(),
		Some("[dkim.domain] name = \"example.org\" is listed more than once")
	);
}

#[test]
fn half_an_rsa_pair_is_named_exactly() {
	let half = dkim(&format!("{ORG}rsa_selector = \"rsa-a\"\n"));
	assert_eq!(
		message(&half, &["example.org"], &[]).as_deref(),
		Some(
			"[dkim.domain] name = \"example.org\": rsa_selector and rsa_key_file must be set together"
		)
	);
}
