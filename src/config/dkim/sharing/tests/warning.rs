//! An install whose default key signs two domains is reported, one whose
//! domains each have a key is not.

use std::collections::HashMap;

use crate::config::Dkim;

fn dkim(overrides: &str) -> Dkim {
	toml::from_str(&format!(
		"selector = \"s1\"\nkey_file = \"/k/default.pem\"\n{overrides}"
	))
	.unwrap_or_else(|error| panic!("parses: {error}"))
}

fn names(list: &[&str]) -> Vec<String> {
	list.iter().map(|d| (*d).to_string()).collect()
}

#[test]
fn one_domain_on_the_default_key_is_not_sharing() {
	let none = HashMap::new();
	assert_eq!(
		dkim("").shared_default_warning(&names(&["a.example"]), &none),
		None
	);
}

#[test]
fn two_domains_on_the_default_key_are_named() {
	let none = HashMap::new();
	let warning = dkim("")
		.shared_default_warning(&names(&["b.example", "A.example"]), &none)
		.expect("shared");
	assert!(
		warning.starts_with("2 domains sign with the one [dkim] key (a.example, b.example)"),
		"{warning}"
	);
	assert!(warning.contains("one [[dkim.domain]] entry"), "{warning}");
}

#[test]
fn an_alias_domain_counts_as_a_signing_domain() {
	let aliases = HashMap::from([("alias.example".to_string(), "a.example".to_string())]);
	assert!(
		dkim("")
			.shared_default_warning(&names(&["a.example"]), &aliases)
			.is_some()
	);
}

#[test]
fn a_domain_with_its_own_entry_is_off_the_default() {
	let none = HashMap::new();
	let own =
		dkim("[[domain]]\nname = \"b.example\"\nselector = \"s1\"\nkey_file = \"/k/b.pem\"\n");
	let domains = names(&["a.example", "b.example"]);
	assert_eq!(
		own.domains_on_default(&domains, &none),
		names(&["a.example"])
	);
	assert_eq!(own.shared_default_warning(&domains, &none), None);
}
