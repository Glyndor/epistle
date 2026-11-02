//! Two domains that name one key file are refused, and the message names
//! both. The acceptance beside each refusal keeps the harness honest: a
//! configuration that fails to parse would otherwise "refuse" everything.

use std::collections::HashMap;

use crate::config::{ConfigError, Dkim};

fn refusal(text: &str, domains: &[&str]) -> Option<String> {
	let dkim: Dkim = toml::from_str(text).unwrap_or_else(|error| panic!("parses: {error}"));
	let domains: Vec<String> = domains.iter().map(|d| (*d).to_string()).collect();
	match dkim.validate(&domains, &HashMap::new()) {
		Ok(()) => None,
		Err(ConfigError::Invalid(text)) => Some(text),
		Err(other) => panic!("not a validation refusal: {other}"),
	}
}

const HEAD: &str = "selector = \"s1\"\nkey_file = \"/k/default.pem\"\n";

fn entry(name: &str, file: &str) -> String {
	format!("[[domain]]\nname = \"{name}\"\nselector = \"s1\"\nkey_file = \"{file}\"\n")
}

#[test]
fn two_entries_with_their_own_files_are_accepted() {
	let text = format!(
		"{HEAD}{}{}",
		entry("a.example", "/k/a.pem"),
		entry("b.example", "/k/b.pem")
	);
	assert_eq!(refusal(&text, &["a.example", "b.example"]), None);
}

#[test]
fn two_entries_on_one_file_are_refused_naming_both() {
	let text = format!(
		"{HEAD}{}{}",
		entry("a.example", "/k/shared.pem"),
		entry("B.example", "/k/shared.pem")
	);
	let message = refusal(&text, &["a.example", "b.example"]).expect("refused");
	assert!(
		message.starts_with(
			"[dkim.domain] name = \"b.example\" and [dkim.domain] name = \"a.example\" \
			 use the same key file /k/shared.pem"
		),
		"{message}"
	);
}

#[test]
fn the_same_file_spelled_differently_is_the_same_file() {
	let text = format!(
		"{HEAD}{}{}",
		entry("a.example", "/k/shared.pem"),
		entry("b.example", "/k/./shared.pem")
	);
	assert!(refusal(&text, &["a.example", "b.example"]).is_some());
}

#[test]
fn an_entry_on_the_default_key_file_is_refused_naming_the_default() {
	let text = format!("{HEAD}{}", entry("a.example", "/k/default.pem"));
	let message = refusal(&text, &["a.example", "b.example"]).expect("refused");
	assert!(
		message.contains("[dkim.domain] name = \"a.example\" and [dkim] (the key every domain"),
		"{message}"
	);
}

#[test]
fn an_rsa_file_shared_between_entries_is_refused() {
	let rsa = |name: &str, ed: &str| {
		format!(
			"[[domain]]\nname = \"{name}\"\nselector = \"s1\"\nkey_file = \"{ed}\"\n\
			 rsa_selector = \"s2\"\nrsa_key_file = \"/k/rsa.pem\"\n"
		)
	};
	let text = format!(
		"{HEAD}{}{}",
		rsa("a.example", "/k/a.pem"),
		rsa("b.example", "/k/b.pem")
	);
	let message = refusal(&text, &["a.example", "b.example"]).expect("refused");
	assert!(message.contains("/k/rsa.pem"), "{message}");
}
