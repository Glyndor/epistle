//! Static addresses and domains are read in lowercase, and every entry that
//! was not is named.

use super::*;

const MIXED: &str = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
srs_secret = "a shared srs secret"
domains = ["Example.ORG"]

[domain_aliases]
"Example.NET" = "Example.ORG"

[[accounts]]
name = "alice"
addresses = ["Alice.Smith@Example.ORG", "postmaster@example.org"]
forward = ["Alice@Elsewhere.Example"]
catch_all = ["EXAMPLE.org"]

[[alias]]
address = "Team@Example.ORG"
members = ["Alice.Smith@example.org"]
senders = ["ALICE.SMITH@example.org"]
"#;

fn parse(text: &str) -> Config {
	Config::parse_text(text, std::path::Path::new("mail.toml")).expect("valid config")
}

#[test]
fn static_addresses_and_domains_are_read_in_lowercase() {
	let config = parse(MIXED);
	assert_eq!(config.domains, vec!["example.org"]);
	assert_eq!(
		config.domain_aliases.get("example.net").map(String::as_str),
		Some("example.org")
	);
	let alice = &config.accounts[0];
	assert_eq!(
		alice.addresses,
		vec!["alice.smith@example.org", "postmaster@example.org"]
	);
	assert_eq!(alice.forward, vec!["alice@elsewhere.example"]);
	assert_eq!(alice.catch_all, vec!["example.org"]);
	let team = &config.alias[0];
	assert_eq!(team.address, "team@example.org");
	assert_eq!(team.members, vec!["alice.smith@example.org"]);
	assert_eq!(team.senders, vec!["alice.smith@example.org"]);
}

#[test]
fn every_entry_that_was_not_lowercase_is_named() {
	let config = parse(MIXED);
	assert_eq!(
		config.mixed_case,
		vec![
			"domains: \"Example.ORG\" (used as \"example.org\")",
			"domain_aliases: \"Example.NET\" = \"Example.ORG\" (used as \"example.net\" = \"example.org\")",
			"account \"alice\": address \"Alice.Smith@Example.ORG\" (used as \"alice.smith@example.org\")",
			"account \"alice\": forward \"Alice@Elsewhere.Example\" (used as \"alice@elsewhere.example\")",
			"account \"alice\": catch_all \"EXAMPLE.org\" (used as \"example.org\")",
			"alias \"Team@Example.ORG\" (used as \"team@example.org\")",
			"alias \"team@example.org\": member \"Alice.Smith@example.org\" (used as \"alice.smith@example.org\")",
			"alias \"team@example.org\": sender \"ALICE.SMITH@example.org\" (used as \"alice.smith@example.org\")",
		]
	);
}

#[test]
fn a_lowercase_file_names_nothing() {
	let config = parse(&MIXED.to_lowercase());
	assert!(config.mixed_case.is_empty(), "{:?}", config.mixed_case);
}

#[test]
fn a_unicode_domain_is_still_refused() {
	let text = MIXED.replace(
		"domains = [\"Example.ORG\"]",
		"domains = [\"Example.ORG\", \"Bücher.example\"]",
	);
	let error = Config::parse_text(&text, std::path::Path::new("mail.toml"))
		.expect_err("configuration domains stay ASCII");
	assert!(
		error
			.to_string()
			.contains("must be written as its ASCII form"),
		"{error}"
	);
}

#[test]
fn two_static_accounts_with_one_address_refuse_to_start_naming_both() {
	let text = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "first"
addresses = ["Ärger@example.org", "postmaster@example.org"]

[[accounts]]
name = "second"
addresses = ["ärger@example.org"]
"#;
	let error = Config::parse_text(text, std::path::Path::new("mail.toml"))
		.expect_err("one mailbox cannot belong to two accounts");
	assert_eq!(
		error.to_string(),
		"invalid configuration: address \"ärger@example.org\" belongs to both account \"first\" and account \"second\""
	);
}
