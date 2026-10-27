//! A disabled domain stays hosted but takes no mail and lends no sender.

use super::{Directory, Resolution};
use crate::smtp::address::Address;

fn parse(raw: &str) -> Address {
	Address::parse(raw).expect("valid address")
}

fn directory(disabled: &[&str]) -> Directory {
	Directory::new(
		["example.org".to_string(), "example.net".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("alice@example.net".to_string(), "alice".to_string()),
		],
	)
	.with_domain_aliases([("alias.example.net".to_string(), "example.net".to_string())])
	.with_catch_all([("example.net".to_string(), "alice".to_string())])
	.with_masked([("shop.abc@example.net".to_string(), "alice".to_string())])
	.with_disabled_domains(disabled.iter().map(|domain| (*domain).to_string()))
}

#[test]
fn mail_for_an_enabled_domain_is_delivered() {
	let directory = directory(&["example.net"]);
	assert_eq!(
		directory.resolve(&parse("alice@example.org")),
		Resolution::Account("alice".to_string())
	);
}

#[test]
fn mail_for_a_disabled_domain_is_rejected_like_an_unknown_user() {
	let directory = directory(&["example.net"]);
	for raw in [
		"alice@example.net",
		"ALICE@Example.NET",
		"alice+tag@example.net",
		"anyone@example.net",
		"shop.abc@example.net",
		"alice@alias.example.net",
	] {
		assert_eq!(
			directory.resolve(&parse(raw)),
			Resolution::UnknownUser,
			"{raw} must not be delivered while its domain is disabled"
		);
	}
}

#[test]
fn nobody_sends_as_an_address_in_a_disabled_domain() {
	let directory = directory(&["example.net"]);
	assert!(directory.owns_address("alice", &parse("alice@example.org")));
	assert!(!directory.owns_address("alice", &parse("alice@example.net")));
	assert!(!directory.owns_address("alice", &parse("shop.abc@example.net")));
}

#[test]
fn a_disabled_domain_is_still_hosted() {
	let directory = directory(&["example.net"]);
	assert!(directory.hosts_domain("example.net"));
	assert!(directory.domains().contains(&"example.net".to_string()));
}

#[test]
fn nothing_changes_while_no_domain_is_disabled() {
	let directory = directory(&[]);
	assert_eq!(
		directory.resolve(&parse("alice@example.net")),
		Resolution::Account("alice".to_string())
	);
	assert!(directory.owns_address("alice", &parse("alice@example.net")));
}
