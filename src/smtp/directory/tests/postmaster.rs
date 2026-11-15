//! RFC 5321 section 4.5.1: `postmaster` is accepted at the server's own name
//! and at every hosted domain, and reaches the operator's postmaster mailbox.

use super::{Directory, Resolution};
use crate::smtp::address::Address;

fn parse(raw: &str) -> Address {
	Address::parse(raw).expect("valid address")
}

/// `example.net` has no postmaster of its own and `example.org` has one that
/// belongs to `ops`; `mail.example.org` is the server's name, hosted by nobody.
fn directory() -> Directory {
	Directory::new(
		["example.org".to_string(), "example.net".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("postmaster@example.org".to_string(), "ops".to_string()),
			("bob@example.net".to_string(), "bob".to_string()),
		],
	)
	.with_server_name("Mail.Example.Org")
}

#[test]
fn postmaster_at_the_server_name_reaches_the_operator_mailbox() {
	for raw in ["postmaster@mail.example.org", "POSTMASTER@MAIL.EXAMPLE.ORG"] {
		assert_eq!(
			directory().resolve(&parse(raw)),
			Resolution::Account("ops".to_string()),
			"{raw}"
		);
	}
}

#[test]
fn postmaster_at_a_hosted_domain_without_one_reaches_the_operator_mailbox() {
	assert_eq!(
		directory().resolve(&parse("postmaster@example.net")),
		Resolution::Account("ops".to_string())
	);
}

#[test]
fn a_hosted_domains_own_postmaster_wins() {
	let directory = Directory::new(
		["example.org".to_string(), "example.net".to_string()],
		[
			("postmaster@example.org".to_string(), "ops".to_string()),
			("postmaster@example.net".to_string(), "net".to_string()),
		],
	)
	.with_server_name("mail.example.org");
	assert_eq!(
		directory.resolve(&parse("postmaster@example.net")),
		Resolution::Account("net".to_string())
	);
}

#[test]
fn only_postmaster_is_accepted_at_the_server_name() {
	assert_eq!(
		directory().resolve(&parse("alice@mail.example.org")),
		Resolution::NotLocal
	);
}

#[test]
fn without_a_server_name_the_hostname_is_not_local() {
	let directory = Directory::new(
		["example.org".to_string()],
		[("postmaster@example.org".to_string(), "ops".to_string())],
	);
	assert_eq!(
		directory.resolve(&parse("postmaster@mail.example.org")),
		Resolution::NotLocal
	);
}

#[test]
fn without_any_postmaster_nothing_is_invented() {
	let directory = Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_server_name("mail.example.org");
	assert_eq!(
		directory.resolve(&parse("postmaster@example.org")),
		Resolution::UnknownUser
	);
	assert_eq!(
		directory.resolve(&parse("postmaster@mail.example.org")),
		Resolution::NotLocal
	);
}

#[test]
fn a_switched_off_domain_gets_no_postmaster() {
	let directory = directory().with_disabled_domains(["example.net".to_string()]);
	assert_eq!(
		directory.resolve(&parse("postmaster@example.net")),
		Resolution::UnknownUser
	);
}

#[test]
fn a_catch_all_or_an_alias_domain_postmaster_is_found() {
	let directory = Directory::new(
		["example.org".to_string(), "example.net".to_string()],
		[("bob@example.net".to_string(), "bob".to_string())],
	)
	.with_catch_all([("example.net".to_string(), "bob".to_string())])
	.with_domain_aliases([("alias.example.net".to_string(), "example.org".to_string())])
	.with_server_name("mail.example.org");
	assert_eq!(
		directory.resolve(&parse("postmaster@mail.example.org")),
		Resolution::Account("bob".to_string())
	);
	assert_eq!(
		directory.resolve(&parse("postmaster@alias.example.net")),
		Resolution::Account("bob".to_string())
	);
}

#[test]
fn the_server_name_is_not_an_identity_to_sign_in_as() {
	assert_eq!(
		directory().resolve_exact(&parse("postmaster@mail.example.org")),
		None
	);
}

#[test]
fn delivery_names_the_operator_account_for_the_server_name() {
	assert_eq!(
		directory().final_recipients(&parse("postmaster@mail.example.org")),
		Some(vec![(
			"ops".to_string(),
			"postmaster@example.org".to_string()
		)])
	);
}

#[test]
fn the_server_name_counts_as_a_report_domain_but_not_a_hosted_one() {
	let directory = directory();
	assert!(
		directory
			.report_domains()
			.contains(&"mail.example.org".to_string())
	);
	assert!(!directory.hosts_domain("mail.example.org"));
}
