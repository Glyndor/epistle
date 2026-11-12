//! A receive-only domain takes mail and lends no sender: nobody owns an
//! address in it, and what delivery would send on its own is dropped.

use super::{Directory, Resolution};
use crate::smtp::address::Address;

fn parse(raw: &str) -> Address {
	Address::parse(raw).expect("valid address")
}

fn directory(send_off: &[&str]) -> Directory {
	Directory::new(
		["example.org".to_string(), "example.net".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("alice@example.net".to_string(), "alice".to_string()),
		],
	)
	.with_domain_aliases([("alias.example.net".to_string(), "example.net".to_string())])
	.with_send_off_domains(send_off.iter().map(|domain| (*domain).to_string()))
}

#[test]
fn nobody_owns_an_address_in_a_receive_only_domain() {
	let directory = directory(&["example.net"]);
	for raw in ["alice@example.net", "ALICE@Example.NET"] {
		assert!(!directory.owns_address("alice", &parse(raw)), "{raw}");
	}
}

#[test]
fn the_same_account_still_owns_its_address_in_another_domain() {
	let directory = directory(&["example.net"]);
	assert!(directory.owns_address("alice", &parse("alice@example.org")));
}

#[test]
fn a_domain_nobody_listed_lends_senders() {
	let directory = directory(&[]);
	assert!(directory.owns_address("alice", &parse("alice@example.net")));
}

#[test]
fn an_alias_of_a_receive_only_domain_lends_no_sender() {
	let directory = directory(&["example.net"]);
	assert!(directory.domain_send_off("alias.example.net"));
}

#[test]
fn a_receive_only_domain_still_takes_mail() {
	let directory = directory(&["example.net"]);
	assert_eq!(
		directory.resolve(&parse("alice@example.net")),
		Resolution::Account("alice".to_string())
	);
}

#[test]
fn delivery_to_an_address_of_the_domain_may_not_send_on_its_own() {
	let directory = directory(&["example.net"]);
	assert!(!directory.address_may_send("alice@example.net"));
	assert!(!directory.address_may_send("Alice@EXAMPLE.net"));
	assert!(directory.address_may_send("alice@example.org"));
	assert!(directory.address_may_send("not-an-address"));
}
