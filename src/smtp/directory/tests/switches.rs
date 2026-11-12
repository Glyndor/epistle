//! The send and receive switches: an account that does not receive resolves
//! like an address that does not exist (and hands its mail to nobody else),
//! an account that does not send owns no sender address, and neither one
//! stops a login.

use super::{AliasSpec, Directory, Resolution};
use crate::config::Protocol;
use crate::smtp::address::Address;
use crate::smtp::auth::tests::base::hash;
use crate::smtp::scram::{ScramCredentials, ScramStored};
use crate::test_support::fixtures;

fn parse(raw: &str) -> Address {
	Address::parse(raw).expect("valid address")
}

/// `app` and `bob` in one domain; `bob` also catches the unknown users and
/// both sit in the alias `team`. `app` has a masked address.
fn directory(send_off: &[&str], receive_off: &[&str]) -> Directory {
	let stored = ScramStored::from_credentials(&ScramCredentials::derive(
		fixtures::password(),
		fixtures::salt(),
		4096,
	));
	Directory::new(
		["example.org".to_string()],
		[
			("app@example.org".to_string(), "app".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	)
	.with_catch_all([("example.org".to_string(), "bob".to_string())])
	.with_masked([("shop.abc@example.org".to_string(), "app".to_string())])
	.with_aliases([(
		"team@example.org".to_string(),
		AliasSpec {
			members: vec!["app@example.org".to_string(), "bob@example.org".to_string()],
			senders: Vec::new(),
			hidden: false,
			list_id: None,
		},
	)])
	.with_password_hashes([("app".to_string(), hash(fixtures::password()))])
	.with_scram([("app".to_string(), stored)])
	.with_switches(
		send_off.iter().map(|name| (*name).to_string()),
		receive_off.iter().map(|name| (*name).to_string()),
	)
}

#[test]
fn an_account_that_does_not_receive_resolves_like_an_unknown_user() {
	let directory = directory(&[], &["app"]);
	assert_eq!(
		directory.resolve(&parse("app@example.org")),
		Resolution::UnknownUser
	);
}

#[test]
fn a_sub_address_and_a_masked_address_of_it_resolve_the_same_way() {
	let directory = directory(&[], &["app"]);
	for raw in ["app+tag@example.org", "shop.abc@example.org"] {
		assert_eq!(
			directory.resolve(&parse(raw)),
			Resolution::UnknownUser,
			"{raw}"
		);
	}
}

#[test]
fn its_mail_is_not_handed_to_the_catch_all() {
	// The address exists, so it must not fall through to bob's catch-all.
	let directory = directory(&[], &["app"]);
	assert_ne!(
		directory.resolve(&parse("app@example.org")),
		Resolution::Account("bob".to_string())
	);
	assert_eq!(
		directory.resolve(&parse("nobody@example.org")),
		Resolution::Account("bob".to_string())
	);
}

#[test]
fn an_alias_drops_the_members_that_do_not_receive() {
	let directory = directory(&[], &["app"]);
	assert_eq!(
		directory.resolve(&parse("team@example.org")),
		Resolution::Alias(vec!["bob".to_string()])
	);
	let finals = directory
		.final_recipients(&parse("team@example.org"))
		.expect("alias resolves");
	assert_eq!(
		finals,
		vec![("bob".to_string(), "bob@example.org".to_string())]
	);
}

#[test]
fn an_alias_whose_members_all_stopped_receiving_is_unknown() {
	let directory = directory(&[], &["app", "bob"]);
	assert_eq!(
		directory.resolve(&parse("team@example.org")),
		Resolution::UnknownUser
	);
	assert!(
		directory
			.final_recipients(&parse("team@example.org"))
			.is_none()
	);
}

#[test]
fn an_account_that_does_not_receive_still_signs_in_by_its_address() {
	let directory = directory(&[], &["app"]);
	assert!(
		directory
			.authenticate("app@example.org", fixtures::password(), Protocol::Smtp)
			.is_some()
	);
	assert!(directory.credentials("app@example.org").is_some());
}

#[test]
fn it_still_has_scram_credentials_by_its_address() {
	let directory = directory(&[], &["app"]);
	assert!(directory.scram_credentials("app@example.org").is_some());
}

#[test]
fn an_account_that_does_not_send_owns_no_sender_address() {
	let directory = directory(&["app"], &[]);
	for raw in [
		"app@example.org",
		"shop.abc@example.org",
		"team@example.org",
	] {
		assert!(
			!directory.owns_address("app", &parse(raw)),
			"{raw} must not be a sender of an account that does not send"
		);
	}
	assert!(directory.owns_address("bob", &parse("team@example.org")));
}

#[test]
fn an_account_that_does_not_send_still_receives_and_signs_in() {
	let directory = directory(&["app"], &[]);
	assert_eq!(
		directory.resolve(&parse("app@example.org")),
		Resolution::Account("app".to_string())
	);
	assert!(
		directory
			.authenticate("app", fixtures::password(), Protocol::Imap)
			.is_some()
	);
}

#[test]
fn nothing_changes_for_accounts_that_set_neither() {
	let directory = directory(&[], &[]);
	assert_eq!(
		directory.resolve(&parse("app@example.org")),
		Resolution::Account("app".to_string())
	);
	assert!(directory.owns_address("app", &parse("app@example.org")));
	assert!(directory.can_send("app") && directory.receives("app"));
}

#[test]
fn the_names_are_matched_without_regard_to_case() {
	let directory = directory(&["App"], &["APP"]);
	assert!(!directory.can_send("app") && !directory.receives("app"));
}
