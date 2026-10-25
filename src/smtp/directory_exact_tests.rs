//! `resolve_exact` names an account only through the account's own address:
//! the near matches `resolve` delivers mail by do not open a mailbox.

use super::Directory;
use crate::smtp::address::Address;

fn directory() -> Directory {
	Directory::new(
		["example.org".to_string(), "other.example".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@other.example".to_string(), "bob".to_string()),
		],
	)
	.with_catch_all([("example.org".to_string(), "bob".to_string())])
	.with_masked([("mask@example.org".to_string(), "alice".to_string())])
	.with_domain_aliases([("alias.example".to_string(), "example.org".to_string())])
	.with_disabled_domains(["other.example".to_string()])
}

fn exact(raw: &str) -> Option<String> {
	directory().resolve_exact(&Address::parse(raw).expect("address"))
}

#[test]
fn an_account_address_names_the_account_in_any_case_and_through_a_domain_alias() {
	assert_eq!(exact("alice@example.org").as_deref(), Some("alice"));
	assert_eq!(exact("Alice@EXAMPLE.org").as_deref(), Some("alice"));
	assert_eq!(exact("alice@alias.example").as_deref(), Some("alice"));
}

#[test]
fn a_catch_all_a_mask_a_sub_address_and_a_disabled_domain_name_no_account() {
	assert_eq!(exact("nobody@example.org"), None);
	assert_eq!(exact("mask@example.org"), None);
	assert_eq!(exact("alice+tag@example.org"), None);
	assert_eq!(exact("bob@other.example"), None);
	assert_eq!(exact("alice@elsewhere.example"), None);
}

#[test]
fn an_account_is_named_only_when_it_can_hold_a_password() {
	let directory = directory().with_password_hashes([("alice".to_string(), "h".to_string())]);
	assert_eq!(directory.named_account("Alice").as_deref(), Some("alice"));
	assert_eq!(directory.named_account("bob"), None);
}
