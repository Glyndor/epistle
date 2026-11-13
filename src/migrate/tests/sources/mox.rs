//! `domains.conf` of a hostile Mox installation.

use super::bounded;
use crate::migrate::mox::{self, fixture};

/// A directory with the fixture's `mox.conf` and the given `domains.conf`.
fn directory(domains: String) -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(dir.path().join("mox.conf"), fixture::MOX_CONF).expect("write");
	std::fs::write(dir.path().join("domains.conf"), domains).expect("write");
	dir
}

#[test]
fn a_hundred_thousand_domains_are_read_in_linear_time() {
	let mut text = String::from("Domains:\n");
	for index in 0..100_000 {
		text.push_str(&format!("\td{index}.example:\n\t\tDescription: x\n"));
	}
	let dir = directory(text);
	let path = dir.path().to_path_buf();
	let plan = bounded(move || mox::read(&path).expect("plan"));
	assert_eq!(plan.domains.len(), 100_000);
	assert!(plan.skipped.is_empty(), "{:?}", plan.skipped.first());
}

#[test]
fn a_hundred_thousand_accounts_and_addresses_are_read_in_linear_time() {
	let mut text = String::from("Domains:\n\texample.org:\nAccounts:\n");
	for index in 0..100_000 {
		text.push_str(&format!(
			"\tu{index}:\n\t\tDestinations:\n\t\t\tu{index}@example.org:\n"
		));
	}
	let dir = directory(text);
	let path = dir.path().to_path_buf();
	let plan = bounded(move || mox::read(&path).expect("plan"));
	assert_eq!(plan.accounts.len(), 100_000);
}

#[test]
fn names_with_control_characters_are_skipped_and_never_reach_the_report() {
	let text = "Domains:\n\texample.org:\n\t\tAliases:\n\t\t\tbad\u{1b}[2Jname:\n\t\t\t\tAddresses:\n\t\t\t\t\t- alice@example.org\nAccounts:\n\tev\u{1b}]0;x\u{7}il:\n\t\tDestinations:\n\t\t\tevil@example.org:\n";
	let dir = directory(text.to_string());
	let plan = mox::read(dir.path()).expect("plan");
	assert!(plan.accounts.is_empty(), "{:?}", plan.accounts);
	assert!(plan.aliases.is_empty(), "{:?}", plan.aliases);
	let shown = format!("{:?}", plan.skipped);
	assert!(shown.contains("alias"), "{shown}");
	assert!(shown.contains("account"), "{shown}");
}

#[test]
fn a_clean_account_of_the_same_shape_is_imported() {
	// Pair for the case above: the same blocks with plain names.
	let text = "Domains:\n\texample.org:\nAccounts:\n\tevil:\n\t\tDestinations:\n\t\t\tevil@example.org:\n";
	let dir = directory(text.to_string());
	let plan = mox::read(dir.path()).expect("plan");
	assert_eq!(plan.accounts.len(), 1);
	assert!(plan.skipped.is_empty());
}
