//! Tests for `epistle account save-sent` and the `on`/`off` switch
//! it shares with `app-password create --save-sent`. Kept in a
//! sibling file so the umbrella `cli_account_subcommand_tests`
//! stays under the per-file line budget.

use std::process::ExitCode;

use crate::cli::account;
use crate::cli::cli_account_subcommand_tests::{DYNAMIC_NAME, STATIC_NAME, build, reload_store};

#[test]
fn parse_on_off_accepts_on_and_off_in_either_case() {
	assert!(account::parse_on_off("on").unwrap());
	assert!(account::parse_on_off("ON").unwrap());
	assert!(!account::parse_on_off("off").unwrap());
	assert!(!account::parse_on_off("OFF").unwrap());
	assert!(account::parse_on_off("true").is_err());
	assert!(account::parse_on_off("maybe").is_err());
}

#[test]
fn save_sent_setter_persists_to_disk_and_rebuilds_the_directory() {
	let harness = build();
	let store = reload_store(&harness);
	assert_eq!(
		account::save_sent_with_store(&store, DYNAMIC_NAME, false),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	assert_eq!(
		store.handle().current().save_sent_for(DYNAMIC_NAME),
		Some(false)
	);
	// Toggle back on.
	let store = reload_store(&harness);
	assert_eq!(
		account::save_sent_with_store(&store, DYNAMIC_NAME, true),
		ExitCode::SUCCESS
	);
	let store = reload_store(&harness);
	assert_eq!(
		store.handle().current().save_sent_for(DYNAMIC_NAME),
		Some(true)
	);
}

#[test]
fn save_sent_setter_rejects_a_static_account() {
	let harness = build();
	let store = reload_store(&harness);
	// The handler maps a static account to a refused exit code; the
	// mutator returns `NotFound`, which the CLI surfaces as the
	// "edit the config" hint.
	assert_ne!(
		account::save_sent_with_store(&store, STATIC_NAME, false),
		ExitCode::SUCCESS
	);
}

#[test]
fn save_sent_setter_rejects_an_unknown_account() {
	let harness = build();
	let store = reload_store(&harness);
	assert_ne!(
		account::save_sent_with_store(&store, "carol", true),
		ExitCode::SUCCESS
	);
}
