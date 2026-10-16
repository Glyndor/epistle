//! `epistle account show` prints an account's log pseudonym and
//! `epistle account find-log-id` maps a pseudonym back to the account.

use std::path::Path;

use super::*;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::auth::tests::{fixture_password, hash};

fn store_with(dir: &Path, names: &[&str]) -> AccountStore {
	let store = AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");
	for name in names {
		store
			.add(DynamicAccount {
				name: (*name).to_string(),
				addresses: vec![format!("{name}@example.org")],
				password_hash: hash(fixture_password()),
				scram: None,
				totp_secret: None,
				disabled: false,
				quota_bytes: None,
				allowed_protocols: None,
				..DynamicAccount::default()
			})
			.expect("add account");
	}
	store
}

#[test]
fn show_prints_the_log_pseudonym() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with(dir.path(), &["bob"]);
	let mut out = Vec::new();
	assert_eq!(
		account::show_with_store(&store, "bob", &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	let expected = format!("log_id: {}\n", crate::log_id::account("bob"));
	assert!(
		text.contains(&expected),
		"`account show` must print the log_id line"
	);
}

#[test]
fn find_log_id_maps_a_pseudonym_back_to_its_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with(dir.path(), &["bob", "carol"]);
	let mut out = Vec::new();
	let code =
		account::find_log_id_with_store(&store, &crate::log_id::account("carol"), &mut out, false);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(String::from_utf8(out).expect("utf8"), "carol\n");
}

#[test]
fn find_log_id_matches_a_login_that_was_an_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with(dir.path(), &["bob"]);
	let mut out = Vec::new();
	let code = account::find_log_id_with_store(
		&store,
		&crate::log_id::account("bob@example.org"),
		&mut out,
		false,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(String::from_utf8(out).expect("utf8"), "bob\n");
}

#[test]
fn find_log_id_reports_no_match_without_printing_anything() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with(dir.path(), &["bob"]);
	let mut out = Vec::new();
	let code = account::find_log_id_with_store(&store, "acct-000000000000", &mut out, false);
	assert_eq!(code, ExitCode::from(2));
	assert!(out.is_empty(), "a miss must print nothing on stdout");
}

#[test]
fn find_log_id_subcommand_parses() {
	let cli = Cli::try_parse_from(["epistle", "account", "find-log-id", "acct-0123456789ab"])
		.expect("parse");
	assert!(
		matches!(
			cli.command,
			Command::Account {
				action: account::Subcommand::FindLogId { .. },
				..
			}
		),
		"`account find-log-id <id>` must parse to Subcommand::FindLogId"
	);
}
