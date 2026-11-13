//! The reset of the accounts: run alone with `--accounts-only`, listed by its
//! dry run, and continued after a cut without undoing what an administrator
//! did in between.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::Value;

use crate::api::ApiKeyStore;
use crate::directory_store::ResetTarget;
use crate::directory_store::credential_reset::hash_digest;

use super::super::journal::{Intent, Journal, Kind, Scope, State, Step};
use super::checks::account_reset;
use super::fixture::{ACCOUNT, KEYS, accounts, add_account, rotate_dir, run_scoped, server};

const NOW: u64 = 1_900_000_000;

#[test]
fn accounts_only_resets_the_accounts_and_nothing_else() {
	let server = server();
	let ran = run_scoped(&server.config, NOW, Scope::Accounts);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	let result: Value = serde_json::from_str(&ran.out).expect("one JSON object");
	let kinds: Vec<&str> = result["steps"]
		.as_array()
		.unwrap()
		.iter()
		.map(|step| step["kind"].as_str().unwrap())
		.collect();
	assert_eq!(kinds, ["account-reset", "restart"]);
	assert_eq!(result["accounts_reset"], serde_json::json!([ACCOUNT]));
	assert_eq!(result["remaining"], serde_json::json!([]));
	account_reset(&server);
	let keys = ApiKeyStore::open(&server.data_dir).unwrap();
	for (label, before) in KEYS.iter().zip(&server.key_hashes) {
		assert_eq!(
			keys.hash_of(label).as_ref(),
			Some(before),
			"API key {label} was rotated"
		);
	}
	assert!(!rotate_dir(&server).join("journal.json").exists());
}

/// Every file under `dir` with its bytes, by path.
fn tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
	let mut files = Vec::new();
	let mut pending = vec![dir.to_path_buf()];
	while let Some(next) = pending.pop() {
		for entry in std::fs::read_dir(&next).unwrap() {
			let path = entry.unwrap().path();
			if path.is_dir() {
				pending.push(path.clone());
				files.push((path, Vec::new()));
			} else {
				let bytes = std::fs::read(&path).unwrap();
				files.push((path, bytes));
			}
		}
	}
	files.sort();
	files
}

#[test]
fn the_dry_run_lists_the_accounts_and_writes_nothing() {
	let server = server();
	let before = tree(&server.data_dir);
	let mut out = Vec::new();
	let code = super::super::super::accounts::dry_run(&server.config, true, &mut out);
	assert_eq!(code, ExitCode::SUCCESS);
	let listed: Value = serde_json::from_slice(&out).expect("one JSON object");
	assert_eq!(listed["accounts"], serde_json::json!([ACCOUNT]));
	assert_eq!(
		tree(&server.data_dir),
		before,
		"the dry run changed the disk"
	);
	assert!(!rotate_dir(&server).exists());
	let reread = accounts(&server.data_dir).dynamic_account(ACCOUNT).unwrap();
	assert_eq!(reread.password_hash, server.account_hash);
	assert_eq!(reread.reset, None);
}

/// Leave the journal a run cut right after it recorded the reset of
/// `names` would leave.
fn cut_after_prepare(data_dir: &Path, scope: Scope, names: &[&str]) {
	let store = accounts(data_dir);
	let targets = names
		.iter()
		.map(|name| ResetTarget {
			name: name.to_string(),
			digest: hash_digest(&store.dynamic_account(name).unwrap().password_hash),
		})
		.collect();
	let mut reset = Step::pending(Kind::AccountReset, "", None);
	reset.state = State::Prepared;
	reset.intent = Some(Intent::Reset { targets });
	let steps = vec![reset, Step::pending(Kind::Restart, "", None)];
	let dir = super::super::journal::dir(data_dir);
	drop(super::super::lock(data_dir).unwrap());
	Journal::new(scope, NOW, steps, Vec::new())
		.save(&dir)
		.unwrap();
}

#[test]
fn a_password_set_between_the_cut_and_the_resume_is_not_reset_again() {
	let server = server();
	add_account(&server.data_dir, "carol");
	cut_after_prepare(&server.data_dir, Scope::Accounts, &[ACCOUNT, "carol"]);
	let secret = crate::queue::srs::generate_secret().expect("random bytes");
	let fresh = crate::smtp::auth::hash_password(&secret).unwrap();
	accounts(&server.data_dir)
		.set_password_hash("carol", fresh.clone(), None)
		.unwrap();
	let ran = run_scoped(&server.config, NOW + 60, Scope::Accounts);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	account_reset(&server);
	let carol = accounts(&server.data_dir).dynamic_account("carol").unwrap();
	assert_eq!(
		carol.password_hash, fresh,
		"the password the administrator set was undone"
	);
	assert_eq!(carol.reset, None, "carol was locked again");
	assert!(carol.totp_secret.is_some(), "carol lost her second factor");
}

#[test]
fn a_cut_run_of_the_other_scope_is_finished_by_its_own_command_first() {
	let server = server();
	cut_after_prepare(&server.data_dir, Scope::All, &[ACCOUNT]);
	let ran = run_scoped(&server.config, NOW + 60, Scope::Accounts);
	assert_eq!(ran.code, ExitCode::FAILURE);
	let account = accounts(&server.data_dir).dynamic_account(ACCOUNT).unwrap();
	assert_eq!(account.password_hash, server.account_hash);
	assert!(rotate_dir(&server).join("journal.json").exists());
	let ran = run_scoped(&server.config, NOW + 120, Scope::All);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	account_reset(&server);
}
