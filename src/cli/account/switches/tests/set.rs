//! `account set --send/--receive`: what is written, what is reported, and
//! that an account nobody touched keeps a file without the keys.

use std::process::ExitCode;

use super::support::store_with_app;
use super::*;

fn run(
	store: &AccountStore,
	send: Option<bool>,
	receive: Option<bool>,
	json: bool,
) -> (ExitCode, String) {
	let mut out = Vec::new();
	let code = set(store, "app", send, receive, &mut out, json);
	(code, String::from_utf8(out).expect("utf8"))
}

#[test]
fn turning_send_off_is_stored_and_leaves_receive_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	let (code, text) = run(&store, Some(false), None, false);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(text.contains("send off, receive on"), "{text}");
	assert_eq!(store.switches("app"), (false, true));
	let file = std::fs::read_to_string(store.store_path()).expect("accounts.toml");
	assert!(file.contains("send = false"), "{file}");
	assert!(!file.contains("receive"), "{file}");
}

#[test]
fn turning_receive_off_is_stored_and_leaves_send_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	let (code, _) = run(&store, None, Some(false), false);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(store.switches("app"), (true, false));
}

#[test]
fn both_switches_change_in_one_call() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	run(&store, Some(false), Some(false), false);
	assert_eq!(store.switches("app"), (false, false));
}

#[test]
fn turning_a_switch_back_on_removes_the_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	let before = std::fs::read_to_string(store.store_path()).expect("accounts.toml");
	run(&store, Some(false), Some(false), false);
	run(&store, Some(true), Some(true), false);
	let after = std::fs::read_to_string(store.store_path()).expect("accounts.toml");
	assert_eq!(before, after);
}

#[test]
fn an_account_nobody_touched_has_both_switches_on() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	assert_eq!(store.switches("app"), (true, true));
	let file = std::fs::read_to_string(store.store_path()).expect("accounts.toml");
	assert!(
		!file.contains("send") && !file.contains("receive"),
		"{file}"
	);
}

#[test]
fn a_second_identical_run_reports_unchanged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	let (_, first) = run(&store, Some(false), None, true);
	let (_, second) = run(&store, Some(false), None, true);
	assert!(first.contains("\"result\":\"saved\""), "{first}");
	assert!(second.contains("\"result\":\"unchanged\""), "{second}");
	assert!(second.contains("\"send\":false"), "{second}");
}

#[test]
fn an_unknown_account_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	let mut out = Vec::new();
	let code = set(&store, "ghost", Some(false), None, &mut out, false);
	assert_ne!(code, ExitCode::SUCCESS);
}
