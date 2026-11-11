//! The switches in `account show` and `account list --json`, for a dynamic
//! and a static account.

use std::process::ExitCode;

use super::support::{config, store, store_with_app};
use super::*;
use crate::cli::account::json as account_json;
use crate::cli::account::show_with_store;

#[test]
fn show_prints_the_switches_of_a_dynamic_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	let mut sink = Vec::new();
	set(&store, "app", Some(false), None, &mut sink, false);
	let mut out = Vec::new();
	assert_eq!(show_with_store(&store, "app", &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("send: off"), "{text}");
	assert!(text.contains("receive: on"), "{text}");
}

#[test]
fn show_json_carries_the_switches_of_a_dynamic_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	let mut sink = Vec::new();
	set(&store, "app", None, Some(false), &mut sink, false);
	let mut out = Vec::new();
	assert_eq!(
		account_json::show(&store, "app", &mut out),
		ExitCode::SUCCESS
	);
	let view: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(view["send"], true);
	assert_eq!(view["receive"], false);
}

const STATIC_RELAY: &str = r#"
[[accounts]]
name = "relay"
addresses = ["relay@example.org"]
password_hash = "stub"
send = false
"#;

#[test]
fn a_static_account_reads_its_switches_from_the_configuration() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), STATIC_RELAY);
	let store = store(dir.path(), &config);
	assert_eq!(store.switches("relay"), (false, true));
}

#[test]
fn show_prints_the_switches_of_a_static_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), STATIC_RELAY);
	let store = store(dir.path(), &config);
	let mut out = Vec::new();
	assert_eq!(
		show_with_store(&store, "relay", &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("send: off"), "{text}");
	assert!(text.contains("receive: on"), "{text}");
}

#[test]
fn show_json_carries_the_switches_of_a_static_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), STATIC_RELAY);
	let store = store(dir.path(), &config);
	let mut out = Vec::new();
	assert_eq!(
		account_json::show(&store, "relay", &mut out),
		ExitCode::SUCCESS
	);
	let view: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(view["send"], false);
	assert_eq!(view["receive"], true);
}

#[test]
fn list_json_carries_the_switches_of_every_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_app(&dir);
	let mut sink = Vec::new();
	set(&store, "app", Some(false), Some(false), &mut sink, false);
	let config = config(dir.path(), "");
	let mut out = Vec::new();
	assert_eq!(
		account_json::list(&config, false, &mut out),
		ExitCode::SUCCESS
	);
	let rows: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(rows[0]["send"], false);
	assert_eq!(rows[0]["receive"], false);
}
