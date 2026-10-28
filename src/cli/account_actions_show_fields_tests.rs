//! `epistle account show`: forwards, catch-all, and two-factor
//! enrolment are visible for both dynamic and static accounts, in
//! both the text and the JSON output. The text view previously
//! rendered only the loader-controlled fields for a static row and
//! the dynamic fields for a dynamic row, leaving an operator staring
//! at two different shapes; a static account that forwards mail to a
//! relay is no longer the surprise it was.
//!
//! Lives in a sibling so `account_actions.rs` stays under the per-file
//! code-line budget.

use std::process::ExitCode;

use super::*;
use crate::cli::account_json;
use crate::config::Config;
use crate::directory_store::AccountStore;
use crate::smtp::auth::tests::base::{fixture_password, hash};

fn config_with(data_dir: &std::path::Path, accounts: &str) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{accounts}\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn store(dir: &std::path::Path, config: &Config) -> AccountStore {
	AccountStore::open(
		dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("open store")
}

#[test]
fn show_dynamic_reports_forwards_catch_all_and_two_factor() {
	let dir = tempfile::tempdir().expect("tempdir");
	// No static `alice` so the dynamic mutators accept the add.
	let config = config_with(dir.path(), "");
	let store = store(dir.path(), &config);
	store
		.add(DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: hash(fixture_password()),
			scram: None,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			forward: Vec::new(),
			catch_all: Vec::new(),
			display_name: None,
			save_sent: None,
		})
		.expect("add account");
	store
		.add_forward("alice", "outside@example.com")
		.expect("add forward");
	store
		.add_catch_all("alice", "example.org")
		.expect("add catch-all");

	let mut out = Vec::new();
	assert_eq!(
		show_with_store(&store, "alice", &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.contains("forwards: outside@example.com"),
		"missing forwards line"
	);
	assert!(
		text.contains("catch_all: example.org"),
		"missing catch_all line"
	);
	assert!(text.contains("two_factor: no"), "missing two_factor line");
}

#[test]
fn show_dynamic_two_factor_yes_when_totp_enrolled() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config_with(dir.path(), "");
	let store = store(dir.path(), &config);
	store
		.add(DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: hash(fixture_password()),
			scram: None,
			totp_secret: Some(crate::test_fixtures::fresh_secret()),
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			forward: Vec::new(),
			catch_all: Vec::new(),
			display_name: None,
			save_sent: None,
		})
		.expect("add account");

	let mut out = Vec::new();
	assert_eq!(
		show_with_store(&store, "alice", &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.contains("two_factor: yes"),
		"enrolled TOTP must print as yes"
	);
}

#[test]
fn show_static_reports_forwards_catch_all_and_two_factor() {
	let dir = tempfile::tempdir().expect("tempdir");
	let static_accounts = r#"
[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
forward = ["outside@example.com"]
catch_all = ["example.org"]
password_hash = "stub"
"#;
	let config = config_with(dir.path(), static_accounts);
	let store = store(dir.path(), &config);

	let mut out = Vec::new();
	assert_eq!(
		show_with_store(&store, "alice", &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	// A static account has no disabled flag and no TOTP enrolment; the
	// text view must still print those fields so a script can grep a
	// single shape.
	assert!(text.contains("disabled: no"), "static must report disabled");
	assert!(
		text.contains("forwards: outside@example.com"),
		"static must report forwards"
	);
	assert!(
		text.contains("catch_all: example.org"),
		"static must report catch_all"
	);
	assert!(
		text.contains("two_factor: no"),
		"static must report two_factor"
	);
}

#[test]
fn show_static_no_forwards_or_catch_all_prints_unset() {
	let dir = tempfile::tempdir().expect("tempdir");
	let static_accounts = r#"
[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
password_hash = "stub"
"#;
	let config = config_with(dir.path(), static_accounts);
	let store = store(dir.path(), &config);

	let mut out = Vec::new();
	assert_eq!(
		show_with_store(&store, "alice", &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.contains("forwards: (none)"),
		"empty forwards list must read as (none)"
	);
	assert!(
		text.contains("catch_all: (none)"),
		"empty catch_all list must read as (none)"
	);
}

#[test]
fn show_static_json_includes_forwards_catch_all_and_two_factor() {
	let dir = tempfile::tempdir().expect("tempdir");
	let static_accounts = r#"
[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
forward = ["outside@example.com"]
catch_all = ["example.org"]
password_hash = "stub"
"#;
	let config = config_with(dir.path(), static_accounts);
	let store = store(dir.path(), &config);
	let mut out = Vec::new();
	assert_eq!(
		account_json::show(&store, "alice", &mut out),
		ExitCode::SUCCESS
	);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("parse json");
	let view = value.as_object().expect("object");
	assert_eq!(view["source"], "static");
	assert_eq!(view["two_factor"], false);
	assert_eq!(view["forward"][0], "outside@example.com");
	assert_eq!(view["catch_all"][0], "example.org");
}
