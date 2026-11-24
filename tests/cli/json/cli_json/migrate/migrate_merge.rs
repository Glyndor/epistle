//! What a second `epistle migrate mox` or `migrate stalwart` does to a
//! configuration that already holds what the source describes: refuses
//! without `--merge`, keeps what exists with it, and writes nothing with
//! `--dry-run`, for both sources.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::harness::{Env, env, epistle};
use crate::migrate_import::{
	DOMAINS_CONF, account, accounts, configured_domains, mox_source, stderr, stdout,
};

const STALWART: &str = r#"
[server]
hostname = "mx.moved.example"

[storage]
directory = "memory"

[directory."memory"]
type = "memory"

[[directory."memory".principals]]
class = "individual"
name = "john"
secret = "not-a-real-secret"
description = "John Doe"
email = ["john@moved.example"]
"#;

fn stalwart_source(env: &Env, text: &str) -> PathBuf {
	let file = env.dir.path().join("stalwart.toml");
	std::fs::write(&file, text).expect("stalwart config");
	file
}

fn stalwart(env: &Env, source: &Path, extra: &[&str]) -> std::process::Output {
	let mut args = vec![
		"migrate",
		"--config",
		env.config.as_str(),
		"stalwart",
		"--from",
		source.to_str().expect("utf-8"),
	];
	args.extend_from_slice(extra);
	epistle(&args, b"")
}

fn mox(env: &Env, source: &Path, extra: &[&str]) -> std::process::Output {
	crate::migrate_import::migrate(env, source, extra)
}

/// The Mox directory again, with `bob` beside `alice`.
fn second_mox_source(env: &Env) -> PathBuf {
	let dir = mox_source(env);
	let more = format!(
		"{DOMAINS_CONF}\tbob:\n\t\tDomain: moved.example\n\t\tDestinations:\n\t\t\tbob@moved.example: nil\n"
	);
	std::fs::write(dir.join("domains.conf"), more).expect("domains.conf");
	dir
}

fn json_of(output: &std::process::Output) -> Value {
	serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
		panic!("stdout is not JSON: {error}; stderr: {}", stderr(output));
	})
}

#[test]
fn a_second_import_is_refused_and_says_to_merge() {
	let env = env("");
	let source = mox_source(&env);
	assert_eq!(
		mox(&env, &source, &["--password-reset"]).status.code(),
		Some(0)
	);
	let (config, names) = (configured_domains(&env), accounts(&env));
	let output = mox(&env, &source, &["--password-reset"]);
	assert_eq!(output.status.code(), Some(2));
	assert!(stdout(&output).is_empty());
	let message = stderr(&output);
	assert!(
		message.contains("refusing to overwrite what exists"),
		"{message}"
	);
	assert!(
		message.contains("domain moved.example is already configured"),
		"{message}"
	);
	assert!(
		message.contains("account alice already exists"),
		"{message}"
	);
	assert!(message.contains("--merge"), "{message}");
	assert_eq!((configured_domains(&env), accounts(&env)), (config, names));
}

#[test]
fn merge_keeps_what_exists_and_adds_the_rest() {
	let env = env("");
	let source = mox_source(&env);
	assert_eq!(
		mox(&env, &source, &["--password-reset"]).status.code(),
		Some(0)
	);
	let renamed = epistle(
		&[
			"account",
			"set-name",
			"alice",
			"Alice Kept",
			"--config",
			&env.config,
		],
		b"",
	);
	assert_eq!(renamed.status.code(), Some(0), "{}", stderr(&renamed));

	let more = second_mox_source(&env);
	let output = mox(&env, &more, &["--merge", "--password-reset", "--json"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let changes = &json_of(&output)["changes"];
	assert_eq!(changes["accounts_added"], serde_json::json!(["bob"]));
	assert_eq!(changes["accounts_kept"], serde_json::json!(["alice"]));
	assert_eq!(changes["domains_added"], serde_json::json!([]));
	assert_eq!(
		changes["domains_kept"],
		serde_json::json!(["moved.example"])
	);
	assert_eq!(accounts(&env), ["alice", "bob"]);
	assert_eq!(account(&env, "alice")["display_name"], "Alice Kept");
	assert_eq!(account(&env, "bob")["disabled"], Value::Bool(true));
	assert_eq!(
		configured_domains(&env).matches("moved.example").count(),
		1,
		"the domain is configured once"
	);
}

#[test]
fn merge_with_a_dry_run_writes_nothing() {
	let env = env("");
	let source = mox_source(&env);
	assert_eq!(
		mox(&env, &source, &["--password-reset"]).status.code(),
		Some(0)
	);
	let (config, names) = (configured_domains(&env), accounts(&env));
	let more = second_mox_source(&env);
	let output = mox(&env, &more, &["--merge", "--dry-run"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let text = stdout(&output);
	assert!(text.contains("accounts would add: bob"), "{text}");
	assert!(
		text.contains("accounts already here, kept as they are: alice"),
		"{text}"
	);
	assert_eq!((configured_domains(&env), accounts(&env)), (config, names));
}

#[test]
fn stalwart_dry_run_prints_the_plan_and_writes_nothing() {
	let env = env("");
	let source = stalwart_source(&env, STALWART);
	let before = configured_domains(&env);
	let output = stalwart(&env, &source, &["--dry-run", "--json"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	let value = json_of(&output);
	assert_eq!(value["dry_run"], Value::Bool(true));
	assert_eq!(
		value["changes"]["accounts_added"],
		serde_json::json!(["john"])
	);
	assert_eq!(
		value["changes"]["domains_added"],
		serde_json::json!(["moved.example"])
	);
	assert_eq!(configured_domains(&env), before);
	assert!(accounts(&env).is_empty());
	assert!(!env.data_dir().join("accounts.toml").exists());
	assert!(!env.data_dir().join("dkim-migrated").exists());
}

#[test]
fn stalwart_needs_a_password_choice_and_then_imports_for_real() {
	let env = env("");
	let source = stalwart_source(&env, STALWART);
	let before = configured_domains(&env);
	let refused = stalwart(&env, &source, &[]);
	assert_eq!(refused.status.code(), Some(2));
	assert_eq!(configured_domains(&env), before);
	assert!(accounts(&env).is_empty());

	let output = stalwart(&env, &source, &["--password-reset"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	assert_eq!(accounts(&env), ["john"]);
	assert_eq!(account(&env, "john")["disabled"], Value::Bool(true));
	assert_eq!(account(&env, "john")["display_name"], "John Doe");
	assert!(configured_domains(&env).contains("moved.example"));
}

#[test]
fn stalwart_refuses_a_second_import_and_merges_when_asked() {
	let env = env("");
	let source = stalwart_source(&env, STALWART);
	assert_eq!(
		stalwart(&env, &source, &["--password-reset"]).status.code(),
		Some(0)
	);
	let again = stalwart(&env, &source, &["--password-reset"]);
	assert_eq!(again.status.code(), Some(2));
	assert!(stderr(&again).contains("--merge"), "{}", stderr(&again));

	let merged = stalwart(&env, &source, &["--password-reset", "--merge", "--json"]);
	assert_eq!(merged.status.code(), Some(0), "{}", stderr(&merged));
	let changes = &json_of(&merged)["changes"];
	assert_eq!(changes["accounts_added"], serde_json::json!([]));
	assert_eq!(changes["accounts_kept"], serde_json::json!(["john"]));
	assert_eq!(accounts(&env), ["john"]);
}

#[test]
fn an_unreadable_source_is_refused_before_anything_is_written() {
	let env = env("");
	let before = configured_domains(&env);
	for source in ["/nonexistent/stalwart.toml", "/nonexistent/mox"] {
		let output = if source.ends_with("toml") {
			stalwart(&env, Path::new(source), &["--password-reset"])
		} else {
			mox(&env, Path::new(source), &["--password-reset"])
		};
		assert_eq!(output.status.code(), Some(2), "{source}");
		assert!(stdout(&output).is_empty());
	}
	assert_eq!(configured_domains(&env), before);
}
