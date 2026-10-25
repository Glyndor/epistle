//! The credential label rule, driven through every entry that names a
//! credential.
//!
//! An app password and an API key are each named by a label the operator
//! types. Before the audit only the app password entry checked it, so an API
//! key could be called `""` or carry an escape sequence that the next
//! `api-key list` would print. The rule is one (`epistle::util::label_rule`);
//! this table is the premise that every entry applies it.
//!
//! Declared from `tests/validation_matrix.rs`.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::common::{Row, assert_printable, cell, fixture_password, matrix};
use super::single_label::{cli_config, epistle};
use epistle::util::label_rule;

const PATHS: [&str; 4] = [
	"rule",
	"app-password-create",
	"app-password-rename",
	"api-key-create",
];

/// A config and a known account to hang an app password on.
fn setup() -> (tempfile::TempDir, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = cli_config(dir.path());
	let password = fixture_password(24);
	let mut child = Command::new(env!("CARGO_BIN_EXE_epistle"))
		.args([
			"account",
			"--config",
			&config,
			"add",
			"torre",
			"--address",
			"torre@example.org",
		])
		.env("NO_COLOR", "1")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("spawn epistle");
	child
		.stdin
		.take()
		.expect("stdin")
		.write_all(format!("{password}\n").as_bytes())
		.expect("password");
	let output = child.wait_with_output().expect("wait epistle");
	assert!(
		output.status.success(),
		"the fixture account was refused: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	(dir, config)
}

/// Create an app password, and take it away again when it was made, so the
/// next entry in the table can use the same label.
fn app_password_create(config: &str, label: &str) -> (bool, String) {
	let answer = epistle(&["app-password", "--config", config, "create", "torre", label]);
	if answer.0 {
		let (revoked, said) = epistle(&[
			"app-password",
			"--config",
			config,
			"revoke",
			"torre",
			label,
			"--yes",
		]);
		assert!(revoked, "the fixture could not be cleaned up: {said}");
	}
	answer
}

fn app_password_rename(config: &str, label: &str) -> (bool, String) {
	// One old label per case, so a refused rename leaves nothing behind that
	// the next case's fixture would collide with.
	static NEXT: AtomicUsize = AtomicUsize::new(0);
	let old = format!("old-{}", NEXT.fetch_add(1, Ordering::Relaxed));
	let (made, said) = epistle(&["app-password", "--config", config, "create", "torre", &old]);
	assert!(made, "the fixture app password was refused: {said}");
	let answer = epistle(&[
		"app-password",
		"--config",
		config,
		"rename",
		"torre",
		&old,
		label,
	]);
	let kept = if answer.0 { label } else { &old };
	let (revoked, said) = epistle(&[
		"app-password",
		"--config",
		config,
		"revoke",
		"torre",
		kept,
		"--yes",
	]);
	assert!(revoked, "the fixture could not be cleaned up: {said}");
	answer
}

fn api_key_create(config: &str, label: &str) -> (bool, String) {
	epistle(&[
		"api-key", "--config", config, "create", label, "--scope", "read",
	])
}

#[test]
fn a_credential_label_answers_the_same_through_every_entry() {
	let long_wide = "\u{e9}".repeat(label_rule::MAX_LEN);
	let at_max = "a".repeat(label_rule::MAX_LEN);
	let over_max = "a".repeat(label_rule::MAX_LEN + 1);
	let cases: Vec<(&'static str, String, bool)> = vec![
		("empty", String::new(), false),
		("only spaces", "   ".to_string(), false),
		("plain", "iphone".to_string(), true),
		("a space inside", "work phone".to_string(), true),
		("non-ASCII", "tel\u{e9}fono".to_string(), true),
		("a hyphen first", "x-ci".to_string(), true),
		("a tab", "work\tphone".to_string(), false),
		("a newline", "work\nphone".to_string(), false),
		("an escape", "work\u{1b}[2Jphone".to_string(), false),
		("a bidi override", "work\u{202e}phone".to_string(), false),
		("a zero-width space", "work\u{200b}phone".to_string(), false),
		("a line separator", "work\u{2028}phone".to_string(), false),
		(
			"an Arabic letter mark",
			"work\u{61c}phone".to_string(),
			false,
		),
		("a soft hyphen", "work\u{ad}phone".to_string(), false),
		("a space before", " iphone".to_string(), false),
		("a space after", "iphone ".to_string(), false),
		("at the maximum length", at_max, true),
		("one over the maximum", over_max, false),
		("the maximum in two-byte letters", long_wide, true),
	];
	// One account for the whole table: hashing its password is the slow part.
	let (_dir, config) = setup();
	let mut rows = Vec::new();
	for (what, label, _) in &cases {
		let mut accepted = vec![label_rule::check(label).is_ok()];
		let mut messages = Vec::new();
		for run in [app_password_create, app_password_rename, api_key_create] {
			let (ok, said) = run(&config, label);
			if !ok {
				messages.push(said);
			}
			accepted.push(ok);
		}
		// A refusal that reaches the operator says which value, which rule,
		// and what to type instead, and never echoes a control character.
		for said in messages {
			assert!(said.contains("label"), "{label:?}: {said}");
			assert!(said.contains("for example"), "{label:?}: {said}");
			assert_printable(&said, &format!("label {label:?}"));
			// A character the rule refuses for being invisible is echoed as
			// its escape, so the operator can see which one it was.
			if let Some(c) = label
				.chars()
				.find(|c| epistle::util::validation::is_invisible_format(*c))
			{
				assert!(
					said.contains(&c.escape_unicode().to_string()),
					"{label:?}: {said}"
				);
			}
		}
		rows.push(Row {
			what,
			value: label.clone(),
			accepted,
		});
	}
	for (what, _, expected) in &cases {
		for path in 0..PATHS.len() {
			cell(&rows, &PATHS, what, path, *expected);
		}
	}
	// The table is also the proof that the four columns agree row by row.
	for row in &rows {
		assert!(
			row.accepted.iter().all(|got| *got == row.accepted[0]),
			"two entries disagree on the label {:?}{}",
			row.value,
			matrix(&rows, &PATHS)
		);
	}
}
