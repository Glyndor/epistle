//! The host name rule, driven through every entry that takes a host name.
//!
//! A host name is a domain name written for a machine: the name in SMTP
//! greetings and certificates. There is one definition of what a domain name
//! is (`epistle::domain::normalize`), and the two entries that take a host name
//! apply it with a different amount of tidying around it. The tidying is
//! deliberate and is written into the table as a cell, so a third behaviour
//! turns the build red:
//!
//! - the configuration file trims, lowercases and drops trailing dots before it
//!   checks (`config::normalize`), and refuses a name that is not already in
//!   ASCII, so the file on disk stays ASCII;
//! - `epistle init` reads the answer as typed and stores the A-label.
//!
//! Declared from `tests/contracts/validation_matrix.rs`.

use std::path::Path;

use super::common::{Row, assert_printable, cell, matrix, toml_string};
use super::single_label::{config_refusal, epistle};
use epistle::domain;

const PATHS: [&str; 3] = ["rule", "config", "init"];

/// The answer `epistle init --dry-run` gives for a host name: whether it took
/// it, and what it said.
fn init(hostname: &str) -> (bool, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let data = dir.path().join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	let answers = dir.path().join("answers.toml");
	write_answers(&answers, hostname, &data, &dir.path().join("etc/mail.toml"));
	epistle(&[
		"init",
		"--answers",
		answers.to_str().expect("path"),
		"--dry-run",
	])
}

fn write_answers(answers: &Path, hostname: &str, data: &Path, config: &Path) {
	std::fs::write(
		answers,
		format!(
			"mode = \"manual\"\nhostname = {}\ndomains = [\"example.org\"]\n\
			 public_ipv4 = \"8.8.8.8\"\ndata_dir = \"{}\"\nconfig_path = \"{}\"\n\
			 image = \"localhost/epistle:dev\"\n\n[services]\ndatabase = false\n",
			toml_string(hostname),
			data.to_string_lossy(),
			config.to_string_lossy(),
		),
	)
	.expect("write answers");
}

/// The message the configuration file is refused with, or `None`.
fn config(hostname: &str) -> Option<String> {
	config_refusal(&format!(
		"hostname = {}\ndata_dir = \"{{data}}\"\ndomains = [\"example.org\"]\n",
		toml_string(hostname)
	))
}

#[test]
fn a_host_name_answers_the_same_through_every_entry_except_where_the_file_tidies() {
	let label_63 = "a".repeat(63);
	let label_64 = "a".repeat(64);
	let long_253 = format!("{label_63}.{label_63}.{label_63}.{}", "d".repeat(61));
	let long_254 = format!("{label_63}.{label_63}.{label_63}.{}", "d".repeat(62));
	assert_eq!((long_253.len(), long_254.len()), (253, 254));
	// (what, value, [rule, config, init])
	let cases: Vec<(&'static str, String, [bool; 3])> = vec![
		("plain", "mail.example.net".into(), [true, true, true]),
		("capitals", "Mail.Example.NET".into(), [true, true, true]),
		(
			"a trailing dot",
			"mail.example.net.".into(),
			[false, true, false],
		),
		(
			"spaces around",
			" mail.example.net ".into(),
			[false, true, false],
		),
		("empty", String::new(), [false, false, false]),
		("one label", "mail".into(), [false, false, false]),
		(
			"an underscore",
			"mail_1.example.net".into(),
			[false, false, false],
		),
		(
			"a hyphen first",
			"-mail.example.net".into(),
			[false, false, false],
		),
		(
			"a hyphen last",
			"mail-.example.net".into(),
			[false, false, false],
		),
		(
			"an empty label",
			"mail..example.net".into(),
			[false, false, false],
		),
		(
			"an address literal",
			"[192.0.2.1]".into(),
			[false, false, false],
		),
		(
			"a space inside",
			"mail .example.net".into(),
			[false, false, false],
		),
		(
			"a label of 63",
			format!("{label_63}.example.net"),
			[true, true, true],
		),
		(
			"a label of 64",
			format!("{label_64}.example.net"),
			[false, false, false],
		),
		("253 characters", long_253, [true, true, true]),
		("254 characters", long_254, [false, false, false]),
		(
			"an A-label",
			"xn--bcher-kva.example.net".into(),
			[true, true, true],
		),
		(
			"a U-label",
			"b\u{fc}cher.example.net".into(),
			[true, false, true],
		),
		(
			"a Cyrillic look-alike",
			"\u{435}xample.net".into(),
			[false, false, false],
		),
	];
	let mut rows = Vec::new();
	for (what, value, _) in &cases {
		let from_config = config(value);
		let (init_ok, init_said) = init(value);
		rows.push(Row {
			what,
			value: value.clone(),
			accepted: vec![
				domain::normalize(value).is_ok(),
				from_config.is_none(),
				init_ok,
			],
		});
		// A refusal that reaches the operator says which value, which rule
		// and what to type instead.
		for (path, said) in [
			("config", from_config),
			("init", (!init_ok).then_some(init_said)),
		] {
			let Some(said) = said else { continue };
			assert_printable(&said, &format!("{path} for {value:?}"));
			assert!(
				said.contains("for example") || said.contains("must be written as its ASCII form"),
				"{path} refused the host name {value:?} without an example: {said}"
			);
		}
	}
	for (what, _, expected) in &cases {
		for (path, want) in expected.iter().enumerate() {
			cell(&rows, &PATHS, what, path, *want);
		}
	}
	let _ = matrix(&rows, &PATHS);
}
