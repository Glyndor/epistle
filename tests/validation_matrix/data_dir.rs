//! The data directory rule, driven through the two entries that take one.
//!
//! The configuration file only needs the directory to be an absolute path that
//! exists. `epistle init` also writes the path into a compose file and prints
//! it on a terminal, so it refuses what would be rewritten or misread there:
//! a `$` (compose interpolates it), a control or invisible formatting
//! character, and a `..` that climbs out of the root. Those extra refusals are
//! written into the table as cells, so a third behaviour, or an entry that
//! quietly starts accepting a `$`, turns the build red.
//!
//! Declared from `tests/validation_matrix.rs`.

use super::common::{Row, assert_printable, cell, matrix, toml_string};
use super::single_label::{config_refusal, epistle};

const PATHS: [&str; 2] = ["config", "init"];

fn config(data_dir: &str) -> Option<String> {
	config_refusal(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {}\ndomains = [\"example.org\"]\n",
		toml_string(data_dir)
	))
}

fn init(data_dir: &str) -> (bool, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers = dir.path().join("answers.toml");
	std::fs::write(
		&answers,
		format!(
			"mode = \"manual\"\nhostname = \"mail.example.org\"\ndomains = [\"example.org\"]\n\
			 public_ipv4 = \"8.8.8.8\"\ndata_dir = {}\nconfig_path = \"{}\"\n\
			 image = \"localhost/epistle:dev\"\n\n[services]\ndatabase = false\n",
			toml_string(data_dir),
			dir.path().join("etc/mail.toml").to_string_lossy(),
		),
	)
	.expect("write answers");
	epistle(&[
		"init",
		"--answers",
		answers.to_str().expect("path"),
		"--dry-run",
	])
}

#[test]
fn a_data_directory_answers_the_same_except_where_init_guards_the_compose_file() {
	let base = tempfile::tempdir().expect("tempdir");
	let root = base.path().join("data");
	std::fs::create_dir_all(&root).expect("data dir");
	let root = root.to_string_lossy().into_owned();
	// (what, value, [config, init])
	let cases: Vec<(&'static str, String, [bool; 2])> = vec![
		("absolute", root.clone(), [true, true]),
		("a trailing slash", format!("{root}/"), [true, true]),
		("a dot component", format!("{root}/."), [true, true]),
		(
			"a dot-dot that stays inside",
			format!("{root}/../data"),
			[true, true],
		),
		("empty", String::new(), [false, false]),
		("relative", "data".into(), [false, false]),
		("a dollar", format!("{root}/$HOME"), [true, false]),
		("an escape", format!("{root}/\u{1b}[2J"), [true, false]),
		(
			"a bidi override",
			format!("{root}/\u{202e}x"),
			[true, false],
		),
		("a dot-dot above the root", "/../data".into(), [true, false]),
	];
	let mut rows = Vec::new();
	for (what, value, _) in &cases {
		let from_config = config(value);
		let (init_ok, init_said) = init(value);
		rows.push(Row {
			what,
			value: value.clone(),
			accepted: vec![from_config.is_none(), init_ok],
		});
		for (path, said) in [
			("config", from_config),
			("init", (!init_ok).then_some(init_said)),
		] {
			let Some(said) = said else { continue };
			assert!(
				said.contains("data_dir"),
				"{path} refused {value:?} without naming the field: {said}"
			);
			assert_printable(&said, &format!("{path} for {value:?}"));
		}
	}
	for (what, _, expected) in &cases {
		for (path, want) in expected.iter().enumerate() {
			cell(&rows, &PATHS, what, path, *want);
		}
	}
	let _ = matrix(&rows, &PATHS);
}
