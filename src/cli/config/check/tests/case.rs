//! `config-check` names every address or domain the file spells with
//! capitals, and still accepts the file.

use std::io::Write;
use std::process::ExitCode;

#[test]
fn config_check_warns_about_entries_that_are_not_lowercase() {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(
		br#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[alias]]
address = "Team@Example.org"
members = ["alice@example.org"]
"#,
	)
	.expect("write");
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		crate::cli::config::check::tests::run(file.path(), false, &mut out, &mut err),
		ExitCode::SUCCESS
	);
	assert_eq!(
		without_colour(&String::from_utf8_lossy(&err)),
		"warning: alias \"Team@Example.org\" (used as \"team@example.org\") is not lowercase in the configuration file\n"
	);
	assert_eq!(String::from_utf8_lossy(&out), "configuration is valid\n");
}

/// The text with ANSI SGR sequences (`ESC [ ... m`) removed.
fn without_colour(text: &str) -> String {
	let mut out = String::new();
	let mut chars = text.chars();
	while let Some(c) = chars.next() {
		if c == '\u{1b}' {
			chars.by_ref().find(|c| *c == 'm');
		} else {
			out.push(c);
		}
	}
	out
}
