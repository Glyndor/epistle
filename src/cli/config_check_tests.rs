//! Tests for the `config-check` dispatch handler. Lives next to the
//! handler so the test file can assert against the writers it asks for,
//! instead of going through the process boundary to read the warning.

use super::*;
use clap::Parser;
use std::io::Write;

fn write_config(toml: &str) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(toml.as_bytes()).expect("write");
	file
}

#[test]
fn config_check_accepts_a_file_with_no_dkim_section() {
	let file = write_config(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
	);
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		super::run(file.path(), &mut out, &mut err),
		ExitCode::SUCCESS
	);
	let out_text = String::from_utf8_lossy(&out);
	let err_text = String::from_utf8_lossy(&err);
	assert!(out_text.contains("configuration is valid"), "{out_text}");
	assert!(
		!err_text.contains("signs with one key only"),
		"absent [dkim] must not warn: {err_text}"
	);
}

#[test]
fn config_check_emits_single_signature_warning_when_dkim_has_no_rsa() {
	// [dkim] present, RSA fields absent: the dispatch handler must call
	// the shared helper, write the warning to stderr, and still exit
	// SUCCESS (a warning is not a failure).
	let file = write_config(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
"#,
	);
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		super::run(file.path(), &mut out, &mut err),
		ExitCode::SUCCESS,
		"warning must not change the exit code"
	);
	let err_text = String::from_utf8_lossy(&err);
	assert!(
		err_text.contains("warning:"),
		"stderr must carry the `warning:` prefix: {err_text}"
	);
	assert!(
		err_text.contains("signs with one key only"),
		"stderr must carry the single-signature warning: {err_text}"
	);
}

#[test]
fn config_check_emits_no_warning_when_both_rsa_fields_are_set() {
	// Generate a real RSA key in a tempdir the way `epistle dkim-keygen
	// --rsa` would, so the configuration validates and the signer could
	// in principle load it. Skipped with a printed reason when openssl
	// is not on PATH, matching the precedent set by the dkim-keygen
	// tests.
	if !openssl_on_path() {
		eprintln!("skip: openssl not on PATH");
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let key_path = dir.path().join("rsa.pem");
	let cli = crate::cli::Cli::try_parse_from([
		"epistle",
		"dkim-keygen",
		"--rsa",
		"--out",
		key_path.to_str().expect("utf-8 path"),
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::SUCCESS);

	let file = write_config(&format!(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
rsa_selector = "rsa1"
rsa_key_file = {:?}
"#,
		key_path
	));
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		super::run(file.path(), &mut out, &mut err),
		ExitCode::SUCCESS
	);
	let err_text = String::from_utf8_lossy(&err);
	assert!(
		!err_text.contains("signs with one key only"),
		"both RSA fields set: stderr must not carry the warning: {err_text}"
	);
}

/// Returns true when an `openssl` binary resolves somewhere on PATH. Mirrors
/// the helper in `cli_tests_d.rs`: we need it again here because tests in
/// sibling files do not share helpers.
fn openssl_on_path() -> bool {
	let Some(path) = std::env::var_os("PATH") else {
		return false;
	};
	std::env::split_paths(&path).any(|dir| dir.join("openssl").is_file())
}
