//! Tests for the `config-check` dispatch handler. Lives next to the
//! handler so the test file can assert against the writers it asks for,
//! instead of going through the process boundary to read the warning.

use crate::cli::config::check::tests::*;
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
		crate::cli::config::check::tests::run(file.path(), false, &mut out, &mut err),
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
		crate::cli::config::check::tests::run(file.path(), false, &mut out, &mut err),
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
	// in principle load it.
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
		crate::cli::config::check::tests::run(file.path(), false, &mut out, &mut err),
		ExitCode::SUCCESS
	);
	let err_text = String::from_utf8_lossy(&err);
	assert!(
		!err_text.contains("signs with one key only"),
		"both RSA fields set: stderr must not carry the warning: {err_text}"
	);
}

/// A host with no route to 123/udp or 4460/tcp switches the external probe
/// off. `config-check` accepts the file: the block is still validated, and
/// `enabled = false` is a value it knows.
#[test]
fn config_check_accepts_a_disabled_external_clock_probe() {
	for block in [
		"[clock_external]\nenabled = false\n",
		"[clock_external]\nenabled = false\nallow_private_networks = true\nallowed_ports = [4460]\n",
	] {
		let file = write_config(&format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{block}"
		));
		let mut out = Vec::new();
		let mut err = Vec::new();
		assert_eq!(
			crate::cli::config::check::tests::run(file.path(), false, &mut out, &mut err),
			ExitCode::SUCCESS,
			"{block} must load: {}",
			String::from_utf8_lossy(&err)
		);
		assert!(
			String::from_utf8_lossy(&out).contains("configuration is valid"),
			"{block}"
		);
	}
}

#[test]
fn config_check_says_when_it_raised_a_message_size_below_64k() {
	let file = write_config(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\nmax_message_size = 1000\n",
	);
	let mut out = Vec::new();
	let mut err = Vec::new();
	assert_eq!(
		crate::cli::config::check::tests::run(file.path(), false, &mut out, &mut err),
		ExitCode::SUCCESS,
		"the file still loads"
	);
	let text = String::from_utf8_lossy(&err).to_string();
	assert!(
		text.contains("max_message_size is 1000 bytes in the file"),
		"{text}"
	);
	assert!(text.contains("65536 bytes are used"), "{text}");
}
