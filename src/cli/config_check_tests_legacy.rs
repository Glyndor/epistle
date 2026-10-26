//! A file written by an older release is checked, started and reported on
//! rather than refused: `config-check` says what is ignored, and the commands
//! that repair an installation run on a file the validation refuses.

use std::io::Write;
use std::process::ExitCode;

fn write_config(toml: &str) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(toml.as_bytes()).expect("write");
	file
}

const BASE: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";
const INVALID: &str = "[[alias]]\naddress = \"team@example.org\"\nmembers = []\n";

#[test]
fn config_check_accepts_a_site_local_public_ipv6_and_names_it() {
	let file = write_config(&format!(
		"{BASE}public_ipv6 = \"fec0::5054:ff:fe12:3456\"\n"
	));
	let (mut out, mut err) = (Vec::new(), Vec::new());
	assert_eq!(
		super::run(file.path(), false, &mut out, &mut err),
		ExitCode::SUCCESS
	);
	let err = String::from_utf8_lossy(&err);
	assert!(
		err.contains("public_ipv6 \"fec0::5054:ff:fe12:3456\""),
		"{err}"
	);
	assert!(err.contains("ignored"), "{err}");
	let json = {
		let mut out = Vec::new();
		super::run(file.path(), true, &mut out, &mut Vec::new());
		String::from_utf8_lossy(&out).into_owned()
	};
	assert!(
		json.contains("\"result\":\"valid\"") || json.contains("\"result\": \"valid\""),
		"{json}"
	);
	assert!(json.contains("fec0::5054"), "{json}");
}

#[test]
fn the_recovery_commands_run_on_a_file_the_validation_refuses() {
	let file = write_config(&format!("{BASE}{INVALID}"));
	let ran = std::cell::Cell::new(false);
	let code = crate::cli::dispatch::with_config_lenient(file.path(), |config| {
		ran.set(config.validation_error.is_some());
		ExitCode::SUCCESS
	});
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(ran.get(), "the command ran and saw why the file is refused");
	let strict = crate::cli::dispatch::with_config(file.path(), |_| ExitCode::SUCCESS);
	assert_eq!(
		strict,
		ExitCode::FAILURE,
		"the other commands still refuse it"
	);
}
