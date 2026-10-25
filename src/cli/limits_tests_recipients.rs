//! `epistle limits` sets the recipients one message may name. Below the
//! 100 RFC 5321 §4.5.3.1.8 requires a server to accept the value is refused,
//! and the file is left as it was.

use std::process::ExitCode;

use super::tests_session_limits::{assert_shown, limits};

const REFUSAL: &str = "refused: RFC 5321 §4.5.3.1.8 requires accepting at least 100 recipients\n";

#[test]
fn a_cap_is_set_shown_and_unset() {
	let (_dir, file) = super::tests_config::config_file();
	assert_shown(
		file.path(),
		&["max-recipients\t100\tdefault\tmust\tRFC 5321 §4.5.3.1.8 (at least 100)"],
	);
	let (code, printed) = limits(file.path(), &["set", "max-recipients", "500"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	let text = std::fs::read_to_string(file.path()).expect("config");
	assert!(text.contains("max_recipients = 500"), "{text}");
	assert_shown(
		file.path(),
		&["max-recipients\t500\tconfigured\tmust\tRFC 5321 §4.5.3.1.8 (at least 100)"],
	);
	let (code, printed) = limits(file.path(), &["unset", "max-recipients"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	assert_shown(
		file.path(),
		&["max-recipients\t100\tdefault\tmust\tRFC 5321 §4.5.3.1.8 (at least 100)"],
	);
}

#[test]
fn a_cap_below_one_hundred_is_refused_and_the_file_is_not_touched() {
	let (_dir, file) = super::tests_config::config_file();
	let before = std::fs::read_to_string(file.path()).expect("config");
	for value in ["0", "1", "99"] {
		let (code, printed) = limits(file.path(), &["set", "max-recipients", value]);
		assert_eq!(
			code,
			ExitCode::from(2),
			"{value}: input the command rejects exits 2"
		);
		assert_eq!(printed, REFUSAL, "{value}");
		assert_eq!(
			std::fs::read_to_string(file.path()).expect("config"),
			before,
			"{value}"
		);
	}
}

#[test]
fn a_cap_of_exactly_one_hundred_and_one_above_ten_thousand() {
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "max-recipients", "100"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	let (code, printed) = limits(file.path(), &["set", "max-recipients", "10001"]);
	assert_eq!(code, ExitCode::FAILURE, "{printed}");
	assert!(
		printed.starts_with("cannot update limits: max-recipients: "),
		"{printed}"
	);
}
