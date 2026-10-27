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

const SIZE_REFUSAL: &str =
	"refused: RFC 5321 §4.5.3.1.7 requires accepting messages of at least 64K octets\n";

#[test]
fn a_message_size_below_64k_is_refused_and_the_file_is_not_touched() {
	let (_dir, file) = super::tests_config::config_file();
	let before = std::fs::read_to_string(file.path()).expect("config");
	for value in ["1k", "65535"] {
		let (code, printed) = limits(file.path(), &["set", "max-message-size", value]);
		assert_eq!(code, ExitCode::from(2), "{value}");
		assert_eq!(printed, SIZE_REFUSAL, "{value}");
		assert_eq!(
			std::fs::read_to_string(file.path()).expect("config"),
			before,
			"{value}"
		);
	}
	let (code, printed) = limits(file.path(), &["set", "max-message-size", "64k"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
}

#[test]
fn a_configured_message_size_below_64k_is_raised_to_it_with_a_warning() {
	let (_dir, file) = super::tests_config::config_file();
	let text = std::fs::read_to_string(file.path()).expect("config");
	std::fs::write(file.path(), format!("max_message_size = 1000\n{text}")).expect("write");
	let config = crate::config::Config::load(file.path()).expect("it still loads");
	assert_eq!(config.max_message_size, Some(65536));
	let [line] = config.adjusted.as_slice() else {
		panic!("one line expected")
	};
	assert!(
		line.contains("1000 bytes"),
		"the line names the value in the file"
	);
	assert!(
		line.contains("65536 bytes are used"),
		"the value in use: {line}"
	);
	assert!(
		line.contains("epistle limits set max-message-size 64k"),
		"the fix: {line}"
	);
}

#[test]
fn a_message_size_of_zero_or_at_the_floor_is_not_adjusted() {
	for value in ["0", "65536", "26214400"] {
		let (_dir, file) = super::tests_config::config_file();
		let text = std::fs::read_to_string(file.path()).expect("config");
		std::fs::write(file.path(), format!("max_message_size = {value}\n{text}")).expect("write");
		let config = crate::config::Config::load(file.path()).expect("loads");
		assert!(
			config.adjusted.is_empty(),
			"a value at or above the floor is not adjusted"
		);
	}
}

#[test]
fn a_message_size_below_64k_already_in_the_file_is_fixed_by_set_or_unset() {
	for args in [
		&["set", "max-message-size", "64k"][..],
		&["unset", "max-message-size"][..],
	] {
		let (_dir, file) = super::tests_config::config_file();
		let text = std::fs::read_to_string(file.path()).expect("config");
		std::fs::write(file.path(), format!("max_message_size = 1000\n{text}")).expect("write");
		let (code, printed) = limits(file.path(), args);
		assert_eq!(code, ExitCode::SUCCESS, "{args:?}: {printed}");
		assert!(crate::config::Config::load(file.path()).is_ok(), "{args:?}");
	}
}

#[test]
fn a_message_size_of_zero_means_the_default_as_in_the_config() {
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "max-message-size", "0"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	assert!(printed.contains("0 means the default"), "{printed}");
	assert!(crate::config::Config::load(file.path()).is_ok());
}
