//! Input validation: durations, sizes, on/off and floats all reject
//! malformed values with the same message the operator should see.

use std::io::Write;
use std::path::Path;

use super::*;
use crate::cli::config_edit::ConfigDocument;

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn open(path: &Path) -> ConfigDocument {
	ConfigDocument::open(path).expect("config document must open")
}

#[test]
fn durations_accept_suffixes_and_seconds() {
	for (input, expected) in [
		("0", 0u64),
		("42", 42),
		("10s", 10),
		("2m", 120),
		("3h", 10800),
		("7d", 604800),
		("1w", 604800),
	] {
		assert_eq!(
			parse_duration_seconds(input).unwrap(),
			expected,
			"{input:?} must parse"
		);
	}
}

#[test]
fn durations_reject_garbage_with_the_documented_message() {
	for bad in ["", "abc", "10x", "-1", "5 minutes", "10sm"] {
		assert_eq!(
			parse_duration_seconds(bad).unwrap_err(),
			"expected a non-negative integer or a duration suffix (s, m, h, d, w)",
			"{bad:?} must fail with the documented message"
		);
	}
}

#[test]
fn sizes_accept_binary_suffixes_and_bytes() {
	for (input, expected) in [
		("1", 1i64),
		("1024", 1024),
		("4K", 4 * 1024),
		("2M", 2 * 1024 * 1024),
		("1G", 1024 * 1024 * 1024),
		("1T", 1024_i64.pow(4)),
	] {
		assert_eq!(
			parse_size_bytes(input).unwrap(),
			expected,
			"{input:?} must parse"
		);
	}
}

#[test]
fn sizes_reject_zero_and_garbage() {
	for bad in ["", "0", "abc", "1P", "-1", "1.5G"] {
		assert!(
			parse_size_bytes(bad).is_err(),
			"{bad:?} must fail (got {:?})",
			parse_size_bytes(bad)
		);
	}
}

#[test]
fn on_off_accepts_every_alias() {
	for (input, expected) in [
		("on", true),
		("ON", true),
		("true", true),
		("yes", true),
		("1", true),
		("off", false),
		("FALSE", false),
		("no", false),
		("0", false),
	] {
		assert_eq!(
			parse_on_off(input).unwrap(),
			expected,
			"{input:?} must parse to {expected}"
		);
	}
}

#[test]
fn on_off_rejects_unknown_words() {
	assert!(parse_on_off("maybe").is_err());
	assert!(parse_on_off("").is_err());
}

#[test]
fn unit_interval_rejects_out_of_range_values() {
	assert!(parse_unit_interval("-0.1").is_err());
	assert!(parse_unit_interval("1.5").is_err());
	assert!(parse_unit_interval("abc").is_err());
	assert_eq!(parse_unit_interval("0").unwrap(), 0.0);
	assert_eq!(parse_unit_interval("1").unwrap(), 1.0);
	assert_eq!(parse_unit_interval("0.5").unwrap(), 0.5);
}

#[test]
fn scanner_conflict_message_is_the_specific_loader_one() {
	let (_dir, file) = fixture("scanner_hook_url = \"http://scanner.example/\"\n");
	let mut document = open(file.path());
	let err = apply_set(
		&mut document,
		Key::ClamdSocket,
		&["/run/clamav/clamd.sock".to_string()],
	)
	.unwrap_err();
	assert_eq!(
		err,
		"clamd-socket and scanner-hook-url cannot be set together: only one scanner per server"
	);
}

#[test]
fn scalar_set_rejects_multi_value_lists_for_non_list_keys() {
	let (_dir, file) = fixture("");
	let mut document = open(file.path());
	let err = apply_set(
		&mut document,
		Key::ClamdTimeout,
		&["30".to_string(), "60".to_string()],
	)
	.unwrap_err();
	assert!(
		err.contains("takes exactly one value"),
		"unexpected message: {err}"
	);
}

#[test]
fn list_set_rejects_empty_values() {
	let (_dir, file) = fixture("");
	let mut document = open(file.path());
	let err = apply_set(&mut document, Key::DnsblZones, &[]).unwrap_err();
	assert!(
		err.contains("requires at least one value"),
		"unexpected message: {err}"
	);
}
