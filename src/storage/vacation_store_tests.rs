//! Tests for the per-account vacation setting store.

use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn data_dir() -> tempfile::TempDir {
	tempfile::tempdir().expect("tempdir")
}

fn write_enabled(dir: &Path, account: &str) -> VacationSetting {
	let setting = VacationSetting {
		is_enabled: true,
		from_date: None,
		to_date: None,
		subject: Some("OOO".to_string()),
		text_body: Some("Away.".to_string()),
		html_body: None,
	};
	write(dir, account, &setting).expect("write");
	setting
}

#[test]
fn disabled_default_is_inert() {
	let dir = data_dir();
	let setting = read(dir.path(), "alice").expect("read missing");
	assert_eq!(setting, VacationSetting::disabled());
}

#[test]
fn write_then_read_round_trip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let stored = write_enabled(dir.path(), "alice");
	let read_back = read(dir.path(), "alice").expect("read");
	assert_eq!(read_back, stored);
}

#[test]
fn file_lives_inside_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_enabled(dir.path(), "alice");
	let path = vacation_file(dir.path(), "alice").expect("path");
	assert!(path.starts_with(dir.path().join("accounts").join("alice")));
}

#[test]
fn write_uses_crash_safe_rename() {
	let dir = tempfile::tempdir().expect("tempdir");
	let setting = write_enabled(dir.path(), "alice");
	let path = vacation_file(dir.path(), "alice").expect("path");
	// Confirm no leftover temp file from a prior write sits next to the
	// vacation file: the rename was atomic.
	let siblings: Vec<_> = std::fs::read_dir(path.parent().unwrap())
		.expect("readdir")
		.map(|entry| entry.expect("entry").file_name())
		.filter(|name| name.to_string_lossy().starts_with(".vacation.json."))
		.collect();
	assert!(siblings.is_empty(), "leftover temp files: {siblings:?}");
	// And the file parses back to what we wrote.
	let bytes = std::fs::read(&path).expect("read");
	let parsed: VacationSetting = serde_json::from_slice(&bytes).expect("parse");
	assert_eq!(parsed, setting);
}

#[test]
fn clear_removes_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_enabled(dir.path(), "alice");
	clear(dir.path(), "alice").expect("clear");
	let setting = read(dir.path(), "alice").expect("read");
	assert_eq!(setting, VacationSetting::disabled());
	// Clearing a missing file is a no-op.
	clear(dir.path(), "alice").expect("clear again");
}

#[test]
fn vacation_file_rejects_traversal_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert!(vacation_file(dir.path(), "../evil").is_err());
	assert!(vacation_file(dir.path(), "").is_err());
	assert!(vacation_file(dir.path(), "a/b").is_err());
	assert!(vacation_file(dir.path(), ".").is_err());
	assert!(vacation_file(dir.path(), "..").is_err());
	// A valid account name must resolve.
	assert!(vacation_file(dir.path(), "alice").is_ok());
}

#[test]
fn write_rejects_traversal_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let setting = write_enabled(dir.path(), "alice");
	assert!(write(dir.path(), "../evil", &setting).is_err());
	assert!(write(dir.path(), "", &setting).is_err());
}

#[test]
fn invalid_json_is_a_propagated_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = vacation_file(dir.path(), "alice").expect("path");
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent).expect("mkdir");
	}
	std::fs::write(&path, b"not-json").expect("write");
	let error = read(dir.path(), "alice").expect_err("read");
	assert!(matches!(
		error.kind(),
		io::ErrorKind::Other | io::ErrorKind::InvalidData
	));
}

#[test]
fn utc_date_parses_iso_z() {
	let secs = utc_date_to_unix_secs(Some("1970-01-01T00:00:00Z")).expect("epoch");
	assert_eq!(secs, 0);
	let secs = utc_date_to_unix_secs(Some("2000-01-01T00:00:00Z")).expect("y2k");
	// Y2K is 30 years after the epoch, 7 of them are leap years.
	assert_eq!(secs, 946_684_800);
}

#[test]
fn utc_date_rejects_bad_shapes() {
	for bad in [
		"",
		"1970-01-01T00:00:00",   // missing Z
		"1970-01-01 00:00:00Z",  // space
		"1970-1-1T00:00:00Z",    // single-digit
		"1970-01-01T00:00:00.0", // missing Z
		"1970-13-01T00:00:00Z",  // month out of range
		"1970-00-01T00:00:00Z",  // zero month
		"1970-01-32T00:00:00Z",  // day out of range
		"1970-01-01T24:00:00Z",
		"1970-01-01T00:60:00Z",
		"1970-01-01T00:00:60Z",
		"2030-02-30T00:00:00Z", // Feb 30 rolls into March
	] {
		assert_eq!(
			utc_date_to_unix_secs(Some(bad)),
			None,
			"value {bad} should reject"
		);
	}
	assert_eq!(utc_date_to_unix_secs(None), None);
}

#[test]
fn window_open_when_no_bounds_set() {
	let setting = VacationSetting::disabled();
	assert!(setting.is_within_window(0));
	let setting = VacationSetting {
		is_enabled: true,
		from_date: None,
		to_date: None,
		subject: None,
		text_body: None,
		html_body: None,
	};
	assert!(setting.is_within_window(0));
	assert!(
		setting.is_within_window(
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_secs()
		)
	);
}

#[test]
fn window_rejects_outside_bounds() {
	let setting = VacationSetting {
		is_enabled: true,
		from_date: Some("2000-01-01T00:00:00Z".to_string()),
		to_date: Some("2000-12-31T23:59:59Z".to_string()),
		subject: None,
		text_body: None,
		html_body: None,
	};
	assert!(!setting.is_within_window(0));
	assert!(setting.is_within_window(utc_date_to_unix_secs(Some("2000-06-01T00:00:00Z")).unwrap()));
	assert!(
		!setting.is_within_window(utc_date_to_unix_secs(Some("2001-01-01T00:00:00Z")).unwrap())
	);
}

#[test]
fn window_only_uses_unparseable_bound_as_safe() {
	// A single unparseable bound is treated as "no bound": it never strands
	// an account whose date drifted into a format we don't recognise.
	let setting = VacationSetting {
		is_enabled: true,
		from_date: Some("not-a-date".to_string()),
		to_date: None,
		subject: None,
		text_body: None,
		html_body: None,
	};
	assert!(setting.is_within_window(0));
}
