use super::*;

const NOW: u64 = 1_792_000_000;

#[test]
fn a_fresh_request_is_taken_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert!(!take(dir.path(), NOW), "nothing was asked");
	request(dir.path(), NOW).expect("request");
	assert!(take(dir.path(), NOW + 120));
	assert!(!take(dir.path(), NOW + 120), "taken twice");
}

#[test]
fn an_old_request_is_dropped_not_kept_for_later() {
	let dir = tempfile::tempdir().expect("tempdir");
	request(dir.path(), NOW).expect("request");
	assert!(!take(dir.path(), NOW + FRESH_SECS + 1));
	assert!(
		!path(dir.path()).exists(),
		"an old request was left to be taken"
	);
}

#[test]
fn a_request_for_a_clock_that_has_since_jumped_back_is_not_taken() {
	let dir = tempfile::tempdir().expect("tempdir");
	request(dir.path(), NOW + 400 * 86_400).expect("request");
	assert!(!take(dir.path(), NOW));
}

#[test]
fn a_request_that_cannot_be_read_is_not_taken() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::storage::write_secret(&path(dir.path()), b"{").expect("write");
	assert!(!take(dir.path(), NOW));
	assert!(!path(dir.path()).exists());
}
