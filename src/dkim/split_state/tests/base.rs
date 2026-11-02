//! The state a split leaves for its next run.

use std::time::Duration;

use super::*;

fn selector(name: &str, p: &str) -> StaleSelector {
	StaleSelector {
		selector: name.into(),
		expected: vec![p.into()],
	}
}

#[test]
fn a_written_domain_is_pending_until_the_restart_is_recorded() {
	let dir = tempfile::tempdir().unwrap();
	record_written(dir.path(), "B.example", 10, vec![selector("s1", "AAA")]).unwrap();
	assert_eq!(pending(dir.path()).unwrap(), ["b.example"]);
	assert_eq!(mark_restarted(dir.path(), 99).unwrap(), ["b.example"]);
	assert!(pending(dir.path()).unwrap().is_empty());
	let moved = &read(dir.path()).unwrap()["b.example"];
	assert_eq!((moved.written, moved.restarted), (10, Some(99)));
}

#[test]
fn the_selectors_of_the_shared_key_outlive_a_second_record() {
	let dir = tempfile::tempdir().unwrap();
	record_written(dir.path(), "b.example", 10, vec![selector("ed1", "AAA")]).unwrap();
	record_written(
		dir.path(),
		"b.example",
		20,
		vec![selector("ed1", "BBB"), selector("ed2", "CCC")],
	)
	.unwrap();
	let moved = &read(dir.path()).unwrap()["b.example"];
	assert_eq!(moved.written, 10, "the first moment stands");
	assert_eq!(moved.stale.len(), 2);
	assert_eq!(moved.stale[0].expected, ["AAA", "BBB"]);
}

#[test]
fn a_file_that_does_not_parse_is_an_error_not_an_empty_state() {
	let dir = tempfile::tempdir().unwrap();
	std::fs::write(dir.path().join(FILE), "{").unwrap();
	assert!(read(dir.path()).is_err());
	assert!(pending(dir.path()).is_err());
}

#[test]
fn a_second_run_waits_for_the_lock_and_then_says_who_holds_it() {
	let dir = tempfile::tempdir().unwrap();
	let first = lock(dir.path(), Duration::from_millis(100)).unwrap();
	let error = lock(dir.path(), Duration::from_millis(300)).unwrap_err();
	assert!(error.contains("another dkim split is running"), "{error}");
	drop(first);
	lock(dir.path(), Duration::from_millis(100)).expect("free again once released");
}
