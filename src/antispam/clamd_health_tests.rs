use super::*;

#[test]
fn failures_accumulate_and_the_next_success_clears_them() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(read(dir.path()), None, "nothing recorded yet");
	let file = HealthFile::new(dir.path());
	file.failed();
	file.failed();
	let health = read(dir.path()).expect("recorded");
	assert_eq!(health.failures, 2);
	let since = health.failing_since.expect("since");
	assert!(health.last_failure.expect("last") >= since);
	assert_eq!(health.recovered_at, None);
	file.succeeded();
	let health = read(dir.path()).expect("still there");
	assert_eq!(health.failures, 0);
	assert_eq!(health.failing_since, None);
	assert!(health.recovered_at.is_some());
	assert!(health.last_failure.is_some(), "the last failure is kept");
}

#[test]
fn a_new_process_clears_what_an_earlier_one_left_on_its_first_success() {
	let dir = tempfile::tempdir().expect("tempdir");
	HealthFile::new(dir.path()).failed();
	let restarted = HealthFile::new(dir.path());
	restarted.succeeded();
	assert_eq!(read(dir.path()).expect("record").failures, 0);
}

#[test]
fn successes_without_failures_write_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = HealthFile::new(dir.path());
	file.succeeded();
	file.succeeded();
	assert!(!dir.path().join(FILE).exists());
}
