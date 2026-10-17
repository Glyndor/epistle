//! The bounded query: it answers, fails with the reason, or is stopped.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use super::query_within_program;

fn program(dir: &std::path::Path, body: &str) -> String {
	let path = dir.join("podup");
	std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	path.to_string_lossy().into_owned()
}

fn ask(program: &str, limit: Duration) -> Result<String, String> {
	query_within_program(
		program,
		std::path::Path::new("/nonexistent/compose.yaml"),
		"SELECT 1",
		limit,
	)
}

#[test]
fn an_answer_in_time_is_returned_trimmed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let podup = program(dir.path(), "echo '  16.4|1  '");
	assert_eq!(ask(&podup, Duration::from_secs(10)).unwrap(), "16.4|1");
}

#[test]
fn a_failure_carries_the_status_and_what_psql_said() {
	let dir = tempfile::tempdir().expect("tempdir");
	let podup = program(dir.path(), "echo 'psql: FATAL: no' >&2; exit 2");
	let error = ask(&podup, Duration::from_secs(10)).unwrap_err();
	assert!(error.starts_with("the query in db failed ("), "{error}");
	assert!(error.ends_with("psql: FATAL: no"), "{error}");
}

#[test]
fn a_query_that_never_answers_is_stopped_at_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let podup = program(dir.path(), "exec sleep 30");
	let began = Instant::now();
	let error = ask(&podup, Duration::from_millis(300)).unwrap_err();
	assert!(error.contains("did not answer within"), "{error}");
	assert!(
		began.elapsed() < Duration::from_secs(10),
		"the query was not stopped: {:?}",
		began.elapsed()
	);
}

#[test]
fn a_program_that_is_not_there_is_reported() {
	let error = ask("/nonexistent/podup", Duration::from_secs(1)).unwrap_err();
	assert!(error.starts_with("cannot run podup exec"), "{error}");
}

#[test]
fn sql_with_a_single_quote_is_refused_before_anything_runs() {
	let error = query_within_program(
		"/nonexistent/podup",
		std::path::Path::new("/c.yaml"),
		"SELECT 'x'",
		Duration::from_secs(1),
	)
	.unwrap_err();
	assert_eq!(error, "the query contains a single quote");
}
