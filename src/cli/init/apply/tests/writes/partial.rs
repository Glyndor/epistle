//! A run that fails halfway reports what it had already written.

use super::super::helpers::answers::answers_minimal;
use super::*;

#[test]
fn apply_partial_failure_renders_what_was_written() {
	// Force a failure after the keys have been written: create a
	// regular file where the config parent must be a directory. The
	// apply phase must surface every step that completed before the
	// failure, so the operator can see what is already on disk.
	let dir = tempfile::tempdir().expect("tempdir");
	let blocker = dir.path().join("etc");
	std::fs::write(&blocker, b"not a directory").expect("blocker");
	let config_path = blocker.join("mail.toml");
	let data_dir = dir.path().join("data");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	let error = outcome
		.error
		.expect("apply must surface the error after partial progress");
	assert!(
		matches!(
			error,
			ApplyError::ConfigRead(_, _) | ApplyError::ConfigWrite(_, _)
		),
		"unexpected error variant: {error:?}"
	);
	let s1 = data_dir.join("keys/s1.pem");
	assert!(
		s1.exists(),
		"the keys that ran before the failure must be on disk"
	);
	assert!(
		outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::Wrote(p) if p == &s1)),
		"partial report must list the keys that completed; got {:?}",
		outcome.report.steps
	);
}
