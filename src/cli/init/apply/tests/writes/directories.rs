//! The directories the apply phase creates around the files it writes,
//! and the lock a re-run takes on the operator's config.

use super::super::helpers::answers::answers_minimal;
use super::*;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
#[test]
fn apply_creates_missing_config_parent_dir_with_mode_0750() {
	let dir = tempfile::tempdir().expect("tempdir");
	let etc = dir.path().join("etc");
	let config_path = etc.join("mail.toml");
	let data_dir = dir.path().join("data");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	// The plan must list the missing parent as a step the operator
	// sees before confirming, before any apply has had a chance to
	// create it.
	let plan = plan(&answers).expect("plan");
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::ConfigDir { path } if path == &etc)),
		"plan must list the missing parent as a ConfigDir step"
	);
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	assert!(etc.exists(), "apply did not create the parent directory");
	let mode = std::fs::metadata(&etc).expect("stat").permissions().mode();
	assert_eq!(
		mode & 0o777,
		0o750,
		"config parent must be 0750, got {:o}",
		mode & 0o777
	);
	assert!(
		outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::CreatedDir(p) if p == &etc)),
		"apply must report the created directory; report was {:?}",
		outcome.report.steps
	);
	// A second apply finds the directory already there and does not
	// create or report it again.
	let outcome = apply(&answers);
	assert!(outcome.error.is_none());
	assert!(
		!outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::CreatedDir(_))),
		"second apply must not re-create the existing parent; report was {:?}",
		outcome.report.steps
	);
}

#[cfg(unix)]
#[test]
fn apply_leaves_existing_config_parent_mode_untouched() {
	let dir = tempfile::tempdir().expect("tempdir");
	let etc = dir.path().join("etc");
	std::fs::create_dir(&etc).expect("mkdir");
	std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	let config_path = etc.join("mail.toml");
	let data_dir = dir.path().join("data");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none());
	let mode = std::fs::metadata(&etc).expect("stat").permissions().mode();
	assert_eq!(
		mode & 0o777,
		0o755,
		"apply must not change the mode of an existing directory, got {:o}",
		mode & 0o777
	);
}

#[test]
fn a_rerun_waits_for_service_edits_before_reading_the_config() {
	use std::sync::mpsc;
	use std::time::Duration;
	let dir = tempfile::tempdir().unwrap();
	let mut answers = answers_minimal();
	answers.data_dir = dir.path().join("data");
	answers.config_path = dir.path().join("mail.toml");
	assert!(apply(&answers).error.is_none());
	let held = crate::cli::service::lock::acquire(&answers.config_path).unwrap();
	std::thread::scope(|scope| {
		let (tx, rx) = mpsc::channel();
		let answers = &answers;
		scope.spawn(move || {
			tx.send(apply(answers)).unwrap();
		});
		let early = rx.recv_timeout(Duration::from_millis(300));
		let mut document =
			crate::cli::config_edit::ConfigDocument::open(&answers.config_path).unwrap();
		document
			.upsert_element("listeners", "kind", "smtp", &[("port", 2525.into())])
			.unwrap();
		document.commit().unwrap();
		drop(held);
		assert!(
			matches!(early, Err(mpsc::RecvTimeoutError::Timeout)),
			"init escaped the shared lock"
		);
		assert!(
			rx.recv_timeout(Duration::from_secs(20))
				.unwrap()
				.error
				.is_none()
		);
	});
	let config = crate::config::Config::load(&answers.config_path).unwrap();
	assert_eq!(config.listeners[0].socket_addr().port(), 2525);
}
