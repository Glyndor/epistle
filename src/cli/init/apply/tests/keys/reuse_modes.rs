//! The modes the apply phase leaves on disk: the data directory it
//! creates, the one it does not touch, and the paths it cannot read.

use super::reuse::answers_minimal;
use super::*;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
#[test]
fn apply_creates_missing_data_dir_with_mode_0700() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	// The plan must list the missing data dir as a step the operator
	// sees before confirming, before any apply has a chance to create
	// it.
	let plan = plan(&answers).expect("plan");
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::DataDir { path } if path == &data_dir)),
		"plan must list the missing data_dir as a DataDir step"
	);
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	let mode = std::fs::metadata(&data_dir)
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(
		mode & 0o777,
		0o700,
		"data_dir must be 0700 when init creates it, got {:o}",
		mode & 0o777
	);
	assert!(
		outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::CreatedDir(p) if p == &data_dir)),
		"apply must report the created data_dir; report was {:?}",
		outcome.report.steps
	);
}

#[cfg(unix)]
#[test]
fn apply_leaves_existing_data_dir_mode_untouched() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir(&data_dir).expect("mkdir");
	std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	let mode = std::fs::metadata(&data_dir)
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(
		mode & 0o777,
		0o755,
		"apply must not silently tighten an existing data_dir, got {:o}",
		mode & 0o777
	);
	assert!(
		!outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::CreatedDir(p) if p == &data_dir)),
		"existing data_dir must not appear as CreatedDir; report was {:?}",
		outcome.report.steps
	);
}

/// A directory in place of the secret file must surface in the
/// plan as `reused: false` (the apply phase cannot read it) and
/// the apply phase must then fail with
/// `ExistingSecretUnreadable` before any effect. A directory is
/// the case the test can exercise even when the suite runs as
/// root (`fs::read` on a directory returns `Is a directory`,
/// which root cannot bypass). The plan and the apply must
/// agree on what would happen; a previous shape had the plan
/// saying `reuse` on `path.exists()` and the apply silently
/// rewriting the unreadable entry, which would have locked
/// epistle out of the running database.
#[test]
fn plan_and_apply_agree_on_an_unreadable_db_password_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	std::fs::create_dir_all(data_dir.join("secrets")).expect("secrets dir");
	// Drop the regular file (if any) and put a directory at
	// the secret path so the read returns `Is a directory`.
	let path = data_dir.join("secrets").join("epistle_db_password");
	let _ = std::fs::remove_file(&path);
	std::fs::create_dir(&path).expect("create dir at secret path");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	answers.services.database = true;
	// The plan must say `reused: false` because the read fails.
	let plan = plan(&answers).expect("plan");
	let db_step = plan
		.steps
		.iter()
		.find_map(|s| match s {
			PlanStep::DbPassword { path, reused } => Some((path.clone(), *reused)),
			_ => None,
		})
		.expect("plan must list a DbPassword step");
	assert_eq!(db_step.0, path);
	assert!(
		!db_step.1,
		"plan must mark the unreadable secret as `reused: false`; \
		 the apply phase will mint a fresh value, but the read \
		 fails first and stops the run before any effect"
	);
	// The apply phase must fail with the typed error and the
	// report must show the entry was not touched.
	let outcome = apply(&answers);
	let error = outcome
		.error
		.expect("apply must fail on an unreadable secret");
	let path_matches = matches!(
		&error,
		ApplyError::ExistingSecretUnreadable(p, _) if p == &path
	);
	let rendered = format!("{error}");
	assert!(
		path_matches,
		"apply must surface ExistingSecretUnreadable with the secret path, got: {error:?}"
	);
	assert!(
		rendered.contains(&path.display().to_string()),
		"apply error must name the secret path, got: {rendered}"
	);
	// The directory at the path is still a directory: the apply
	// phase did not rewrite it.
	assert!(
		std::fs::metadata(&path).expect("metadata").is_dir(),
		"the unreadable entry at the secret path must be left in place"
	);
}
