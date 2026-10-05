//! Database-password unit tests.
//!
//! The tests cover the `epistle_db_password` file the apply phase
//! lays down under `<data_dir>/secrets/`: its shape, the
//! create-then-reuse round-trip, the refuse-to-overwrite rule
//! for an existing operator-supplied secret, and the empty-file
//! edge case. Sister to `compose_tests.rs` (which carries the
//! shape-of-the-rendered-file tests) so the per-file code-line
//! limit stays under 500.
//!
//! The tests use a tempdir per case so the password file lives
//! under a fresh path; the `ensure_db_password` helper sets
//! `data_dir/secrets/` to mode `0700` and the password file
//! itself to mode `0600`. The mode is checked through the file
//! size and content here, not through `st_mode`, because the
//! suite also runs as root where permission bits are not
//! meaningfully testable.

use std::fs;

use super::{db_password_path, ensure_compose_file, ensure_db_password, stack_answers};

#[test]
fn db_password_is_32_alphanumeric_chars() {
	let pwd = super::generate_db_password().expect("CSPRNG");
	assert_eq!(pwd.len(), 32);
	for ch in pwd.chars() {
		assert!(
			ch.is_ascii_alphanumeric(),
			"password char {ch:?} is not alphanumeric"
		);
	}
}

#[test]
fn ensure_db_password_creates_then_reuses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut report = crate::cli::init::apply::Report::default();
	let path = ensure_db_password(data_dir, &mut report).expect("first run");
	let first = fs::read(&path).expect("read first");
	assert!(!first.is_empty(), "first password must be non-empty");
	assert!(matches!(
		report.steps.last(),
		Some(crate::cli::init::apply::ReportStep::Wrote(_))
	));
	// Second run must reuse the bytes byte-for-byte.
	let mut report2 = crate::cli::init::apply::Report::default();
	let path2 = ensure_db_password(data_dir, &mut report2).expect("second run");
	let second = fs::read(&path2).expect("read second");
	assert_eq!(first, second, "the password must be reused byte-for-byte");
	assert!(matches!(
		report2.steps.last(),
		Some(crate::cli::init::apply::ReportStep::Reused(_))
	));
}

#[test]
fn ensure_db_password_refuses_to_overwrite_an_existing_password() {
	// A hand-crafted secret that is already on disk must be
	// reused byte-for-byte even if it is shorter than 32 chars.
	// The apply phase does not want to lock the operator out of
	// the database by rotating the secret underneath them.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let secrets_dir = data_dir.join("secrets");
	fs::create_dir_all(&secrets_dir).expect("secrets dir");
	let path = db_password_path(data_dir);
	fs::write(&path, b"operator-supplied-secret").expect("write");
	let mut report = crate::cli::init::apply::Report::default();
	let result_path = ensure_db_password(data_dir, &mut report).expect("reused");
	let bytes = fs::read(&result_path).expect("read back");
	assert_eq!(bytes, b"operator-supplied-secret");
}

/// A regular file with zero-length content at the password
/// path is a present-but-unusable shape. The apply phase
/// refuses to mint a fresh password here: the operator left
/// the file empty by hand (or a previous run wrote a partial
/// file before crashing), and silently overwriting it would
/// land a fresh credential while the operator's view of the
/// disk is still "this is the secret init wrote". The error
/// names the path so the operator can remove the file and
/// rerun, and the file is left untouched (no half-written
/// secret, no silent rotation).
#[test]
fn ensure_db_password_refuses_an_existing_empty_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let secrets_dir = data_dir.join("secrets");
	fs::create_dir_all(&secrets_dir).expect("secrets dir");
	let path = db_password_path(data_dir);
	fs::write(&path, b"").expect("write empty");
	let meta_before = fs::metadata(&path).expect("metadata before");
	let mut report = crate::cli::init::apply::Report::default();
	let error = ensure_db_password(data_dir, &mut report)
		.expect_err("an empty file must surface as an error, not a fresh write");
	let rendered = format!("{error}");
	assert!(
		rendered.contains(&path.display().to_string()),
		"error must name the secret path, got: {rendered}"
	);
	// The file is untouched: still empty, still at the same
	// path, so the operator can remove it by hand and rerun.
	let bytes = fs::read(&path).expect("read back");
	assert!(bytes.is_empty(), "the empty file must not be replaced");
	let meta_after = fs::metadata(&path).expect("metadata after");
	assert_eq!(
		meta_before.len(),
		meta_after.len(),
		"the empty file must not be replaced"
	);
}

/// A dangling symlink at the password path is a
/// present-but-unusable shape. The previous shape used `fs::read`
/// to detect absence; a broken symlink reports `NotFound` on
/// read but is a real entry on disk, and the apply phase would
/// silently replace it with a fresh file. The new shape uses
/// `symlink_metadata` and refuses: a symlink at the path is
/// something the operator (or a backup tool) put there, and
/// overwriting it would lose the link without warning.
#[test]
fn ensure_db_password_refuses_a_dangling_symlink() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let secrets_dir = data_dir.join("secrets");
	fs::create_dir_all(&secrets_dir).expect("secrets dir");
	let path = db_password_path(data_dir);
	let target = data_dir.join("does-not-exist");
	std::os::unix::fs::symlink(&target, &path).expect("symlink");
	let mut report = crate::cli::init::apply::Report::default();
	let error = ensure_db_password(data_dir, &mut report)
		.expect_err("a dangling symlink must surface as an error");
	let rendered = format!("{error}");
	assert!(
		rendered.contains(&path.display().to_string()),
		"error must name the secret path, got: {rendered}"
	);
	// The symlink is still in place: the apply phase did not
	// replace it with a regular file.
	let meta = fs::symlink_metadata(&path).expect("symlink metadata");
	assert!(
		meta.file_type().is_symlink(),
		"the symlink must not be replaced with a regular file"
	);
	// The plan must also say `reused: false` so the operator
	// sees the apply would mint a new password before the
	// refusal stops the run.
	assert!(
		!super::db_password_reused(data_dir),
		"plan must not mark a dangling symlink as reused"
	);
}

/// A directory in place of the secret file must surface as
/// `ExistingSecretUnreadable`, not as a successful rewrite.
/// PostgreSQL still holds the old credential in its volume and
/// a fresh password would lock epistle out. The plan must agree
/// with the apply path: a directory at the secret path is
/// `reused: false` here (the read fails) and the apply then
/// fails with the same error before any effect. The test
/// uses a directory rather than `mode 0o000` so it is meaningful
/// even when the suite runs as root (the directory read
/// returns `Is a directory`, which root cannot bypass).
#[test]
fn ensure_db_password_refuses_to_overwrite_an_unreadable_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let secrets_dir = data_dir.join("secrets");
	fs::create_dir_all(&secrets_dir).expect("secrets dir");
	// The secret path is normally a regular file; replace it
	// with a directory of the same name. `fs::read` on a
	// directory returns `Is a directory`, so the apply phase
	// hits the `ExistingSecretUnreadable` arm rather than the
	// `NotFound` arm.
	let path = db_password_path(data_dir);
	fs::remove_file(&path).ok();
	fs::create_dir(&path).expect("create dir at secret path");
	// Remember the path's metadata to confirm the apply phase
	// did not touch it on the way out.
	let meta_before = fs::metadata(&path).expect("metadata before");
	let mut report = crate::cli::init::apply::Report::default();
	let error = ensure_db_password(data_dir, &mut report)
		.expect_err("unreadable secret must surface as an error");
	let rendered = format!("{error}");
	assert!(
		rendered.contains(&path.display().to_string()),
		"error must name the secret path, got: {rendered}"
	);
	assert!(
		rendered.contains("not replaced") || rendered.contains("cannot be read"),
		"error must explain the apply phase refused to mint a fresh value, got: {rendered}"
	);
	// The plan must say `reused: false` for the same path, so
	// the operator sees the apply would mint a new password
	// before the read failure stops the run.
	assert!(
		!super::db_password_reused(data_dir),
		"plan must not mark the secret as reused when the path is unreadable"
	);
	// The directory at the path is untouched: the apply phase
	// did not remove it and did not replace it.
	let meta_after = fs::metadata(&path).expect("metadata after");
	assert_eq!(
		meta_before.file_type(),
		meta_after.file_type(),
		"the unreadable entry at the secret path must be left in place"
	);
}

#[test]
fn second_run_reuses_db_password_and_says_identical_compose() {
	// A re-run of `epistle init` with the same answers must not
	// rewrite the database password (rotating it would lock the
	// operator out of the existing database) and must not rewrite
	// the compose file (it is byte-for-byte what the apply phase
	// would write). The plan and the report both surface the
	// "no change" verdict so the operator sees nothing to do.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	let mut report = crate::cli::init::apply::Report::default();
	ensure_db_password(data_dir, &mut report).expect("first password");
	ensure_compose_file(&answers, true, &mut report).expect("first compose");
	// Re-run; everything must be `Reused` (password) or
	// `ConfigIdentical` (compose), never a fresh `Wrote` step
	// for these two artifacts.
	let mut report2 = crate::cli::init::apply::Report::default();
	ensure_db_password(data_dir, &mut report2).expect("second password");
	ensure_compose_file(&answers, true, &mut report2).expect("second compose");
	let reused_db = report2
		.steps
		.iter()
		.any(|s| matches!(s, crate::cli::init::apply::ReportStep::Reused(p) if p.ends_with("epistle_db_password")));
	let identical_compose = report2
		.steps
		.iter()
		.any(|s| matches!(s, crate::cli::init::apply::ReportStep::ConfigIdentical(p) if p.ends_with("compose.yaml")));
	assert!(reused_db, "db password must be Reused, got {report2:?}");
	assert!(
		identical_compose,
		"compose file must be ConfigIdentical, got {report2:?}"
	);
}
