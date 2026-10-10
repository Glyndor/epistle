//! The mode pin the apply phase lands on `compose/README`. The
//! README is operator-facing documentation, not a secret, and a
//! tight umask (for example, `0o077`) on the runner would
//! otherwise leave the file at `0o600`, denying a follow-up
//! `cat README` from a different account. The tests run the
//! apply phase under a captured-and-restored `0o077` umask so
//! the apply phase has to explicitly `set_permissions(0o644)`
//! for the assertion to pass.

use super::*;

/// The README that `init` writes next to the compose file is
/// operator-facing documentation, not a secret. The apply
/// phase pins the mode to `0o644` explicitly so a tight umask
/// (for example, `0o077`) does not leave the file at `0o600`,
/// which would make a follow-up `cat README` from a different
/// account quietly deny access.
///
/// The previous shape of this test created the parent
/// directories with explicit modes (`0o700`) and asserted the
/// README lands at `0o644`, but did not change the process
/// umask. On a runner with the default umask `0o022`, an
/// `OpenOptions::new().create(true).truncate(true).open(&path)`
/// call (the shape the apply phase uses to create the README)
/// lands the file at `0o644` even when the apply phase does
/// NOT call `set_permissions(0o644)`, so a regression that
/// dropped the `set_permissions` call stayed green. The new
/// shape runs the apply phase under a `0o077` umask so the
/// default file mode is `0o600`; the apply phase must
/// explicitly set `0o644` to make the assertion pass. The
/// original umask is captured before the change and restored
/// before the test returns so the side effect does not leak
/// into other tests in the same binary.
#[cfg(unix)]
#[test]
fn compose_readme_is_pinned_to_mode_0644() {
	use crate::cli::init::apply;
	use std::os::unix::fs::PermissionsExt;
	// Save the current umask and set a restrictive one for
	// the duration of the test. `libc::umask` returns the
	// previous mask and sets the new one in a single call.
	// The previous mask is restored before the test returns
	// so the side effect does not leak into other tests.
	let previous = unsafe { libc::umask(0o077) };
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	std::fs::create_dir_all(config_path.parent().unwrap()).expect("mkdir etc");
	// Pre-create the parent directories the apply phase would
	// also create. Under the `0o077` umask, `create_dir_all`
	// lands them at `0o700` (the default for a directory is
	// `0o777 & ~umask`). The explicit `OpenOptionsExt::mode`
	// is not needed for the parent because the parent's mode
	// does not influence the mode the apply phase sets on
	// the README; the umask does.
	std::fs::create_dir_all(data_dir.join("keys")).expect("mkdir keys");
	std::fs::set_permissions(
		data_dir.join("keys"),
		std::fs::Permissions::from_mode(0o700),
	)
	.expect("set keys mode");
	std::fs::create_dir_all(data_dir.join("compose")).expect("mkdir compose");
	std::fs::set_permissions(
		data_dir.join("compose"),
		std::fs::Permissions::from_mode(0o700),
	)
	.expect("set compose mode");
	let mut answers = minimal_answers();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	// Custom image mode skips the host-binary check the test
	// environment cannot satisfy (no `/usr/bin/epistle`).
	answers.image = Some("localhost/epistle:dev".to_string());
	let outcome = apply::apply(&answers);
	// Restore the umask before any assertion that could
	// panic, so a failing test still leaves the process
	// umask at its original value.
	unsafe {
		libc::umask(previous);
	}
	assert!(outcome.error.is_none(), "first apply: {:?}", outcome.error);
	drop(outcome);
	let readme = data_dir.join("compose").join("README");
	let mode = std::fs::metadata(&readme)
		.expect("stat")
		.permissions()
		.mode()
		& 0o777;
	assert_eq!(
		mode, 0o644,
		"the README must land at 0o644 under a 0o077 umask; the apply phase has to \
		 call set_permissions(0o644) explicitly because a plain open() under this umask \
		 would land the file at 0o600. got {:o}",
		mode
	);
}

/// The mode pin must hold on a re-run too. The apply phase
/// selects the `Reused` step when the README's bytes are
/// unchanged; the previous shape set the mode only inside the
/// `Wrote` arm, so a README left at `0o600` by an earlier run
/// under a tight umask would stay at `0o600` forever. The new
/// shape calls `set_permissions(0o644)` before the byte
/// comparison, so the Reused arm lands on a freshly-permissioned
/// file. The test pre-creates the README at `0o600` with the
/// right bytes (no umask change, no interference with parallel
/// tests) and asserts the apply phase brings it to `0o644`
/// while still saying `Reused`.
#[cfg(unix)]
#[test]
fn compose_readme_mode_is_pinned_on_a_reused_readme() {
	use crate::cli::init::apply;
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	std::fs::create_dir_all(config_path.parent().unwrap()).expect("mkdir etc");
	let compose_dir = data_dir.join("compose");
	std::fs::create_dir_all(&compose_dir).expect("mkdir compose");
	// Pre-create the README with the exact bytes the apply
	// phase would write, at the tight mode the previous
	// implementation would have left behind. The apply
	// phase sees the same bytes, takes the Reused arm, and
	// (with the fix in place) re-pins the mode.
	let readme = compose_dir.join("README");
	std::fs::write(&readme, super::COMPOSE_README.as_bytes()).expect("write readme");
	std::fs::set_permissions(&readme, std::fs::Permissions::from_mode(0o600)).expect("set 0o600");
	let mut answers = minimal_answers();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	// Custom image mode skips the host-binary check the test
	// environment cannot satisfy (no `/usr/bin/epistle`).
	answers.image = Some("localhost/epistle:dev".to_string());
	let outcome = apply::apply(&answers);
	assert!(outcome.error.is_none(), "apply: {:?}", outcome.error);
	assert!(
		outcome.report.steps.iter().any(|s| matches!(
			s,
			crate::cli::init::apply::ReportStep::Reused(p) if p.ends_with("README")
		)),
		"the unchanged README must take the Reused arm; got report: {:?}",
		outcome.report
	);
	let mode = std::fs::metadata(&readme)
		.expect("stat")
		.permissions()
		.mode()
		& 0o777;
	assert_eq!(
		mode, 0o644,
		"the README must come out of the Reused arm at 0o644, not 0o600; got {:o}",
		mode
	);
}
