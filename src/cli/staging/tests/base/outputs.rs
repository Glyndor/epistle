//! Output paths: delivered only on success, refused when they cannot be.

use super::*;

fn mox_out(source: &Path, out: &Path) -> Vec<OsString> {
	write(&source.join("mox.conf"), "", 0o600);
	os(&[
		"migrate",
		"mox",
		"--from",
		source.to_str().unwrap(),
		"--passwords-out",
		out.to_str().unwrap(),
	])
}

#[test]
fn the_password_list_moves_to_the_requested_path_only_on_success() {
	for success in [true, false] {
		let (home, source, out) = (
			tempfile::tempdir().unwrap(),
			tempfile::tempdir().unwrap(),
			tempfile::tempdir().unwrap(),
		);
		let requested = out.path().join("passwords.txt");
		let line = mox_out(source.path(), &requested);
		let stage = Stage::prepare(&line, home.path(), me(), &Owner::default().chown()).unwrap();
		let staged = PathBuf::from(&stage.args()[5]);
		assert!(
			staged.starts_with(home.path()),
			"the run writes into the staging directory"
		);
		assert!(!requested.exists(), "nothing is written before the run");
		// The delegated run writes the list.
		write(&staged, "bob\tpassword\n", 0o600);
		stage.finish(success).unwrap();
		assert!(
			entries(home.path()).is_empty(),
			"the staging directory goes either way"
		);
		if success {
			assert_eq!(fs::read_to_string(&requested).unwrap(), "bob\tpassword\n");
			assert_eq!(mode(&requested), 0o600);
			let owner = fs::metadata(&requested).unwrap().uid();
			// SAFETY: geteuid takes no arguments and cannot fail.
			assert_eq!(
				owner,
				unsafe { libc::geteuid() },
				"owned by the root parent"
			);
		} else {
			assert!(
				!requested.exists(),
				"a failed run leaves nothing at the path"
			);
		}
	}
}

#[test]
fn an_output_is_refused_before_the_run_when_it_cannot_be_delivered() {
	let (home, source, out) = (
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
	);
	let existing = out.path().join("passwords.txt");
	write(&existing, "keep", 0o600);
	let message = refused(
		&mox_out(source.path(), &existing),
		home.path(),
		table::STAGED,
	);
	assert!(message.contains("already exists"), "{message}");
	assert_eq!(fs::read_to_string(&existing).unwrap(), "keep");
	let nowhere = out.path().join("missing/passwords.txt");
	let message = refused(
		&mox_out(source.path(), &nowhere),
		home.path(),
		table::STAGED,
	);
	assert!(message.contains("does not exist"), "{message}");

	let full = out.path().join("export");
	write(&full.join("cur/old"), "old", 0o600);
	let line = os(&[
		"export",
		"--account",
		"a",
		"--maildir",
		full.to_str().unwrap(),
	]);
	let message = refused(&line, home.path(), table::STAGED);
	assert!(message.contains("not an empty directory"), "{message}");
}

#[test]
fn a_link_left_by_the_account_is_not_moved() {
	let (home, source, out) = (
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
	);
	let secret = source.path().join("shadow");
	write(&secret, "root only", 0o600);
	let requested = out.path().join("passwords.txt");
	let stage = Stage::prepare(
		&mox_out(&source.path().join("mox"), &requested),
		home.path(),
		me(),
		&Owner::default().chown(),
	)
	.unwrap();
	std::os::unix::fs::symlink(&secret, PathBuf::from(&stage.args()[5])).unwrap();
	assert!(
		stage.finish(true).is_err(),
		"a link in place of the output is refused"
	);
	assert!(!requested.exists());
	assert!(entries(home.path()).is_empty());
	assert_eq!(fs::read_to_string(&secret).unwrap(), "root only");
}

#[test]
fn an_export_moves_its_tree_on_success_only() {
	for success in [true, false] {
		let (home, out) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
		let requested = out.path().join("backup/Maildir");
		let line = os(&[
			"export",
			"--account",
			"a",
			"--maildir",
			requested.to_str().unwrap(),
		]);
		let stage = Stage::prepare(&line, home.path(), me(), &Owner::default().chown()).unwrap();
		let staged = PathBuf::from(&stage.args()[4]);
		write(&staged.join("cur/1:2,S"), "mail", 0o644);
		write(&staged.join(".Work/cur/2:2,"), "work", 0o644);
		stage.finish(success).unwrap();
		assert!(entries(home.path()).is_empty());
		if success {
			assert_eq!(
				fs::read_to_string(requested.join(".Work/cur/2:2,")).unwrap(),
				"work"
			);
			assert_eq!(mode(&requested), 0o700);
			assert_eq!(mode(&requested.join("cur/1:2,S")), 0o600);
		} else {
			assert!(!requested.exists());
		}
	}
}
