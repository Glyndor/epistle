use super::*;
use crate::cli::staging::Stage;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;

/// The account's uid here: this process plays it and writes the outputs.
fn me() -> u32 {
	// SAFETY: geteuid takes no arguments and cannot fail.
	unsafe { libc::geteuid() }
}

fn write(path: &Path, text: &str) {
	fs::create_dir_all(path.parent().unwrap()).unwrap();
	fs::write(path, text).unwrap();
}

fn os(list: &[&str]) -> Vec<OsString> {
	list.iter().map(OsString::from).collect()
}

struct Dirs {
	home: tempfile::TempDir,
	source: tempfile::TempDir,
	out: tempfile::TempDir,
}

fn dirs() -> Dirs {
	Dirs {
		home: tempfile::tempdir().unwrap(),
		source: tempfile::tempdir().unwrap(),
		out: tempfile::tempdir().unwrap(),
	}
}

/// A `migrate mox --passwords-out` run staged for the account at `account`.
fn passwords(dirs: &Dirs, account: u32) -> (Stage, PathBuf, PathBuf) {
	write(&dirs.source.path().join("mox.conf"), "");
	let requested = dirs.out.path().join("passwords.txt");
	let line = os(&[
		"migrate",
		"mox",
		"--from",
		dirs.source.path().to_str().unwrap(),
		"--passwords-out",
		requested.to_str().unwrap(),
	]);
	let stage = Stage::prepare(&line, dirs.home.path(), account, &|_, _| Ok(())).unwrap();
	let staged = PathBuf::from(&stage.args()[5]);
	(stage, staged, requested)
}

/// An `export --maildir` run staged for this process as the account.
fn export(dirs: &Dirs) -> (Stage, PathBuf, PathBuf) {
	let requested = dirs.out.path().join("export");
	let line = os(&[
		"export",
		"--account",
		"a",
		"--maildir",
		requested.to_str().unwrap(),
	]);
	let stage = Stage::prepare(&line, dirs.home.path(), me(), &|_, _| Ok(())).unwrap();
	let staged = PathBuf::from(&stage.args()[4]);
	(stage, staged, requested)
}

fn refused(stage: Stage, needle: &str) {
	let message = stage.finish(true).expect_err("refused").to_string();
	assert!(message.contains(needle), "{message}");
}

#[test]
fn a_hard_link_in_place_of_the_password_list_is_refused() {
	let dirs = dirs();
	let secret = dirs.out.path().join("shadow");
	write(&secret, "root only");
	let (stage, staged, requested) = passwords(&dirs, me());
	fs::hard_link(&secret, &staged).unwrap();
	refused(stage, "more than one hard link");
	assert!(!requested.exists(), "nothing reaches the requested path");
	assert_eq!(fs::read_to_string(&secret).unwrap(), "root only");
	assert_eq!(fs::read_dir(dirs.home.path()).unwrap().count(), 0);
}

#[test]
fn an_output_the_account_does_not_own_is_refused() {
	let dirs = dirs();
	let (stage, staged, requested) = passwords(&dirs, me().wrapping_add(1));
	write(&staged, "bob\tpw\n");
	refused(stage, "not owned by the service account");
	assert!(!requested.exists());
}

#[test]
fn a_hard_link_inside_an_export_is_refused_and_nothing_is_kept() {
	let dirs = dirs();
	let secret = dirs.source.path().join("shadow");
	write(&secret, "root only");
	let (stage, staged, requested) = export(&dirs);
	write(&staged.join("cur/1:2,S"), "mail");
	fs::hard_link(&secret, staged.join("cur/2:2,")).unwrap();
	refused(stage, "more than one hard link");
	assert!(
		!requested.exists(),
		"the directory this run made is removed"
	);
}

#[test]
fn a_link_planted_at_the_export_target_is_not_written_through() {
	let dirs = dirs();
	let elsewhere = dirs.source.path().join("elsewhere");
	fs::create_dir(&elsewhere).unwrap();
	let (stage, staged, requested) = export(&dirs);
	write(&staged.join("cur/1:2,S"), "mail");
	// Planted after the check before the run, before the move.
	std::os::unix::fs::symlink(&elsewhere, &requested).unwrap();
	refused(stage, "is a symbolic link");
	assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[test]
fn a_directory_planted_at_the_export_target_is_refused() {
	let dirs = dirs();
	let (stage, staged, requested) = export(&dirs);
	write(&staged.join("cur/1:2,S"), "mail");
	write(&requested.join("planted"), "theirs");
	refused(stage, "is not empty");
	assert_eq!(
		fs::read_to_string(requested.join("planted")).unwrap(),
		"theirs"
	);

	let dirs = self::dirs();
	let (mut stage, staged, _) = export(&dirs);
	write(&staged.join("cur/1:2,S"), "mail");
	// A directory root does not own is someone else's: pretend root is
	// another uid, so the one this test made is not root's.
	stage.root = me().wrapping_add(1);
	refused(stage, "not a directory owned by root");
}

#[test]
fn an_export_larger_than_the_free_room_is_refused_and_removed() {
	let dirs = dirs();
	let (stage, staged, requested) = export(&dirs);
	write(&staged.join("cur/1:2,S"), "12345678");
	let handle = &stage.dir.as_ref().unwrap().handle;
	let error = move_dir(handle, &stage.outputs[0], me(), me(), |_| Ok(3)).unwrap_err();
	assert!(error.to_string().contains("less than 5% free"), "{error}");
	assert!(!requested.exists());
	// `cur` and the file cost a block each, plus the file's eight bytes.
	let exact = 2 * super::super::super::copy::ENTRY_COST + 8;
	move_dir(handle, &stage.outputs[0], me(), me(), |_| Ok(exact)).expect("fits exactly");
	assert_eq!(
		fs::read_to_string(requested.join("cur/1:2,S")).unwrap(),
		"12345678"
	);
	assert_eq!(
		fs::metadata(&requested).unwrap().permissions().mode() & 0o777,
		0o700
	);
}

#[test]
fn the_room_keeps_five_percent_of_the_filesystem_free() {
	assert_eq!(room_for(50, 100), 45);
	assert_eq!(room_for(4, 100), 0, "a nearly full disk takes nothing");
	assert!(free_room(&File::open(".").unwrap()).is_ok());
}
