//! A backup and `rotate --all`: only what the rotation may restore goes into
//! the archive, and the two never run at once.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::backup::collect::collect_files;
use crate::config::Config;

#[test]
fn of_the_rotation_directory_only_the_journal_and_the_last_run_are_archived() {
	let root = tempfile::tempdir().expect("dir");
	let rotate = root.path().join("rotate");
	std::fs::create_dir(&rotate).expect("mkdir");
	for name in [
		"journal.json",
		"last-run.json",
		"secrets.json",
		// The staging copy `write_secret` makes of the secrets file.
		".secrets.json.0196f3c4-7a21-7c3e-9a55-4c2f0b1e8d77.tmp",
		".journal.json.0196f3c4-7a21-7c3e-9a55-4c2f0b1e8d78.tmp",
		"lock",
		"anything-else",
	] {
		std::fs::write(rotate.join(name), b"{}").expect("file");
	}
	std::fs::write(root.path().join("api_keys.toml"), b"").expect("file");
	std::fs::write(root.path().join("rotate-notes"), b"").expect("file");
	let names: Vec<String> = collect_files(root.path())
		.expect("collect")
		.into_iter()
		.map(|(name, ..)| name)
		.collect();
	assert_eq!(
		names,
		[
			"data/api_keys.toml",
			"data/rotate-notes",
			"data/rotate/journal.json",
			"data/rotate/last-run.json"
		]
	);
}

fn config_for(data_dir: &Path) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	))
	.expect("config")
}

#[test]
fn a_backup_is_refused_while_a_rotation_holds_the_lock_and_runs_after_it() {
	let root = tempfile::tempdir().expect("dir");
	std::fs::write(root.path().join("seed.eml"), b"seed").expect("seed");
	let config = config_for(root.path());
	let held = crate::cli::rotate::lock(root.path())
		.expect("lock")
		.expect("free");
	let (mut archive, mut warnings) = (Vec::new(), Vec::new());
	let exit = super::super::create::run(&config, &mut archive, &mut warnings);
	assert_eq!(exit, ExitCode::FAILURE);
	assert!(
		archive.is_empty(),
		"an archive was written under a running rotation"
	);
	drop(held);
	let exit = super::super::create::run(&config, &mut archive, &mut warnings);
	assert_eq!(exit, ExitCode::SUCCESS);
	assert!(!archive.is_empty());
	// The backup let go of the lock, so a rotation can start.
	assert!(
		crate::cli::rotate::lock(root.path())
			.expect("lock")
			.is_some()
	);
}

#[test]
fn a_backup_of_a_server_that_never_rotated_writes_nothing_into_its_data() {
	let root = tempfile::tempdir().expect("dir");
	std::fs::write(root.path().join("seed.eml"), b"seed").expect("seed");
	let (mut archive, mut warnings) = (Vec::new(), Vec::new());
	let exit = super::super::create::run(&config_for(root.path()), &mut archive, &mut warnings);
	assert_eq!(exit, ExitCode::SUCCESS);
	assert!(!root.path().join("rotate").exists());
}

#[test]
fn a_data_dir_reached_through_a_link_is_collected_and_its_own_links_are_not_followed() {
	let outer = tempfile::tempdir().expect("dir");
	let real = outer.path().join("real");
	let outside = outer.path().join("outside");
	std::fs::create_dir_all(real.join("accounts")).expect("mkdir");
	std::fs::create_dir(&outside).expect("mkdir");
	std::fs::write(real.join("accounts").join("m.eml"), b"x").expect("file");
	std::fs::write(outside.join("note"), b"y").expect("file");
	std::os::unix::fs::symlink(&outside, real.join("linked")).expect("link");
	let alias = outer.path().join("alias");
	std::os::unix::fs::symlink(&real, &alias).expect("link");
	let names: Vec<String> = collect_files(&alias)
		.expect("collect")
		.into_iter()
		.map(|(name, ..)| name)
		.collect();
	assert_eq!(names, ["data/accounts/m.eml"]);
}

#[cfg(unix)]
#[test]
fn a_name_that_is_not_plain_utf8_is_left_out_without_failing_the_backup() {
	use std::os::unix::ffi::OsStrExt;
	let root = tempfile::tempdir().expect("dir");
	std::fs::write(root.path().join("kept"), b"x").expect("file");
	std::fs::write(
		root.path().join(std::ffi::OsStr::from_bytes(b"caf\xe9")),
		b"y",
	)
	.expect("file");
	std::fs::write(root.path().join("a\\b"), b"z").expect("file");
	let odd_dir = root.path().join(std::ffi::OsStr::from_bytes(b"d\xff"));
	std::fs::create_dir(&odd_dir).expect("mkdir");
	std::fs::write(odd_dir.join("inner"), b"w").expect("file");
	let names: Vec<String> = collect_files(root.path())
		.expect("one odd name must not fail the backup")
		.into_iter()
		.map(|(name, ..)| name)
		.collect();
	assert_eq!(names, ["data/kept"]);
}
