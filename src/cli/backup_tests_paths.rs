use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

fn config_for(data_dir: &Path) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n",
		data_dir
	))
	.expect("config")
}

fn restore_entry(data_dir: &Path, name: &str, mode: u32) -> (ExitCode, Vec<u8>) {
	let archive = tar_gz(&[
		("data/first".into(), 0o600, b"first".to_vec()),
		(name.into(), mode, b"replacement".to_vec()),
	])
	.expect("archive");
	let mut out = Vec::new();
	let exit = run_restore(&config_for(data_dir), &archive, &mut out);
	(exit, out)
}

fn rejects_name(name: &str) {
	let root = tempfile::tempdir_in(std::env::current_dir().expect("cwd")).expect("tempdir");
	let data_dir = root.path().join("data");
	std::fs::create_dir(&data_dir).expect("data dir");
	let outside = root.path().join("x");
	std::fs::write(&outside, b"unchanged").expect("outside sentinel");
	let destination = data_dir.join(name.strip_prefix("data/").unwrap_or(name));
	let state = |path: &Path| {
		std::fs::symlink_metadata(path)
			.ok()
			.map(|metadata| (metadata.ino(), metadata.len(), metadata.mode()))
	};
	let before = state(&destination);
	let (exit, out) = restore_entry(&data_dir, name, 0o600);
	assert!(
		!data_dir.join("first").exists(),
		"invalid archive names must be rejected before any file is written"
	);
	assert_eq!(exit, ExitCode::FAILURE, "invalid name must fail restore");
	assert!(out.is_empty(), "failed restore must emit no success line");
	assert_eq!(
		state(&destination),
		before,
		"invalid name must leave its destination unchanged"
	);
	assert!(
		std::fs::read(outside).expect("sentinel") == b"unchanged",
		"restore must leave files outside data_dir unchanged"
	);
	assert_eq!(std::fs::read_dir(data_dir).expect("entries").count(), 0);
}

macro_rules! invalid_names {
	($($test:ident: $name:literal),* $(,)?) => {
		$(#[test]
		fn $test() {
			rejects_name($name);
		})*
	};
}

invalid_names! {
	restore_rejects_parent_component: "data/../x",
	restore_rejects_repeated_separator: "data//abs",
	restore_rejects_absolute_name: "/etc/x",
	restore_rejects_current_component: "data/./x",
	restore_rejects_empty_relative_path: "data/",
	restore_rejects_trailing_separator: "data/x/",
	restore_rejects_unknown_name: "x",
}

fn rejects_symlink(ancestor: bool) {
	let root = tempfile::tempdir_in(std::env::current_dir().expect("cwd")).expect("tempdir");
	let data_dir = root.path().join("data");
	let outside = root.path().join("outside");
	std::fs::create_dir(&data_dir).expect("data dir");
	std::fs::create_dir(&outside).expect("outside dir");
	let sentinel = outside.join("x");
	std::fs::write(&sentinel, b"unchanged").expect("sentinel");
	let (link, target, name) = if ancestor {
		(data_dir.join("link"), outside, "data/link/x")
	} else {
		(data_dir.join("x"), sentinel.clone(), "data/x")
	};
	symlink(target, &link).expect("symlink");
	let (exit, out) = restore_entry(&data_dir, name, 0o600);
	assert!(
		!data_dir.join("first").exists(),
		"symlinks must be rejected before any file is written"
	);
	assert_eq!(exit, ExitCode::FAILURE, "symlink must fail restore");
	assert!(out.is_empty(), "failed restore must emit no success line");
	assert!(
		std::fs::read(sentinel).expect("sentinel") == b"unchanged",
		"restore must leave the symlink target unchanged"
	);
	assert!(std::fs::symlink_metadata(link).expect("link").is_symlink());
}

#[test]
fn restore_rejects_symlink_ancestor() {
	rejects_symlink(true);
}

#[test]
fn restore_rejects_symlink_destination() {
	rejects_symlink(false);
}

#[test]
fn restore_strips_special_mode_bits() {
	let root = tempfile::tempdir_in(std::env::current_dir().expect("cwd")).expect("tempdir");
	let data_dir = root.path().join("data");
	let (exit, out) = restore_entry(&data_dir, "data/key", 0o7600);
	assert_eq!(exit, ExitCode::SUCCESS);
	assert!(
		out == b"restored 2 entries\n",
		"restore must report two entries"
	);
	assert_eq!(
		std::fs::metadata(data_dir.join("key"))
			.expect("key")
			.permissions()
			.mode() & 0o7777,
		0o600,
		"restore must strip setuid, setgid and sticky bits"
	);
}

#[test]
fn restore_replaces_files_without_writing_through_hardlinks() {
	let root = tempfile::tempdir_in(std::env::current_dir().expect("cwd")).expect("tempdir");
	let data_dir = root.path().join("data");
	std::fs::create_dir(&data_dir).expect("data dir");
	let outside = root.path().join("outside");
	std::fs::write(&outside, b"unchanged").expect("outside");
	std::fs::hard_link(&outside, data_dir.join("x")).expect("hardlink");
	let (exit, _) = restore_entry(&data_dir, "data/x", 0o600);
	assert_eq!(exit, ExitCode::SUCCESS);
	assert!(
		std::fs::read(outside).expect("outside") == b"unchanged",
		"restore must replace the destination inode without changing outside hardlinks"
	);
	assert!(std::fs::read(data_dir.join("x")).expect("restored") == b"replacement");
	assert_eq!(std::fs::read_dir(data_dir).expect("entries").count(), 2);
}
