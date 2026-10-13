//! On upgrade the preinst keeps the binary it is about to replace, so
//! `epistle stack rollback` has something to put back.

use super::read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Run `preinst <args>` against a fixture binary and state directory.
fn preinst(root: &Path, args: &[&str], binary: &str) -> std::process::Output {
	std::fs::create_dir_all(root.join("state")).unwrap();
	std::fs::write(root.join("epistle"), binary).unwrap();
	std::fs::set_permissions(root.join("epistle"), std::fs::Permissions::from_mode(0o755)).unwrap();
	let mut script = read("debian/epistle.preinst");
	for (from, to) in [
		("/usr/bin/epistle", "epistle"),
		("/var/lib/glyndor/epistle", "state"),
	] {
		script = script.replace(from, root.join(to).to_str().unwrap());
	}
	let path = root.join("preinst");
	std::fs::write(&path, script).unwrap();
	Command::new("sh").arg(&path).args(args).output().unwrap()
}

fn kept(root: &Path) -> Vec<String> {
	let mut names: Vec<String> = std::fs::read_dir(root.join("state/rollback"))
		.map(|entries| {
			entries
				.map(|entry| entry.unwrap().file_name().into_string().unwrap())
				.collect()
		})
		.unwrap_or_default();
	names.sort();
	names
}

#[test]
fn an_upgrade_keeps_the_replaced_binary_and_only_the_two_newest() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	for (version, bytes) in [("0.9.2", "old"), ("0.10.1", "older"), ("0.10.10", "newest")] {
		let output = preinst(root, &["upgrade", version], bytes);
		assert_eq!(output.status.code(), Some(0), "{output:?}");
	}
	assert_eq!(
		kept(root),
		["epistle-0.10.1", "epistle-0.10.10"],
		"by version, not by text"
	);
	let copy = root.join("state/rollback/epistle-0.10.10");
	assert_eq!(std::fs::read_to_string(&copy).unwrap(), "newest");
	assert_eq!(
		std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
		0o755
	);
	let dir_mode = std::fs::metadata(root.join("state/rollback"))
		.unwrap()
		.permissions()
		.mode();
	assert_eq!(dir_mode & 0o777, 0o700, "the kept binaries are root's");
}

#[test]
fn a_fresh_install_keeps_nothing() {
	let dir = tempfile::tempdir().unwrap();
	let output = preinst(dir.path(), &["install"], "x");
	assert_eq!(output.status.code(), Some(0));
	assert!(kept(dir.path()).is_empty());
}
