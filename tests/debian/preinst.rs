//! Exercise rollback package storage using remapped paths and simulated root ownership.

use super::read;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub(super) fn prepare(root: &Path) {
	std::fs::create_dir_all(root.join("var/lib/glyndor/epistle")).unwrap();
	for parent in ["var", "var/lib"] {
		std::fs::set_permissions(root.join(parent), std::fs::Permissions::from_mode(0o755))
			.unwrap();
	}
	std::fs::write(root.join("epistle"), "installed binary").unwrap();
	std::fs::set_permissions(root.join("epistle"), std::fs::Permissions::from_mode(0o755)).unwrap();
}

pub(super) fn script(root: &Path, name: &str) -> String {
	read(&format!("debian/epistle.{name}"))
		.replace("/usr/bin/epistle", root.join("epistle").to_str().unwrap())
		.replace("/var", root.join("var").to_str().unwrap())
}

pub(super) fn run(root: &Path, script: &str, args: &[&str], setup: &str) -> Output {
	// Use the GNU tools Debian ships when the host also provides prefixed copies.
	let bin = root.join("tools");
	std::fs::create_dir_all(&bin).unwrap();
	for tool in ["stat", "chown", "chmod", "mkdir", "mktemp", "cp"] {
		let gnu = format!("/usr/bin/gnu{tool}");
		if Path::new(&gnu).exists() && !bin.join(tool).exists() {
			symlink(gnu, bin.join(tool)).unwrap();
		}
	}
	let path = root.join("maintainer");
	std::fs::write(&path, script).unwrap();
	Command::new("fakeroot")
		.args(["sh", "-ec"])
		.arg(format!("{setup}\nsh \"$@\"\nif [ -d var/lib/epistle-rollback ]; then stat -c '%u:%g %a' var/lib/epistle-rollback; fi"))
		.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
		.arg("fixture")
		.arg(path)
		.args(args)
		.current_dir(root)
		.output()
		.unwrap_or_else(|error| {
			// fakeroot is what lets an unprivileged test run exercise the root
			// ownership the preinst checks on every path it touches. Without it
			// the script refuses to copy anything, so these tests would answer
			// nothing. Say so loudly rather than skip: a green run that covered
			// nothing is what R2-03 flagged. The packaging workflow installs the
			// package (`apt-packages` in ci.yml), so CI never lands here.
			panic!(
				"fakeroot is required to exercise the root ownership the package \
				 maintainer scripts check; install it (Debian: apt install fakeroot) \
				 and re-run to cover these tests. Underlying error: {error}"
			)
		})
}

pub(super) fn preinst(root: &Path, args: &[&str], setup: &str) -> Output {
	run(root, &script(root, "preinst"), args, setup)
}

pub(super) fn store(root: &Path) -> PathBuf {
	root.join("var/lib/epistle-rollback")
}

/// One saved version: the directory the preinst renamed into place with the
/// binary and the digest it checks before installing.
pub(super) fn generation(root: &Path, version: &str) -> PathBuf {
	store(root).join(format!("epistle-{version}"))
}

pub(super) fn listing(root: &Path) -> Vec<String> {
	let mut names: Vec<_> = std::fs::read_dir(store(root))
		.unwrap()
		.map(|entry| entry.unwrap().file_name().into_string().unwrap())
		.collect();
	names.sort();
	names
}

pub(super) fn mode(path: &Path) -> u32 {
	std::fs::metadata(path).unwrap().permissions().mode()
}

pub(super) fn sha256_of(path: &Path) -> String {
	let output = Command::new("sha256sum").arg(path).output().unwrap();
	String::from_utf8_lossy(&output.stdout)
		.split_whitespace()
		.next()
		.unwrap()
		.to_string()
}

/// Whether the saved binary and the digest saved next to it still belong
/// together, which is what the rollback command checks before it installs.
pub(super) fn generation_installs(root: &Path, version: &str) -> bool {
	let kept = generation(root, version).join("epistle");
	let manifest = generation(root, version).join("epistle.sha256");
	kept.is_file()
		&& manifest.is_file()
		&& std::fs::read_to_string(&manifest).unwrap().trim() == sha256_of(&kept)
}

#[test]
fn an_upgrade_keeps_the_replaced_binary_and_only_the_two_newest() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare(root);
	for version in ["0.9.2", "0.10.1", "0.10.10"] {
		// Each upgrade replaces a different binary: bytes already saved are
		// not saved again under another name.
		std::fs::write(root.join("epistle"), format!("binary {version}")).unwrap();
		let output = preinst(root, &["upgrade", version], "");
		assert!(output.status.success(), "{output:?}");
		assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0:0 700");
	}
	assert_eq!(listing(root), ["epistle-0.10.1", "epistle-0.10.10"]);
	let kept = generation(root, "0.10.10");
	assert_eq!(
		std::fs::read_to_string(kept.join("epistle")).unwrap(),
		"binary 0.10.10"
	);
	assert_eq!(mode(&kept) & 0o777, 0o700);
	assert_eq!(mode(&kept.join("epistle")) & 0o777, 0o755);
	assert_eq!(mode(&kept.join("epistle.sha256")) & 0o022, 0);
	assert_eq!(
		std::fs::read_to_string(kept.join("epistle.sha256"))
			.unwrap()
			.trim(),
		sha256_of(&root.join("epistle"))
	);
}

#[test]
fn a_fresh_install_creates_a_private_root_store_without_binaries() {
	let dir = tempfile::tempdir().unwrap();
	prepare(dir.path());
	let output = preinst(dir.path(), &["install"], "");
	assert!(output.status.success(), "{output:?}");
	assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0:0 700");
	assert_eq!(std::fs::read_dir(store(dir.path())).unwrap().count(), 0);
}

#[test]
fn postinst_also_prepares_the_store_on_configure() {
	let dir = tempfile::tempdir().unwrap();
	prepare(dir.path());
	let script = script(dir.path(), "postinst");
	let setup = script.split("\t# 1. The account.").next().unwrap();
	let output = run(
		dir.path(),
		&format!("{setup}\n;;\nesac\n"),
		&["configure"],
		"",
	);
	assert!(output.status.success(), "{output:?}");
	assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0:0 700");
}

#[test]
fn links_in_the_store_and_its_parents_are_rejected_without_writes() {
	for linked in ["var", "var/lib", "var/lib/epistle-rollback"] {
		let dir = tempfile::tempdir().unwrap();
		let root = dir.path();
		prepare(root);
		let outside = root.join("outside");
		std::fs::create_dir(&outside).unwrap();
		std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
		let link = root.join(linked);
		if link.exists() {
			std::fs::remove_dir_all(&link).unwrap();
		}
		symlink(&outside, &link).unwrap();
		let output = preinst(root, &["upgrade", "0.12.1"], "");
		assert!(output.status.success(), "{output:?}");
		assert!(
			String::from_utf8_lossy(&output.stderr).contains("rollback"),
			"{output:?}"
		);
		assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0);
		let postinst = script(root, "postinst");
		let block = postinst.split("\t# 1. The account.").next().unwrap();
		let output = run(root, &format!("{block}\n;;\nesac\n"), &["configure"], "");
		assert!(output.status.success());
		assert!(String::from_utf8_lossy(&output.stderr).contains("rollback"));
		assert_eq!(std::fs::read_dir(root.join("outside")).unwrap().count(), 0);
		assert_eq!(
			std::fs::metadata(root.join("outside"))
				.unwrap()
				.permissions()
				.mode() & 0o777,
			0o755
		);
	}
}

#[test]
fn untrusted_source_binaries_are_not_saved() {
	for setup in [
		"chown 1234 epistle 2>/dev/null || test \"$(stat -c %u epistle)\" = 1234",
		"chmod 0777 epistle",
		"mv epistle actual; ln -s actual epistle",
	] {
		let dir = tempfile::tempdir().unwrap();
		prepare(dir.path());
		let output = preinst(dir.path(), &["upgrade", "0.12.1"], setup);
		assert!(output.status.success(), "{output:?}");
		assert!(!store(dir.path()).join("epistle-0.12.1").exists());
		assert!(
			String::from_utf8_lossy(&output.stderr).contains("could not keep"),
			"{output:?}"
		);
	}
}

#[test]
fn legacy_binaries_and_prepared_temporary_names_are_ignored() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare(root);
	std::fs::create_dir_all(root.join("var/lib/glyndor/epistle/rollback")).unwrap();
	std::fs::write(
		root.join("var/lib/glyndor/epistle/rollback/epistle-0.12.0"),
		"legacy",
	)
	.unwrap();
	std::fs::create_dir(store(root)).unwrap();
	std::fs::set_permissions(store(root), std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::write(root.join("victim"), "keep me").unwrap();
	let outside = root.join("outside");
	std::fs::create_dir(&outside).unwrap();
	std::fs::write(outside.join("epistle"), "keep me too").unwrap();
	// Names an implementation without an exclusive temporary would reuse: the
	// ones it would write in place, and the staging ones it would write into.
	for name in ["epistle-0.12.1.partial", ".epistle-fixed", ".digest-fixed"] {
		symlink(root.join("victim"), store(root).join(name)).unwrap();
	}
	for name in [".stage", ".stage-fixed"] {
		symlink(&outside, store(root).join(name)).unwrap();
	}
	let output = preinst(root, &["upgrade", "0.12.1"], "");
	assert!(output.status.success(), "{output:?}");
	assert_eq!(
		std::fs::read_to_string(root.join("victim")).unwrap(),
		"keep me"
	);
	assert_eq!(
		std::fs::read_to_string(outside.join("epistle")).unwrap(),
		"keep me too"
	);
	assert!(!store(root).join("epistle-0.12.0").exists());
	assert!(
		String::from_utf8_lossy(&output.stderr).contains("legacy"),
		"{output:?}"
	);
	assert!(generation(root, "0.12.1").is_dir());
	assert!(generation_installs(root, "0.12.1"));
	assert_eq!(
		std::fs::read_to_string(generation(root, "0.12.1").join("epistle")).unwrap(),
		"installed binary"
	);
}

#[test]
fn configure_with_only_legacy_copies_does_not_make_rollback_available() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare(root);
	let legacy = root.join("var/lib/glyndor/epistle/rollback");
	std::fs::create_dir(&legacy).unwrap();
	std::fs::write(legacy.join("epistle-0.12.1"), "legacy").unwrap();
	let output = preinst(root, &["install"], "");
	assert!(output.status.success());
	assert!(String::from_utf8_lossy(&output.stderr).contains("legacy"));
	assert_eq!(std::fs::read_dir(store(root)).unwrap().count(), 0);
	assert_eq!(
		std::fs::read_to_string(legacy.join("epistle-0.12.1")).unwrap(),
		"legacy"
	);
}

#[test]
fn non_root_or_writable_store_parents_are_rejected() {
	for setup in [
		"chown 1234 var/lib 2>/dev/null || test \"$(stat -c %u var/lib)\" = 1234",
		"chmod 0777 var/lib",
		"mkdir var/lib/epistle-rollback; chown 1234 var/lib/epistle-rollback 2>/dev/null || test \"$(stat -c %u var/lib/epistle-rollback)\" = 1234",
	] {
		let dir = tempfile::tempdir().unwrap();
		prepare(dir.path());
		let output = preinst(dir.path(), &["upgrade", "0.12.1"], setup);
		assert!(output.status.success(), "{output:?}");
		assert!(String::from_utf8_lossy(&output.stderr).contains("could not prepare"));
		assert!(!store(dir.path()).join("epistle-0.12.1").exists());
	}
}
