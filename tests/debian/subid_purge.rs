//! Purge removes the subordinate id ranges `glyndor-epistle` actually holds.
//!
//! The postinst picks a free block per host, so the postrm cannot name a fixed
//! range: it reads the account's entries back from /etc/subuid and
//! /etc/subgid. These tests run the purge against fixture tables with
//! `usermod`, `deluser` and `loginctl` stubbed.

use super::{read, stubs::write_stub};
use std::process::Command;

/// Run `postrm purge` against the given tables and return the `usermod`
/// arguments, one per line (empty when it was not called).
fn purge(subuid: &str, subgid: &str) -> String {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	std::fs::create_dir_all(root.join("state")).unwrap();
	std::fs::write(root.join("subuid"), subuid).unwrap();
	std::fs::write(root.join("subgid"), subgid).unwrap();
	let bin = root.join("bin");
	std::fs::create_dir(&bin).unwrap();
	for (name, body) in [
		("loginctl", "exit 0"),
		("deluser", "exit 0"),
		("usermod", "printf '%s\\n' \"$@\" > \"$USERMOD_LOG\""),
	] {
		write_stub(&bin.join(name), body);
	}
	let mut script = read("debian/epistle.postrm");
	for (from, to) in [
		("/etc/subuid", "subuid"),
		("/etc/subgid", "subgid"),
		("/var/lib/glyndor/epistle", "state"),
		("/run/systemd/system", "no-systemd"),
	] {
		script = script.replace(from, root.join(to).to_str().unwrap());
	}
	assert!(
		!script.contains("/var/lib/glyndor") && !script.contains("/etc/sub"),
		"the purge under test must only touch the fixture directory"
	);
	let script_path = root.join("postrm");
	std::fs::write(&script_path, script).unwrap();
	let log = root.join("usermod.log");
	let output = Command::new("sh")
		.arg(&script_path)
		.arg("purge")
		.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
		.env("USERMOD_LOG", &log)
		.output()
		.unwrap();
	assert_eq!(output.status.code(), Some(0), "purge must not fail");
	std::fs::read_to_string(log).unwrap_or_default()
}

#[test]
fn purge_removes_every_range_the_account_holds_and_no_other() {
	let subuid = "jaroc:100000:65536\nglyndor-epistle:165536:65536\n";
	let subgid = "glyndor-epistle:165536:65536\njaroc:100000:65536\nglyndor-epistle:400000:10\n";
	assert_eq!(
		purge(subuid, subgid),
		"--del-subuids\n165536-231071\n--del-subgids\n165536-231071\n--del-subgids\n\
		 400000-400009\nglyndor-epistle\n",
		"purge must remove exactly the ranges listed for glyndor-epistle"
	);
}

#[test]
fn purge_without_ranges_does_not_call_usermod() {
	assert_eq!(
		purge("jaroc:100000:65536\n", ""),
		"",
		"purge must not ask usermod to remove ranges the account does not hold"
	);
}

#[test]
fn the_postrm_no_longer_names_a_fixed_range() {
	assert!(
		!read("debian/epistle.postrm").contains("100000-165535"),
		"debian/epistle.postrm must not name the fixed 100000-165535 range: the postinst \
		 allocates a block per host"
	);
}
