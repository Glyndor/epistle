//! On upgrade, the postinst moves a subordinate id block that
//! `glyndor-epistle` shares with another account.
//!
//! Packages up to 0.10.1 gave the account 100000-165535, which useradd also
//! gives the first regular user. These tests run the whole postinst as an
//! upgrade from 0.10.1 against fixture tables, with `epistle` stubbed to
//! record what it was asked to do: the postinst decides whether to move and
//! where to, `epistle move-subids` does the move and undoes it on failure.

use super::{read, stubs::write_stub};
use std::process::Command;

/// What one upgrade run did: the `epistle` arguments (empty when it was not
/// called), stderr and the exit code.
struct Run {
	epistle: String,
	stderr: String,
	code: Option<i32>,
}

/// Run `postinst configure 0.10.1` with the given tables; `epistle` exits
/// with `exit`.
fn upgrade(subuid: &str, subgid: &str, login_defs: &str, exit: u8) -> Run {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	std::fs::create_dir_all(root.join("state/data")).unwrap();
	std::fs::create_dir_all(root.join("config")).unwrap();
	std::fs::write(root.join("subuid"), subuid).unwrap();
	std::fs::write(root.join("subgid"), subgid).unwrap();
	std::fs::write(root.join("login.defs"), login_defs).unwrap();
	let bin = root.join("bin");
	std::fs::create_dir(&bin).unwrap();
	for (name, body) in [
		("getent", "exit 0".to_string()),
		("id", "echo 103".to_string()),
		("loginctl", "exit 0".to_string()),
		("runuser", "exit 0".to_string()),
		("podman", "exit 0".to_string()),
		(
			"usermod",
			"echo usermod must not run here >&2; exit 1".to_string(),
		),
		(
			"epistle",
			format!("printf '%s\\n' \"$*\" >> \"$EPISTLE_LOG\"; exit {exit}"),
		),
	] {
		write_stub(&bin.join(name), &body);
	}
	let mut script = read("debian/epistle.postinst");
	for (from, to) in [
		("/etc/subuid", "subuid"),
		("/etc/subgid", "subgid"),
		("/etc/login.defs", "login.defs"),
		("/var/lib/glyndor/epistle", "state"),
		("/var/lib/epistle-rollback", "rollback"),
		("/etc/epistle", "config"),
		("/run/systemd/system", "no-systemd"),
		("/proc/sys", "missing-sys"),
	] {
		script = script.replace(from, root.join(to).to_str().unwrap());
	}
	let script_path = root.join("postinst");
	std::fs::write(&script_path, script).unwrap();
	let log = root.join("epistle.log");
	let output = Command::new("sh")
		.arg(&script_path)
		.arg("configure")
		.arg("0.10.1")
		.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
		.env("EPISTLE_LOG", &log)
		.output()
		.unwrap();
	Run {
		epistle: std::fs::read_to_string(log).unwrap_or_default(),
		stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
		code: output.status.code(),
	}
}

const OVERLAP: &str = "tester:100000:65536\nglyndor-epistle:100000:65536\n";
const CLEAN: &str = "tester:100000:65536\nglyndor-epistle:165536:65536\n";

#[test]
fn the_0_10_1_overlap_is_moved_to_the_first_free_block() {
	let run = upgrade(OVERLAP, OVERLAP, "", 0);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(
		run.epistle, "move-subids --uid-start 165536 --gid-start 165536\n",
		"the postinst must hand the allocator's block to epistle move-subids"
	);
}

#[test]
fn an_overlap_in_one_table_is_enough() {
	let run = upgrade(CLEAN, OVERLAP, "", 0);
	assert_eq!(
		run.epistle,
		"move-subids --uid-start 231072 --gid-start 231072\n"
	);
}

#[test]
fn a_clean_host_is_left_alone() {
	let run = upgrade(CLEAN, CLEAN, "", 0);
	assert_eq!(run.code, Some(0));
	assert_eq!(run.epistle, "", "no overlap, no move");
	let below = "glyndor-epistle:34464:65536\ntester:100000:65536\n";
	assert_eq!(upgrade(below, below, "", 0).epistle, "");
}

#[test]
fn the_block_keeps_the_accounts_size() {
	let table = "tester:100000:65536\nglyndor-epistle:100000:1000\n";
	let defs = "SUB_UID_MAX 166535\nSUB_GID_MAX 166535\n";
	assert_eq!(
		upgrade(table, table, defs, 0).epistle,
		"move-subids --uid-start 165536 --gid-start 165536\n",
		"a 1000-id block fits under a maximum a 65536-id block would not"
	);
}

#[test]
fn a_failed_move_warns_and_never_fails_the_upgrade() {
	let run = upgrade(OVERLAP, OVERLAP, "", 1);
	assert_eq!(
		run.code,
		Some(0),
		"apt must not fail on a move it could not do"
	);
	assert!(
		run.stderr
			.contains("epistle: could not move the subordinate ids of glyndor-epistle"),
		"{}",
		run.stderr
	);
}

#[test]
fn no_room_warns_without_calling_epistle() {
	let run = upgrade(OVERLAP, OVERLAP, "SUB_UID_MAX 200000\n", 0);
	assert_eq!(run.code, Some(0));
	assert_eq!(run.epistle, "");
	assert!(
		run.stderr.contains("no free block of 65536 ids"),
		"{}",
		run.stderr
	);
}
