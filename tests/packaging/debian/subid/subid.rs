//! The postinst gives `glyndor-epistle` a block of subordinate ids that no
//! other account holds.
//!
//! On Debian and Ubuntu `useradd` hands the first regular user exactly
//! 100000-165535, so a fixed range for the service account would share host
//! ids with that user's rootless containers. These tests run the whole postinst
//! against fixture subuid, subgid and login.defs files, with `usermod` stubbed
//! to record what it was asked to add.

use super::{read, stubs::write_stub};
use std::path::Path;
use std::process::Command;

/// What one postinst run did: the `usermod` arguments (one per line, empty
/// when it was not called), stderr and the exit code.
struct Run {
	usermod: String,
	stderr: String,
	code: Option<i32>,
}

/// Write `text` to `path`, or leave the file absent when `text` is `None`.
fn fixture(path: &Path, text: Option<&str>) {
	if let Some(text) = text {
		std::fs::write(path, text).unwrap();
	}
}

/// Run `postinst configure` on a fresh install with the given tables.
fn configure(subuid: Option<&str>, subgid: Option<&str>, login_defs: Option<&str>) -> Run {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	std::fs::create_dir_all(root.join("state/data")).unwrap();
	std::fs::create_dir_all(root.join("config")).unwrap();
	fixture(&root.join("subuid"), subuid);
	fixture(&root.join("subgid"), subgid);
	fixture(&root.join("login.defs"), login_defs);
	let bin = root.join("bin");
	std::fs::create_dir(&bin).unwrap();
	for (name, body) in [
		("getent", "exit 0"),
		("id", "echo 103"),
		("loginctl", "exit 0"),
		("runuser", "exit 0"),
		("podman", "exit 0"),
		("usermod", "printf '%s\\n' \"$@\" > \"$USERMOD_LOG\""),
	] {
		write_stub(&bin.join(name), body);
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
	let log = root.join("usermod.log");
	let output = Command::new("sh")
		.arg(&script_path)
		.arg("configure")
		.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
		.env("USERMOD_LOG", &log)
		.output()
		.unwrap();
	Run {
		usermod: std::fs::read_to_string(log).unwrap_or_default(),
		stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
		code: output.status.code(),
	}
}

/// The `usermod` arguments that add both ranges.
fn both(uid: u64, gid: u64) -> String {
	format!(
		"--add-subuids\n{uid}-{}\n--add-subgids\n{gid}-{}\nglyndor-epistle\n",
		uid + 65535,
		gid + 65535
	)
}

/// Assert the run added exactly `expected` and did not fail the install.
fn assert_added(run: &Run, expected: &str, case: &str) {
	assert_eq!(run.code, Some(0), "{case}: the postinst must not fail");
	assert_eq!(
		run.usermod, expected,
		"{case}: usermod was asked for the wrong subordinate id ranges"
	);
}

#[test]
fn empty_or_missing_tables_start_at_100000() {
	assert_added(
		&configure(Some(""), Some(""), None),
		&both(100000, 100000),
		"empty",
	);
	assert_added(
		&configure(None, None, None),
		&both(100000, 100000),
		"missing",
	);
}

#[test]
fn a_user_at_the_default_range_pushes_the_service_past_it() {
	let table = "jaroc:100000:65536\n";
	assert_added(
		&configure(Some(table), Some(table), None),
		&both(165536, 165536),
		"jaroc at 100000",
	);
}

#[test]
fn a_hole_is_used_only_when_the_whole_block_fits() {
	let short = "a:100000:65536\nb:200000:65536\n";
	assert_added(
		&configure(Some(short), Some(short), None),
		&both(265536, 265536),
		"34464-id hole",
	);
	let exact = "a:100000:65536\nb:231072:65536\n";
	assert_added(
		&configure(Some(exact), Some(exact), None),
		&both(165536, 165536),
		"65536-id hole",
	);
}

#[test]
fn entries_out_of_order_are_all_avoided() {
	let table = "c:231072:65536\na:100000:65536\nb:165536:65536\n";
	assert_added(
		&configure(Some(table), Some(table), None),
		&both(296608, 296608),
		"unsorted",
	);
}

#[test]
fn differing_tables_share_a_start_when_one_is_free_in_both() {
	assert_added(
		&configure(Some("jaroc:100000:65536\n"), Some(""), None),
		&both(165536, 165536),
		"uid taken, gid free",
	);
}

#[test]
fn differing_tables_allocate_independently_when_no_common_start_fits() {
	let defs = "SUB_UID_MAX 231071\nSUB_GID_MAX 600100000\n";
	assert_added(
		&configure(
			Some("a:100000:65536\n"),
			Some("b:165536:65536\n"),
			Some(defs),
		),
		&both(165536, 100000),
		"no common start under SUB_UID_MAX",
	);
}

#[test]
fn login_defs_bounds_are_honoured() {
	let defs = "#SUB_UID_MIN 5\nSUB_UID_MIN\t\t200000\nSUB_GID_MIN 300000\n";
	assert_added(
		&configure(Some(""), Some(""), Some(defs)),
		&both(300000, 300000),
		"SUB_UID_MIN 200000, SUB_GID_MIN 300000",
	);
	let full = configure(Some(""), Some(""), Some("SUB_UID_MAX 150000\n"));
	assert_added(&full, "", "no room under SUB_UID_MAX 150000");
	assert!(
		full.stderr
			.contains("epistle: no free block of 65536 subordinate ids for glyndor-epistle"),
		"a host without room must be told so on stderr: {}",
		full.stderr
	);
}

#[test]
fn existing_entries_of_the_account_are_kept() {
	let mine = "glyndor-epistle:300000:65536\n";
	assert_added(&configure(Some(mine), Some(mine), None), "", "both present");
	assert_added(
		&configure(Some(mine), Some(""), None),
		"--add-subgids\n100000-165535\nglyndor-epistle\n",
		"only the subgid missing",
	);
}

#[test]
fn the_postinst_no_longer_names_a_fixed_range() {
	assert!(
		!read("debian/epistle.postinst").contains("100000-165535"),
		"debian/epistle.postinst must not name the fixed 100000-165535 range: useradd gives that \
		 range to the first regular user on Debian and Ubuntu"
	);
}
