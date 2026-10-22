//! Purge removes the footprint in one order, and stops when it cannot.
//!
//! The postrm used to warn and carry on: a `deluser` that failed still ended
//! with `rm -rf /var/lib/glyndor/epistle` and exit 0, so the account stayed with
//! no home behind it and no error anywhere. Nothing stopped the writers either,
//! so the mail could be deleted under a running server or container, and the
//! configuration directory the postinst created was never removed at all.
//!
//! These tests run the purge case with `loginctl`, `usermod`, `deluser` and `id`
//! stubbed and every path pointed at a fixture tree. The writers check reads
//! a private proc fixture, so no host process is signalled by these tests.

use super::{read, stubs::write_stub};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A system UID with no process in the private proc fixture.
const UNUSED_UID: &str = "901";

/// How the account resolves and how each command behaves in one run.
struct Fixture {
	/// `id -u glyndor-epistle` output. UID 900 has a simulated writer.
	uid: &'static str,
	/// `deluser` exit code.
	deluser_exit: i32,
	/// Whether /run/systemd/system exists, which is what gates loginctl.
	systemd: bool,
	/// Whether /etc/epistle is a symlink instead of a directory.
	config_symlink: bool,
}

/// What one purge run did to the fixture tree.
struct Outcome {
	code: Option<i32>,
	stderr: String,
	/// Every command the stubs were called with, one argv per line.
	calls: String,
	state: PathBuf,
	config: PathBuf,
	/// Whether the file behind a symlinked config directory survived, measured
	/// while the fixture tree was still on disk.
	outside_kept: bool,
	/// The fixture tree, held so the assertions run before it is removed.
	_tree: tempfile::TempDir,
}

/// Run `postrm purge` against a fixture tree built from `fixture`.
fn purge(fixture: Fixture) -> Outcome {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	// The state directory stands for both the mailbox and the stack data, so
	// its survival means the mail is still there.
	let state = root.join("state");
	let config = root.join("config");
	fs::create_dir_all(state.join("mail/example.net")).unwrap();
	fs::write(state.join("mail/example.net/INBOX"), "message\n").unwrap();
	let outside = root.join("outside");
	fs::create_dir_all(&outside).unwrap();
	fs::write(outside.join("kept"), "not ours\n").unwrap();
	if fixture.config_symlink {
		std::os::unix::fs::symlink(&outside, &config).unwrap();
	} else {
		fs::create_dir(&config).unwrap();
		fs::write(config.join("mail.toml"), "owner-only\n").unwrap();
		fs::set_permissions(&config, fs::Permissions::from_mode(0o750)).unwrap();
	}
	let systemd = root.join("run/systemd/system");
	if fixture.systemd {
		fs::create_dir_all(&systemd).unwrap();
	}
	let bin = root.join("bin");
	fs::create_dir(&bin).unwrap();
	let calls = root.join("calls.log");
	fs::create_dir_all(root.join("proc/123")).unwrap();
	if fixture.uid == own_uid() {
		fs::write(root.join("proc/123/status"), "Uid:\t900\t900\t900\t900\n").unwrap();
	}
	for (name, body) in [
		(
			"getent",
			format!(
				"echo 'glyndor-epistle:x:{}:900::{}:/usr/sbin/nologin'",
				fixture.uid,
				state.display()
			),
		),
		(
			"systemctl",
			"printf 'systemctl %s\\n' \"$*\" >> \"$CALLS_LOG\"".to_owned(),
		),
		("start-stop-daemon", "exit 0".to_owned()),
		("id", format!("printf '%s\\n' {}", fixture.uid)),
		(
			"loginctl",
			"printf 'loginctl %s\\n' \"$*\" >> \"$CALLS_LOG\"\nexit 0".to_owned(),
		),
		(
			"usermod",
			"printf 'usermod %s\\n' \"$*\" >> \"$CALLS_LOG\"".to_owned(),
		),
		(
			"deluser",
			format!(
				"printf 'deluser %s\\n' \"$*\" >> \"$CALLS_LOG\"\nexit {}",
				fixture.deluser_exit
			),
		),
	] {
		write_stub(&bin.join(name), &body);
	}
	// The tables carry nothing for the account, so usermod is never reached;
	// pointing them at the fixture keeps the purge away from the real ones.
	fs::write(root.join("subuid"), "someone-else:100000:65536\n").unwrap();
	fs::write(root.join("subgid"), "someone-else:100000:65536\n").unwrap();

	let mut script = read("debian/epistle.postrm");
	for (from, to) in [
		("/var/lib/glyndor/epistle", state.to_str().unwrap()),
		("/etc/epistle", config.to_str().unwrap()),
		("/etc/glyndor", root.join("legacy-parent").to_str().unwrap()),
		("/proc/", root.join("proc/").to_str().unwrap()),
		("/run/systemd/system", systemd.to_str().unwrap()),
		("/etc/subuid", root.join("subuid").to_str().unwrap()),
		("/etc/subgid", root.join("subgid").to_str().unwrap()),
		("EPISTLE_STOP_WAIT=30", "EPISTLE_STOP_WAIT=0"),
	] {
		script = script.replace(from, to);
	}
	for untouched in ["/var/lib/glyndor", "/etc/epistle", "/etc/sub"] {
		assert!(
			!script.contains(untouched),
			"the purge under test must only touch the fixture tree, but {untouched} survived"
		);
	}
	let script_path = root.join("postrm");
	fs::write(&script_path, script).unwrap();
	let output = Command::new("sh")
		.arg(&script_path)
		.arg("purge")
		.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
		.env("CALLS_LOG", &calls)
		.output()
		.unwrap();
	Outcome {
		code: output.status.code(),
		stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
		calls: fs::read_to_string(&calls).unwrap_or_default(),
		state,
		config,
		outside_kept: outside.join("kept").is_file(),
		_tree: dir,
	}
}

/// The system UID with a writer in the private proc fixture.
fn own_uid() -> &'static str {
	"900"
}

/// Assert the fixture tree still carries the operator's mail.
fn assert_data_kept(outcome: &Outcome, why: &str) {
	assert!(
		outcome.state.join("mail/example.net/INBOX").is_file(),
		"{why}: the mail must survive a purge that could not complete"
	);
	assert!(
		Path::new(&outcome.config).exists(),
		"{why}: the config directory must survive too"
	);
}

#[test]
fn purge_refuses_to_remove_anything_while_the_account_has_a_running_process() {
	let outcome = purge(Fixture {
		uid: own_uid(),
		deluser_exit: 0,
		systemd: true,
		config_symlink: false,
	});

	assert_eq!(
		outcome.code,
		Some(1),
		"purge must fail while a writer of the account is running, got {:?} with stderr: {}",
		outcome.code,
		outcome.stderr
	);
	assert_data_kept(&outcome, "a writer is still running");
	assert!(
		!outcome.calls.contains("deluser"),
		"nothing may be removed before the writers are gone, but the account was removed anyway: {}",
		outcome.calls
	);
	assert!(
		outcome
			.calls
			.contains("loginctl terminate-user glyndor-epistle"),
		"the account's processes are the writers, so the purge must terminate them: {}",
		outcome.calls
	);
	assert!(
		outcome.stderr.contains("still has processes running"),
		"the refusal must name the reason, got: {}",
		outcome.stderr
	);
	assert!(
		outcome.stderr.contains("dpkg --purge epistle again"),
		"the refusal must name how to retry, got: {}",
		outcome.stderr
	);
}

#[test]
fn purge_stops_the_account_before_it_removes_the_footprint() {
	let outcome = purge(Fixture {
		uid: UNUSED_UID,
		deluser_exit: 0,
		systemd: true,
		config_symlink: false,
	});

	assert_eq!(
		outcome.code,
		Some(0),
		"purge must not fail: {}",
		outcome.stderr
	);
	let lines: Vec<&str> = outcome.calls.lines().collect();
	assert_eq!(
		lines,
		vec![
			"systemctl stop epistle.socket",
			"systemctl disable epistle.socket",
			"systemctl stop epistle.service",
			"systemctl disable epistle.service",
			"loginctl disable-linger glyndor-epistle",
			"loginctl terminate-user glyndor-epistle",
			"deluser --system --quiet glyndor-epistle",
		],
		"purge must stop the account, then remove it, and must not call usermod for ranges the \
		 account does not hold"
	);
	assert!(
		!outcome.state.exists(),
		"purge must remove the state directory"
	);
	assert!(
		!outcome.config.exists(),
		"purge must remove the config directory it created"
	);
}

#[test]
fn purge_keeps_the_mail_when_the_account_cannot_be_removed() {
	let outcome = purge(Fixture {
		uid: UNUSED_UID,
		deluser_exit: 8,
		systemd: false,
		config_symlink: false,
	});

	assert_eq!(
		outcome.code,
		Some(1),
		"a failed account removal must fail the purge instead of deleting the mail anyway"
	);
	assert_data_kept(&outcome, "deluser failed");
	assert!(
		outcome.stderr.contains(
			"could not remove the glyndor-epistle account, so its data was left in place"
		),
		"the failure must say the mail is still there, got: {}",
		outcome.stderr
	);
}

#[test]
fn purge_completes_when_the_account_is_already_gone() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	let state = root.join("state");
	std::fs::create_dir_all(&state).unwrap();
	let bin = root.join("bin");
	std::fs::create_dir(&bin).unwrap();
	write_stub(&bin.join("id"), "exit 1");
	write_stub(&bin.join("deluser"), "exit 0");
	write_stub(&bin.join("usermod"), "exit 0");
	write_stub(&bin.join("loginctl"), "exit 0");
	std::fs::write(root.join("subuid"), "").unwrap();
	std::fs::write(root.join("subgid"), "").unwrap();
	let mut script = read("debian/epistle.postrm");
	for (from, to) in [
		("/var/lib/glyndor/epistle", state.to_str().unwrap()),
		("/etc/epistle", root.join("config").to_str().unwrap()),
		("/etc/glyndor", root.join("legacy-parent").to_str().unwrap()),
		(
			"/run/systemd/system",
			root.join("no-systemd").to_str().unwrap(),
		),
		("/etc/subuid", root.join("subuid").to_str().unwrap()),
		("/etc/subgid", root.join("subgid").to_str().unwrap()),
	] {
		script = script.replace(from, to);
	}
	let script_path = root.join("postrm");
	std::fs::write(&script_path, script).unwrap();
	let output = Command::new("sh")
		.arg(&script_path)
		.arg("purge")
		.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
		.output()
		.unwrap();

	assert_eq!(
		output.status.code(),
		Some(0),
		"purge must complete when the account no longer exists, got: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(
		!state.exists(),
		"the data still goes when there is no account left to hold a uid"
	);
}

#[test]
fn purge_leaves_a_symlinked_config_directory_alone() {
	let outcome = purge(Fixture {
		uid: UNUSED_UID,
		deluser_exit: 0,
		systemd: false,
		config_symlink: true,
	});

	assert_eq!(
		outcome.code,
		Some(0),
		"purge must not fail: {}",
		outcome.stderr
	);
	assert!(
		!outcome.state.exists(),
		"the data the package owns still goes"
	);
	assert!(
		outcome.config.is_symlink(),
		"a symlink where the config directory belongs is not what the postinst created, so it must \
		 be left in place rather than followed"
	);
	assert!(
		outcome.outside_kept,
		"nothing outside the config path may be removed"
	);
	assert!(
		outcome
			.stderr
			.contains("is a symlink and was left in place"),
		"the operator must be told what was left, got: {}",
		outcome.stderr
	);
}
