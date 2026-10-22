//! The port floor is applied only while the operator has not chosen one.
//!
//! `debian/rules` ships the floor as
//! `/usr/lib/sysctl.d/30-glyndor-epistle.conf` and claims that `/etc/sysctl.d`
//! stays the operator's, so an override survives an upgrade. It did not: every
//! configure ran `sysctl -p` on the packaged file and wrote 25 over whatever
//! the administrator had set, on every upgrade and on every reinstall. The
//! floor is a machine-wide value, so that is not a detail of this package.
//!
//! These tests run the step with `sysctl` stubbed and the operator's
//! configuration in a fixture tree: an `/etc/sysctl.conf` value, a
//! `/etc/sysctl.d` value, a `/run/sysctl.d` value, a same-basename file that
//! masks the packaged one, and the cases where the setting is not writable or
//! `sysctl` fails.

use super::{read, stubs::write_stub};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/// What one scenario does to the operator's configuration.
struct Override {
	/// Path relative to the fixture root, as `sysctl` would see it.
	path: &'static str,
	/// Contents of that file.
	body: &'static str,
}

/// What one run of the step produced.
struct Run {
	code: Option<i32>,
	/// The argv `sysctl` was called with, empty when it was never called.
	argv: String,
	stderr: String,
	/// The fixture root, because a warning names the fixture path the step
	/// actually prints rather than the `/etc` path it would print on a host.
	root: String,
}

/// Pull the body of a shell function written as `name() { ... }`, from the
/// opening line to the first line that carries nothing but `}`.
fn extract_function(text: &str, name: &str) -> String {
	let mut lines: Vec<&str> = Vec::new();
	let mut inside = false;
	for line in text.lines() {
		let trimmed = line.trim_start();
		if !inside {
			if trimmed.starts_with(&format!("{name}() {{")) {
				inside = true;
				lines.push(line);
			}
			continue;
		}
		lines.push(line);
		// Only a brace in the first column closes the function: the awk
		// programs these helpers carry have braces of their own.
		if trimmed == "}" && line.len() == trimmed.len() {
			break;
		}
	}
	assert!(inside, "debian/epistle.postinst has no {name} function");
	lines.join("\n")
}

/// The lines between the first that contains `from` and the first after it
/// that contains `to`.
fn extract_block(text: &str, from: &str, to: &str) -> String {
	let lines: Vec<&str> = text.lines().collect();
	let start = lines
		.iter()
		.position(|line| line.contains(from))
		.unwrap_or_else(|| panic!("debian/epistle.postinst has no {from:?}"));
	let end = lines
		.iter()
		.enumerate()
		.skip(start + 1)
		.find(|(_, line)| line.contains(to))
		.unwrap_or_else(|| panic!("debian/epistle.postinst has no {to:?} after {from:?}"))
		.0;
	lines[start..end].join("\n")
}

/// Run the port-floor step against a fixture tree.
fn run(writable: bool, sysctl_exit: i32, overrides: &[Override]) -> Run {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	let proc_sys = root.join("fake-proc-sys");
	let setting = proc_sys.join("net/ipv4/ip_unprivileged_port_start");
	std::fs::create_dir_all(setting.parent().unwrap()).unwrap();
	// A missing file is not writable for anyone, root included; a mode bit
	// alone would not stop root, which runs this test in the package build.
	if writable {
		std::fs::write(&setting, "1024\n").unwrap();
	}
	std::fs::set_permissions(&proc_sys, std::fs::Permissions::from_mode(0o555)).unwrap();
	for over in overrides {
		let path = root.join(over.path);
		std::fs::create_dir_all(path.parent().unwrap()).unwrap();
		std::fs::write(path, over.body).unwrap();
	}
	let bin = root.join("bin");
	std::fs::create_dir(&bin).unwrap();
	write_stub(
		&bin.join("sysctl"),
		&format!("printf '%s\\n' \"$@\" > \"$SYSCTL_LOG\"\nexit {sysctl_exit}"),
	);

	let postinst = read("debian/epistle.postinst");
	let mut block = format!(
		"{}\n{}\n{}",
		extract_function(&postinst, "epistle_admin_sysctl_value"),
		extract_function(&postinst, "epistle_sysctl_masked"),
		extract_block(&postinst, "# 5. The port floor", "# Only an enabled stack",),
	);
	for (from, to) in [
		("/proc/sys", proc_sys.to_str().unwrap()),
		// Every fixture is named so that no replacement target contains the
		// absolute path it replaces, which is what lets the guard below tell
		// "never rewritten" from "already rewritten".
		("/run/sysctl.d", root.join("run-sysctl.d").to_str().unwrap()),
		("/etc/sysctl.d", root.join("sysctl.d").to_str().unwrap()),
		(
			"/etc/sysctl.conf",
			root.join("sysctl.conf").to_str().unwrap(),
		),
	] {
		block = block.replace(from, to);
	}
	for untouched in ["/etc/sysctl", "/run/sysctl", "/proc/sys"] {
		assert!(
			!block.contains(untouched),
			"the step under test must only read the fixture tree, but {untouched} survived"
		);
	}
	let log = root.join("sysctl.log");
	let output = Command::new("/bin/sh")
		.args(["-c", &block])
		// The stub directory comes first so `sysctl` resolves to the stub;
		// the helpers in the step also need the real cat and awk.
		.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
		.env("SYSCTL_LOG", &log)
		.output()
		.unwrap();
	Run {
		code: output.status.code(),
		argv: std::fs::read_to_string(&log).unwrap_or_default(),
		stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
		root: root.to_str().unwrap().to_owned(),
	}
}

/// The argv the packaged `sysctl -p` produces when it does run.
const PACKAGED_SYSCTL: &str = "-p\n/usr/lib/sysctl.d/30-glyndor-epistle.conf\n";

/// The floor the operator chose, as one of their files would carry it.
const ADMIN_FLOOR: &str = "net.ipv4.ip_unprivileged_port_start = 1024\n";

#[test]
fn postinst_leaves_the_floor_to_the_operator_when_they_chose_one() {
	for (label, override_path) in [
		("an /etc/sysctl.conf value", "sysctl.conf"),
		("an /etc/sysctl.d value", "sysctl.d/99-admin.conf"),
		("a /run/sysctl.d value", "run-sysctl.d/99-admin.conf"),
	] {
		let out = run(
			true,
			0,
			&[Override {
				path: override_path,
				body: ADMIN_FLOOR,
			}],
		);
		assert_eq!(
			out.code,
			Some(0),
			"{label}: the step must never fail configuration"
		);
		assert!(
			out.argv.is_empty(),
			"{label}: the packaged floor must not be written over the operator's choice, but \
			 sysctl was called with {:?}",
			out.argv
		);
		assert_eq!(
			out.stderr,
			"epistle: the local sysctl configuration sets net.ipv4.ip_unprivileged_port_start to \
			 1024, so the packaged floor was not applied; epistle init will check the \
			 unprivileged port floor\n",
			"{label}: the operator has to be told why the packaged floor was skipped"
		);
	}
}

#[test]
fn postinst_leaves_the_floor_alone_when_a_local_file_masks_the_packaged_one() {
	let out = run(
		true,
		0,
		&[Override {
			path: "sysctl.d/30-glyndor-epistle.conf",
			// A masking file replaces the packaged one by name and carries
			// no key of ours, so the step would apply 25 unless it asks
			// whether its own file is still the one in effect.
			body: "# local replacement\nnet.core.somaxconn = 4096\n",
		}],
	);
	assert_eq!(out.code, Some(0));
	assert!(out.argv.is_empty(), "a masked file must not be re-applied");
	assert_eq!(
		out.stderr,
		format!(
			"epistle: {}/sysctl.d/30-glyndor-epistle.conf replaces the packaged file, so the \
			 port floor was left as configured there\n",
			out.root
		),
		"the warning must name the file that took over"
	);
}

#[test]
fn postinst_applies_the_packaged_floor_when_the_operator_configured_nothing() {
	for sysctl_exit in [0, 1] {
		let out = run(true, sysctl_exit, &[]);
		assert_eq!(out.code, Some(0), "the step must never fail configuration");
		assert_eq!(
			out.argv, PACKAGED_SYSCTL,
			"the packaged file must be applied"
		);
		let expected = if sysctl_exit == 0 {
			""
		} else {
			"epistle: sysctl -p /usr/lib/sysctl.d/30-glyndor-epistle.conf failed, so the \
			 unprivileged port floor may still be above 25; epistle init will check it\n"
		};
		assert_eq!(out.stderr, expected, "a failing sysctl must be reported");
	}
}

#[test]
fn postinst_warns_when_the_setting_is_not_writable() {
	let out = run(false, 0, &[]);
	assert_eq!(out.code, Some(0));
	assert!(
		out.argv.is_empty(),
		"nothing may be applied without a writable setting"
	);
	assert_eq!(
		out.stderr,
		"epistle: could not apply /usr/lib/sysctl.d/30-glyndor-epistle.conf; epistle init will \
		 check the unprivileged port floor\n",
		"an unapplied floor must be reported"
	);
}
