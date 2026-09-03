//! The package must create, and purge, the isolated `glyndor-epistle` account.
//!
//! `docs/configuration.md:813` and the README tell the operator to run under
//! `[privileges] user = "glyndor-epistle"`, and `src/privdrop.rs` resolves that
//! name with `getpwnam_r` and fails closed when it does not exist. Nothing used
//! to create it: `debian/` carried no maintainer scripts, which is the gap
//! `docs/threat-model.md` recorded. `debian/epistle.postinst` now creates the
//! account, its state directory, the subuid/subgid ranges rootless Podman
//! needs, the linger flag and the port floor.
//!
//! The postinst attempts and warns; it never aborts an installation. `epistle
//! init` is the half that verifies the state and refuses to continue when
//! something is missing. These tests pin the shape of the scripts, because each
//! defect they guard against reads as tidying: dropping a step, collapsing an
//! `if` into an `&&`/`||` chain that runs the wrong branch, or moving the purge
//! work into the `remove` case, where it would delete the operator's mail.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository root, as cargo hands it to an integration test.
fn root() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Read one of the maintainer scripts, failing the test when it is absent.
fn read(relative: &str) -> String {
	let path = root().join(relative);
	fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The 0-based index of the first line containing `needle`, if any.
fn line_of(text: &str, needle: &str) -> Option<usize> {
	text.lines().position(|line| line.contains(needle))
}

#[test]
fn postinst_creates_the_isolated_user_and_its_ranges() {
	let postinst = read("debian/epistle.postinst");

	for needle in [
		"adduser --system",
		"glyndor-epistle",
		"--add-subuids 100000-165535",
		"enable-linger",
		"podman system migrate",
	] {
		assert!(
			postinst.contains(needle),
			"debian/epistle.postinst must still {needle:?}: the isolated account, its Podman \
			 ranges, its linger flag and its rootless runtime are all set up there"
		);
	}
}

#[test]
fn postinst_tolerates_a_host_without_systemd() {
	let postinst = read("debian/epistle.postinst");

	let guard = line_of(&postinst, "/run/systemd/system")
		.expect("the postinst tests /run/systemd/system before touching loginctl");
	let linger = line_of(&postinst, "enable-linger").expect("the postinst enables linger");

	assert!(
		guard < linger,
		"enable-linger must sit inside a test on /run/systemd/system (guard at line {}, \
		 enable-linger at line {}); an unguarded loginctl call fails the install in a container \
		 image where systemd is not running",
		guard + 1,
		linger + 1
	);
}

#[test]
fn postinst_never_runs_migrate_when_the_ranges_failed() {
	let postinst = read("debian/epistle.postinst");

	for (index, line) in postinst.lines().enumerate() {
		let chained = line.contains("usermod")
			&& line.contains("||")
			&& line
				.split("||")
				.nth(1)
				.is_some_and(|tail| tail.contains("migrate"));
		assert!(
			!chained,
			"line {} chains the id ranges and the Podman migration with ||, which runs the \
			 migration exactly when the ranges failed; use separate if blocks: {line}",
			index + 1
		);
	}
}

#[test]
fn postrm_removes_the_footprint_only_on_purge() {
	let postrm = read("debian/epistle.postrm");

	let purge = line_of(&postrm, "purge)").expect("the postrm has a purge case");
	let deluser = line_of(&postrm, "deluser").expect("the postrm deletes the account");
	let rmtree = line_of(&postrm, "rm -rf /var/lib/glyndor/epistle")
		.expect("the postrm removes the state directory on purge");

	assert!(
		purge < deluser && purge < rmtree,
		"deluser (line {}) and the state removal (line {}) must come after the purge label \
		 (line {})",
		deluser + 1,
		rmtree + 1,
		purge + 1
	);

	let between = &postrm.lines().collect::<Vec<_>>()[purge + 1..deluser.max(rmtree)];
	assert!(
		!between
			.iter()
			.any(|line| line.trim_start().starts_with("remove)")),
		"a remove) label sits between purge) and the removal steps, so removing the package \
		 would delete the operator's mail; only purge may"
	);
}

#[test]
fn maintainer_scripts_are_executable_in_git() {
	let scripts = ["debian/epistle.postinst", "debian/epistle.postrm"];

	let output = match Command::new("git")
		.current_dir(root())
		.arg("ls-files")
		.arg("-s")
		.args(scripts)
		.output()
	{
		Ok(output) => output,
		Err(error) => {
			println!("skipped: git is not available to read the index ({error})");
			return;
		}
	};
	assert!(output.status.success(), "git ls-files failed: {output:?}");

	let listing = String::from_utf8_lossy(&output.stdout);
	let lines: Vec<&str> = listing.lines().collect();
	assert_eq!(
		lines.len(),
		scripts.len(),
		"git ls-files must list both maintainer scripts; got: {listing}"
	);
	for line in lines {
		assert!(
			line.starts_with("100755"),
			"dpkg runs the maintainer scripts directly, so the mode in the index must be \
			 100755 (set it with git update-index --chmod=+x): {line}"
		);
	}
}

#[test]
fn sysctl_lowers_the_port_floor_to_25() {
	let sysctl = read("debian/epistle.sysctl");

	assert!(
		sysctl
			.lines()
			.any(|line| line.trim() == "net.ipv4.ip_unprivileged_port_start = 25"),
		"debian/epistle.sysctl must set net.ipv4.ip_unprivileged_port_start = 25: a rootless \
		 container cannot be granted CAP_NET_BIND_SERVICE, so without this floor the isolated \
		 account cannot bind the SMTP port at all. The file is: {sysctl}"
	);
}

#[test]
fn sample_unit_runs_as_the_isolated_user() {
	let unit = read("docs/epistle.service");

	for needle in [
		"User=glyndor-epistle",
		"Group=glyndor-epistle",
		"ExecStart=/usr/bin/epistle",
	] {
		assert!(
			unit.contains(needle),
			"docs/epistle.service must carry {needle:?}: the unit runs under the persistent \
			 account the package creates, and the package installs /usr/bin/epistle"
		);
	}

	assert!(
		!unit.contains("DynamicUser"),
		"DynamicUser must not appear in docs/epistle.service, not even in a comment: a transient \
		 account has no stable uid, no subuid range and no persistent home, so rootless Podman \
		 cannot run under it"
	);
}

#[test]
fn maintainer_scripts_parse_as_posix_sh() {
	for script in ["debian/epistle.postinst", "debian/epistle.postrm"] {
		let output = match Command::new("sh")
			.arg("-n")
			.arg(root().join(script))
			.output()
		{
			Ok(output) => output,
			Err(error) => {
				println!("skipped: no sh to parse {script} ({error})");
				return;
			}
		};
		assert!(
			output.status.success(),
			"sh -n {script} rejected the script: {}",
			String::from_utf8_lossy(&output.stderr)
		);
	}
}
