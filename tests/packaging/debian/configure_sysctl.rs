//! Run the complete configure script with bounded, isolated sysctl fixtures.
use super::{read, stubs::write_stub};
use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

fn configure(setup: impl FnOnce(&Path)) -> (String, String) {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	for path in [
		"etc/sysctl.d",
		"run/sysctl.d",
		"usr/lib/sysctl.d",
		"bin",
		"proc/sys/net/ipv4",
		"state/data",
	] {
		fs::create_dir_all(root.join(path)).unwrap();
	}
	fs::write(
		root.join("proc/sys/net/ipv4/ip_unprivileged_port_start"),
		"1024",
	)
	.unwrap();
	fs::write(
		root.join("usr/lib/sysctl.d/30-glyndor-epistle.conf"),
		"net.ipv4.ip_unprivileged_port_start=25\n",
	)
	.unwrap();
	for name in ["subuid", "subgid"] {
		fs::write(
			root.join("etc").join(name),
			"glyndor-epistle:100000:65536\n",
		)
		.unwrap();
	}
	for name in [
		"getent", "install", "usermod", "adduser", "runuser", "loginctl", "epistle",
	] {
		write_stub(&root.join("bin").join(name), "exit 0");
	}
	write_stub(
		&root.join("bin/sysctl"),
		"printf '%s\\n' \"$*\" >> \"$SYSCTL_LOG\"",
	);
	setup(root);
	let mut script = read("debian/epistle.postinst");
	for (from, to) in [
		("/etc", "etc"),
		("/run", "run"),
		("/usr/lib/sysctl.d", "usr/lib/sysctl.d"),
		("/proc/sys", "proc/sys"),
		("/var/lib/glyndor/epistle", "state"),
	] {
		script = script.replace(from, root.join(to).to_str().unwrap());
	}
	let out = Command::new("timeout")
		.args([
			"--kill-after=1",
			"5",
			"sh",
			"-c",
			&script,
			"postinst",
			"configure",
			"0.12.2",
		])
		.env(
			"PATH",
			format!("{}:/usr/bin:/bin", root.join("bin").display()),
		)
		.env("SYSCTL_LOG", root.join("sysctl.log"))
		.output()
		.unwrap();
	assert_eq!(
		out.status.code(),
		Some(0),
		"configure must finish successfully: {out:?}"
	);
	(
		fs::read_to_string(root.join("sysctl.log")).unwrap_or_default(),
		String::from_utf8(out.stderr).unwrap(),
	)
}

#[test]
fn configure_respects_alternate_sysctl_key_syntax() {
	for key in [
		"net/ipv4/ip_unprivileged_port_start",
		"-net.ipv4.ip_unprivileged_port_start",
		"-net/ipv4/ip_unprivileged_port_start",
		"net.ipv4.ip_unprivileged_port_*",
		"net/ipv4/ip_unprivileged_port_?tart",
		"net.ipv4.ip_unprivileged_port_[s]tart",
	] {
		let (calls, _) = configure(|root| {
			fs::write(
				root.join("etc/sysctl.d/99-admin.conf"),
				format!("{key} = 1024\n"),
			)
			.unwrap();
		});
		assert!(
			calls.is_empty(),
			"{key}: do not apply the packaged floor: {calls}"
		);
	}
}

#[test]
fn configure_reads_only_effective_conf_files_in_global_order() {
	let (calls, stderr) = configure(|root| {
		fs::write(
			root.join("usr/lib/sysctl.d/99-admin.conf"),
			"net.ipv4.ip_unprivileged_port_start=2048\n",
		)
		.unwrap();
		fs::write(
			root.join("etc/sysctl.d/40-admin.conf"),
			"net.ipv4.ip_unprivileged_port_start=1024\n",
		)
		.unwrap();
	});
	assert!(
		calls.is_empty(),
		"another effective vendor file is an override"
	);
	assert!(
		stderr.contains("to 2048,"),
		"global filename order: {stderr}"
	);
	let (calls, _) = configure(|root| {
		fs::write(
			root.join("run/sysctl.d/99-runtime.conf"),
			"net.ipv4.ip_unprivileged_port_start=1024\n",
		)
		.unwrap();
		fs::write(root.join("etc/sysctl.d/99-runtime.conf"), "# replaced\n").unwrap();
		fs::write(
			root.join("etc/sysctl.d/admin.conf.bak"),
			"net.ipv4.ip_unprivileged_port_start=1024\n",
		)
		.unwrap();
	});
	assert!(
		!calls.is_empty(),
		"masked files and backups are not overrides"
	);
	let (calls, stderr) = configure(|root| {
		fs::write(
			root.join("run/sysctl.d/99-runtime.conf"),
			"net.ipv4.ip_unprivileged_port_start=2048\n",
		)
		.unwrap();
		fs::write(
			root.join("etc/sysctl.conf"),
			"net.ipv4.ip_unprivileged_port_start=4096\n",
		)
		.unwrap();
	});
	assert!(calls.is_empty());
	assert!(
		stderr.contains("to 4096,"),
		"sysctl.conf is applied last: {stderr}"
	);
}

#[test]
fn configure_ignores_unsafe_sysctl_entries_with_a_warning() {
	for kind in ["fifo", "broken", "directory", "device", "large"] {
		for base in ["etc", "run", "usr/lib"] {
			let (calls, stderr) = configure(|root| {
				let path = root.join(base).join("sysctl.d/99-unsafe.conf");
				match kind {
					"fifo" => assert!(
						Command::new("mkfifo")
							.arg(&path)
							.status()
							.unwrap()
							.success()
					),
					"broken" => symlink(root.join("absent"), &path).unwrap(),
					"directory" => fs::create_dir(&path).unwrap(),
					"device" => symlink("/dev/zero", &path).unwrap(),
					"large" => fs::write(&path, "#".repeat(65537)).unwrap(),
					_ => unreachable!(),
				}
			});
			assert!(
				!calls.is_empty(),
				"{kind}: unusable entries carry no override"
			);
			assert!(
				stderr.contains("ignoring") && stderr.contains("99-unsafe.conf"),
				"{kind}: warn about ignored input: {stderr}"
			);
		}
	}
}

#[test]
fn configure_accepts_regular_symlink_overrides_and_null_masks() {
	for mask in [false, true] {
		let (calls, _) = configure(|root| {
			if mask {
				symlink(
					"/dev/null",
					root.join("etc/sysctl.d/30-glyndor-epistle.conf"),
				)
				.unwrap();
			} else {
				fs::write(
					root.join("admin"),
					"net/ipv4/ip_unprivileged_port_start=1024\n",
				)
				.unwrap();
				symlink(root.join("admin"), root.join("etc/sysctl.d/99-admin.conf")).unwrap();
			}
		});
		assert!(calls.is_empty(), "honor administrative links");
	}
}

#[test]
fn configure_tolerates_failed_and_stalled_reads_of_regular_files() {
	for reader in ["exit 1", "sleep 10"] {
		let (calls, stderr) = configure(|root| {
			fs::write(
				root.join("etc/sysctl.d/99-admin.conf"),
				"net.ipv4.ip_unprivileged_port_start=1024\n",
			)
			.unwrap();
			write_stub(&root.join("bin/dd"), reader);
		});
		assert!(!calls.is_empty(), "unreadable entries carry no override");
		assert!(
			stderr.contains("ignoring unreadable"),
			"warn without failing configure: {stderr}"
		);
	}
}
