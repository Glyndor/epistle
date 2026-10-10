use super::read;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn postinst_applies_only_its_own_sysctl_when_the_setting_is_writable() {
	for writable in [false, true] {
		for exit_code in [0, 1] {
			let dir = tempfile::tempdir().unwrap();
			let proc_sys = dir.path().join("proc/sys");
			let setting = proc_sys.join("net/ipv4/ip_unprivileged_port_start");
			std::fs::create_dir_all(setting.parent().unwrap()).unwrap();
			// A missing file is not writable for anyone, root included;
			// a mode bit alone would not stop root, which runs this test
			// in the package build.
			if writable {
				std::fs::write(&setting, "1024\n").unwrap();
			}
			std::fs::set_permissions(&proc_sys, std::fs::Permissions::from_mode(0o555)).unwrap();
			let bin = dir.path().join("bin");
			std::fs::create_dir(&bin).unwrap();
			let sysctl = bin.join("sysctl");
			std::fs::write(
				&sysctl,
				format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SYSCTL_LOG\"\nexit {exit_code}\n"),
			)
			.unwrap();
			std::fs::set_permissions(&sysctl, std::fs::Permissions::from_mode(0o755)).unwrap();
			let script = read("debian/epistle.postinst");
			let block = script
				.lines()
				.skip_while(|line| !line.contains("# 5. The port floor"))
				.take_while(|line| !line.contains("# Only an enabled stack"))
				.collect::<Vec<_>>()
				.join("\n")
				.replace("/proc/sys", proc_sys.to_str().unwrap());
			let log = dir.path().join("sysctl.log");
			let output = Command::new("/bin/sh")
				.args(["-c", &block])
				.env("PATH", &bin)
				.env("SYSCTL_LOG", &log)
				.output()
				.unwrap();
			assert_eq!(
				output.status.code(),
				Some(0),
				"sysctl setup must never fail package configuration"
			);
			let argv = std::fs::read_to_string(log).unwrap_or_default();
			let expected = if writable {
				"-p\n/usr/lib/sysctl.d/30-glyndor-epistle.conf\n"
			} else {
				""
			};
			assert_eq!(
				argv, expected,
				"postinst must apply only its package sysctl file when the port-floor setting is writable"
			);
			let expected_warning = if !writable {
				"epistle: could not apply /usr/lib/sysctl.d/30-glyndor-epistle.conf; epistle init will check the unprivileged port floor\n"
			} else if exit_code != 0 {
				"epistle: sysctl -p /usr/lib/sysctl.d/30-glyndor-epistle.conf failed, so the unprivileged port floor may still be above 25; epistle init will check it\n"
			} else {
				""
			};
			assert_eq!(
				String::from_utf8_lossy(&output.stderr),
				expected_warning,
				"postinst must warn precisely when its port-floor setup cannot be applied"
			);
		}
	}
}
