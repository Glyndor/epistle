use super::read;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn postinst_enables_the_service_socket_with_runtime_environment_and_tolerates_failure() {
	for systemd in [false, true] {
		for runtime_exists in [false, true] {
			for exit_code in [0, 1] {
				let dir = tempfile::tempdir().unwrap();
				let root = dir.path();
				let runtime = root.join("run/user/103");
				std::fs::create_dir_all(root.join("state")).unwrap();
				std::fs::create_dir_all(root.join("config")).unwrap();
				if systemd {
					std::fs::create_dir_all(root.join("run/systemd/system")).unwrap();
				}
				if runtime_exists {
					std::fs::create_dir_all(&runtime).unwrap();
				}
				let bin = root.join("bin");
				std::fs::create_dir(&bin).unwrap();
				for (name, body) in [
					("getent", "exit 0".to_owned()),
					("grep", "exit 0".to_owned()),
					("id", "echo 103".to_owned()),
					("loginctl", "exit 0".to_owned()),
					(
						"runuser",
						format!("printf '%s\\n' \"$@\" > \"$ARGV_LOG\"\nexit {exit_code}"),
					),
				] {
					let path = bin.join(name);
					std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
					std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
				}
				let mut script = read("debian/epistle.postinst");
				for (from, to) in [
					("/var/lib/glyndor/epistle", "state"),
					("/etc/epistle", "config"),
					("/run/systemd/system", "run/systemd/system"),
					("/run/user", "run/user"),
					("/proc/sys", "missing-sys"),
				] {
					script = script.replace(from, root.join(to).to_str().unwrap());
				}
				let script_path = root.join("postinst");
				std::fs::write(&script_path, script).unwrap();
				let log = root.join("argv");
				let output = Command::new("sh")
					.arg(script_path)
					.arg("configure")
					.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
					.env("ARGV_LOG", &log)
					.output()
					.unwrap();
				assert_eq!(
					output.status.code(),
					Some(0),
					"socket setup must never fail package configuration"
				);
				let argv = std::fs::read_to_string(log).unwrap_or_default();
				let expected = if systemd && runtime_exists {
					format!(
						"-u\nglyndor-epistle\n--\nenv\nXDG_RUNTIME_DIR={}\nDBUS_SESSION_BUS_ADDRESS=unix:path={}/bus\nsystemctl\n--user\nenable\n--now\npodman.socket\n",
						runtime.display(),
						runtime.display()
					)
				} else {
					String::new()
				};
				assert_eq!(
					argv, expected,
					"postinst must enable the service socket only with systemd and a user runtime"
				);
				if systemd && runtime_exists && exit_code != 0 {
					assert!(
						String::from_utf8_lossy(&output.stderr).contains(
							"run systemctl --user enable --now podman.socket as glyndor-epistle"
						),
						"postinst socket warning must name the service-account repair"
					);
				}
			}
		}
	}
}
