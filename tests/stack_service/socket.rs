use super::helpers::*;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn every_stack_action_repairs_an_absent_socket_before_podup() {
	for action in ["up", "down", "ps", "logs", "restart", "update"] {
		let dir = tempfile::tempdir().unwrap();
		let shim = dir.path().join("bin");
		let log = dir.path().join("argv.log");
		let canned = write_ps_fixture(dir.path());
		install_podup_shim(&shim, &ps_shim(&log, &canned));
		let systemctl = shim.join("systemctl");
		std::fs::write(
			&systemctl,
			format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\n", log.display()),
		)
		.unwrap();
		std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
		let data = data_dir_with_compose(dir.path());
		std::fs::write(
			data.join("compose/compose.yaml"),
			r#"{"services":{"mail":{"image":"operator/mail:stable"}}}"#,
		)
		.unwrap();
		let cfg = write_config(&data);
		let output = Command::new(binary())
			.args(["stack", "--config", cfg.to_str().unwrap(), action])
			.env("PATH", path_with_shim_first(&shim))
			.env("XDG_RUNTIME_DIR", dir.path().join("runtime"))
			.env("NO_COLOR", "1")
			.output()
			.unwrap();
		assert_eq!(
			output.status.code(),
			Some(0),
			"stack action must proceed after socket activation"
		);
		let argv = read_argv_log(&log);
		assert_eq!(
			argv.iter().take(5).map(String::as_str).collect::<Vec<_>>(),
			["--user", "enable", "--now", "podman.socket", "--version"],
			"every stack action must enable the API socket before invoking podup"
		);
	}
}

#[test]
fn failed_socket_activation_prints_one_repair_error_and_never_invokes_podup() {
	let dir = tempfile::tempdir().unwrap();
	let shim = dir.path().join("bin");
	let log = dir.path().join("argv.log");
	install_podup_shim(&shim, &recorder_shim(&log));
	let systemctl = shim.join("systemctl");
	std::fs::write(&systemctl, "#!/bin/sh\necho systemctl-noise >&2\nexit 1\n").unwrap();
	std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
	let data = data_dir_with_compose(dir.path());
	let cfg = write_config(&data);
	let output = Command::new(binary())
		.args(["stack", "--config", cfg.to_str().unwrap(), "up"])
		.env("PATH", path_with_shim_first(&shim))
		.env("XDG_RUNTIME_DIR", dir.path().join("runtime"))
		.env_remove("CLICOLOR_FORCE")
		.env("NO_COLOR", "1")
		.output()
		.unwrap();
	assert_eq!(
		String::from_utf8_lossy(&output.stderr),
		"error: cannot enable Podman's API socket; run `systemctl --user enable --now podman.socket`\n",
		"socket failure must produce exactly one repair error line"
	);
	assert_eq!(output.status.code(), Some(1));
	assert!(
		!log.exists(),
		"socket failure must stop before invoking podup"
	);
}
