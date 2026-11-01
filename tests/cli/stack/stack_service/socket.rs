use super::helpers::*;
use std::process::Command;

#[test]
fn every_stack_action_repairs_an_absent_socket_before_podup() {
	for action in ["up", "down", "ps", "logs", "restart", "update"] {
		let dir = tempfile::tempdir().unwrap();
		let shim = dir.path().join("bin");
		let log = dir.path().join("argv.log");
		// `update` waits for the healthcheck mail's generated definition has,
		// and only a `healthy` row ends that wait.
		let canned = write_ps_fixture(dir.path());
		let rows = std::fs::read_to_string(&canned).unwrap();
		std::fs::write(
			&canned,
			rows.replace(r#""Health": """#, r#""Health": "healthy""#),
		)
		.unwrap();
		install_podup_shim(&shim, &ps_shim(&log, &canned));
		let systemctl = shim.join("systemctl");
		executable::write_executable(
			&systemctl,
			format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\n", log.display()),
		);
		let data = data_dir_with_compose(dir.path());
		let cfg = write_config(&data);
		std::fs::write(
			data.join("compose/compose.yaml"),
			format!(
				r#"{{"services":{{"mail":{{"image":"operator/mail:stable","command":["serve","--config",{cfg:?}]}}}}}}"#
			),
		)
		.unwrap();
		// The systemctl shim only records its arguments, so the socket unit
		// "comes up" once the shim has run: bind the API then.
		let socket = dir.path().join("runtime/podman/podman.sock");
		let seen = log.clone();
		std::thread::spawn(move || {
			while std::fs::read_to_string(&seen).map_or(true, |text| text.is_empty()) {
				std::thread::sleep(std::time::Duration::from_millis(10));
			}
			std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
			serve_ping(std::os::unix::net::UnixListener::bind(&socket).unwrap());
		});
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
	executable::write_executable(&systemctl, "#!/bin/sh\necho systemctl-noise >&2\nexit 1\n");
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
