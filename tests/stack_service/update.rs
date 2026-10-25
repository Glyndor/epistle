use super::helpers::*;

/// A podup shim that logs each call on one line and answers `ps` with a
/// healthy mail service, so the update's health wait passes at once.
fn healthy_shim(log: &std::path::Path) -> String {
	format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$*\" >> {log}\n\
		 case \"$*\" in\n\
		 \t--version) printf '\\npodup version v5.13.0\\n\\n' ;;\n\
		 \t*' ps '*) printf '%s' '[{{\"Service\":\"mail\",\"State\":\"running\",\"Health\":\"healthy\",\"ExitCode\":0,\"Image\":\"x\"}}]' ;;\n\
		 esac\n\
		 exit 0\n",
		log = log.display()
	)
}

/// The logged podup calls that change the stack: every call but the
/// `ps` polls of the health wait.
fn changes(log: &std::path::Path) -> Vec<String> {
	std::fs::read_to_string(log)
		.unwrap()
		.lines()
		.filter(|line| !line.contains(" ps "))
		.map(str::to_string)
		.collect()
}

#[test]
fn update_renders_the_compose_file_again_then_restarts_mail_on_the_new_binary() {
	// The default compose file (host binary bind-mounted on the
	// distroless base) is rendered again with this release's code: an
	// older file is replaced and `up -d` recreates what changed. Once the
	// file is current, the update only has to restart `mail`, which picks
	// up the new host binary through the bind-mount.
	let dir = tempfile::tempdir().unwrap();
	let shim = dir.path().join("bin");
	let log = dir.path().join("argv.log");
	install_podup_shim(&shim, &healthy_shim(&log));
	let data = data_dir_with_compose(dir.path());
	let compose = data.join("compose/compose.yaml");
	let cfg = write_config(&data);
	// The runtime stage of the Containerfile is the pinned mail base; reading it
	// keeps this test right when the base image digest is bumped.
	let distroless = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Containerfile"))
		.lines()
		.filter_map(|line| line.strip_prefix("FROM "))
		.next_back()
		.expect("a runtime stage")
		.trim()
		.to_string();
	std::fs::write(
		&compose,
		format!(
			r#"{{"x-epistle-managed-image":true,"services":{{"mail":{{"image":"{distroless}","command":["serve","--config",{cfg:?}],"volumes":["data:/data"]}}}},"volumes":{{"data":{{}}}}}}"#,
		),
	)
	.unwrap();
	let override_path = compose.with_file_name("compose.override.yaml");
	let override_text = "services:\n  mail:\n    mem_limit: 1g\n";
	std::fs::write(&override_path, override_text).unwrap();
	let call = |extra: &str| {
		format!(
			"-f {} -f {} {extra}",
			compose.display(),
			override_path.display()
		)
	};
	let update = || {
		std::fs::write(&log, "").unwrap();
		run_with_podup(
			&["stack", "--config", cfg.to_str().unwrap(), "update"],
			&shim,
		)
	};
	let out = update();
	assert_eq!(
		out.status.code(),
		Some(0),
		"{}",
		String::from_utf8_lossy(&out.stderr)
	);
	assert_eq!(
		changes(&log),
		["--version".to_string(), call("up -d")],
		"the rewritten file is brought up"
	);
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(
		stderr.contains("freshclam: added") && stderr.contains("mail: "),
		"the change is shown before it is applied: {stderr}"
	);
	let value: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&compose).unwrap()).unwrap();
	assert_eq!(value["services"]["mail"]["image"], distroless);
	assert!(value["services"]["freshclam"].is_object());
	assert_eq!(
		std::fs::read_to_string(&override_path).unwrap(),
		override_text,
		"the operator's override is never touched"
	);
	let again = update();
	assert_eq!(again.status.code(), Some(0));
	assert_eq!(
		changes(&log),
		["--version".to_string(), call("up -d"), call("restart mail")],
		"a current file leaves mail's definition alone, so mail is restarted for the new binary"
	);
}

#[test]
fn update_pulls_then_recreates_for_a_custom_image_compose() {
	// Custom image mode keeps the previous behaviour: a `pull`
	// followed by `up -d`, so an operator that pushes a fresh
	// image gets it picked up.
	let dir = tempfile::tempdir().unwrap();
	let shim = dir.path().join("bin");
	let log = dir.path().join("argv.log");
	install_podup_shim(&shim, &healthy_shim(&log));
	let data = data_dir_with_compose(dir.path());
	let compose = data.join("compose/compose.yaml");
	let cfg = write_config(&data);
	std::fs::write(
		&compose,
		format!(
			r#"{{"x-epistle-managed-image":false,"services":{{"mail":{{"image":"ghcr.io/example/mail:0.9.1","command":["serve","--config",{cfg:?}],"volumes":["data:/data"]}}}},"volumes":{{"data":{{}}}}}}"#
		),
	)
	.unwrap();
	let override_path = compose.with_file_name("compose.override.yaml");
	std::fs::write(&override_path, "services:\n  mail:\n    mem_limit: 1g\n").unwrap();
	let out = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "update"],
		&shim,
	);
	assert_eq!(
		out.status.code(),
		Some(0),
		"stack update must be accepted and complete"
	);
	let call = |extra: &str| {
		format!(
			"-f {} -f {} {extra}",
			compose.display(),
			override_path.display()
		)
	};
	assert_eq!(
		changes(&log),
		["--version".to_string(), call("pull"), call("up -d")],
		"custom image mode must pull then up -d"
	);
	// Custom mode does not rewrite the operator's image.
	let value: serde_json::Value =
		serde_json::from_slice(&std::fs::read(compose).unwrap()).unwrap();
	assert_eq!(
		value["services"]["mail"]["image"], "ghcr.io/example/mail:0.9.1",
		"custom mode must leave the operator's image untouched"
	);
}

#[test]
fn update_waits_while_another_command_holds_the_compose_file() {
	use std::os::fd::AsRawFd;
	let dir = tempfile::tempdir().unwrap();
	let shim = dir.path().join("bin");
	let log = dir.path().join("argv.log");
	install_podup_shim(&shim, &healthy_shim(&log));
	let data = data_dir_with_compose(dir.path());
	let compose = data.join("compose/compose.yaml");
	let cfg = write_config(&data);
	std::fs::write(
		&compose,
		format!(
			r#"{{"x-epistle-managed-image":false,"services":{{"mail":{{"image":"ghcr.io/example/mail:0.9.1","command":["serve","--config",{cfg:?}],"volumes":["data:/data"]}}}},"volumes":{{"data":{{}}}}}}"#
		),
	)
	.unwrap();
	// The lock `epistle stack resources set` holds while it rewrites the file.
	let lock = std::fs::OpenOptions::new()
		.create(true)
		.truncate(false)
		.read(true)
		.write(true)
		.open(compose.with_file_name(".compose.yaml.lock"))
		.unwrap();
	// SAFETY: the descriptor is open for the whole call.
	assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
	let before = std::fs::read(&compose).unwrap();
	let child = std::process::Command::new(binary())
		.args(["stack", "--config", cfg.to_str().unwrap(), "update"])
		.env("PATH", path_with_shim_first(&shim))
		.env("XDG_RUNTIME_DIR", fake_podman_runtime(&shim))
		.env("NO_COLOR", "1")
		.stdin(std::process::Stdio::null())
		.stdout(std::process::Stdio::piped())
		.stderr(std::process::Stdio::piped())
		.spawn()
		.unwrap();
	std::thread::sleep(std::time::Duration::from_secs(3));
	let held = (changes(&log), std::fs::read(&compose).unwrap() == before);
	drop(lock);
	let out = child.wait_with_output().unwrap();
	assert_eq!(
		held,
		(vec!["--version".to_string()], true),
		"update ran podup or rewrote the file while the lock was held"
	);
	assert_eq!(
		out.status.code(),
		Some(0),
		"{}",
		String::from_utf8_lossy(&out.stderr)
	);
	assert!(changes(&log).len() > 1, "update ran once the lock was free");
}
