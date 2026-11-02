use super::helpers::*;

/// A podup shim that logs each call on one line and answers `ps` with a
/// healthy mail service, so the update's health wait passes at once.
fn healthy_shim(log: &std::path::Path) -> String {
	format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$*\" >> {log}\n\
		 case \"$*\" in\n\
		 \t--version) printf '\\npodup version v5.15.4\\n\\n' ;;\n\
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

/// A `podman` shim that logs each call and answers the four the update
/// makes about images: which references exist and what they are, which
/// images a container was made from, and `rmi`.
fn podman_shim(log: &std::path::Path, known: &[(&str, char)], used: &[char]) -> String {
	let exists: String = known
		.iter()
		.map(|(reference, _)| format!("{reference}) exit 0 ;;\n"))
		.collect();
	let inspect: String = known
		.iter()
		.map(|(reference, id)| {
			format!(
				"{reference}) printf '%s\\n' {} ;;\n",
				id.to_string().repeat(64)
			)
		})
		.collect();
	let in_use: String = used
		.iter()
		.map(|id| format!("printf '%s\\n' {}\n", id.to_string().repeat(64)))
		.collect();
	format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$*\" >> {log}\n\
		 case \"$1 $2\" in\n\
		 \t'image exists') case \"$3\" in\n{exists}*) exit 1 ;; esac ;;\n\
		 \t'image inspect') case \"$5\" in\n{inspect}*) exit 1 ;; esac ;;\n\
		 \t'ps --all') {in_use} ;;\n\
		 esac\n\
		 exit 0\n",
		log = log.display()
	)
}

/// The `FROM` line of `deploy/images/Dockerfile` that ends in `AS <name>`.
fn pinned_image(name: &str) -> String {
	include_str!(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/deploy/images/Dockerfile"
	))
	.lines()
	.filter_map(|line| line.strip_prefix("FROM "))
	.find_map(|line| line.strip_suffix(&format!(" AS {name}")))
	.unwrap_or_else(|| panic!("no {name} image in deploy/images/Dockerfile"))
	.to_string()
}

#[test]
fn update_removes_the_images_it_stopped_using_and_only_those() {
	// A stack made by an older release ran the version-tagged epistle image
	// and an older ClamAV digest. After the update the new references are
	// the mail base and the pinned ClamAV; the old mail image has no
	// container, the old ClamAV one is still held by a container that is not
	// the stack's.
	let dir = tempfile::tempdir().unwrap();
	let shim = dir.path().join("bin");
	let log = dir.path().join("argv.log");
	let engine = dir.path().join("podman.log");
	install_podup_shim(&shim, &healthy_shim(&log));
	let old_mail = "ghcr.io/glyndor/epistle:0.12.5";
	let old_clamav = format!("docker.io/clamav/clamav:1.5@sha256:{}", "1".repeat(64));
	let base = pinned_image("mail");
	let clamav = pinned_image("clamav");
	write_podman_shim(
		&shim,
		&podman_shim(
			&engine,
			&[
				(old_mail, 'a'),
				(&old_clamav, 'b'),
				(&base, 'c'),
				(&clamav, 'd'),
				("docker.io/library/redis:8", 'e'),
			],
			&['b', 'c', 'd', 'e'],
		),
	);
	let data = data_dir_with_compose(dir.path());
	let compose = data.join("compose/compose.yaml");
	let cfg = write_config(&data);
	std::fs::write(
		&compose,
		format!(
			r#"{{"x-epistle-managed-image":true,"services":{{"mail":{{"image":"{old_mail}","command":["serve","--config",{cfg:?}],"volumes":["data:/data"]}},"clamav":{{"image":"{old_clamav}"}}}},"volumes":{{"data":{{}}}}}}"#
		),
	)
	.unwrap();
	let out = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "update"],
		&shim,
	);
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert_eq!(out.status.code(), Some(0), "{stderr}");
	let calls = std::fs::read_to_string(&engine).unwrap();
	let removals: Vec<&str> = calls
		.lines()
		.filter(|line| line.starts_with("rmi"))
		.collect();
	assert_eq!(
		removals,
		[format!("rmi {}", "a".repeat(64))],
		"only the retired image nothing uses goes: {calls}"
	);
	assert!(
		stderr.contains(&format!("removed the image {old_mail}"))
			&& stderr.contains(&format!(
				"kept the image {old_clamav}: a container still uses it"
			)),
		"{stderr}"
	);
	assert!(
		!calls.contains("redis"),
		"an image the stack never named is not looked at: {calls}"
	);
}
