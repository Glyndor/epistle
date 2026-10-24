//! Regression checks for coordinated service configuration and publication.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::{cli::fixture, stack_helpers as helpers};

fn ports(path: &std::path::Path) -> serde_json::Value {
	let document: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
	document["services"]["mail"]["ports"].clone()
}

// The podup double makes no network requests. Its socket path is only an
// availability marker for commands that recreate mail or edit resources.
fn podup_fixture(bin: &std::path::Path) {
	helpers::install_podup_shim(
		bin,
		"#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'podup version v5.10.13'; fi\nexit 0\n",
	);
	let runtime = bin.join("runtime");
	fs::create_dir_all(runtime.join("podman")).unwrap();
	fs::write(runtime.join("podman/podman.sock"), "").unwrap();
}

#[test]
fn concurrent_commands_share_the_config_lock_and_preserve_the_previous_update() {
	for args in [
		vec!["service", "set", "imaps", "--port", "19994"],
		vec!["service", "enable", "imap"],
		vec!["service", "disable", "imaps"],
		vec!["stack", "resources", "set", "mail", "--pids", "123"],
	] {
		let (dir, config) = fixture();
		let compose = dir.path().join("compose/compose.yaml");
		fs::create_dir_all(compose.parent().unwrap()).unwrap();
		fs::write(
			&compose,
			r#"{"services":{"mail":{"ports":["25:25","19993:19993"]}}}"#,
		)
		.unwrap();
		let lock = fs::OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.truncate(false)
			.mode(0o600)
			.open(dir.path().join(".epistle-config.lock"))
			.unwrap();
		assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
		let bin = dir.path().join("bin");
		podup_fixture(&bin);
		let runtime = bin.join("runtime");
		let mut child = Command::new(helpers::binary())
			.args(&args)
			.arg("--config")
			.arg(&config)
			.env("PATH", helpers::path_with_shim_first(&bin))
			.env("XDG_RUNTIME_DIR", runtime)
			.env("NO_COLOR", "1")
			.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped())
			.spawn()
			.unwrap();
		std::thread::sleep(Duration::from_millis(200));
		let early = child.try_wait().unwrap();
		if early.is_some() {
			drop(lock);
			let output = child.wait_with_output().unwrap();
			panic!(
				"{args:?} escaped the lock: {early:?}, {}",
				String::from_utf8_lossy(&output.stderr)
			);
		}
		let previous = format!(
			"{}\n# concurrent writer\n",
			fs::read_to_string(&config).unwrap()
		);
		fs::write(&config, &previous).unwrap();
		fs::write(
			&compose,
			r#"{"services":{"mail":{"ports":["127.0.0.2:25:25","19993:19993"]}}}"#,
		)
		.unwrap();
		drop(lock);
		let output = child.wait_with_output().unwrap();
		assert!(
			output.status.success(),
			"{args:?}: {}",
			String::from_utf8_lossy(&output.stderr)
		);
		assert!(
			fs::read_to_string(&config)
				.unwrap()
				.contains("# concurrent writer")
		);
		assert_eq!(
			ports(&compose)[0],
			"127.0.0.2:25:25",
			"{args:?} lost the previous map"
		);
	}
}

/// A wildcard publishes on every address the host owns either way, so the map
/// keeps the plain form pasta accepts on Podman 5.4.2 in both families, and the
/// family the operator named stays in the bind the container uses.
#[test]
fn a_wildcard_publishes_every_address_and_single_inline_override_reaches_the_cli() {
	for address in ["0.0.0.0", "::"] {
		let (dir, config) = fixture();
		let compose = dir.path().join("compose/compose.yaml");
		fs::create_dir_all(compose.parent().unwrap()).unwrap();
		fs::write(
			&compose,
			r#"{"services":{"mail":{"ports":["25:25","19993:19993"]}}}"#,
		)
		.unwrap();
		let operator = compose.with_file_name("compose.override.yaml");
		let text = "services:\n  mail:\n    ports: [\"19993:19993\"]\n";
		fs::write(&operator, text).unwrap();
		let bin = dir.path().join("bin");
		podup_fixture(&bin);
		let output = helpers::run_with_podup(
			&[
				"service",
				"--config",
				config.to_str().unwrap(),
				"set",
				"imaps",
				"--bind",
				address,
			],
			&bin,
		);
		assert!(
			output.status.success(),
			"{}",
			String::from_utf8_lossy(&output.stderr)
		);
		assert_eq!(
			ports(&compose)[1],
			"19993:19993",
			"a wildcard is never written as an explicit address"
		);
		assert_eq!(
			epistle::config::Config::load(&config).unwrap().listeners[1]
				.addr
				.to_string(),
			"::",
			"the container bind that answers {address} is left alone"
		);
		assert!(
			String::from_utf8_lossy(&output.stderr)
				.contains("compose.override.yaml publishes a port")
		);
		assert_eq!(fs::read_to_string(&operator).unwrap(), text);
	}
}

#[test]
fn external_http_publication_is_refused_for_host_and_stack_even_with_certificates() {
	for stack in [false, true] {
		for service in ["api", "webdav"] {
			let (dir, config) = fixture();
			let kind = if service == "api" { "api" } else { "web-dav" };
			let text = format!(
				"{}\n[[listeners]]\nkind = '{kind}'\naddr = '127.0.0.1'\n[api]\ntoken_hash = 'sha256:{}'\n",
				fs::read_to_string(&config).unwrap(),
				"0".repeat(64)
			);
			fs::write(&config, &text).unwrap();
			fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
			let compose = dir.path().join("compose/compose.yaml");
			if stack {
				fs::create_dir_all(compose.parent().unwrap()).unwrap();
				fs::write(
					&compose,
					r#"{"services":{"mail":{"ports":["25:25","19993:19993"]}}}"#,
				)
				.unwrap();
			}
			let before = fs::read(&compose).ok();
			let output = Command::new(helpers::binary())
				.args([
					"service",
					"--config",
					config.to_str().unwrap(),
					"set",
					service,
					"--bind",
					"0.0.0.0",
				])
				.output()
				.unwrap();
			assert_eq!(output.status.code(), Some(1));
			assert!(String::from_utf8_lossy(&output.stderr).contains("serves HTTP without TLS"));
			assert_eq!(fs::read_to_string(&config).unwrap(), text);
			assert_eq!(fs::read(&compose).ok(), before);
		}
	}
}
