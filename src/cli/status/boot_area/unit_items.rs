//! The items about the user manager and the units: linger, the manager, the
//! boot unit, its file list and Podman's socket.

use std::path::{Path, PathBuf};

use super::host::{Account, BootHost};
use crate::cli::stack::autostart::{self, UNIT};
use crate::cli::status::report::{Item, Level};

/// The command that runs `command` as the account, inside its user manager.
pub(super) fn as_account(account: &Account, command: &str) -> String {
	format!(
		"sudo runuser -u {} -- env XDG_RUNTIME_DIR=/run/user/{} {command}",
		account.name, account.uid
	)
}

/// Linger is on: without it the user manager, and the stack with it, does
/// not start until someone logs in.
pub(super) fn linger(host: &mut impl BootHost, account: &Account) -> Item {
	let path = PathBuf::from("/var/lib/systemd/linger").join(&account.name);
	if host.exists(&path) {
		return Item::new("linger", Level::Ok, format!("on for {}", account.name));
	}
	Item::new(
		"linger",
		Level::Fail,
		format!(
			"linger is off for {name}, so its user manager does not start at boot and the stack does not come back; run `sudo loginctl enable-linger {name}`",
			name = account.name
		),
	)
}

/// The user manager runs: `user@<uid>.service` is active and its runtime
/// directory exists.
pub(super) fn manager(host: &mut impl BootHost, account: &Account) -> Item {
	let service = format!("user@{}.service", account.uid);
	let runtime = PathBuf::from(format!("/run/user/{}", account.uid));
	let state = host
		.system_systemctl(&["is-active", &service])
		.unwrap_or_default();
	if state == "active" && host.exists(&runtime) {
		return Item::new("user manager", Level::Ok, format!("{service} is active"));
	}
	let seen = if state.is_empty() { "unknown" } else { &state };
	Item::new(
		"user manager",
		Level::Fail,
		format!(
			"{service} is {seen} or {} is missing, so nothing of the account runs; run `sudo loginctl enable-linger {name}` and `sudo systemctl start {service}`",
			runtime.display(),
			name = account.name
		),
	)
}

/// What systemd says of the boot unit: `ActiveState` and `Result`, each
/// `unknown` when it cannot be read.
pub(super) fn state(host: &mut impl BootHost) -> (String, String) {
	let shown = host
		.systemctl(&["show", UNIT, "-p", "ActiveState", "-p", "Result"])
		.unwrap_or_default();
	let property = |key: &str| {
		shown
			.lines()
			.find_map(|line| {
				line.strip_prefix(key)
					.and_then(|rest| rest.strip_prefix('='))
			})
			.unwrap_or("unknown")
			.to_string()
	};
	(property("ActiveState"), property("Result"))
}

/// The boot unit is installed, enabled and its last run succeeded.
pub(super) fn unit(host: &mut impl BootHost, account: &Account) -> Item {
	let fix = autostart::FIX;
	let path = host.unit_path();
	match host.read(&path) {
		Ok(Some(_)) => {}
		Ok(None) => {
			return Item::new(
				"boot unit",
				Level::Fail,
				format!(
					"{UNIT} is not installed ({} is missing); {fix}",
					path.display()
				),
			);
		}
		Err(error) => return Item::new("boot unit", Level::Warn, error),
	}
	let enabled = host.systemctl(&["is-enabled", UNIT]).unwrap_or_default();
	if enabled != "enabled" {
		let seen = if enabled.is_empty() {
			"unknown"
		} else {
			&enabled
		};
		return Item::new(
			"boot unit",
			Level::Fail,
			format!("{UNIT} is {seen}, so the stack does not start at boot; {fix}"),
		);
	}
	let (active, result) = state(host);
	if result != "success" || active == "failed" {
		let why = host
			.unit_log()
			.ok()
			.and_then(|log| super::address::bind_failure(&log))
			.map(|line| {
				format!(
					"; the journal says a published address did not exist yet when the start ran (`{line}`), see the `port addresses` item"
				)
			})
			.unwrap_or_default();
		return Item::new(
			"boot unit",
			Level::Fail,
			format!(
				"{UNIT} is {active} and its last result is {result}{why}; read why with `sudo journalctl _UID={} --user-unit={UNIT} -b`, then {fix}",
				account.uid
			),
		);
	}
	Item::new(
		"boot unit",
		Level::Ok,
		format!("{UNIT} is enabled and its last result is {result}"),
	)
}

/// The compose files the unit starts from are the ones the stack has now.
pub(super) fn files(host: &mut impl BootHost, compose: &Path) -> Item {
	let fix = autostart::FIX;
	let path = host.unit_path();
	let text = match host.read(&path) {
		Ok(Some(text)) => text,
		Ok(None) => {
			return Item::new(
				"unit files",
				Level::Fail,
				format!("there is no unit to compare with the compose files; {fix}"),
			);
		}
		Err(error) => return Item::new("unit files", Level::Warn, error),
	};
	let mut current = vec![compose.to_path_buf()];
	let extra = compose.with_file_name("compose.override.yaml");
	if host.exists(&extra) {
		current.push(extra);
	}
	let listed = |files: &[PathBuf]| {
		files
			.iter()
			.map(|file| file.display().to_string())
			.collect::<Vec<_>>()
			.join(", ")
	};
	match autostart::compose_files(&text) {
		Some(files) if autostart::same_files(&files, &current) => Item::new(
			"unit files",
			Level::Ok,
			format!("the unit starts from {}", listed(&current)),
		),
		Some(files) => Item::new(
			"unit files",
			Level::Fail,
			format!(
				"the unit starts from {} and the stack runs from {}, so a reboot starts a stack that is not this one or fails; {fix}",
				listed(&files),
				listed(&current)
			),
		),
		None => Item::new(
			"unit files",
			Level::Fail,
			format!("the unit has no ExecStart line to read the compose files from; {fix}"),
		),
	}
}

/// Podman's API socket is enabled and active: podup speaks to it.
pub(super) fn socket(host: &mut impl BootHost, account: &Account) -> Item {
	let enabled = host
		.systemctl(&["is-enabled", "podman.socket"])
		.unwrap_or_default();
	let active = host
		.systemctl(&["is-active", "podman.socket"])
		.unwrap_or_default();
	if enabled == "enabled" && active == "active" {
		return Item::new(
			"podman socket",
			Level::Ok,
			"podman.socket is enabled and active",
		);
	}
	let word = |state: &str| {
		if state.is_empty() {
			"unknown".to_string()
		} else {
			state.to_string()
		}
	};
	Item::new(
		"podman socket",
		Level::Fail,
		format!(
			"podman.socket is {} and {}, and podup cannot reach Podman without it; run `{}`",
			word(&enabled),
			word(&active),
			as_account(account, "systemctl --user enable --now podman.socket")
		),
	)
}
