//! The real [`Host`]: the user's unit directory, `systemctl --user` and podup.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use super::dropins::{self, Change, Outcome as DropIn};
use super::{Host, Outcome, UNIT, ensure};
use crate::config::Boot;

/// The install of the boot unit, without starting it, for the stack at `compose`.
struct Live<'a> {
	podup: &'a str,
	compose: &'a Path,
}

/// `${XDG_CONFIG_HOME:-$HOME/.config}`, the directory podup derives the unit
/// directory from, so both read the same place.
fn config_home() -> PathBuf {
	if let Some(home) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
		return PathBuf::from(home);
	}
	match std::env::var_os("HOME").filter(|value| !value.is_empty()) {
		Some(home) => PathBuf::from(home).join(".config"),
		None => PathBuf::from(".config"),
	}
}

/// Where `podup autostart install` writes the unit of the `epistle` project.
pub(in crate::cli) fn unit_file() -> PathBuf {
	config_home().join("systemd/user").join(UNIT)
}

impl Host for Live<'_> {
	fn unit_path(&self) -> PathBuf {
		unit_file()
	}

	fn read(&mut self, path: &Path) -> Result<Option<String>, String> {
		match std::fs::read_to_string(path) {
			Ok(text) => Ok(Some(text)),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
			Err(error) => Err(format!("cannot read {}: {error}", path.display())),
		}
	}

	fn systemctl(&mut self, args: &[&str]) -> Result<String, String> {
		// The negative answers (`disabled`, `not-found`) exit non-zero, so the
		// text on stdout is the answer whatever the status is.
		let output = Command::new("systemctl")
			.arg("--user")
			.args(args)
			.stdin(Stdio::null())
			.stderr(Stdio::null())
			.output()
			.map_err(|error| format!("cannot run systemctl: {error}"))?;
		Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
	}

	fn install(&mut self) -> Result<(), String> {
		// `--no-start` writes the unit and reloads systemd without enabling
		// or starting it: `enable --now` would run the unit's `up -d` at
		// once, and that can recreate a container whose definition changed.
		// The unit is enabled below with a plain `enable`, which only
		// arranges the next boot.
		let step = ["autostart", "install", "--no-start"];
		if super::super::run_sequence(self.podup, self.compose, &[&step]) != ExitCode::SUCCESS {
			return Err("`podup autostart install --no-start` failed".to_string());
		}
		let status = Command::new("systemctl")
			.args(["--user", "enable", UNIT])
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.status()
			.map_err(|error| format!("cannot run systemctl: {error}"))?;
		if status.success() {
			Ok(())
		} else {
			Err(format!(
				"`systemctl --user enable {UNIT}` exited with {status}"
			))
		}
	}
}

/// The compose files the stack runs from now: the generated file and the
/// operator's override when there is one, the list `build_command` passes.
pub(in crate::cli) fn current_files(compose: &Path) -> Vec<PathBuf> {
	let mut files = vec![compose.to_path_buf()];
	let override_path = compose.with_file_name("compose.override.yaml");
	if override_path.exists() {
		files.push(override_path);
	}
	files
}

/// After a path that left the stack running: leave the boot unit installed,
/// loaded, enabled and current, and its user drop-in as `boot` says. It
/// changes no container and no image and starts nothing: a reboot starts the
/// stack, this only arranges for it. A failure is a warning that names the
/// repair: the command that ran has already done what it was asked.
pub(in crate::cli) fn run(podup: &str, compose: &Path, boot: &Boot) {
	let mut host = Live { podup, compose };
	match ensure(&mut host, &current_files(compose)) {
		Ok(Outcome::Unchanged) => {}
		Ok(Outcome::Installed(reason)) => crate::cli::style::warn(format_args!(
			"{UNIT} {}; it is installed now, so the stack comes back after a reboot",
			reason.describe()
		)),
		Err(error) => {
			crate::cli::style::warn(format_args!(
				"the stack would not come back after a reboot: {error}; {}",
				super::FIX
			));
			return;
		}
	}
	harden(boot);
}

/// Leave the user drop-in of the boot unit as `boot` says, with a warning
/// that names the repair when that cannot be done.
pub(in crate::cli) fn harden(boot: &Boot) {
	let path = dropins::user_path(&config_home());
	match dropins::ensure_user(&mut dropins::Live, &path, boot) {
		Ok(DropIn::Done(_)) => {}
		Ok(DropIn::TooOld(version)) => crate::cli::style::warn(format_args!(
			"systemd {version} is older than {}, which refuses a retry on a oneshot unit, so {UNIT} is not retried when its start fails",
			dropins::RESTART_FROM
		)),
		Err(error) => crate::cli::style::warn(format_args!(
			"{UNIT} is not retried when its start fails: {error}; {}",
			super::FIX
		)),
	}
}

/// After `stack down`: the unit is gone, so its drop-in goes with it.
pub(in crate::cli) fn remove_dropin() {
	let path = dropins::user_path(&config_home());
	match dropins::remove_user(&mut dropins::Live, &path) {
		Ok(Change::Removed | Change::Unchanged | Change::Written) => {}
		Err(error) => crate::cli::style::warn(format_args!(
			"the drop-in of {UNIT} was left in place: {error}"
		)),
	}
}
