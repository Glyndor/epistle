//! Enable the current user's libpod API socket before invoking podup.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

fn repair_error() -> io::Error {
	io::Error::other(
		"cannot enable Podman's API socket; run `systemctl --user enable --now podman.socket`",
	)
}

fn ensure_with(
	runtime: &Path,
	exists: impl FnOnce(&Path) -> bool,
	spawn: impl FnOnce(&mut Command) -> io::Result<ExitStatus>,
) -> io::Result<()> {
	if exists(&runtime.join("podman/podman.sock")) {
		return Ok(());
	}
	let mut command = Command::new("systemctl");
	command
		.args(["--user", "enable", "--now", "podman.socket"])
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null());
	let status = spawn(&mut command).map_err(|_| repair_error())?;
	if status.success() {
		Ok(())
	} else {
		Err(repair_error())
	}
}

pub(super) fn ensure() -> io::Result<()> {
	let runtime = std::env::var_os("XDG_RUNTIME_DIR")
		.filter(|value| !value.is_empty())
		.map(PathBuf::from)
		.unwrap_or_else(|| {
			#[cfg(unix)]
			// SAFETY: geteuid takes no arguments and cannot fail.
			let uid = unsafe { libc::geteuid() };
			#[cfg(not(unix))]
			let uid = 0;
			PathBuf::from(format!("/run/user/{uid}"))
		});
	ensure_with(&runtime, Path::exists, |command| command.status())
}

#[cfg(test)]
#[path = "stack_socket_tests.rs"]
mod tests;
