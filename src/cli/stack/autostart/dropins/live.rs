//! The real [`Host`]: the file system and `systemctl`.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use super::{Host, Scope};

/// The host this process runs on.
pub(in crate::cli) struct Live;

/// The major version in the first line of `systemctl --version`, which reads
/// `systemd 255 (255.4-1ubuntu8)`.
pub(in crate::cli) fn parse_version(text: &str) -> Option<u32> {
	let line = text.lines().next()?;
	let mut words = line.split_whitespace();
	if words.next()? != "systemd" {
		return None;
	}
	words.next()?.parse().ok()
}

impl Host for Live {
	fn read(&mut self, path: &Path) -> Result<Option<String>, String> {
		match std::fs::read_to_string(path) {
			Ok(text) => Ok(Some(text)),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
			Err(error) => Err(format!("cannot read {}: {error}", path.display())),
		}
	}

	fn write(&mut self, path: &Path, text: &str) -> Result<(), String> {
		let failed = |error: std::io::Error| format!("cannot write {}: {error}", path.display());
		let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
			return Err(format!("{} has no directory", path.display()));
		};
		std::fs::create_dir_all(dir).map_err(failed)?;
		// One rename publishes the whole file: a reader sees the old text or
		// the new one, never half of it. `create_new` refuses a name someone
		// planted, so the write never follows a link.
		let temp = dir.join(format!(
			".{}.{}",
			name.to_string_lossy(),
			std::process::id()
		));
		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o644)
			.open(&temp)
			.map_err(failed)?;
		let written = file
			.write_all(text.as_bytes())
			.and_then(|()| file.sync_all())
			.and_then(|()| std::fs::rename(&temp, path));
		if let Err(error) = written {
			let _ = std::fs::remove_file(&temp);
			return Err(failed(error));
		}
		Ok(())
	}

	fn remove(&mut self, path: &Path) -> Result<bool, String> {
		match std::fs::remove_file(path) {
			Ok(()) => {}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
			Err(error) => return Err(format!("cannot remove {}: {error}", path.display())),
		}
		if let Some(dir) = path.parent() {
			// Only an empty directory goes: another file in it is not ours.
			let _ = std::fs::remove_dir(dir);
		}
		Ok(true)
	}

	fn is_root(&self) -> bool {
		// SAFETY: geteuid takes no arguments and cannot fail.
		unsafe { libc::geteuid() == 0 }
	}

	fn systemd_version(&mut self) -> Option<u32> {
		let output = Command::new("systemctl")
			.arg("--version")
			.stdin(Stdio::null())
			.stderr(Stdio::null())
			.output()
			.ok()?;
		parse_version(&String::from_utf8_lossy(&output.stdout))
	}

	fn reload(&mut self, scope: Scope) -> Result<(), String> {
		let mut command = Command::new("systemctl");
		if scope == Scope::User {
			command.arg("--user");
		}
		let status = command
			.arg("daemon-reload")
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.status()
			.map_err(|error| format!("cannot run systemctl: {error}"))?;
		if status.success() {
			Ok(())
		} else {
			Err(format!("`systemctl daemon-reload` exited with {status}"))
		}
	}
}
