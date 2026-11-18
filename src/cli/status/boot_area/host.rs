//! What the `boot` checks read from the host. Every question is read-only:
//! nothing here starts, enables or installs anything. The tests fake it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli::stack::autostart::{self, Host};

/// The account whose stack has to come back at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Account {
	pub(super) name: String,
	pub(super) uid: u32,
}

/// The host as the `boot` area sees it, on top of what the unit check needs.
pub(super) trait BootHost: Host {
	/// The account the stack runs as.
	fn account(&self) -> Account;
	/// Whether a file or directory exists at `path`.
	fn exists(&mut self, path: &Path) -> bool;
	/// Ask the system manager (`systemctl <args>`); stdout, trimmed.
	fn system_systemctl(&mut self, args: &[&str]) -> Result<String, String>;
	/// What systemd will apply as sysctl settings at the next boot, the
	/// merged `sysctl.d` configuration in the order it is applied.
	fn sysctl_at_boot(&mut self) -> Result<String, String>;
	/// Whether the account's container storage holds `image`.
	fn image_exists(&mut self, image: &str) -> Result<bool, String>;
	/// Where the account's container storage lives.
	fn storage_dir(&self) -> PathBuf;
	/// The major version of the running systemd; `None` when it cannot be read.
	fn systemd_version(&mut self) -> Option<u32>;
	/// What `podup ps --format json` prints for the stack at `compose`.
	fn ps_json(&mut self, compose: &Path) -> Result<String, String>;
	/// What the boot unit logged this boot, oldest line first.
	fn unit_log(&mut self) -> Result<String, String>;
}

/// The real host.
pub(super) struct Live {
	account: Account,
}

impl Live {
	/// The packaged account when it exists, otherwise the user running the
	/// command, which is the one whose rootless stack there is to check.
	pub(super) fn new() -> Self {
		let account = match crate::cli::rootless::lookup_user() {
			Ok(Some(user)) => Account {
				name: "glyndor-epistle".to_string(),
				uid: user.uid,
			},
			_ => {
				// SAFETY: geteuid takes no arguments and cannot fail.
				let uid = unsafe { libc::geteuid() };
				let name = std::env::var("USER").unwrap_or_else(|_| uid.to_string());
				Account { name, uid }
			}
		};
		Live { account }
	}
}

fn stdout_of(command: &mut Command) -> Result<String, String> {
	let output = command
		.stdin(Stdio::null())
		.stderr(Stdio::null())
		.output()
		.map_err(|error| error.to_string())?;
	Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

impl Host for Live {
	fn unit_path(&self) -> PathBuf {
		autostart::unit_file()
	}

	fn read(&mut self, path: &Path) -> Result<Option<String>, String> {
		match std::fs::read_to_string(path) {
			Ok(text) => Ok(Some(text)),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
			Err(error) => Err(format!("cannot read {}: {error}", path.display())),
		}
	}

	fn systemctl(&mut self, args: &[&str]) -> Result<String, String> {
		stdout_of(Command::new("systemctl").arg("--user").args(args))
			.map_err(|error| format!("cannot run systemctl: {error}"))
	}

	fn install(&mut self) -> Result<(), String> {
		Err("the boot checks never install anything".to_string())
	}
}

impl BootHost for Live {
	fn account(&self) -> Account {
		self.account.clone()
	}

	fn exists(&mut self, path: &Path) -> bool {
		path.exists()
	}

	fn system_systemctl(&mut self, args: &[&str]) -> Result<String, String> {
		stdout_of(Command::new("systemctl").args(args))
			.map_err(|error| format!("cannot run systemctl: {error}"))
	}

	fn sysctl_at_boot(&mut self) -> Result<String, String> {
		let mut text = stdout_of(Command::new("systemd-analyze").args(["cat-config", "sysctl.d"]))
			.map_err(|error| format!("cannot run systemd-analyze: {error}"))?;
		// systemd-sysctl reads this file after every `sysctl.d` one.
		if let Ok(legacy) = std::fs::read_to_string("/etc/sysctl.conf") {
			text.push('\n');
			text.push_str(&legacy);
		}
		if text.trim().is_empty() {
			return Err("systemd-analyze cat-config printed nothing".to_string());
		}
		Ok(text)
	}

	fn image_exists(&mut self, image: &str) -> Result<bool, String> {
		let status = Command::new("podman")
			.args(["image", "exists", image])
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map_err(|error| format!("cannot run podman: {error}"))?;
		match status.code() {
			Some(0) => Ok(true),
			Some(1) => Ok(false),
			_ => Err(format!(
				"`podman image exists {image}` exited with {status}"
			)),
		}
	}

	fn storage_dir(&self) -> PathBuf {
		if let Some(data) = std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
			return PathBuf::from(data).join("containers");
		}
		let home = std::env::var_os("HOME").unwrap_or_default();
		PathBuf::from(home).join(".local/share/containers")
	}

	fn systemd_version(&mut self) -> Option<u32> {
		let text = stdout_of(Command::new("systemctl").arg("--version")).ok()?;
		autostart::dropins::parse_version(&text)
	}

	fn ps_json(&mut self, compose: &Path) -> Result<String, String> {
		let mut command =
			crate::cli::stack::build_command("podup", compose, &["ps", "--format", "json"]);
		stdout_of(&mut command).map_err(|error| format!("cannot run podup: {error}"))
	}

	fn unit_log(&mut self) -> Result<String, String> {
		stdout_of(Command::new("journalctl").args([
			"--user",
			"--unit",
			autostart::UNIT,
			"--boot",
			"--lines",
			"200",
			"--output",
			"cat",
			"--no-pager",
		]))
		.map_err(|error| format!("cannot run journalctl: {error}"))
	}
}
