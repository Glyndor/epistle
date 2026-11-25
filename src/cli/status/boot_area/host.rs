//! What the `boot` checks read from the host. Every question is read-only:
//! nothing here starts, enables or installs anything. The tests fake it.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::stack::autostart::{self, Host};

/// The account whose stack has to come back at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Account {
	pub(super) name: String,
	pub(super) uid: u32,
}

/// What owns an address the stack publishes a port on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Link {
	/// An interface backed by hardware: it has its address once the network
	/// is up, which the boot unit already waits for.
	Physical,
	/// A WireGuard interface, which `wg-quick@<name>.service` brings up.
	WireGuard(String),
	/// Any other software interface (a tunnel, a bridge, a dummy).
	Virtual(String),
	/// No interface holds the address now.
	Absent,
	/// The host could not be asked.
	Unknown,
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
	/// What holds `ip` on this host now.
	fn link_of(&mut self, ip: IpAddr) -> Link;
}

/// An interface name that is safe to write into a unit name and a command
/// line: the characters the kernel and `wg-quick` both accept.
fn plain_name(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= 15
		&& name
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '=' | '+'))
}

/// The kind of the interface called `name`, read from sysfs.
fn classify(name: &str) -> Link {
	let base = Path::new("/sys/class/net").join(name);
	let uevent = std::fs::read_to_string(base.join("uevent")).unwrap_or_default();
	if uevent
		.lines()
		.any(|line| line.trim() == "DEVTYPE=wireguard")
		&& plain_name(name)
	{
		Link::WireGuard(name.to_string())
	} else if base.join("device").exists() {
		Link::Physical
	} else {
		Link::Virtual(name.to_string())
	}
}

/// The real host.
pub(super) struct Live {
	account: Account,
	/// When every program this host runs is killed: the end of the check.
	until: std::time::Instant,
}

impl Live {
	/// The packaged account when it exists, otherwise the user running the
	/// command, which is the one whose rootless stack there is to check.
	pub(super) fn new() -> Self {
		Self::until(std::time::Instant::now() + super::super::AREA_DEADLINE)
	}

	/// [`Live::new`] with programs killed at `until`.
	pub(super) fn until(until: std::time::Instant) -> Self {
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
		Live { account, until }
	}
}

fn stdout_of(command: &mut Command, until: std::time::Instant) -> Result<String, String> {
	let (_, stdout) = super::super::bounded::output_until(command, until)?;
	Ok(String::from_utf8_lossy(&stdout).trim().to_string())
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
		stdout_of(
			Command::new("systemctl").arg("--user").args(args),
			self.until,
		)
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
		stdout_of(Command::new("systemctl").args(args), self.until)
			.map_err(|error| format!("cannot run systemctl: {error}"))
	}

	fn sysctl_at_boot(&mut self) -> Result<String, String> {
		let mut text = stdout_of(
			Command::new("systemd-analyze").args(["cat-config", "sysctl.d"]),
			self.until,
		)
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
		let (status, _) = super::super::bounded::output_until(
			Command::new("podman").args(["image", "exists", image]),
			self.until,
		)
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
		let text = stdout_of(Command::new("systemctl").arg("--version"), self.until).ok()?;
		autostart::dropins::parse_version(&text)
	}

	fn ps_json(&mut self, compose: &Path) -> Result<String, String> {
		let mut command =
			crate::cli::stack::build_command("podup", compose, &["ps", "--format", "json"]);
		stdout_of(&mut command, self.until).map_err(|error| format!("cannot run podup: {error}"))
	}

	fn unit_log(&mut self) -> Result<String, String> {
		stdout_of(
			Command::new("journalctl").args([
				"--user",
				"--unit",
				autostart::UNIT,
				"--boot",
				"--lines",
				"200",
				"--output",
				"cat",
				"--no-pager",
			]),
			self.until,
		)
		.map_err(|error| format!("cannot run journalctl: {error}"))
	}

	fn link_of(&mut self, ip: IpAddr) -> Link {
		let Ok(entries) = nix::ifaddrs::getifaddrs() else {
			return Link::Unknown;
		};
		for entry in entries {
			let Some(address) = entry.address else {
				continue;
			};
			let held = address.as_sockaddr_in().map(|a| IpAddr::V4(a.ip())) == Some(ip)
				|| address.as_sockaddr_in6().map(|a| IpAddr::V6(a.ip())) == Some(ip);
			if held {
				return classify(&entry.interface_name);
			}
		}
		Link::Absent
	}
}
