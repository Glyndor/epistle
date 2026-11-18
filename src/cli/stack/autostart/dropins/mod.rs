//! The two drop-ins that harden the boot unit.
//!
//! `podup-epistle.service` is a `Type=oneshot` unit with no `Restart=`, so a
//! start that fails leaves it `failed` until someone looks, and a user unit
//! cannot be ordered against a system unit, so at boot it can run before the
//! network or the sysctl that opens the low ports.
//!
//! * The **user drop-in**, `podup-epistle.service.d/10-epistle.conf` in the
//!   account's unit directory, retries a failed start every 30 seconds without
//!   giving up and bounds a start that never ends. The account writes it.
//! * The **system drop-in**, `user@<uid>.service.d/glyndor-epistle-boot.conf`,
//!   starts the account's user manager after the network and the sysctl. It
//!   lives under `/etc/systemd/system`, so only root writes it, from the
//!   process that delegates to the account: the account never does.
//!
//! Neither carries an `Exec` line: the unit keeps running
//! `up -d --no-build --pull never`, so a reboot starts the containers that
//! exist and never builds, pulls or recreates anything.

use std::path::{Path, PathBuf};

use super::UNIT;

mod live;
mod root;
mod system;
mod user;

pub(in crate::cli) use live::{Live, parse_version};
pub(in crate::cli) use root::after_delegation;
pub(in crate::cli) use system::{ensure_system, remove_system};
pub(in crate::cli) use user::{Outcome, ensure_user, remove_user};

/// The file name of the user drop-in.
const USER_FILE: &str = "10-epistle.conf";
/// The file name of the system drop-in. The uid-specific directory it lives in
/// keeps it from touching any other user manager of the host.
const SYSTEM_FILE: &str = "glyndor-epistle-boot.conf";
/// `Restart=on-failure` is valid for a `Type=oneshot` unit from this systemd
/// version on; an older one refuses the unit.
pub(in crate::cli) const RESTART_FROM: u32 = 244;
/// Where the kernel lists the mounts.
pub(in crate::cli) const MOUNTINFO: &str = "/proc/self/mountinfo";

/// The user drop-in of the boot unit, under the account's `config_home`.
pub(in crate::cli) fn user_path(config_home: &Path) -> PathBuf {
	user_path_beside(&config_home.join("systemd/user").join(UNIT))
}

/// The user drop-in of the unit file at `unit`.
pub(in crate::cli) fn user_path_beside(unit: &Path) -> PathBuf {
	unit.with_file_name(format!("{UNIT}.d")).join(USER_FILE)
}

/// The system drop-in of the user manager of `uid`.
pub(in crate::cli) fn system_path(uid: u32) -> PathBuf {
	PathBuf::from(format!("/etc/systemd/system/user@{uid}.service.d")).join(SYSTEM_FILE)
}

/// The text of the user drop-in. A failed start is tried again every 30
/// seconds with no limit on the tries, and a start that does not end in 15
/// minutes is a failure instead of the `activating` that `oneshot` waits in
/// for ever.
pub(in crate::cli) fn user_text() -> String {
	"# Written by epistle; `[boot] restart_on_failure = false` removes it.\n\
	 [Unit]\n\
	 StartLimitIntervalSec=0\n\
	 \n\
	 [Service]\n\
	 Restart=on-failure\n\
	 RestartSec=30s\n\
	 TimeoutStartSec=15min\n"
		.to_string()
}

/// `path` as one word safe to write into a unit file, or why it is not. The
/// text of a unit is read line by line by systemd, which splits values on
/// white space and expands `%` and `\`, so the path has to be absolute, plain
/// and made of characters none of that touches: a newline in a `data_dir`
/// would otherwise start a new directive such as `ExecStartPre=`.
pub(in crate::cli) fn checked_path(path: &Path) -> Result<&str, String> {
	let refuse = |why: &str| {
		Err(format!(
			"{path:?} cannot go into a systemd unit: {why}; use a data_dir made of letters, digits and `/ . _ - + @ : ,`"
		))
	};
	let Some(text) = path.to_str() else {
		return refuse("it is not UTF-8");
	};
	if !path.is_absolute() {
		return refuse("it is not absolute");
	}
	if let Some(bad) = text
		.chars()
		.find(|c| !(c.is_ascii_alphanumeric() || "/._-+@:,".contains(*c)))
	{
		return refuse(&format!("it holds {bad:?}"));
	}
	if text.len() > 1 && (text.ends_with('/') || text.contains("//")) {
		return refuse("it is not normalised");
	}
	if text.split('/').any(|part| part == ".." || part == ".") {
		return refuse("it is not normalised");
	}
	Ok(text)
}

/// The text of the system drop-in. `mount` is the directory `data_dir` is
/// mounted under when it is on a mount of its own: the user manager then
/// waits for it. A `mount` that cannot be written safely is an error and
/// nothing is rendered.
pub(in crate::cli) fn system_text(mount: Option<&Path>) -> Result<String, String> {
	let mut text = "# Written by epistle; `[boot] order_after_network = false` removes it.\n\
	 [Unit]\n\
	 Wants=network-online.target\n\
	 After=network-online.target systemd-sysctl.service\n"
		.to_string();
	if let Some(path) = mount {
		text.push_str(&format!("RequiresMountsFor={}\n", checked_path(path)?));
	}
	Ok(text)
}

/// `path` when it lies on a mount of its own, judged by the mount table
/// `mountinfo`: some mount point other than `/` holds it.
pub(in crate::cli) fn own_mount(mountinfo: &str, path: &Path) -> Option<PathBuf> {
	let own = mountinfo
		.lines()
		.filter_map(|line| line.split_whitespace().nth(4))
		.map(unescape)
		.any(|point| point != "/" && path.starts_with(point));
	own.then(|| path.to_path_buf())
}

/// A mount point as `/proc/self/mountinfo` writes it: a space, a tab, a
/// newline and a backslash are octal escapes.
fn unescape(field: &str) -> String {
	let mut out = String::new();
	let mut rest = field;
	while let Some(at) = rest.find('\\') {
		out.push_str(&rest[..at]);
		let code = rest
			.get(at + 1..at + 4)
			.and_then(|d| u8::from_str_radix(d, 8).ok());
		match code {
			Some(byte) => {
				out.push(char::from(byte));
				rest = &rest[at + 4..];
			}
			None => {
				out.push('\\');
				rest = &rest[at + 1..];
			}
		}
	}
	out.push_str(rest);
	out
}

/// Which manager a reload goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::cli) enum Scope {
	/// The account's user manager (`systemctl --user`).
	User,
	/// The system manager.
	System,
}

/// What the drop-ins need from the host; the tests fake it.
pub(in crate::cli) trait Host {
	/// The text of the file at `path`; `None` when it does not exist.
	fn read(&mut self, path: &Path) -> Result<Option<String>, String>;
	/// Write `text` to `path`, creating its directory: all of it or none.
	fn write(&mut self, path: &Path, text: &str) -> Result<(), String>;
	/// Remove the file at `path` and its directory when that is left empty.
	/// `false` when there was no file.
	fn remove(&mut self, path: &Path) -> Result<bool, String>;
	/// Whether this process is root.
	fn is_root(&self) -> bool;
	/// The major version of the running systemd; `None` when it cannot be read.
	fn systemd_version(&mut self) -> Option<u32>;
	/// Make `scope`'s manager read its unit files again.
	fn reload(&mut self, scope: Scope) -> Result<(), String>;
}

/// What a sync of one drop-in did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::cli) enum Change {
	/// The file was as wanted, or absent when none was wanted.
	Unchanged,
	/// The file was written.
	Written,
	/// The file was removed.
	Removed,
}

/// Leave `path` holding `wanted`, or absent when nothing is wanted, and make
/// `scope`'s manager read it again when that changed anything. A file that
/// already holds the text is not touched, so a second run changes nothing.
fn sync(
	host: &mut impl Host,
	scope: Scope,
	path: &Path,
	wanted: Option<&str>,
) -> Result<Change, String> {
	let current = host.read(path)?;
	let change = match (wanted, current.as_deref()) {
		(Some(text), Some(have)) if text == have => Change::Unchanged,
		(Some(text), _) => {
			host.write(path, text)?;
			Change::Written
		}
		(None, Some(_)) => {
			host.remove(path)?;
			Change::Removed
		}
		(None, None) => Change::Unchanged,
	};
	if change != Change::Unchanged {
		host.reload(scope).map_err(|error| {
			format!(
				"{} was updated but the manager did not read it again: {error}",
				path.display()
			)
		})?;
	}
	Ok(change)
}

#[cfg(test)]
mod tests;
