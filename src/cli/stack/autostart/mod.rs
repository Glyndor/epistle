//! Keeping the boot unit installed after every path that leaves the stack
//! running.
//!
//! `podup autostart install` writes `podup-epistle.service`, the user unit
//! that starts the stack at boot, and records the compose files it starts
//! from. Only `stack up` installed it, so a stack brought up by `update`,
//! `apply`, `restart` or `db upgrade`, or one that `stack down` had
//! uninstalled, stayed up until the host rebooted and then did not come back.
//!
//! [`ensure`] reads the installed unit, checks that systemd has it loaded and
//! enabled and that its file list is the one the stack has now, and installs
//! it again only when one of those is not so. It never touches a container or
//! an image: its one podup call is `autostart install`, whose unit starts
//! with `--no-build --pull never`, so a reboot starts what exists and a
//! version change stays `stack update`. The install is `--no-start` followed
//! by a plain `systemctl --user enable`, so it never starts the unit now: the
//! unit's `up -d` could recreate a container whose definition changed. `stack down` and `stack stop` do not
//! call it, so a stack the operator stopped on purpose stays without a unit.

use std::path::{Path, PathBuf};

mod live;
mod unit;

pub(in crate::cli) use live::{run, unit_file};
pub(in crate::cli) use unit::{compose_files, orders_after, same_files};

/// The user unit `podup autostart install` writes for the `epistle` project.
pub(in crate::cli) const UNIT: &str = "podup-epistle.service";

/// The repair for a boot unit that is not right. `stack start` starts the
/// containers that exist without recreating them and installs the unit; it
/// pulls and builds nothing, which a version change does through
/// `stack update`.
pub(in crate::cli) const FIX: &str = "run `sudo epistle stack start`, which starts the existing containers without recreating them and installs the boot unit (`sudo epistle stack up` when they do not exist yet)";

/// What [`ensure`] needs from the host; the tests fake it.
pub(in crate::cli) trait Host {
	/// Where the unit file lives.
	fn unit_path(&self) -> PathBuf;
	/// The text of the file at `path`; `None` when it does not exist.
	fn read(&mut self, path: &Path) -> Result<Option<String>, String>;
	/// Ask the user manager (`systemctl --user <args>`) and return what it
	/// printed on stdout, trimmed. `Err` when it could not be asked.
	fn systemctl(&mut self, args: &[&str]) -> Result<String, String>;
	/// Install the unit and enable it for the next boot, without starting it.
	fn install(&mut self) -> Result<(), String>;
}

/// Why the unit had to be installed again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::cli) enum Reason {
	/// There is no unit file.
	Missing,
	/// The unit starts from other files than the stack has now.
	Stale,
	/// The file is there but systemd has not loaded it.
	NotLoaded,
	/// systemd has it but it is not enabled for the next boot.
	Disabled,
}

impl Reason {
	/// What the operator reads.
	pub(in crate::cli) fn describe(self) -> &'static str {
		match self {
			Reason::Missing => "was not installed",
			Reason::Stale => "started from other compose files than the stack has now",
			Reason::NotLoaded => "was not loaded by systemd",
			Reason::Disabled => "was not enabled",
		}
	}
}

/// What [`ensure`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::cli) enum Outcome {
	/// The unit was installed, loaded, enabled and current; nothing ran.
	Unchanged,
	/// It was not; `podup autostart install` ran and the unit is right now.
	Installed(Reason),
}

/// Judge the installed unit against `current`, the compose files the stack
/// runs from now, without changing anything.
pub(in crate::cli) fn judge(
	host: &mut impl Host,
	current: &[PathBuf],
) -> Result<Option<Reason>, String> {
	let path = host.unit_path();
	let Some(text) = host.read(&path)? else {
		return Ok(Some(Reason::Missing));
	};
	match unit::compose_files(&text) {
		Some(files) if same_files(&files, current) => {}
		_ => return Ok(Some(Reason::Stale)),
	}
	let loaded = host
		.systemctl(&["show", UNIT, "-p", "LoadState"])
		.is_ok_and(|state| state == "LoadState=loaded");
	if !loaded {
		return Ok(Some(Reason::NotLoaded));
	}
	let enabled = host
		.systemctl(&["is-enabled", UNIT])
		.is_ok_and(|state| state == "enabled");
	Ok((!enabled).then_some(Reason::Disabled))
}

/// Leave the boot unit installed, loaded, enabled and current. Idempotent:
/// a unit that already is changes nothing. `Err` when the install failed or
/// left the unit still not right.
pub(in crate::cli) fn ensure(host: &mut impl Host, current: &[PathBuf]) -> Result<Outcome, String> {
	let Some(reason) = judge(host, current)? else {
		return Ok(Outcome::Unchanged);
	};
	host.install()?;
	match judge(host, current)? {
		None => Ok(Outcome::Installed(reason)),
		Some(still) => Err(format!(
			"`podup autostart install` ran but {UNIT} still {}",
			still.describe()
		)),
	}
}

#[cfg(test)]
mod tests;
