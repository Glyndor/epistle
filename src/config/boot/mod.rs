//! Which boot drop-ins `epistle` writes for the stack's units.
//!
//! Both are written by `stack up`, `stack start` and the commands that leave
//! the stack running, and both are removed by `stack down` and by the package
//! purge. A drop-in changes when and how often the unit starts the stack; it
//! never changes what the unit runs, so a reboot still only starts the
//! containers that exist.

use serde::Deserialize;

use super::defaults::default_yes;

/// The `[boot]` table.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Boot {
	/// Write the user drop-in that retries `podup-epistle.service` when its
	/// start fails, every 30 seconds and without giving up. Needs systemd 244
	/// or later. Turn it off to leave the unit as podup writes it.
	#[serde(default = "default_yes")]
	pub restart_on_failure: bool,
	/// Write the system drop-in that starts the account's user manager after
	/// `network-online.target` and `systemd-sysctl.service`, so the stack
	/// does not race the network or the port floor at boot. Needs root, so
	/// `sudo epistle` writes it and the account never does.
	#[serde(default = "default_yes")]
	pub order_after_network: bool,
}

impl Default for Boot {
	fn default() -> Self {
		Boot {
			restart_on_failure: true,
			order_after_network: true,
		}
	}
}

#[cfg(test)]
mod tests;
