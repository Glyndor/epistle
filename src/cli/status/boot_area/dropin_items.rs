//! The items about the two drop-ins that harden the boot unit: the retry of a
//! failed start and the order after the network.

use std::path::Path;

use super::host::{Account, BootHost};
use crate::cli::stack::autostart::{self, UNIT, dropins};
use crate::cli::status::report::{Item, Level};
use crate::config::Config;

/// What a drop-in file is, against what `epistle` would write now.
enum Found {
	/// Absent.
	Absent,
	/// Present and equal to the wanted text.
	Current,
	/// Present and something else.
	Other,
}

fn find(host: &mut impl BootHost, path: &Path, wanted: &str) -> Result<Found, String> {
	Ok(match host.read(path)? {
		None => Found::Absent,
		Some(text) if text == wanted => Found::Current,
		Some(_) => Found::Other,
	})
}

/// The user drop-in beside the boot unit retries a start that failed.
pub(super) fn retry(host: &mut impl BootHost, config: &Config) -> Item {
	let path = dropins::user_path_beside(&host.unit_path());
	let wanted = dropins::user_text();
	let fix = autostart::FIX;
	let found = match find(host, &path, &wanted) {
		Ok(found) => found,
		Err(error) => return Item::new("retry drop-in", Level::Warn, error),
	};
	if !config.boot.restart_on_failure {
		return match found {
			Found::Absent => Item::new(
				"retry drop-in",
				Level::Ok,
				"turned off in the configuration (`[boot] restart_on_failure = false`)",
			),
			_ => Item::new(
				"retry drop-in",
				Level::Warn,
				format!(
					"{} is there although `[boot] restart_on_failure` is false; `sudo epistle stack start` removes it",
					path.display()
				),
			),
		};
	}
	match host.systemd_version() {
		Some(version) if version < dropins::RESTART_FROM => {
			return Item::new(
				"retry drop-in",
				Level::Warn,
				format!(
					"systemd {version} is older than {}, which refuses a retry on a oneshot unit, so a failed start of {UNIT} stays failed until someone starts it; update systemd or turn the drop-in off with `[boot] restart_on_failure = false`",
					dropins::RESTART_FROM
				),
			);
		}
		_ => {}
	}
	match found {
		Found::Current => Item::new(
			"retry drop-in",
			Level::Ok,
			format!("{UNIT} is retried every 30 seconds when its start fails"),
		),
		Found::Absent => Item::new(
			"retry drop-in",
			Level::Warn,
			format!(
				"{} is missing, so a start of {UNIT} that fails leaves it failed until someone starts it; {fix}",
				path.display()
			),
		),
		Found::Other => Item::new(
			"retry drop-in",
			Level::Warn,
			format!(
				"{} is not what epistle writes, so the retry of {UNIT} may not be the one it describes; {fix}",
				path.display()
			),
		),
	}
}

/// The system drop-in of the account's user manager orders it after the
/// network and the sysctl.
pub(super) fn order(host: &mut impl BootHost, account: &Account, config: &Config) -> Item {
	let path = dropins::system_path(account.uid);
	let mount = host
		.read(Path::new(dropins::MOUNTINFO))
		.ok()
		.flatten()
		.and_then(|table| dropins::own_mount(&table, &config.data_dir));
	let wanted = match dropins::system_text(mount.as_deref()) {
		Ok(text) => text,
		Err(error) => {
			return Item::new(
				"order drop-in",
				Level::Warn,
				format!("the drop-in is not written: {error}"),
			);
		}
	};
	let found = match find(host, &path, &wanted) {
		Ok(found) => found,
		Err(error) => return Item::new("order drop-in", Level::Warn, error),
	};
	let fix = "run `sudo epistle stack start`, which writes it (only root can)";
	if !config.boot.order_after_network {
		return match found {
			Found::Absent => Item::new(
				"order drop-in",
				Level::Ok,
				"turned off in the configuration (`[boot] order_after_network = false`)",
			),
			_ => Item::new(
				"order drop-in",
				Level::Warn,
				format!(
					"{} is there although `[boot] order_after_network` is false; `sudo epistle stack start` removes it",
					path.display()
				),
			),
		};
	}
	let service = format!("user@{}.service", account.uid);
	match found {
		Found::Current => Item::new(
			"order drop-in",
			Level::Ok,
			format!("{service} starts after the network and the sysctl"),
		),
		Found::Absent => Item::new(
			"order drop-in",
			Level::Warn,
			format!(
				"{} is missing, so {service} can start before the network is up or the port floor is applied; {fix}",
				path.display()
			),
		),
		Found::Other => Item::new(
			"order drop-in",
			Level::Warn,
			format!("{} is not what epistle writes now; {fix}", path.display()),
		),
	}
}
