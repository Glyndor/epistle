//! The network wait of the boot unit.

use super::host::BootHost;
use crate::cli::stack::autostart::{self, UNIT};
use crate::cli::status::report::{Item, Level};

/// The unit Podman ships, from 5.3.0, to order a user unit after the
/// network is up.
const SHIM: &str = "podman-user-wait-network-online.service";

/// The unit waits for the network and what it waits on exists: systemd
/// drops an `After=` on a unit it cannot load without saying so, and the
/// shim only waits when `network-online.target` is pulled in.
pub(super) fn wait(host: &mut impl BootHost) -> Item {
	let path = host.unit_path();
	let text = match host.read(&path) {
		Ok(Some(text)) => text,
		Ok(None) => {
			return Item::new(
				"network wait",
				Level::Warn,
				format!("not checked: {UNIT} is not installed"),
			);
		}
		Err(error) => return Item::new("network wait", Level::Warn, error),
	};
	if !autostart::orders_after(&text, SHIM) {
		return Item::new(
			"network wait",
			Level::Warn,
			format!(
				"{UNIT} does not wait for the network, so the start can run before it is up; {}",
				autostart::FIX
			),
		);
	}
	let state = host
		.systemctl(&["show", SHIM, "-p", "LoadState"])
		.unwrap_or_default();
	if state != "LoadState=loaded" {
		return Item::new(
			"network wait",
			Level::Warn,
			format!(
				"systemd cannot load {SHIM} ({state}), so the wait the unit declares does nothing; it ships with Podman, and the stack needs Podman 6.2.0 or newer, so update Podman"
			),
		);
	}
	let target = host
		.system_systemctl(&["is-active", "network-online.target"])
		.unwrap_or_default();
	if target != "active" {
		return Item::new(
			"network wait",
			Level::Warn,
			format!(
				"network-online.target is {target:?}, so the wait never ends; run `sudo systemctl enable systemd-networkd-wait-online.service` (or NetworkManager-wait-online.service when NetworkManager runs the network)"
			),
		);
	}
	Item::new(
		"network wait",
		Level::Ok,
		format!("{UNIT} waits for the network and it is online"),
	)
}
