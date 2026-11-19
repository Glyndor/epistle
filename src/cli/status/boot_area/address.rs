//! The addresses the stack publishes ports on.
//!
//! The boot unit runs in the user manager of the account, which systemd starts
//! after the network and the sysctl drop-in and after nothing else. A port
//! published on an address that something else creates at boot (the interface
//! of a WireGuard tunnel brought up by `wg-quick@<name>.service`) can lose the
//! race: the bind fails with "Cannot assign requested address" and, without
//! this item, the first sign is a failed unit three days later.

use std::net::IpAddr;

use super::host::{BootHost, Link};
use crate::cli::status::report::{Item, Level};
use crate::config::Config;

const NAME: &str = "port addresses";

/// The addresses the listeners bind that the host does not own from its first
/// second: every one that is neither the wildcard nor loopback, once.
fn specific(config: &Config) -> Vec<IpAddr> {
	let mut found: Vec<IpAddr> = config
		.listeners
		.iter()
		.map(|listener| listener.socket_addr().ip())
		.filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
		.collect();
	found.sort();
	found.dedup();
	found
}

/// The system units the user manager of the account is ordered after.
fn ordered_after(host: &mut impl BootHost, uid: u32) -> Vec<String> {
	let manager = format!("user@{uid}.service");
	host.system_systemctl(&["show", &manager, "-p", "After", "--value"])
		.unwrap_or_default()
		.split_whitespace()
		.map(str::to_string)
		.collect()
}

/// The drop-in that orders the user manager after `unit`.
fn fix(uid: u32, unit: &str) -> String {
	format!(
		"put `[Unit]`, `After={unit}` and `Wants={unit}` in /etc/systemd/system/user@{uid}.service.d/glyndor-epistle-address.conf and run `sudo systemctl daemon-reload`"
	)
}

/// Every published address that exists at boot only after something the boot
/// unit does not wait for, or is covered.
pub(super) fn bound(host: &mut impl BootHost, config: &Config) -> Item {
	let addresses = specific(config);
	if addresses.is_empty() {
		return Item::new(
			NAME,
			Level::Ok,
			"every published port binds the wildcard or loopback, which exist from the start",
		);
	}
	let uid = host.account().uid;
	let after = ordered_after(host, uid);
	let mut problems = Vec::new();
	for ip in &addresses {
		match host.link_of(*ip) {
			Link::Physical | Link::Unknown => {}
			Link::WireGuard(name) => {
				let unit = format!("wg-quick@{name}.service");
				if !after.contains(&unit) {
					problems.push(format!(
						"{ip} belongs to {name}, which {unit} brings up, and the boot unit does not wait for it, so the start can run before the address exists and fail with \"Cannot assign requested address\"; {}",
						fix(uid, &unit)
					));
				}
			}
			Link::Virtual(name) => problems.push(format!(
				"{ip} belongs to {name}, a software interface that something brings up and the boot unit does not wait for; if it is not up when the stack starts the bind fails with \"Cannot assign requested address\"; order the account's user manager after the system unit that creates {name}: {}",
				fix(uid, "<that unit>.service")
			)),
			Link::Absent => problems.push(format!(
				"{ip} is on no interface now, so nothing can be checked and a port published there will not bind; bring the address up, or publish on one the host owns"
			)),
		}
	}
	if problems.is_empty() {
		return Item::new(
			NAME,
			Level::Ok,
			format!(
				"{} published address{} exist{} once the network is up or are ordered before the boot unit",
				addresses.len(),
				if addresses.len() == 1 { "" } else { "es" },
				if addresses.len() == 1 { "s" } else { "" },
			),
		);
	}
	Item::new(NAME, Level::Warn, problems.join("; "))
}

/// The last journal line of a start that could not bind an address, when the
/// unit failed for that reason.
pub(super) fn bind_failure(log: &str) -> Option<String> {
	log.lines()
		.rev()
		.map(str::trim)
		.find(|line| {
			line.to_ascii_lowercase()
				.contains("cannot assign requested address")
		})
		.map(str::to_string)
}
