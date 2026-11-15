//! The port floor: the lowest port an unprivileged process may bind.

use super::host::BootHost;
use crate::cli::status::report::{Item, Level};
use crate::config::Config;

const KEY: &str = "net.ipv4.ip_unprivileged_port_start";
const PROC_FILE: &str = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
/// The kernel's value when no configuration sets one.
const KERNEL_DEFAULT: u32 = 1024;

/// The last value `text` sets for the floor, in the order the lines come:
/// `sysctl.d` syntax, `key = value`, with `/` or `.` between the words and
/// an optional leading `-`.
pub(super) fn configured(text: &str) -> Option<u32> {
	text.lines()
		.filter_map(|line| {
			let line = line.trim();
			if line.starts_with('#') || line.starts_with(';') {
				return None;
			}
			let (key, value) = line.split_once('=')?;
			let key = key.trim().trim_start_matches('-').replace('/', ".");
			(key == KEY).then(|| value.trim().parse().ok()).flatten()
		})
		.next_back()
}

/// The floor is applied and the configuration systemd applies at the next
/// boot keeps it at or below the lowest port the stack listens on.
pub(super) fn port_floor(host: &mut impl BootHost, config: &Config) -> Item {
	let Some(lowest) = config
		.listeners
		.iter()
		.map(|listener| u32::from(listener.socket_addr().port()))
		.min()
	else {
		return Item::new("port floor", Level::Ok, "the stack listens on no port");
	};
	let fix = format!(
		"put `{KEY} = {lowest}` in /etc/sysctl.d/99-glyndor-epistle.conf, which sorts after the files that set it higher, and run `sudo sysctl --system`"
	);
	let running = match host.read(std::path::Path::new(PROC_FILE)) {
		Ok(Some(text)) => text.trim().parse::<u32>().ok(),
		_ => None,
	};
	let Some(running) = running else {
		return Item::new(
			"port floor",
			Level::Warn,
			format!("cannot read {PROC_FILE}"),
		);
	};
	if running > lowest {
		return Item::new(
			"port floor",
			Level::Fail,
			format!(
				"the floor is {running} and the stack listens on port {lowest}, so it cannot publish it; {fix}"
			),
		);
	}
	let at_boot = match host.sysctl_at_boot() {
		Ok(text) => configured(&text).unwrap_or(KERNEL_DEFAULT),
		Err(error) => {
			return Item::new(
				"port floor",
				Level::Warn,
				format!(
					"the floor is {running}, but the configuration of the next boot could not be read ({error})"
				),
			);
		}
	};
	if at_boot > lowest {
		return Item::new(
			"port floor",
			Level::Fail,
			format!(
				"the floor is {running} now but the next boot sets {at_boot}, above port {lowest} that the stack listens on; {fix}"
			),
		);
	}
	Item::new(
		"port floor",
		Level::Ok,
		format!("{running} now and {at_boot} at the next boot, at or below port {lowest}"),
	)
}
