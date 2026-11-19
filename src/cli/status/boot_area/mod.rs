//! The `boot` check: would the stack come back after a reboot?
//!
//! A server can run for months and fail only at its first reboot, so this
//! area reads what the next boot depends on and says which item would stop
//! it, with the command that fixes that item. Every item is read-only and
//! independent of the others. The ones without which nothing starts (linger,
//! the user manager, the unit, its file list, Podman's socket, the images
//! `--pull never` needs and the port floor) are `fail`; the rest are `warn`.
//!
//! The fixes never recreate anything: `sudo epistle stack start` starts the
//! containers that exist and installs the unit, and a version change is
//! `sudo epistle stack update`, the only command that pulls.

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::config::Config;

mod address;
mod compose_items;
mod dropin_items;
mod floor;
mod host;
mod mounts;
mod network;
mod services;
mod summary;
mod unit_items;

use host::{BootHost, Live};
pub(in crate::cli) use summary::print_summary;

/// Check what the next boot depends on.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config.clone(),
		Err(report) => return report,
	};
	tokio::task::spawn_blocking(move || check_with(&mut Live::new(), &config))
		.await
		.unwrap_or_else(|_| AreaReport::single(Level::Warn, "the boot check did not run"))
}

/// Judge the host through `host` for the stack `config` describes.
fn check_with(host: &mut impl BootHost, config: &Config) -> AreaReport {
	judge(host, config, false)
}

/// [`check_with`]; with `summary` the services and the order drop-in are left
/// out. The first asks podup what runs, which the command that prints the
/// summary has just done; the second is written by the root process only after
/// the account's process, the one that prints it, has finished.
fn judge(host: &mut impl BootHost, config: &Config, summary: bool) -> AreaReport {
	let compose = crate::cli::stack::compose_path(&config.data_dir);
	let text = match host.read(&compose) {
		Ok(Some(text)) => text,
		Ok(None) => {
			return AreaReport::ok(format!(
				"no stack here: {} does not exist, so there is nothing to start at boot",
				compose.display()
			));
		}
		Err(error) => return AreaReport::single(Level::Warn, error),
	};
	let account = host.account();
	let mut items = vec![
		unit_items::linger(host, &account),
		unit_items::manager(host, &account),
		unit_items::unit(host, &account),
		unit_items::files(host, &compose),
		unit_items::socket(host, &account),
		dropin_items::retry(host, config),
		compose_items::restart(&text),
		network::wait(host),
		address::bound(host, config),
		floor::port_floor(host, config),
		mounts::mounted(host, config),
		compose_items::images(host, &text),
	];
	if !summary {
		items.insert(6, dropin_items::order(host, &account, config));
		items.push(services::running(host, &text, &compose));
	}
	let summary = summarize(&items);
	AreaReport::from_items(items, summary)
}

/// The `status` line: the items that would stop the boot, or the all-clear.
fn summarize(items: &[Item]) -> String {
	let problems: Vec<&str> = items
		.iter()
		.filter(|item| item.status != Level::Ok)
		.map(|item| item.name.as_str())
		.collect();
	if problems.is_empty() {
		"the stack comes back after a reboot".to_string()
	} else {
		let failing = items.iter().any(|item| item.status == Level::Fail);
		let lead = if failing {
			"the stack would not come back after a reboot"
		} else {
			"the stack comes back after a reboot, with warnings"
		};
		format!("{lead}: {}", problems.join(", "))
	}
}

#[cfg(test)]
mod tests;
