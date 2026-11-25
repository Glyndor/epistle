//! The `deliverability` check: the sender panels the operator has not
//! enrolled in yet, for the providers the server delivers mail to. It only
//! warns: the list of enrolled panels changes no behaviour of the server,
//! so the finding never blocks anything.
//!
//! The reminder is read, never kept: nothing is written and nothing is
//! logged, so it shows when the operator runs the check and at no other
//! time. `[deliverability] remind = false` turns it off.

mod delivered;

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::config::Portal;

/// Check the sender panels.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	if !config.deliverability.remind {
		return AreaReport::ok("reminder off ([deliverability] remind = false)");
	}
	let missing = config.deliverability.missing();
	if missing.is_empty() {
		return AreaReport::ok("every sender panel is enrolled");
	}
	let days = config.delivery_log_days();
	if days == 0 {
		return AreaReport::ok("delivery log off, so the providers delivered to are unknown");
	}
	let data_dir = config.data_dir.clone();
	let relays = crate::queue::warmup::relay_hosts(&config.transport);
	let groups = ctx
		.blocking(move || delivered::groups(&data_dir, days, &relays))
		.await
		.unwrap_or_else(|error| Err(std::io::Error::other(error)));
	let groups = match groups {
		Ok(groups) => groups,
		Err(error) => {
			return AreaReport::single(
				Level::Warn,
				format!(
					"cannot read the delivery log: {}",
					crate::cli::term::sanitize(&error.to_string())
				),
			);
		}
	};
	let due: Vec<Portal> = missing
		.into_iter()
		.filter(|portal| groups.contains(&delivered::group_of(*portal)))
		.collect();
	if due.is_empty() {
		return AreaReport::ok("no mail delivered to a provider with a sender panel left to enrol");
	}
	let items: Vec<Item> = due
		.iter()
		.map(|portal| {
			Item::new(
				portal.name(),
				Level::Warn,
				format!(
					"not enrolled: {} ({}); the steps are in docs/operations/providers.md",
					portal.what(),
					portal.page()
				),
			)
		})
		.collect();
	let names: Vec<&str> = due.iter().map(|portal| portal.name()).collect();
	let summary = format!(
		"{} of {} sender panels not enrolled: {}",
		due.len(),
		Portal::ALL.len(),
		names.join(", ")
	);
	AreaReport::from_items(items, summary)
}

#[cfg(test)]
mod tests;
