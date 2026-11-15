//! The `deliverability` check: the sender panels the operator has not
//! enrolled in yet. It only warns: the list of enrolled panels changes no
//! behaviour of the server, so the finding never blocks anything.

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::config::Portal;

/// Check the sender panels.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	let missing = config.deliverability.missing();
	if missing.is_empty() {
		return AreaReport::ok("every sender panel is enrolled");
	}
	let items: Vec<Item> = missing
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
	let names: Vec<&str> = missing.iter().map(|portal| portal.name()).collect();
	let summary = format!(
		"{} of {} sender panels not enrolled: {}",
		missing.len(),
		Portal::ALL.len(),
		names.join(", ")
	);
	AreaReport::from_items(items, summary)
}

#[cfg(test)]
mod tests;
