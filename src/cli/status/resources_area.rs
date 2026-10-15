//! The `resources` check: whether the message memory budget fits the memory
//! the `mail` container may use.
//!
//! `status` runs on the host, outside the container's cgroup, so the limit
//! is the `mem_limit` of `mail` in the compose file `epistle init` wrote.

use std::path::Path;

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::config::Config;
use crate::smtp::memory_fit;

/// Check the memory the stack's containers may use.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	evaluate(config, &crate::cli::stack::compose_path(&config.data_dir))
}

/// Judge `config` against the compose file at `compose`.
fn evaluate(config: &Config, compose: &Path) -> AreaReport {
	let budget = budget_item(config, compose);
	let summary = format!("message budget {}", budget.detail);
	AreaReport::from_items(vec![budget], summary)
}

/// The message budget finding: the budget in effect against the `mail`
/// limit, with the start-up warning when a full budget would not fit.
fn budget_item(config: &Config, compose: &Path) -> Item {
	const NAME: &str = "message budget";
	let limit = match memory_fit::read_compose_limit(compose) {
		Some(bytes) => memory_fit::ContainerLimit {
			bytes,
			source: memory_fit::LimitSource::Compose,
		},
		None => memory_fit::ContainerLimit::fallback(),
	};
	let largest = config
		.max_message_size
		.filter(|size| *size > 0)
		.unwrap_or(crate::smtp::session::MAX_MESSAGE_SIZE as u64);
	let budget = memory_fit::effective(config.message_memory_budget, largest, limit);
	if budget.bytes == 0 {
		return Item::new(NAME, Level::Ok, "off (message_memory_budget = 0)");
	}
	if let Some(warning) = memory_fit::warning(&budget) {
		return Item::new(NAME, Level::Warn, warning);
	}
	let detail = if budget.derived {
		format!(
			"{} MiB, derived from the {} MiB the mail container may use ({})",
			memory_fit::mib(budget.bytes),
			memory_fit::mib(limit.bytes),
			limit.source.describe()
		)
	} else {
		format!(
			"{} MiB, set by message_memory_budget",
			memory_fit::mib(budget.bytes)
		)
	};
	Item::new(NAME, Level::Ok, detail)
}

#[cfg(test)]
#[path = "resources_area_tests.rs"]
mod tests;
