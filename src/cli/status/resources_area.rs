//! The `resources` check: whether the memory the stack's containers may use
//! fits the host, and whether the message memory budget fits the memory the
//! `mail` container may use.
//!
//! `status` runs on the host, outside the containers' cgroups, so the limits
//! are the `mem_limit` values in the compose file `epistle init` wrote, and
//! the host's memory is `MemTotal` in `/proc/meminfo`.

use std::path::Path;

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::cli::term::sanitize;
use crate::config::Config;
use crate::smtp::memory_fit;

/// Check the memory the stack's containers may use.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	evaluate(
		config,
		&crate::cli::stack::compose_path(&config.data_dir),
		&ctx.meminfo,
	)
}

/// Judge `config` against the compose file at `compose` and the host's
/// memory in `meminfo`.
fn evaluate(config: &Config, compose: &Path, meminfo: &Path) -> AreaReport {
	let containers = containers_item(compose, meminfo);
	let budget = budget_item(config, compose);
	let warnings: Vec<&str> = [&containers, &budget]
		.into_iter()
		.filter(|item| item.status != Level::Ok)
		.map(|item| item.detail.as_str())
		.collect();
	let summary = if warnings.is_empty() {
		format!("{}; message budget {}", containers.detail, budget.detail)
	} else {
		warnings.join("; ")
	};
	AreaReport::from_items(vec![containers, budget], summary)
}

/// The share of the host's memory, in percent, the containers' limits may
/// add up to before `status` warns: the rest is the host's own (kernel,
/// page cache, sshd, podman and conmon).
const HOST_SHARE_PERCENT: u64 = 85;

/// The step a suggested lower limit is rounded down to: 256 MiB.
const SUGGESTION_STEP: u64 = 256 * 1024 * 1024;

/// The containers finding: the sum of the compose memory limits against the
/// host's `MemTotal`, naming the largest and the command to lower one when
/// they add up to more than [`HOST_SHARE_PERCENT`].
fn containers_item(compose: &Path, meminfo: &Path) -> Item {
	const NAME: &str = "containers";
	let Some(document) = read_bounded(compose).and_then(|text| serde_json::from_str(&text).ok())
	else {
		return Item::new(
			NAME,
			Level::Ok,
			format!(
				"no compose file at {}, no limits to add up",
				compose.display()
			),
		);
	};
	let mut limits: Vec<(String, u64, String)> =
		crate::cli::stack_resources::read_limits(&document)
			.into_iter()
			.filter_map(|limit| Some((limit.service, limit.memory_bytes?, limit.memory?)))
			.collect();
	let Some(total) = mem_total(meminfo) else {
		return Item::new(
			NAME,
			Level::Warn,
			format!("cannot read MemTotal from {}", meminfo.display()),
		);
	};
	let sum: u64 = limits.iter().map(|(_, bytes, _)| *bytes).sum();
	let percent = u128::from(sum) * 100 / u128::from(total);
	let detail = format!(
		"the containers may use {} of the host's {} ({percent}%)",
		gib(sum),
		gib(total)
	);
	let allowed = u128::from(total) * u128::from(HOST_SHARE_PERCENT);
	if u128::from(sum) * 100 <= allowed {
		return Item::new(NAME, Level::Ok, detail);
	}
	limits.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
	let largest: Vec<String> = limits
		.iter()
		.take(2)
		.map(|(service, _, memory)| format!("{} ({})", sanitize(service), sanitize(memory)))
		.collect();
	let (service, bytes, _) = &limits[0];
	// Lower the largest by the excess, rounded down to the step.
	let excess = (u128::from(sum) * 100 - allowed).div_ceil(100);
	let target = u128::from(*bytes).saturating_sub(excess) as u64;
	let suggested = (target / SUGGESTION_STEP).max(1) * SUGGESTION_STEP;
	Item::new(
		NAME,
		Level::Warn,
		format!(
			"{detail}, more than {HOST_SHARE_PERCENT}%; the largest are {}; lower one with \
			 `epistle stack resources set {} --memory {}`",
			largest.join(" and "),
			sanitize(service),
			crate::cli::stack_resources::compose_size(suggested)
		),
	)
}

/// The host's `MemTotal`, in bytes, from a `/proc/meminfo` at `meminfo`.
fn mem_total(meminfo: &Path) -> Option<u64> {
	let text = read_bounded(meminfo)?;
	let line = text
		.lines()
		.find_map(|line| line.strip_prefix("MemTotal:"))?;
	let kib: u64 = line.trim().strip_suffix("kB")?.trim().parse().ok()?;
	kib.checked_mul(1024).filter(|bytes| *bytes > 0)
}

/// Bytes as GiB with one decimal.
fn gib(bytes: u64) -> String {
	format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// At most 1 MiB of `path` as text: `/proc/meminfo` and the compose file
/// `epistle init` writes are a few KiB.
fn read_bounded(path: &Path) -> Option<String> {
	use std::io::Read;
	let mut text = String::new();
	std::fs::File::open(path)
		.ok()?
		.take(1024 * 1024)
		.read_to_string(&mut text)
		.ok()?;
	Some(text)
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

#[cfg(test)]
#[path = "resources_area_tests_containers.rs"]
mod tests_containers;
