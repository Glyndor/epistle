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
use crate::cli::init::host_sizing;
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
	let largest = memory_fit::largest_message(config.max_message_size);
	let containers = containers_item(compose, meminfo, largest);
	let budget = budget_item(config, compose);
	let summary = format!("{}; message budget {}", containers.detail, budget.detail);
	let mut items = vec![containers];
	items.extend(suggested_item(compose, meminfo, largest));
	items.push(budget);
	let warnings: Vec<&str> = items
		.iter()
		.filter(|item| item.status != Level::Ok)
		.map(|item| item.detail.as_str())
		.collect();
	let summary = if warnings.is_empty() {
		summary
	} else {
		warnings.join("; ")
	};
	AreaReport::from_items(items, summary)
}

/// The suggested finding: the limits a new install on this host would get
/// (see [`host_sizing`]) against the ones the compose file has, with the
/// commands that adopt them. `init` never changes an existing install's
/// limits, so this is where the operator hears of them. A warning when the
/// `mail` limit is below the suggestion, since that is the container a
/// burst of large messages fills; `None` when the compose file or
/// `MemTotal` cannot be read (the containers finding says which). `mail` is
/// never suggested less than messages of up to `largest` bytes need.
fn suggested_item(compose: &Path, meminfo: &Path, largest: u64) -> Option<Item> {
	let document: serde_json::Value = serde_json::from_str(&read_bounded(compose)?).ok()?;
	let total = host_sizing::mem_total(meminfo)?;
	let sizing = host_sizing::for_host(total);
	let current = crate::cli::stack::resources::read_limits(&document);
	let host = format!("a new install on this host ({})", gib(total));
	let mut differences = Vec::new();
	let mut commands = Vec::new();
	let mut level = Level::Ok;
	for (service, wanted) in sizing.memory {
		let Some(limit) = current.iter().find(|limit| limit.service == service) else {
			continue;
		};
		if matches!(service, "clamav" | "freshclam") && !sizing.antivirus {
			continue;
		}
		let wanted_bytes = match memory_fit::parse_memory(wanted) {
			Some(bytes) if service == "mail" => Some(bytes.max(needs(service, largest))),
			bytes => bytes,
		};
		let wanted = wanted_bytes.map_or_else(|| wanted.to_string(), compose_size);
		if limit.memory_bytes == wanted_bytes {
			continue;
		}
		if limit.service == "mail" && limit.memory_bytes < wanted_bytes {
			level = Level::Warn;
		}
		differences.push(format!(
			"{service} {wanted} (now {})",
			sanitize(limit.memory.as_deref().unwrap_or("none"))
		));
		commands.push(format!(
			"`epistle stack resources set {service} --memory {wanted}`"
		));
	}
	let mut detail = match commands.len() {
		0 => format!("the limits are what {host} would get"),
		count => {
			let (last, rest) = commands.split_last().expect("one command at least");
			let listed = if rest.is_empty() {
				last.clone()
			} else {
				format!("{} and {last}", rest.join(", "))
			};
			format!(
				"{host} would get {}; adopt {} with {listed}, then `epistle stack update`",
				differences.join(", "),
				if count == 1 { "it" } else { "them" }
			)
		}
	};
	let runs_clamav = current.iter().any(|limit| limit.service == "clamav");
	if runs_clamav && !sizing.antivirus {
		detail.push_str("; a new install on this host leaves clamav and freshclam out");
	}
	Some(Item::new("suggested", level, detail))
}

/// The share of the host's memory, in percent, the containers' limits may
/// add up to before `status` warns: the rest is the host's own (kernel,
/// page cache, sshd, podman and conmon).
const HOST_SHARE_PERCENT: u64 = 85;

/// The step a suggested lower limit is rounded down to: 256 MiB.
const SUGGESTION_STEP: u64 = 256 * 1024 * 1024;

/// The least memory `status` suggests for `service`: for `mail`, room for
/// messages of up to `largest` bytes ([`memory_fit::mail_floor`]) rounded
/// up to [`SUGGESTION_STEP`]; for the others, the least any tier gives it.
fn needs(service: &str, largest: u64) -> u64 {
	if service == "mail" {
		return memory_fit::mail_floor(largest).div_ceil(SUGGESTION_STEP) * SUGGESTION_STEP;
	}
	host_sizing::least(service).unwrap_or(SUGGESTION_STEP)
}

/// A byte count as compose writes it.
fn compose_size(bytes: u64) -> String {
	crate::cli::stack::resources::compose_size(bytes)
}

/// The containers finding: the sum of the compose memory limits against the
/// host's `MemTotal`, naming the largest and the commands to lower enough of
/// them when they add up to more than [`HOST_SHARE_PERCENT`]. A service is
/// never suggested less than it [`needs`]; when the largest cannot go lower,
/// the next one is lowered too.
fn containers_item(compose: &Path, meminfo: &Path, largest: u64) -> Item {
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
		crate::cli::stack::resources::read_limits(&document)
			.into_iter()
			.filter_map(|limit| Some((limit.service, limit.memory_bytes?, limit.memory?)))
			.collect();
	let Some(total) = host_sizing::mem_total(meminfo) else {
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
	let largest_two: Vec<String> = limits
		.iter()
		.take(2)
		.map(|(service, _, memory)| format!("{} ({})", sanitize(service), sanitize(memory)))
		.collect();
	// Lower the largest that can go lower by the excess, rounded down to
	// the step, but not under what it needs; when one is not enough, the
	// next largest, until the sum is under the line or none can go lower.
	let mut lowered: Vec<(&str, u64)> = Vec::new();
	let mut now = u128::from(sum);
	while now * 100 > allowed {
		let excess = (now * 100 - allowed).div_ceil(100);
		let next = limits.iter().find_map(|(service, bytes, _)| {
			if lowered.iter().any(|(done, _)| done == service) {
				return None;
			}
			let target = u128::from(*bytes).saturating_sub(excess) as u64;
			let suggested =
				(target / SUGGESTION_STEP * SUGGESTION_STEP).max(needs(service, largest));
			(suggested < *bytes).then_some((service.as_str(), suggested, *bytes))
		});
		let Some((service, suggested, bytes)) = next else {
			break;
		};
		now -= u128::from(bytes - suggested);
		lowered.push((service, suggested));
	}
	let commands: Vec<String> = lowered
		.iter()
		.map(|(service, suggested)| {
			format!(
				"`epistle stack resources set {} --memory {}`",
				sanitize(service),
				compose_size(*suggested)
			)
		})
		.collect();
	let enough = now * 100 <= allowed;
	let remedy = match (commands.split_last(), enough) {
		(None, _) => {
			"none can be lowered under what it needs, so the host needs more memory".to_string()
		}
		(Some((only, [])), true) => format!("lower one with {only}"),
		(Some((last, rest)), true) => {
			format!("lower them with {} and {last}", rest.join(", "))
		}
		(Some(_), false) => format!(
			"lower them with {}; that leaves {}% and none can go lower under what it needs, \
			 so the host needs more memory",
			commands.join(", "),
			now * 100 / u128::from(total)
		),
	};
	Item::new(
		NAME,
		Level::Warn,
		format!(
			"{detail}, more than {HOST_SHARE_PERCENT}%; the largest are {}; {remedy}",
			largest_two.join(" and "),
		),
	)
}

/// Bytes as GiB with one decimal.
fn gib(bytes: u64) -> String {
	format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// At most 1 MiB of the regular file at `path` as text: the compose file
/// `epistle init` writes is a few KiB, and a FIFO there must not hang
/// `status`.
fn read_bounded(path: &Path) -> Option<String> {
	memory_fit::read_regular(path, 1024 * 1024).ok()
}

/// The message budget finding: the budget in effect against the `mail`
/// limit, with the start-up warning when a full budget would not fit.
fn budget_item(config: &Config, compose: &Path) -> Item {
	const NAME: &str = "message budget";
	let limit = memory_fit::compose_or_fallback(compose);
	let largest = memory_fit::largest_message(config.max_message_size);
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
mod tests;
