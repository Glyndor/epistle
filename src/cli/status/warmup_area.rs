//! The `warmup` check: the IP warm-up report, one finding per receiver
//! group (cap, today's use and health, the verdict so far and the cap it
//! would leave), and, while the warm-up is off, a suggestion to turn it on
//! when the sending address looks new and the volume is high.

use std::path::Path;

use super::Ctx;
use super::clock::epoch;
use super::report::{AreaReport, Item, Level};
use crate::cli::warmup::view::{self, View};
use crate::config::Storage;

/// Recipients a day, or messages queued, from which an address with no
/// history is worth warming up.
const HIGH_VOLUME: u64 = 200;
/// An address whose delivery log goes back less than this is new.
const NEW_DAYS: i64 = 7;

/// Check the warm-up.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	let data_dir = config.data_dir.clone();
	let storage = config.storage.clone();
	let log_days = config.delivery_log_days();
	let now = u64::try_from(epoch(ctx.now)).unwrap_or(0);
	tokio::task::spawn_blocking(move || evaluate(&data_dir, storage.as_ref(), log_days, now))
		.await
		.unwrap_or_else(|error| AreaReport::fail(format!("warm-up check failed: {error}")))
}

/// The report for the files under `data_dir` as of `now`.
fn evaluate(data_dir: &Path, storage: Option<&Storage>, log_days: u64, now: u64) -> AreaReport {
	let report = match view::build(data_dir, storage, log_days, now) {
		Ok(report) => report,
		Err(error) => {
			return AreaReport::single(
				Level::Warn,
				format!(
					"cannot read the warm-up: {}",
					crate::cli::term::sanitize(&error)
				),
			);
		}
	};
	if !report.enabled {
		return off(data_dir, storage, &report, now);
	}
	let items: Vec<Item> = report
		.groups
		.iter()
		.map(|group| {
			let level = match group.verdict {
				"very_bad" => Level::Warn,
				_ => Level::Ok,
			};
			Item::new(
				group.group,
				level,
				format!(
					"cap {}, sent {}, deferred {:.1}%, bounced {:.1}%, verdict {}, next cap {}, waiting {}",
					view::cap(group.cap),
					group.sent,
					group.deferred_percent,
					group.bounced_percent,
					group.verdict,
					view::cap(group.next_cap),
					group.waiting
				),
			)
		})
		.collect();
	let busy: Vec<String> = report
		.groups
		.iter()
		.filter(|group| group.sent > 0 || group.waiting > 0)
		.map(|group| {
			format!(
				"{} {}/{} {}",
				group.group,
				group.sent,
				view::cap(group.cap),
				group.verdict
			)
		})
		.collect();
	let summary = match busy.is_empty() {
		true => format!("{}: nothing sent today", view::mode(&report)),
		false => format!("{}: {}", view::mode(&report), busy.join(", ")),
	};
	AreaReport::from_items(items, summary)
}

/// The report while the warm-up is off.
fn off(data_dir: &Path, storage: Option<&Storage>, report: &View, now: u64) -> AreaReport {
	let today: u64 = report
		.groups
		.iter()
		.map(|group| u64::from(group.attempted))
		.sum();
	let queued = queued(data_dir, storage);
	if is_new(data_dir, now) && (today >= HIGH_VOLUME || queued >= HIGH_VOLUME) {
		return AreaReport::single(
			Level::Warn,
			format!(
				"off; this address looks new ({today} recipients today, {queued} messages queued): \
			 see `epistle warmup plan`, then `epistle warmup start`"
			),
		);
	}
	AreaReport::ok("off")
}

/// Whether the delivery log goes back less than [`NEW_DAYS`] and no day
/// was ever judged.
fn is_new(data_dir: &Path, now: u64) -> bool {
	let today = crate::queue::warmup::day_of(now);
	let oldest_allowed = crate::storage::delivery_log::day_name(today - NEW_DAYS);
	let old_log = std::fs::read_dir(data_dir.join("deliverylog"))
		.map(|entries| {
			entries.flatten().any(|entry| {
				entry
					.file_name()
					.to_str()
					.and_then(|name| name.strip_suffix(".jsonl"))
					.is_some_and(|day| day < oldest_allowed.as_str())
			})
		})
		.unwrap_or(false);
	let judged = crate::queue::warmup::state::load(data_dir)
		.ok()
		.flatten()
		.is_some_and(|state| state.groups.values().any(|group| !group.history.is_empty()));
	!old_log && !judged
}

/// Messages in the outbound spool.
fn queued(data_dir: &Path, storage: Option<&Storage>) -> u64 {
	if !data_dir.join("spool").join("new").is_dir() {
		return 0;
	}
	crate::storage::FsSpool::open_configured(data_dir, storage)
		.and_then(|spool| spool.list())
		.map_or(0, |ids| ids.len() as u64)
}

#[cfg(test)]
#[path = "warmup_area_tests.rs"]
mod tests;
