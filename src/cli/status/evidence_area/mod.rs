//! The `evidence` check: what the server's last evidence verification
//! found, whether transactional mail is held and why, timestamp tokens
//! still being requested, and settings it could not read.

use std::path::Path;

use super::Ctx;
use super::clock::epoch;
use super::report::{AreaReport, Item, Level};
use crate::cli::term::sanitize;
use crate::evidence::tasks::{Status, last_status};

/// The last verification is stale past this, in seconds.
const STALE_SECS: u64 = 3600;
/// Past this share of the time a verification is given, the status warns: the
/// gate closes at the whole of it.
const SLOW_PERCENT: u128 = 50;

/// Check the evidence.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	let root = crate::evidence::service::root_of(&config.data_dir);
	let now = u64::try_from(epoch(ctx.now)).unwrap_or(0);
	tokio::task::spawn_blocking(move || evaluate(&root, now))
		.await
		.unwrap_or_else(|error| AreaReport::fail(format!("evidence check failed: {error}")))
}

/// The report for the evidence under `root` as of `now`.
pub(super) fn evaluate(root: &Path, now: u64) -> AreaReport {
	let status = match last_status(root) {
		Ok(Some(status)) => status,
		Ok(None) => {
			return AreaReport::single(
				Level::Warn,
				"the server has not verified the evidence yet; transactional mail is held until it does",
			);
		}
		Err(error) => {
			return AreaReport::fail(format!("cannot read the evidence status: {}", error.kind()));
		}
	};
	let mut items = Vec::new();
	if let Some(reason) = &status.held {
		items.push(Item::new(
			"transactional mail",
			Level::Fail,
			format!(
				"held: {}; once understood, acknowledge it with `epistle evidence acknowledge`",
				sanitize(reason)
			),
		));
	}
	if let Some(pending) = &status.pending {
		items.push(Item::new("timestamp", Level::Warn, sanitize(pending)));
	}
	if let Ok(waiting) = crate::evidence::tsa::stamp::waiting(root) {
		for (day, entry) in waiting.iter().take(7) {
			items.push(Item::new(
				format!("timestamp {day}"),
				Level::Warn,
				format!(
					"{} failed attempts; last: {}",
					entry.attempts,
					sanitize(&entry.last_error)
				),
			));
		}
	}
	match crate::evidence::tsa::settings::load(root) {
		Ok(settings) if !settings.enabled => items.push(Item::new(
			"timestamps",
			Level::Warn,
			"disabled: sealed days rest on the evidence key alone; `epistle evidence timestamp enable`",
		)),
		Ok(_) => {}
		Err(error) => items.push(Item::new(
			"timestamps",
			Level::Warn,
			format!(
				"settings refused ({}): the server keeps the last good ones",
				error.kind()
			),
		)),
	}
	for error in status.errors.iter().take(10) {
		items.push(Item::new("evidence task", Level::Warn, sanitize(error)));
	}
	let limit = crate::evidence::tasks::AUDIT_TIMEOUT.as_millis();
	if u128::from(status.audit_millis) * 100 >= limit * SLOW_PERCENT {
		items.push(Item::new(
			"verification time",
			Level::Warn,
			format!(
				"the last verification took {} s of the {} s it is given; past that, transactional mail is held. \
				 Fewer records kept (a shorter retention, or fewer messages a day) bring it back",
				status.audit_millis / 1000,
				limit / 1000
			),
		));
	}
	if now.saturating_sub(status.time) > STALE_SECS {
		items.push(Item::new(
			"last verification",
			Level::Warn,
			"older than an hour: is the server running?",
		));
	}
	AreaReport::from_items(items, summary(&status))
}

fn summary(status: &Status) -> String {
	match &status.held {
		Some(_) => "the evidence does not verify: transactional mail is held".to_string(),
		None => format!(
			"{} days, {} records verified in {} s; {} days timestamped{}",
			status.days,
			status.records,
			status.audit_millis / 1000,
			status.stamped,
			match status.acknowledged {
				0 => String::new(),
				n => format!("; {n} acknowledged breaks"),
			}
		),
	}
}

#[cfg(test)]
mod tests;
