//! The `config` check: the configuration file loads, as `config-check` does,
//! and the running server is not older than the file ("restart pending").

use super::Ctx;
use super::clock::epoch;
use super::report::{AreaReport, Item, Level};
use crate::cli::stack_started::mail_started_at;

/// Report whether the configuration loaded and whether a restart is pending.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match &ctx.config {
		Ok(config) => config,
		Err(error) => return AreaReport::fail(error.clone()),
	};
	let data_dir = config.data_dir.clone();
	let podup = ctx.podup.clone();
	let started = tokio::task::spawn_blocking(move || mail_started_at(&data_dir, &podup))
		.await
		.unwrap_or_else(|error| Err(format!("start time lookup failed: {error}")));
	let modified = std::fs::metadata(&ctx.path)
		.and_then(|meta| meta.modified())
		.map(epoch);
	let restart = restart_item(modified.ok(), started);
	let summary = match restart.status {
		Level::Ok => format!("{} loads", ctx.path.display()),
		_ => format!("{} loads, restart pending", ctx.path.display()),
	};
	AreaReport::from_items(vec![restart], summary)
}

/// Decide the "restart pending" finding from the file's modification time and
/// the container's start time (both epoch seconds).
fn restart_item(modified: Option<i64>, started: Result<Option<i64>, String>) -> Item {
	let skipped = |why: &str| Item::new("restart", Level::Ok, format!("skipped: {why}"));
	match (modified, started) {
		(_, Err(reason)) => skipped(&reason),
		(_, Ok(None)) => skipped("no compose stack, so the server start time is not observable"),
		(None, Ok(Some(_))) => skipped("cannot read the configuration file's modification time"),
		(Some(modified), Ok(Some(started))) if modified > started => Item::new(
			"restart",
			Level::Warn,
			"restart pending: the configuration changed after the server started",
		),
		(Some(_), Ok(Some(_))) => Item::new(
			"restart",
			Level::Ok,
			"no restart pending: the server started after the last change",
		),
	}
}

#[cfg(test)]
#[path = "config_area_tests.rs"]
mod tests;
