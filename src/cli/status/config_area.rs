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
	if let Some(why) = &config.validation_error {
		return AreaReport::fail(format!(
			"{} does not pass validation: {why}; `epistle config-check` shows the same, and the other checks ran on the file as it is",
			ctx.path.display()
		));
	}
	let data_dir = config.data_dir.clone();
	let podup = ctx.podup.clone();
	let started = tokio::task::spawn_blocking(move || mail_started_at(&data_dir, &podup))
		.await
		.unwrap_or_else(|error| Err(format!("start time lookup failed: {error}")));
	let modified = std::fs::metadata(&ctx.path)
		.and_then(|meta| meta.modified())
		.map(epoch);
	let restart = restart_item(modified.ok(), started);
	let mut summary = match restart.status {
		Level::Ok => format!("{} loads", ctx.path.display()),
		_ => format!("{} loads, restart pending", ctx.path.display()),
	};
	let addresses = address_items(config);
	let shared = addresses
		.iter()
		.filter(|item| item.status != Level::Ok)
		.count();
	match shared {
		0 => {}
		1 => summary.push_str(", 1 address with two owners"),
		n => summary.push_str(&format!(", {n} addresses with two owners")),
	}
	let mut items: Vec<_> = std::iter::once(restart).chain(addresses).collect();
	if config
		.dns
		.as_ref()
		.is_some_and(|dns| dns.token.is_some() || dns.token_env.is_some())
	{
		let detail = "DNS token is inline or supplied through the environment; move it with `epistle dns provider set <provider> --zone <zone> --store-token`, including the provider's other required settings";
		summary.push_str("; ");
		summary.push_str(detail);
		items.push(Item::new("DNS token", Level::Warn, detail));
	}
	if let Some(line) = crate::cli::oauth_advice::notice(config) {
		items.push(Item::new("bearer sign-in", Level::Ok, line));
	}
	for line in crate::cli::oauth_advice::advice(config) {
		summary.push_str("; ");
		summary.push_str(&line);
		items.push(Item::new("bearer sign-in", Level::Warn, line));
	}
	for line in &config.adjusted {
		summary.push_str("; ");
		summary.push_str(line);
		items.push(Item::new("adjusted value", Level::Warn, line.clone()));
	}
	AreaReport::from_items(items, summary)
}

/// One warning per address two owners claim, the lines the server logs at
/// startup (see `AccountStore::address_collisions`), or a single ok item.
fn address_items(config: &crate::config::Config) -> Vec<Item> {
	let store = crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map(|store| store.with_aliases(config.alias.clone()));
	let collisions = match store {
		Ok(store) => store.address_collisions(),
		Err(error) => {
			let why = format!("skipped: cannot read the account store: {error}");
			return vec![Item::new("addresses", Level::Ok, why)];
		}
	};
	if collisions.is_empty() {
		return vec![Item::new(
			"addresses",
			Level::Ok,
			"every address has one owner",
		)];
	}
	collisions
		.into_iter()
		.map(|line| Item::new("addresses", Level::Warn, line))
		.collect()
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

#[cfg(test)]
#[path = "config_area_tests_addresses.rs"]
mod tests_addresses;

#[cfg(test)]
#[path = "config_area_tests_invalid.rs"]
mod tests_invalid;
