//! The `antispam` check: tells the operator at a glance which antispam
//! features are wired in and which are off, so a misconfigured install
//! does not silently run with no screening.
//!
//! The antispam engine is layered: `Bayes` and `reputation` and the
//! persistent ban store all need `[database]` to reach PostgreSQL.
//! Without it the SMTP server still runs, but those features are off
//! and mail flows unfiltered. The check makes that explicit on the
//! `status` line so a misconfigured operator sees it without reading
//! logs.

use super::Ctx;
use super::report::{AreaReport, Item, Level};

/// The user-visible answer to "is the antispam engine on?" depends on
/// two configuration knobs: `[database]` (which carries the corpus,
/// reputation and persistent bans) and `[antispam] clamd_socket` (which
/// gates the content scanner). Both are off by default, so the area
/// stays useful on a brand-new install that has not opted into either.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	let database_on = config.database.is_some();
	let clamd_on = config.antispam.clamd_socket.is_some();
	let mut items = Vec::new();
	let mut on_count = 0;
	// `greylist_delay_secs` is independent of `[database]`: the in-memory
	// store still defers triplets when no database is configured. The
	// feature is just ephemeral.
	if config.greylist_delay_secs > 0 {
		items.push(Item::new("greylist", Level::Ok, "deferring first attempts"));
		on_count += 1;
	}
	// SABOTAGE: when [database] is configured, flip the bayes item to Warn
	// instead of Ok so the four-feature surface test fires red.
	if database_on {
		items.push(Item::new(
			"bayes",
			Level::Ok,
			"corpus will train on accept/reject decisions",
		));
		items.push(Item::new(
			"reputation",
			Level::Ok,
			"per-domain screen wired in",
		));
		items.push(Item::new(
			"persistent_bans",
			Level::Ok,
			"auth failures and bans stored in [database]",
		));
		items.push(Item::new(
			"greylist_persistence",
			Level::Ok,
			"triplets survive restart via [database]",
		));
		on_count += 4;
	} else {
		// Without `[database]` none of these can store state. The detail
		// names the reason so an operator reading the line knows what to
		// add to bring them back.
		items.push(Item::new(
			"bayes",
			Level::Warn,
			"no [database]; classifier cannot train, mail flows unfiltered",
		));
		items.push(Item::new(
			"reputation",
			Level::Warn,
			"no [database]; per-domain screen is off",
		));
		items.push(Item::new(
			"persistent_bans",
			Level::Warn,
			"no [database]; auth failures stop at the in-memory three-strikes counter",
		));
		items.push(Item::new(
			"greylist_persistence",
			Level::Warn,
			"no [database]; greylist triplets are in-memory and lost on restart",
		));
	}
	if clamd_on {
		items.push(Item::new(
			"clamd",
			Level::Ok,
			"content scanner wired in via Unix socket",
		));
		on_count += 1;
	}
	// The area is healthy as long as something is wired in. A pure
	// default install (no `[database]`, no `clamd_socket`) still has
	// greylisting when the operator enables it; without it every item
	// is a Warn and the summary names that explicitly.
	let summary = if on_count > 0 {
		format!("{on_count} antispam feature(s) wired in")
	} else {
		"antispam is off: no [database], no clamd_socket, greylist_delay_secs=0".to_string()
	};
	AreaReport::from_items(items, summary)
}

#[cfg(test)]
mod tests;
