//! The `clock` area for `epistle status` and `epistle check clock`.
//!
//! Two checks share the area:
//! - Host synchronisation: read-only via `adjtimex` or `timedatectl`.
//! - External clock probe: three independent NTP/NTS sources, real median,
//!   warn/fail thresholds. Run only when the area is reached.

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::clock::external::{ClockExternal, Outcome, ProbeReading, Run, Source};
use crate::clock::sync::{FIX, HostClock, probe};

/// Run both the host probe and the external probe (when the
/// configuration loaded). The area surfaces a one-line summary plus
/// per-source findings.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let host_probe = tokio::task::spawn_blocking(probe)
		.await
		.unwrap_or_else(|_| HostClock::Unknown("the probe did not finish".to_string()));
	let external = ctx
		.config
		.as_ref()
		.ok()
		.and_then(|config| config.clock_external.as_ref())
		.cloned()
		.unwrap_or_default();
	let external_run = tokio::task::spawn_blocking({
		let external = external.clone();
		move || match tokio::runtime::Handle::try_current() {
			Ok(handle) => Some(handle.block_on(crate::clock::external::run(&external))),
			Err(_) => None,
		}
	})
	.await
	.ok()
	.flatten();
	compose(host_probe, external_run.as_ref(), &external)
}

/// Reduce a (host probe, optional external run) pair to the area report.
fn compose(host: HostClock, external: Option<&Run>, external_config: &ClockExternal) -> AreaReport {
	let mut items = Vec::new();
	match &host {
		HostClock::Synced => items.push(Item::new(
			"host synchronisation",
			Level::Ok,
			"a time source disciplines the host clock",
		)),
		HostClock::Unsynced => items.push(Item::new(
			"host synchronisation",
			Level::Warn,
			"nothing disciplines the host clock",
		)),
		HostClock::Unknown(why) => items.push(Item::new(
			"host synchronisation",
			Level::Warn,
			format!("host clock state unknown: {why}"),
		)),
	}
	if matches!(host, HostClock::Unsynced) {
		items.push(Item::new(
			"to fix",
			Level::Warn,
			"configure chrony or systemd-timesyncd; use servers of one provider only, never Cloudflare and Google together",
		));
	}
	if matches!(host, HostClock::Unsynced | HostClock::Unknown(_)) {
		items.push(Item::new("to fix", Level::Warn, FIX));
	}
	if let Some(run) = external {
		items.extend(external_items(run));
	}
	let summary = match external {
		Some(run) => match run.median {
			Some(median) => format!(
				"offset median: {:.3} s; warn at {:.3} s, fail at {:.3} s",
				median.abs_seconds(),
				external_config.effective_warn(),
				external_config.effective_fail(),
			),
			None => "median not available (one or more sources failed)".to_string(),
		},
		None => "external clock probe not run".to_string(),
	};
	AreaReport::from_items(items, summary)
}

/// Per-source render of an external run.
fn external_items(run: &Run) -> Vec<Item> {
	let mut items = Vec::with_capacity(run.readings.len() + 3);
	items.push(authentication_item(&run.sources));
	for reading in &run.readings {
		items.push(render_reading(reading));
	}
	if let Some(index) = run.smear_excluded
		&& let Some(reading) = run.readings.get(index)
	{
		items.push(Item::new(
			"smear policy",
			Level::Warn,
			format!(
				"{} excluded: the two authenticated readings agreed within 100 ms but this source differs from their midpoint by more than 250 ms",
				reading.source.label(),
			),
		));
	}
	match run.median {
		Some(median) => {
			let level = match run.outcome {
				Outcome::Ok => Level::Ok,
				Outcome::Warn => Level::Warn,
				Outcome::Fail => Level::Fail,
			};
			items.push(Item::new(
				"median",
				level,
				format!("{:.3} s", median.abs_seconds()),
			));
		}
		None => {
			let any_failed = run.readings.iter().any(|r| r.error.is_some());
			items.push(Item::new(
				"median",
				if any_failed { Level::Warn } else { Level::Ok },
				"not available (one or more sources failed)",
			));
		}
	}
	items
}

/// State how much of the run was authenticated. NTS-KE covers the
/// sources configured as `nts` and nothing else, so a plain source is
/// unauthenticated by construction. Saying so keeps a run with one
/// authenticated source from reading as three.
fn authentication_item(sources: &[Source]) -> Item {
	let authenticated: Vec<&str> = sources
		.iter()
		.filter(|source| source.is_nts())
		.map(|source| source.host.as_str())
		.collect();
	if authenticated.is_empty() {
		return Item::new(
			"authentication",
			Level::Warn,
			"no source in this run is NTS-authenticated; every offset here is plain NTPv4",
		);
	}
	Item::new(
		"authentication",
		Level::Ok,
		format!(
			"{} of {} sources authenticated over NTS ({}); the rest are plain NTPv4",
			authenticated.len(),
			sources.len(),
			authenticated.join(", ")
		),
	)
}

fn render_reading(reading: &ProbeReading) -> Item {
	match &reading.error {
		Some(why) => Item::new(
			reading.source.label(),
			Level::Warn,
			format!("failed: {why}"),
		),
		None => Item::new(
			reading.source.label(),
			Level::Ok,
			format!(
				"offset {:.3} s, delay {:.3} s",
				reading.offset_seconds, reading.delay_seconds
			),
		),
	}
}

/// Tests exist for the host probe below; the external probe path needs
/// a Rust runtime and is exercised through integration-style unit tests
/// under [`crate::clock::external`].
#[cfg(test)]
#[path = "clock_area_tests.rs"]
mod tests;
