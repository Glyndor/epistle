//! The `clock` area for `epistle status` and `epistle check clock`.
//!
//! Two checks share the area:
//! - Host synchronisation: read-only via `adjtimex` or `timedatectl`.
//! - External clock probe: three independent NTP/NTS sources, diagnostic median,
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
	if !external.enabled {
		return compose_disabled(host_probe, &external);
	}
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

/// The area with the probe switched off: no network is touched and the report
/// says so, so a host that cannot reach 123/udp or 4460/tcp is not told its
/// clock is broken every time it asks.
fn compose_disabled(host: HostClock, external_config: &ClockExternal) -> AreaReport {
	let mut report = compose(host, None, external_config);
	report.detail =
		"external clock probe switched off with [clock_external] enabled = false".to_string();
	report.items.push(Item::new(
		"external probe",
		Level::Ok,
		"switched off with enabled = false; no time source was queried",
	));
	report
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
				"diagnostic median: {:.3} s; verdict uses the largest absolute offset; warn at {:.3} s, fail at {:.3} s",
				median.abs_seconds(),
				external_config.effective_warn(),
				external_config.effective_fail(),
			),
			None => "diagnostic median not available (fewer than three valid readings); verdict uses all valid offsets".to_string(),
		},
		None => "external clock probe not run".to_string(),
	};
	AreaReport::from_items(items, summary)
}

/// Per-source render of an external run.
fn external_items(run: &Run) -> Vec<Item> {
	let mut items = Vec::with_capacity(run.readings.len() + run.sources.len() + 3);
	items.push(authentication_item(&run.sources));
	for reading in &run.readings {
		items.push(render_reading(reading));
	}
	// A probe task that failed before producing a reading leaves the source
	// with no line above, so the gap is named here instead of passing as a
	// source that was never asked.
	for missing in missing_sources(run) {
		items.push(Item::new(
			missing.label(),
			Level::Warn,
			"the probe task reported no reading for this source",
		));
	}
	if let Some(index) = run.smear_excluded
		&& let Some(reading) = run.readings.get(index)
	{
		items.push(Item::new(
			"smear diagnostic",
			Level::Warn,
			format!(
				"{} differs from the authenticated pair midpoint by more than 250 ms; the pair agreed within 100 ms; diagnostic only, this reading still affects the verdict",
				reading.source.label(),
			),
		));
	}
	let level = match run.outcome {
		Outcome::Ok => Level::Ok,
		Outcome::Warn => Level::Warn,
		Outcome::Fail => Level::Fail,
	};
	items.push(Item::new(
		"external verdict",
		level,
		"largest absolute valid offset; fewer than three valid readings gives at least Warn; no valid readings gives Fail",
	));
	let median = match run.median {
		Some(median) => format!(
			"{:.3} s; does not determine the verdict",
			median.abs_seconds()
		),
		None => "not available (fewer than three valid readings)".to_string(),
	};
	items.push(Item::new("diagnostic median", Level::Ok, median));
	items
}

/// The configured sources no reading belongs to: the probe never reported
/// them, either because its task failed or because the run hit its cap.
fn missing_sources(run: &Run) -> Vec<&Source> {
	run.sources
		.iter()
		.filter(|source| {
			!run.readings
				.iter()
				.any(|reading| reading.source == **source)
		})
		.collect()
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
