//! The `clock` check: whether the host keeps its clock synchronised.
//!
//! The container shares the host kernel's clock, so the answer is the
//! host's. Nothing here changes the clock or the host: a clock that is not
//! synchronised is reported with the commands that fix it, and the operator
//! runs them.

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::clock::sync::{FIX, HostClock, probe};

/// Check the host clock. The probe may spawn `timedatectl`, so it runs off
/// the async threads.
pub(super) async fn check(_ctx: &Ctx) -> AreaReport {
	let state = tokio::task::spawn_blocking(probe)
		.await
		.unwrap_or_else(|_| HostClock::Unknown("the probe did not finish".to_string()));
	evaluate(&state)
}

/// Judge a reading of the host clock.
fn evaluate(state: &HostClock) -> AreaReport {
	match state {
		HostClock::Synced => AreaReport::from_items(
			vec![Item::new(
				"synchronisation",
				Level::Ok,
				"a time source disciplines the host clock",
			)],
			"synchronised",
		),
		HostClock::Unsynced => unhealthy(
			"not synchronised",
			"nothing disciplines the host clock, so DKIM signatures, certificate validity, \
			 token and key expiry and the evidence log can all go wrong when it drifts",
		),
		HostClock::Unknown(why) => unhealthy(
			"cannot tell whether it is synchronised",
			&format!("the host clock state is unknown: {why}"),
		),
	}
}

/// A warning with the reason and the suggested commands as findings.
fn unhealthy(summary: &str, reason: &str) -> AreaReport {
	AreaReport::from_items(
		vec![
			Item::new("synchronisation", Level::Warn, reason),
			Item::new("to fix", Level::Warn, FIX),
		],
		summary,
	)
}

#[cfg(test)]
#[path = "clock_area_tests.rs"]
mod tests;
