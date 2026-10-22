//! External clock probe: three independent NTP/NTS sources and the
//! verdict the area reports back to `epistle status` and
//! `epistle check clock`.
//!
//! The protocol lives in [`adapter`] (a thin wrapper around the
//! maintained `ntp-proto` crate). The rest of the module is configuration,
//! decision, and dispatch. Nothing here writes the host clock.

pub mod adapter;
pub mod assessment;
mod endpoint;
pub mod source;

pub use assessment::{Assessment, Outcome, SignedOffset};
pub use source::{ClockExternal, ProbeReading, ProbeSummary, Source, SourceKind};

use std::time::{Duration, Instant};

use tokio::task::JoinSet;
use tokio::time::timeout_at;

pub use crate::clock::external::adapter::ProbeError;

/// One whole measurement run.
#[derive(Debug, Clone)]
pub struct Run {
	/// The three configured sources, in the order they were probed.
	pub sources: Vec<Source>,
	/// The reading for every probe, in the same order as `sources`.
	pub readings: Vec<ProbeReading>,
	/// The rolled-up verdict for the area.
	pub outcome: Outcome,
	/// Median signed offset (remote minus local), when three readings are
	/// valid. `None` with fewer than three valid readings; the verdict
	/// remains independent of this diagnostic value.
	pub median: Option<SignedOffset>,
	/// Potential smear reading, retained in the verdict despite the field name.
	pub smear_excluded: Option<usize>,
	/// Effective warn threshold in seconds, inclusive.
	pub warn_seconds: f64,
	/// Effective fail threshold in seconds, inclusive.
	pub fail_seconds: f64,
	/// When the run finished, used for the "last measured at" rendering.
	pub finished_at: Instant,
}

/// Hard limit for one source, DNS included. Per-source deadline so the
/// three probes cannot pile up: 2 s is the upper bound for the whole
/// probe, dial, TLS handshake, key exchange and authenticated exchange
/// alike. Each stage is armed against the same instant, so a server
/// that answers slowly cannot buy itself a second full budget.
pub const SOURCE_DEADLINE: Duration = Duration::from_secs(2);

/// Hard limit for the whole run. Tighter than the sum of three source
/// deadlines so a hung server cannot pile up `status` calls. The whole
/// `run` aborts at this point and any in-flight probes are cancelled.
pub const RUN_DEADLINE: Duration = Duration::from_millis(2_100);

/// Run all probes concurrently and roll the packets into a [`Run`]. The
/// run is bounded by [`RUN_DEADLINE`]; each probe is bounded by
/// [`SOURCE_DEADLINE`]. A hung source is reported, never retried. A
/// run that would overrun [`RUN_DEADLINE`] is hard-cancelled at the
/// boundary: any probes still running are stopped and the readings they
/// produced up to that moment stand.
pub async fn run(external: &ClockExternal) -> Run {
	let started = Instant::now();
	let deadline = started + RUN_DEADLINE;
	let sources = external.effective_sources();
	let mut set = JoinSet::new();
	let allow_private = external.allow_private_networks;
	for source in sources.iter().cloned() {
		set.spawn(async move { probe_one(source, SOURCE_DEADLINE, allow_private).await });
	}
	let mut readings = Vec::with_capacity(sources.len());
	let collect = async {
		while let Some(joined) = set.join_next().await {
			match joined {
				Ok(reading) => readings.push(reading),
				Err(error) => {
					tracing::warn!(%error, "clock probe task failed");
				}
			}
		}
	};
	let outcome_kind = match timeout_at(deadline.into(), collect).await {
		Ok(()) => "finished",
		Err(_) => {
			set.abort_all();
			tracing::warn!(
				deadline_ms = RUN_DEADLINE.as_millis() as u64,
				"external clock probes hit the run cap"
			);
			"truncated"
		}
	};
	let outcome = assessment::decide(external, &readings);
	let summary = assessment::assessment(external, &readings);
	let _ = outcome_kind;
	let elapsed = started.elapsed();
	if elapsed > RUN_DEADLINE {
		tracing::warn!(
			elapsed_seconds = elapsed.as_secs_f64(),
			"external clock probes overran the run cap"
		);
	}
	Run {
		sources,
		readings,
		outcome,
		median: summary.median,
		smear_excluded: summary.smear_excluded,
		warn_seconds: summary.warn_seconds,
		fail_seconds: summary.fail_seconds,
		finished_at: Instant::now(),
	}
}

/// Probe one source under the operator's destination policy.
async fn probe_one(source: Source, deadline: Duration, allow_private: bool) -> ProbeReading {
	let result = match source.kind {
		SourceKind::Nts => adapter::ke_then_ntp_with_policy(&source, deadline, allow_private).await,
		SourceKind::Ntp => adapter::plain_ntp_with_policy(&source, deadline, allow_private).await,
	};
	match result {
		Ok(value) => ProbeReading::ok(source, value.offset_seconds, value.delay_seconds),
		Err(error) => ProbeReading::failed(source, error.to_string()),
	}
}

#[cfg(test)]
#[path = "tests/mod_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/sabotage_tests.rs"]
mod sabotage_tests;
