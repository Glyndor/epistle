//! One reconcile run without a person in the loop, for the automatic paths
//! (`init` in automatic mode first). It is the same survey and the
//! same apply `epistle dns publish` runs after its question, so what the
//! command shows is what the automatic paths do.

use std::time::Duration;

use super::{Action, apply, survey};
use crate::config::Config;
use crate::dns::provider::DnsProvider;

/// What one run did.
#[derive(Debug, Default)]
pub struct Outcome {
	/// The changes applied, with their zone.
	pub applied: Vec<(String, super::Entry)>,
	/// The records left as they are because somebody else's record is in
	/// the way.
	pub conflicts: Vec<(String, super::Entry)>,
	/// How many needed records no `[dns]` entry writes.
	pub by_hand: usize,
	/// Inputs that could not be read; the records they would produce are
	/// missing from the run.
	pub warnings: Vec<String>,
	/// The zones that could not be read, and why. The other zones were
	/// compared and published.
	pub failures: Vec<survey::ZoneFailure>,
	/// Why the run stopped partway, when it did.
	pub failure: Option<String>,
}

/// Compare every zone with the configuration and apply the difference. The
/// caller holds the ledger lock ([`super::store::lock`]). `Err` when
/// nothing could be compared at all: the record set could not be read.
/// A zone that could not be read is reported in
/// [`Outcome::failures`] and the other zones are compared and published.
pub async fn run(
	config: &Config,
	provider: &dyn DnsProvider,
	now: u64,
	timeout: Duration,
) -> Result<Outcome, String> {
	let desired = crate::dns::desired::from_config(config).map_err(|errors| errors.join("; "))?;
	let incomplete = desired.incomplete();
	let context = survey::Context {
		config,
		provider,
		needed: &desired.records,
		domain: None,
		timeout,
		incomplete: incomplete.as_deref(),
	};
	let survey = survey::survey(&context).await?;
	let changes = survey.changes();
	let survey::Survey {
		zones,
		by_hand,
		failures,
	} = survey;
	let mut outcome = Outcome {
		by_hand: by_hand.len(),
		warnings: desired.warnings,
		failures,
		..Outcome::default()
	};
	for zone in &zones {
		for entry in &zone.plan.entries {
			if entry.action == Action::Conflict {
				outcome
					.conflicts
					.push((zone.plan.zone.clone(), entry.clone()));
			}
		}
	}
	if !changes {
		return Ok(outcome);
	}
	let target = apply::Target {
		provider,
		data_dir: &config.data_dir,
		hostname: &config.hostname,
		timeout,
		now,
	};
	let report = apply::apply(&target, zones).await;
	outcome.applied = report.applied;
	outcome.failure = report.failure;
	Ok(outcome)
}
