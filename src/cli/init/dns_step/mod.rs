//! The `dns` step of `init` in automatic mode: once the configuration and the
//! keys are written, the records it needs are published through the `[dns]`
//! provider, by the same reconcile run `epistle dns publish` and the server
//! use. A step that cannot publish does not undo the install: it says why,
//! and `epistle dns publish` publishes later.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::dns::provider::DnsProvider;
use crate::dns::reconcile::{once, store};

/// How long one provider call may take.
const NET_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the step waits for another publish to release the ledger.
const LOCK_WAIT: Duration = Duration::from_secs(60);

/// Builds the provider the written configuration names; tests hand in a
/// zone in memory.
pub(super) type Provider<'a> = &'a dyn Fn(&Config) -> Option<Arc<dyn DnsProvider>>;

/// Publish the records the configuration at `config_path` needs. Returns the
/// lines for the report; every line is also something the operator can act
/// on.
pub(super) fn publish(config_path: &Path, provider: Provider<'_>, now: u64) -> Vec<String> {
	let config = match Config::load(config_path) {
		Ok(config) => config,
		Err(error) => {
			return vec![format!(
				"dns: not published, the configuration did not load: {error}"
			)];
		}
	};
	let Some(provider) = provider(&config) else {
		return vec![
			"dns: not published, the [dns] credential could not be read; once it can, run `epistle dns publish`".into(),
		];
	};
	let _lock = match store::lock(&config.data_dir, LOCK_WAIT) {
		Ok(Some(lock)) => lock,
		Ok(None) => {
			return vec![
				"dns: not published, another publish holds the ledger; run `epistle dns publish`"
					.into(),
			];
		}
		Err(error) => return vec![format!("dns: not published: {error}")],
	};
	let runtime = match tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
	{
		Ok(runtime) => runtime,
		Err(error) => return vec![format!("dns: not published, no async runtime: {error}")],
	};
	let outcome = runtime.block_on(once::run(&config, provider.as_ref(), now, NET_TIMEOUT));
	lines(outcome)
}

/// The report lines of one run.
fn lines(outcome: Result<once::Outcome, String>) -> Vec<String> {
	let outcome = match outcome {
		Ok(outcome) => outcome,
		Err(error) => return vec![format!("dns: not published: {error}")],
	};
	let mut lines = vec![format!(
		"dns: {} records published or updated",
		outcome
			.applied
			.iter()
			.filter(|(_, e)| e.action.writes())
			.count()
	)];
	for warning in outcome.warnings {
		lines.push(format!("dns: left out: {warning}"));
	}
	for failure in &outcome.failures {
		lines.push(format!(
			"dns: not published in {}: {}",
			failure.zone,
			crate::cli::term::sanitize(&failure.reason)
		));
	}
	for (zone, entry) in &outcome.conflicts {
		lines.push(format!(
			"dns: conflict in {zone}: {}",
			crate::cli::term::sanitize(&entry.reason)
		));
	}
	if outcome.by_hand > 0 {
		lines.push(format!(
			"dns: {} records are in zones no [dns] entry writes; `epistle dns publish --dry-run` lists them",
			outcome.by_hand
		));
	}
	if let Some(failure) = outcome.failure {
		lines.push(format!(
			"dns: stopped partway ({failure}); run `epistle dns publish` to finish"
		));
	}
	lines
}

#[cfg(test)]
mod tests;
