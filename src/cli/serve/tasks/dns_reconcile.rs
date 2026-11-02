//! The DNS reconcile loop of automatic mode: every `[dns_publish]
//! interval_secs` the server compares the zones with the configuration and
//! applies the difference, through the same code `epistle dns publish`
//! runs. Records somebody else wrote are never touched; the loop only
//! creates what is missing, repairs and retires what epistle published.
//!
//! In manual mode (no `[dns]`, or every entry `manual`) nothing is spawned,
//! and an interval of 0 turns the loop off.

use std::time::Duration;

use crate::config::Config;

/// How long one provider call may take inside the loop.
const NET_TIMEOUT: Duration = Duration::from_secs(30);

/// The wait before the first run, so the listeners and the certificate are
/// up before the zones are compared.
const FIRST_RUN_AFTER: Duration = Duration::from_secs(120);

/// Whether the loop runs, and how often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcilePlan {
	/// The loop runs every `every`.
	Run {
		/// The time between two runs.
		every: Duration,
	},
	/// Manual mode: no provider can publish.
	Manual,
	/// `[dns_publish] interval_secs = 0`.
	Off,
}

/// Decide whether the loop runs. Pure, so it is tested without spawning.
pub fn decide(config: &Config) -> ReconcilePlan {
	if !config
		.dns
		.iter()
		.any(|dns| !dns.provider.eq_ignore_ascii_case("manual"))
	{
		return ReconcilePlan::Manual;
	}
	match config.dns_publish.interval_secs {
		0 => ReconcilePlan::Off,
		secs => ReconcilePlan::Run {
			every: Duration::from_secs(secs),
		},
	}
}

/// Spawn the loop when [`decide`] says so.
pub fn spawn(config: &Config) {
	let every = match decide(config) {
		ReconcilePlan::Run { every } => every,
		ReconcilePlan::Manual => return,
		ReconcilePlan::Off => {
			tracing::info!("[dns_publish] interval_secs = 0: the DNS reconcile loop is off");
			return;
		}
	};
	let Some(provider) = config.dns.build_for_host(&config.hostname) else {
		tracing::warn!(
			"the DNS reconcile loop is off: the [dns] credentials could not be read; run `epistle dns provider check`"
		);
		return;
	};
	let config = config.clone();
	tokio::spawn(async move {
		tokio::time::sleep(FIRST_RUN_AFTER).await;
		let mut ticker = tokio::time::interval(every);
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			tick(&config, provider.as_ref()).await;
		}
	});
}

/// One run of the loop. A run that finds the ledger locked (an operator is
/// running `epistle dns publish`) is skipped; the next tick tries again.
pub async fn tick(config: &Config, provider: &dyn crate::dns::provider::DnsProvider) {
	let lock = match crate::dns::reconcile::store::lock(&config.data_dir, Duration::ZERO) {
		Ok(Some(lock)) => lock,
		Ok(None) => {
			tracing::info!("dns reconcile skipped: another publish holds the ledger");
			return;
		}
		Err(error) => {
			tracing::warn!(%error, "dns reconcile skipped: the ledger cannot be locked");
			return;
		}
	};
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let outcome = crate::dns::reconcile::once::run(config, provider, now, NET_TIMEOUT).await;
	drop(lock);
	log(&outcome);
}

/// Log what a run did: every change it made, every conflict it left, and
/// why it stopped.
fn log(outcome: &Result<crate::dns::reconcile::once::Outcome, String>) {
	let outcome = match outcome {
		Ok(outcome) => outcome,
		Err(error) => {
			tracing::warn!(%error, "dns reconcile could not compare the zones; nothing was written");
			return;
		}
	};
	for warning in &outcome.warnings {
		tracing::warn!(%warning, "dns reconcile left records out");
	}
	for (zone, entry) in &outcome.applied {
		tracing::info!(
			%zone,
			action = entry.action_word(),
			name = %entry.record.name,
			kind = entry.record.kind.as_str(),
			"dns reconcile changed a record"
		);
	}
	for (zone, entry) in &outcome.conflicts {
		tracing::warn!(
			%zone,
			name = %entry.record.name,
			kind = entry.record.kind.as_str(),
			reason = %entry.reason,
			"dns reconcile left a record somebody else wrote in place; `epistle dns publish --dry-run` shows it"
		);
	}
	if let Some(failure) = &outcome.failure {
		tracing::warn!(%failure, "dns reconcile stopped partway; the next run tries again");
	}
}
