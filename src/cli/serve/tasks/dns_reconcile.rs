//! The DNS reconcile loop of automatic mode: every `[dns_publish]
//! interval_secs` the server compares the zones with the configuration and
//! applies the difference, through the same code `epistle dns publish`
//! runs. Records somebody else wrote are never touched; the loop only
//! creates what is missing, repairs and retires what epistle published.
//!
//! In manual mode (no `[dns]`, or every entry `manual`) nothing is spawned,
//! and an interval of 0 turns the loop off.
//!
//! A run that fails waits longer before the next one: the interval
//! doubles, up to a cap, spread by a jitter so a fleet of servers that
//! starts at once does not query the provider at the same instant. A run
//! that goes through resets the wait to the configured interval.

use std::future::Future;
use std::time::Duration;

use crate::config::Config;

/// How long one provider call may take inside the loop.
const NET_TIMEOUT: Duration = Duration::from_secs(30);

/// The wait before the first run, so the listeners and the certificate are
/// up before the zones are compared.
pub(super) const FIRST_RUN_AFTER: Duration = Duration::from_secs(120);

/// The longest wait between two runs after repeated failures: eight times
/// the configured interval, never more than a day and never less than the
/// interval itself.
fn cap(every: Duration) -> Duration {
	every
		.saturating_mul(8)
		.min(Duration::from_secs(86_400))
		.max(every)
}

/// The wait before the next run after `failures` failed runs in a row,
/// without the jitter.
///
/// The configured interval, doubling, up to the cap.
pub fn backoff_base(every: Duration, failures: u32) -> Duration {
	let doublings = failures.saturating_sub(1).min(6);
	every.saturating_mul(1u32 << doublings).min(cap(every))
}

/// What one tick of the loop did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
	/// The zones were compared and the difference written.
	Clean,
	/// Another publish holds the ledger: nothing was compared.
	Skipped,
	/// The provider failed, or a zone could not be read: the run did not
	/// go through.
	Failed,
}

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

/// The wait before the next run after `failures` failed runs in a row.
///
/// The base wait, spread by the jitter the queue uses so that servers
/// which start together do not all ask the provider at the same second.
pub fn backoff(every: Duration, failures: u32) -> Duration {
	let base = backoff_base(every, failures);
	let factor = crate::queue::schedule::random_factor();
	Duration::from_secs((base.as_secs() as f64 * factor).round() as u64)
}

/// Spawn the loop when [`decide`] says so.
pub fn spawn(config: &Config) {
	match decide(config) {
		ReconcilePlan::Run { .. } => {}
		ReconcilePlan::Manual => return,
		ReconcilePlan::Off => {
			tracing::info!("[dns_publish] interval_secs = 0: the DNS reconcile loop is off");
			return;
		}
	}
	let Some(provider) = config.dns.build_for_host(&config.hostname) else {
		tracing::warn!(
			"the DNS reconcile loop is off: the [dns] credentials could not be read; run `epistle dns provider check`"
		);
		return;
	};
	let config = config.clone();
	tokio::spawn(async move {
		loop_with(&config, provider.as_ref(), &mut |delay| async move {
			tokio::time::sleep(delay).await;
			true
		})
		.await;
	});
}

/// The loop: compare the zones, wait, compare again.
///
/// `wait` is how the loop waits between two runs and says whether it
/// goes on, so a test can drive the loop without waiting for real.
pub async fn loop_with<F, Fut>(
	config: &Config,
	provider: &dyn crate::dns::provider::DnsProvider,
	mut wait: F,
) where
	F: FnMut(Duration) -> Fut,
	Fut: Future<Output = bool>,
{
	let every = match decide(config) {
		ReconcilePlan::Run { every } => every,
		ReconcilePlan::Manual | ReconcilePlan::Off => return,
	};
	let mut failures = 0u32;
	let mut delay = FIRST_RUN_AFTER;
	loop {
		if !wait(delay).await {
			return;
		}
		match tick(config, provider).await {
			// A run that went through resets the wait: the next one is
			// the configured interval again.
			Tick::Clean => failures = 0,
			// A provider that fails is asked less often.
			Tick::Failed => failures = failures.saturating_add(1),
			// Another publish holds the ledger: the provider was
			// never asked, so the wait does not change.
			Tick::Skipped => {}
		}
		delay = if failures == 0 {
			every
		} else {
			backoff(every, failures)
		};
	}
}

/// One run of the loop. A run that finds the ledger locked (an operator is
/// running `epistle dns publish`) is skipped; the next tick tries again.
pub async fn tick(config: &Config, provider: &dyn crate::dns::provider::DnsProvider) -> Tick {
	let lock = match crate::dns::reconcile::store::lock(&config.data_dir, Duration::ZERO) {
		Ok(Some(lock)) => lock,
		Ok(None) => {
			tracing::info!("dns reconcile skipped: another publish holds the ledger");
			return Tick::Skipped;
		}
		Err(error) => {
			tracing::warn!(%error, "dns reconcile skipped: the ledger cannot be locked");
			return Tick::Skipped;
		}
	};
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let outcome = crate::dns::reconcile::once::run(config, provider, now, NET_TIMEOUT).await;
	drop(lock);
	log(&outcome);
	match &outcome {
		Ok(outcome) if outcome.failures.is_empty() => Tick::Clean,
		_ => Tick::Failed,
	}
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
	for failure in &outcome.failures {
		tracing::warn!(
			zone = %failure.zone,
			reason = %failure.reason,
			"dns reconcile left a zone alone; the other zones were compared"
		);
	}
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
