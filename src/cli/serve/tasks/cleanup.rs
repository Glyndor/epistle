//! The hourly cleanup of Trash, Junk, Rejects and named folders, from
//! `[storage.cleanup]`.

use std::sync::Arc;

use crate::config::Config;
use crate::evidence::timeref::TimeRef;

/// Spawn the hourly cleanup when `[storage.cleanup]` is present. Each run
/// removes at most `max_per_run` messages and acts only on a clock the time
/// reference believes. It logs counts, never an account or a folder.
pub(in crate::cli::serve) fn spawn_cleanup(config: &Config, time: Arc<TimeRef>) {
	let Some(policy) = crate::imap::cleanup::Policy::from_config(config) else {
		return;
	};
	let data_dir = config.data_dir.clone();
	let retention_days = super::retention_days(config);
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		let mut warned = false;
		loop {
			ticker.tick().await;
			let Some(now) = super::clock_gate::believed(time.read(), &mut warned, "cleanup") else {
				continue;
			};
			let data_dir = data_dir.clone();
			let policy = policy.clone();
			let outcome = tokio::task::spawn_blocking(move || {
				crate::imap::cleanup::run(
					&data_dir,
					&policy,
					retention_days,
					now,
					crate::imap::cleanup::Mode::Apply,
				)
			})
			.await;
			match outcome {
				Ok(Ok(report)) if report.messages() == 0 => {}
				Ok(Ok(report)) => {
					tracing::info!(
						removed = report.messages(),
						folders = report.folders.len(),
						capped = report.capped,
						"cleanup removed old mail"
					);
				}
				Ok(Err(error)) => tracing::warn!(kind = ?error.kind(), "cleanup failed"),
				Err(error) => tracing::warn!(%error, "cleanup task failed"),
			}
		}
	});
}
