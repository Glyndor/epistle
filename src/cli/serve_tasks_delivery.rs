//! The hourly sweep of the per-recipient delivery log.

use crate::config::Config;

/// Hourly delivery-log sweep: drop `deliverylog/YYYY-MM-DD.jsonl` files
/// whose date is older than the operator-configured
/// `[storage] delivery_log_days` window. With retention `0` it removes an
/// existing directory, so turning the setting off stops the log outright.
pub(super) fn spawn_delivery_log_sweep(config: &Config) {
	let data_dir = config.data_dir.clone();
	let retention = config.delivery_log_days();
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			let now = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			let log = crate::storage::DeliveryLog::open(&data_dir, retention);
			match log.sweep(now) {
				Ok(0) => {}
				Ok(removed) => {
					tracing::info!(
						retention_days = retention,
						removed,
						"delivery log sweep removed files"
					);
				}
				Err(error) => {
					tracing::warn!(%error, "delivery log sweep failed");
				}
			}
		}
	});
}
