//! Background maintenance tasks spawned by `serve`, kept out of the main
//! startup flow.

use std::sync::Arc;

use crate::config::Config;

/// Spawn the hourly DMARC aggregate-report flush: for each completed day with
/// accumulated delivery records, build the reports and queue them on the
/// outbound spool.
pub(super) fn spawn_dmarc_flush(
	config: &Config,
	spf_dns: Arc<dyn crate::spf::DnsLookup>,
) -> std::io::Result<()> {
	let data_dir = config.data_dir.clone();
	let hostname = config.hostname.clone();
	let spool = crate::storage::FsSpool::open(&config.data_dir)?;
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			interval.tick().await;
			let ts = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			let today = crate::dmarc::aggregate::unix_to_day(ts);
			let messages = crate::dmarc::aggregate::flush_pending(
				&data_dir,
				&today,
				&hostname,
				&format!("postmaster@{hostname}"),
				&hostname,
				spf_dns.as_ref(),
			)
			.await;
			for message in messages {
				if let Err(e) = spool.store(&message) {
					tracing::warn!(%e, "failed to queue DMARC report");
				}
			}
		}
	});
	Ok(())
}
