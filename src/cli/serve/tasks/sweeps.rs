//! Hourly sweeps and report senders that keep on-disk state bounded.

use std::sync::Arc;

use crate::config::Config;

/// Spawn the hourly DMARC aggregate-report flush: for each completed day with
/// accumulated delivery records, build the reports and queue them through
/// `sink` (so the outbound mail is DKIM-signed like any other).
pub(in crate::cli::serve) fn spawn_dmarc_flush(
	config: &Config,
	spf_dns: Arc<dyn crate::spf::DnsLookup>,
	sink: Arc<dyn crate::smtp::sink::MessageSink>,
) -> std::io::Result<()> {
	let data_dir = config.data_dir.clone();
	let hostname = config.hostname.clone();
	let org_email = format!("postmaster@{hostname}");
	let auto_submitted = config.system_auto_submitted;
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			interval.tick().await;
			let now = std::time::SystemTime::now();
			let ts = now
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			let today = crate::dmarc::aggregate::unix_to_day(ts);
			let sender = crate::dmarc::aggregate::Sender {
				data_dir: &data_dir,
				org_name: &hostname,
				org_email: &org_email,
				reporting_domain: &hostname,
				dns: spf_dns.as_ref(),
				sink: sink.as_ref(),
				now,
				auto_submitted,
			};
			crate::dmarc::aggregate::flush_pending(&sender, &today).await;
		}
	});
	Ok(())
}

/// Spawn the hourly TLS-RPT sender: each completed UTC day's recorded
/// sessions become one report per `rua=` of the recipient domain, queued
/// through `sink` (so `mailto:` reports are DKIM-signed like other mail) or
/// POSTed. Not spawned with `[queue] tlsrpt_reports = false`.
pub(in crate::cli::serve) fn spawn_tlsrpt_reports(
	config: &Config,
	dns: Arc<dyn crate::spf::DnsLookup>,
	sink: Arc<dyn crate::smtp::sink::MessageSink>,
) -> std::io::Result<()> {
	if !config.queue.tlsrpt_reports {
		return Ok(());
	}
	let poster = crate::tlsrpt::send::HttpsPoster::new().map_err(std::io::Error::other)?;
	tokio::spawn(crate::tlsrpt::send::run(
		config.data_dir.clone(),
		config.hostname.clone(),
		dns,
		sink,
		Arc::new(poster),
		config.system_auto_submitted,
	));
	Ok(())
}

/// JMAP uploaded blobs are transient (RFC 8620 §6.1): time-to-live for an
/// unreferenced upload before it is reclaimed.
const BLOB_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Spawn the hourly JMAP blob reclamation: delete uploaded blobs older than
/// `BLOB_TTL` from the upload store. Only the blob store is swept; stored mail
/// is never touched.
pub(in crate::cli::serve) fn spawn_blob_reclamation(config: &Config) {
	let data_dir = config.data_dir.clone();
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			let removed = crate::api::reclaim_blobs(&data_dir, BLOB_TTL);
			if removed > 0 {
				tracing::info!(removed, "reclaimed expired JMAP blobs");
			}
		}
	});
}

/// Spawn the hourly archive sweep when `[storage] deleted_retention_days` is
/// positive. The task iterates every account and drops archive entries whose
/// sidecar timestamp is older than the retention window, so the per-account
/// `.archive/` directory cannot grow without bound. No-op when the operator
/// has not opted in (retention = 0).
pub(in crate::cli::serve) fn spawn_archive_sweep(config: &Config) {
	let Some(retention_days) = config
		.storage
		.as_ref()
		.filter(|storage| storage.deleted_retention_days > 0)
		.map(|storage| storage.deleted_retention_days)
	else {
		return;
	};
	let data_dir = config.data_dir.clone();
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			let now = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			match crate::imap::archive::sweep(&data_dir, retention_days, now) {
				Ok(0) => {}
				Ok(removed) => {
					tracing::info!(retention_days, removed, "archive sweep purged entries");
				}
				Err(error) => {
					tracing::warn!(%error, "archive sweep failed");
				}
			}
		}
	});
}

/// The configured archive retention in days, or `0` when `[storage]` is absent
/// or the operator has not opted in. Read here rather than at the call site so
/// the IMAP server and the sweep below cannot drift apart on what "retention"
/// means.
pub(in crate::cli::serve) fn retention_days(config: &Config) -> u64 {
	config
		.storage
		.as_ref()
		.map_or(0, |storage| storage.deleted_retention_days)
}

/// Spawn the hourly DMARC and TLS-RPT report sweep: drop day directories
/// whose `YYYYMMDD` is older than [`crate::reports::RETENTION_DAYS`] (90).
/// Runs in a single task because both buckets share the same window.
pub(in crate::cli::serve) fn spawn_reports_sweep(config: &Config) {
	let data_dir = config.data_dir.clone();
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			crate::reports::prune(&data_dir);
		}
	});
}

/// Spawn the periodic tasks that keep on-disk storage bounded: blob
/// reclamation, and the archive sweep when retention is configured. Grouped
/// so `serve` starts them together and neither can be forgotten on its own.
pub(in crate::cli::serve) fn spawn_storage_maintenance(config: &Config) {
	spawn_blob_reclamation(config);
	spawn_archive_sweep(config);
	spawn_reports_sweep(config);
	super::super::tasks_delivery::spawn_delivery_log_sweep(config);
}
