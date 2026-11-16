//! Hourly sweeps and report senders that keep on-disk state bounded.

use std::sync::Arc;

use crate::config::Config;

/// Where the SMTP server writes the DMARC journal the hourly flush reads:
/// `data_dir`, or nowhere with `[queue] dmarc_reports = false`, since
/// records nobody flushes would pile up under `data_dir/dmarc-reports/`.
pub(in crate::cli::serve) fn dmarc_journal_dir(config: &Config) -> Option<std::path::PathBuf> {
	config.queue.dmarc_reports.then(|| config.data_dir.clone())
}

/// Spawn the hourly DMARC aggregate-report flush: for each completed day with
/// accumulated delivery records, build the reports and queue them through
/// `sink` (so the outbound mail is DKIM-signed like any other). The reports
/// come from `postmaster@<hostname>` unless `[queue] dmarc_report_from` says
/// otherwise. Not spawned with `[queue] dmarc_reports = false`.
pub(in crate::cli::serve) fn spawn_dmarc_flush(
	config: &Config,
	spf_dns: Arc<dyn crate::spf::DnsLookup>,
	sink: Arc<dyn crate::smtp::sink::MessageSink>,
) -> std::io::Result<()> {
	if !config.queue.dmarc_reports {
		return Ok(());
	}
	let data_dir = config.data_dir.clone();
	let hostname = config.hostname.clone();
	let org_email = config.dmarc_report_from();
	let auto_submitted = config.system_auto_submitted;
	let auto_response_suppress = config.system_auto_response_suppress;
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
				auto_response_suppress,
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
		config.system_auto_response_suppress,
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
pub(in crate::cli::serve) fn spawn_archive_sweep(
	config: &Config,
	time: Arc<crate::evidence::timeref::TimeRef>,
) {
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
		let mut warned = false;
		loop {
			ticker.tick().await;
			// A purge on a wrong clock deletes kept messages early and cannot
			// be undone, so it waits for a clock the time reference believes.
			let Some(now) = super::clock_gate::believed(time.read(), &mut warned, "archive sweep")
			else {
				continue;
			};
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

/// The most automatic suppressions one hourly sweep removes.
const SUPPRESSION_SWEEP_CAP: usize = 10_000;

/// Spawn the hourly sweep of automatic suppressions whose lifetime ended and
/// of the bounce counts that fell out of their window. It runs only on a clock
/// the time reference believes, and only when the operator gave a lifetime.
pub(in crate::cli::serve) fn spawn_suppression_sweep(
	config: &Config,
	time: Arc<crate::evidence::timeref::TimeRef>,
) {
	if config.queue.suppression_days == 0 {
		return;
	}
	let rules = crate::queue::SuppressionRules::from_config(config);
	let data_dir = config.data_dir.clone();
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		let mut warned = false;
		loop {
			ticker.tick().await;
			let Some(now) =
				super::clock_gate::believed(time.read(), &mut warned, "suppression sweep")
			else {
				continue;
			};
			let Ok(list) = crate::queue::SuppressionList::open(&data_dir) else {
				continue;
			};
			let removed = list.sweep_expired(&rules, now, SUPPRESSION_SWEEP_CAP);
			if removed > 0 {
				tracing::info!(removed, "suppression sweep removed expired entries");
			}
		}
	});
}

/// Spawn the periodic tasks that keep on-disk storage bounded: blob
/// reclamation, and the archive sweep when retention is configured. Grouped
/// so `serve` starts them together and neither can be forgotten on its own.
pub(in crate::cli::serve) fn spawn_storage_maintenance(
	config: &Config,
	time: Arc<crate::evidence::timeref::TimeRef>,
) {
	spawn_blob_reclamation(config);
	spawn_archive_sweep(config, Arc::clone(&time));
	super::cleanup::spawn_cleanup(config, Arc::clone(&time));
	spawn_suppression_sweep(config, time);
	spawn_reports_sweep(config);
	super::super::tasks_delivery::spawn_delivery_log_sweep(config);
}
