//! The outbound queue worker `serve` starts: MX delivery with MTA-STS,
//! DANE, the retry schedule, suppression, transports and TLS-RPT, and the
//! routing sink for the bounces it writes. Pulled out of `serve.rs`, which
//! was at the code-line limit.

use std::sync::Arc;

use crate::config::Config;
use crate::metrics::Metrics;
use crate::smtp::sink::MessageSink;
use crate::storage::MessageCrypto;

/// Open the IP warm-up under the data directory, judging days from the
/// delivery log and reporting them to the metrics and the webhook, and
/// close each day on a one-minute timer so a day is judged and reported
/// even when no mail is waiting.
pub(super) fn open_warmup(
	config: &Config,
	metrics: &Arc<Metrics>,
	webhook: Option<&Arc<crate::webhook::Webhook>>,
) -> Arc<crate::queue::warmup::Warmup> {
	let log = crate::storage::DeliveryLog::open(&config.data_dir, config.delivery_log_days());
	let now = crate::storage::delivery_log::now_epoch();
	let mut warmup = crate::queue::warmup::Warmup::open(&config.data_dir, Some(log), now)
		.with_relays(crate::queue::warmup::relay_hosts(&config.transport))
		.with_metrics(Arc::clone(metrics));
	if let Some(webhook) = webhook {
		warmup = warmup.with_webhook(Arc::clone(webhook));
	}
	let warmup = Arc::new(warmup);
	let ticking = Arc::clone(&warmup);
	tokio::spawn(async move {
		let mut ticks = tokio::time::interval(std::time::Duration::from_secs(60));
		loop {
			ticks.tick().await;
			let ticking = Arc::clone(&ticking);
			let now = crate::storage::delivery_log::now_epoch();
			// Closing a day reads the day's delivery log: off the runtime.
			let _ = tokio::task::spawn_blocking(move || ticking.tick(now)).await;
		}
	});
	warmup
}

/// Build the queue worker and spawn it, unless outbound delivery is held.
/// A resolver or MTA-STS fetcher that cannot be built, or an unreadable
/// spool or suppression list, stops the start.
pub(super) fn spawn_queue_worker(
	config: &Config,
	crypto: MessageCrypto,
	sink: Arc<dyn MessageSink>,
	spf_dns: Arc<dyn crate::spf::DnsLookup>,
	metrics: &Arc<Metrics>,
	webhook: Option<&Arc<crate::webhook::Webhook>>,
	warmup: Arc<crate::queue::warmup::Warmup>,
) -> std::io::Result<()> {
	let connector = Arc::new(crate::queue::MxConnector::from_system()?);
	let mta_sts = Arc::new(crate::mtasts::PolicyStore::new(Box::new(
		crate::mtasts::SystemFetcher::new().map_err(|error| {
			std::io::Error::other(format!("cannot build MTA-STS fetcher: {error:?}"))
		})?,
	)));
	let mut worker = crate::queue::Worker::new(
		crate::storage::FsSpool::open_with_crypto(&config.data_dir, crypto)?,
		connector,
		&config.hostname,
	)
	.with_bounce_sink(sink)
	.with_mta_sts(mta_sts, Arc::clone(&spf_dns))
	.with_dane(Arc::clone(&spf_dns))
	.with_metrics(metrics.clone())
	.with_max_age(config.queue_give_up_secs.unwrap_or(0))
	.with_retry_schedule(crate::queue::RetrySchedule::from_config(
		config.queue_retry_base_secs,
		config.queue_retry_cap_secs,
		config.queue_delay_warning_secs,
	))
	.with_suppression(crate::queue::SuppressionList::open(&config.data_dir)?)
	.with_transports(config.transport.clone())
	.with_outbound_tls(config.queue.outbound_tls)
	.with_concurrency(
		config.queue.concurrency,
		config.queue.per_domain_concurrency,
	)
	.with_backoff(config.queue.backoff_steps.clone())
	.with_delivery_log(crate::storage::DeliveryLog::open(
		&config.data_dir,
		config.delivery_log_days(),
	))
	.with_warmup(warmup);
	if let Some(webhook) = webhook {
		worker = worker.with_webhook(Arc::clone(webhook));
	}
	if config.queue.tlsrpt_reports {
		worker = worker.with_tlsrpt(&config.data_dir);
	}
	let worker = Arc::new(worker);
	if config.start_queue_worker() {
		tokio::spawn(worker.run(std::time::Duration::from_secs(30)));
	} else {
		tracing::info!("outbound delivery is held: queue worker not started");
	}
	Ok(())
}
