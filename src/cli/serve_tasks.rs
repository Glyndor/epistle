//! Background maintenance tasks spawned by `serve`, kept out of the main
//! startup flow.

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::config::{Config, Listener};

/// Bind a listener's socket and log it. Shared by every `serve` listener arm.
pub(super) async fn bind(listener: &Listener) -> std::io::Result<TcpListener> {
	let addr = listener.socket_addr();
	let bound = TcpListener::bind(addr).await?;
	tracing::info!(%addr, kind = ?listener.kind, "listening");
	Ok(bound)
}

/// Spawn an axum router on a bound listener, returning the serving task. Shared
/// by the plain-HTTP listener arms (autoconfig, ACME, WebDAV, metrics).
pub(super) fn serve_http(
	listener: TcpListener,
	router: axum::Router,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
	tokio::spawn(async move {
		axum::serve(listener, router)
			.await
			.map_err(std::io::Error::other)
	})
}

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
