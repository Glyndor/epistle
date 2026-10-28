//! Daily TLS-RPT report sending (RFC 8460 §4, §5).
//!
//! Once a UTC day is over, every recipient domain with sessions in the
//! journal ([`super::sessions`]) gets one report per `rua=` URI of its
//! `_smtp._tls` TXT record: a `mailto:` URI receives a message with the
//! gzip report attached, queued through the normal outbound path (so it is
//! DKIM-signed like any other mail), and an `https:` URI receives a POST of
//! the gzip report. A domain without a record gets nothing. The day's
//! sessions for a domain are deleted once its reports went out, so a
//! journal file is reported at most once. A transient DNS failure keeps the
//! file for the next pass.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MessageSink;
use crate::spf::DnsLookup;

use super::report::{TlsSession, build_email, build_report};
use super::sessions;

/// A TXT record longer than this is not a TLS-RPT policy record anyone
/// publishes, and is skipped rather than parsed.
const RECORD_BUDGET: usize = 2048;
/// Largest report body POSTed to an `https:` URI. A day of sessions for one
/// domain compresses far below this; anything larger is not sent.
const MAX_HTTPS_BODY: usize = 1024 * 1024;
/// Time allowed for one `https:` POST, connection included.
const HTTPS_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the sender wakes. Each completed day is sent once (its journal
/// is deleted), so this only bounds how soon after midnight UTC it goes.
const INTERVAL: Duration = Duration::from_secs(3600);

type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Delivers a report to an `https:` URI.
pub trait ReportPoster: Send + Sync {
	/// POST `body` (gzip JSON) to `url`; `Err` carries a reason to log.
	fn post<'a>(&'a self, url: &'a str, body: &'a [u8]) -> Fut<'a, Result<(), String>>;
}

/// The production poster: `Content-Type: application/tlsrpt+gzip`, a bounded
/// timeout, and no redirects (the report goes where the record says). The
/// destination is chosen by the recipient domain, so it is checked and the
/// connection pinned first (see `tlsrpt::https_target`).
pub struct HttpsPoster;

impl HttpsPoster {
	/// Build the poster. Kept fallible for the callers that build it at
	/// startup; the per-request client is built after the target is checked.
	pub fn new() -> Result<Self, reqwest::Error> {
		Ok(HttpsPoster)
	}
}

impl ReportPoster for HttpsPoster {
	fn post<'a>(&'a self, url: &'a str, body: &'a [u8]) -> Fut<'a, Result<(), String>> {
		Box::pin(async move {
			let target =
				super::https_target::check(url, super::https_target::system_resolve).await?;
			// Pin the name to the addresses just checked: reqwest would
			// otherwise resolve again, and a second answer could point at an
			// internal host.
			let client = reqwest::Client::builder()
				.timeout(HTTPS_TIMEOUT)
				.redirect(reqwest::redirect::Policy::none())
				.resolve_to_addrs(&target.host, &target.addrs)
				.build()
				.map_err(|error| error.to_string())?;
			let response = client
				.post(target.url.into_url())
				.header("Content-Type", "application/tlsrpt+gzip")
				.body(body.to_vec())
				.send()
				.await
				.map_err(|error| error.to_string())?;
			match response.status().is_success() {
				true => Ok(()),
				false => Err(format!("HTTP {}", response.status())),
			}
		})
	}
}

/// Where the reports go and who signs them.
pub struct Sender<'a> {
	/// The server's data directory (journal root).
	pub data_dir: &'a Path,
	/// Our host name: `organization-name`, the submitter, and the domain of
	/// `postmaster@` the reports come from.
	pub hostname: &'a str,
	/// Resolver for `_smtp._tls` records.
	pub dns: &'a dyn DnsLookup,
	/// Outbound mail path for `mailto:` reports.
	pub sink: &'a dyn MessageSink,
	/// HTTPS path for `https:` reports.
	pub poster: &'a dyn ReportPoster,
	/// Whether outgoing report messages carry
	/// `Auto-Submitted: auto-generated`.
	pub auto_submitted: bool,
}

/// Send the reports for every completed day before `today` (`YYYYMMDD`).
pub async fn send_pending(sender: &Sender<'_>, today: &str) {
	let Ok(days) = crate::util::fs_walk::read_dir(sessions::root(sender.data_dir)) else {
		return;
	};
	for day in days.flatten() {
		let name = day.file_name().to_string_lossy().to_string();
		if name.as_str() >= today || name.len() != 8 || !name.bytes().all(|b| b.is_ascii_digit()) {
			continue;
		}
		let Ok(files) = crate::util::fs_walk::read_dir(day.path()) else {
			continue;
		};
		for file in files.flatten() {
			let path = file.path();
			if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
				send_file(sender, &name, &path).await;
			}
		}
		// Only goes when every domain of the day was handled.
		let _ = std::fs::remove_dir(day.path());
	}
}

/// Report one domain's day, then delete its journal unless DNS was down.
async fn send_file(sender: &Sender<'_>, day: &str, path: &Path) {
	let journal = sessions::read(path);
	let Some(domain) = journal.first().map(|s| s.policy_domain.clone()) else {
		let _ = std::fs::remove_file(path);
		return;
	};
	let rua = match lookup_rua(sender.dns, &domain).await {
		Ok(rua) => rua,
		Err(()) => {
			tracing::debug!(%domain, day, "TLS-RPT record lookup failed; retrying next pass");
			return;
		}
	};
	if !rua.is_empty() {
		deliver(sender, day, &domain, &journal, &rua).await;
	}
	let _ = std::fs::remove_file(path);
}

async fn deliver(
	sender: &Sender<'_>,
	day: &str,
	domain: &str,
	journal: &[TlsSession],
	rua: &[String],
) {
	let start = day_start(day);
	let end = start + 86_400;
	let hostname = sender.hostname;
	let report_id = format!("{day}.{domain}@{hostname}");
	let contact = format!("postmaster@{hostname}");
	let gzip = build_report(hostname, &contact, &report_id, start, end, journal);
	for uri in rua {
		if uri.starts_with("mailto:") {
			// The address comes from a record anyone can publish and goes into
			// a header: only a plain mailbox is used.
			let Some(address) = crate::dmarc::aggregate::report_address(uri) else {
				tracing::debug!(%domain, "TLS-RPT rua is not a plain mailbox; skipped");
				continue;
			};
			let mut data = format!(
				"Date: {}\r\nMessage-ID: <{report_id}>\r\n",
				crate::clock::rfc5322(SystemTime::now())
			)
			.into_bytes();
			data.extend(build_email(
				domain,
				address,
				&report_id,
				start,
				end,
				hostname,
				&gzip,
				sender.auto_submitted,
			));
			let message = AcceptedMessage {
				reverse_path: contact.clone(),
				recipients: vec![address.to_string()],
				data: crate::util::header_block::frame_generated(data),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			};
			if let Err(error) = sender.sink.deliver(message) {
				tracing::warn!(%error, %domain, "TLS-RPT report not queued");
			}
		} else if !uri.starts_with("https:") {
			continue;
		} else if gzip.len() > MAX_HTTPS_BODY {
			tracing::warn!(%domain, bytes = gzip.len(), "TLS-RPT report too large to POST");
		} else if let Err(reason) = sender.poster.post(uri, &gzip).await {
			tracing::warn!(%domain, url = %uri, %reason, "TLS-RPT report POST failed");
		}
	}
}

/// The `rua=` URIs of the domain's `_smtp._tls` record: empty when there is
/// none (or none parses), `Err` on a transient DNS failure.
async fn lookup_rua(dns: &dyn DnsLookup, domain: &str) -> Result<Vec<String>, ()> {
	let records = dns
		.txt(&format!("_smtp._tls.{domain}"))
		.await
		.map_err(|_| ())?;
	Ok(records
		.iter()
		.filter(|record| record.len() <= RECORD_BUDGET)
		.find_map(|record| super::parse(record)?.ok())
		.map(|record| record.rua)
		.unwrap_or_default())
}

/// Midnight UTC of a `YYYYMMDD` day, in Unix seconds.
fn day_start(day: &str) -> u64 {
	let field = |range: std::ops::Range<usize>| day[range].parse::<i64>().unwrap_or(0);
	let (y, m, d) = (field(0..4), field(4..6), field(6..8));
	let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
	let era = y.div_euclid(400);
	let yoe = y - era * 400;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * m + 2) / 5 + d - 1;
	u64::try_from((era * 146_097 + doe - 719_468) * 86_400).unwrap_or(0)
}

/// Send completed days' reports every hour, forever.
#[allow(clippy::too_many_arguments)]
pub async fn run(
	data_dir: std::path::PathBuf,
	hostname: String,
	dns: Arc<dyn DnsLookup>,
	sink: Arc<dyn MessageSink>,
	poster: Arc<dyn ReportPoster>,
	auto_submitted: bool,
) {
	let mut ticker = tokio::time::interval(INTERVAL);
	ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
	loop {
		ticker.tick().await;
		let now = SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		let today = crate::dmarc::aggregate::unix_to_day(now);
		let sender = Sender {
			data_dir: &data_dir,
			hostname: &hostname,
			dns: dns.as_ref(),
			sink: sink.as_ref(),
			poster: poster.as_ref(),
			auto_submitted,
		};
		send_pending(&sender, &today).await;
	}
}

#[cfg(test)]
mod tests;
