//! DMARC aggregate report accumulation and flushing (RFC 7489 §7.2).
//!
//! Records are written as JSONL to
//! `{data_dir}/dmarc-reports/{YYYYMMDD}/{from_domain}.jsonl`
//! by `record_delivery()` during inbound SMTP processing. The day
//! directory holds at most [`MAX_FILES_PER_DAY`] files and each file at
//! most [`MAX_FILE_BYTES`]: a record past either cap is dropped.
//!
//! `flush_pending` reads completed-day directories, generates XML reports
//! and queues one message per `mailto:` `rua=` through the [`Sender`]'s
//! `MessageSink` (so the outbound mail is DKIM-signed like any other).

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;

use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MessageSink;
use crate::spf::DnsFailure;
use crate::spf::DnsLookup;

use super::report::{DeliveryRecord, build_email, build_xml};

/// How long a day's records are kept without a successful delivery
/// attempt. A day older than this is dropped regardless: the report is
/// stale and the data has been kept as long as the spec advises.
const MAX_AGE_DAYS: u64 = 7;

/// Most journal files one day directory may hold.
///
/// Every file is one `From:` domain, and that domain comes from an
/// unauthenticated sender: a day of mail from N domains would otherwise
/// create N files, and the hourly flush would look up N DNS records and
/// build N reports out of them. Past the cap a record for a domain that
/// has no file yet is dropped; a domain that already has one keeps
/// receiving records.
pub const MAX_FILES_PER_DAY: usize = 2000;

/// Largest a journal file may grow, in bytes.
///
/// The file is read whole when its report is built, so this bounds the
/// memory one domain's report costs as well as the disk it takes. Past
/// the cap the record is dropped.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The days whose drops were already reported, so a flood of dropped
/// records leaves one debug line per day and not one per message. The
/// table keeps a handful of days: it only has to outlive a day boundary.
static REPORTED_DROPS: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Where the reports go and who signs them.
pub struct Sender<'a> {
	/// The server's data directory (report journal root).
	pub data_dir: &'a Path,
	/// Human-readable organization name embedded in the report XML.
	pub org_name: &'a str,
	/// Contact email embedded in the report XML.
	pub org_email: &'a str,
	/// The server's host name; appears in the report as the submitter and
	/// as the `From:` domain of every outgoing report message.
	pub reporting_domain: &'a str,
	/// Resolver for `_dmarc` and `<policy>._report._dmarc.<rua>` lookups.
	pub dns: &'a dyn DnsLookup,
	/// Outbound mail path for `mailto:` reports. The same sink used for
	/// regular outgoing mail, so DKIM signing happens transparently.
	pub sink: &'a dyn MessageSink,
	/// Time the `Date:` header of outgoing report messages is taken from.
	/// Injected so tests can pin the value.
	pub now: SystemTime,
	/// Whether outgoing report messages carry
	/// `Auto-Submitted: auto-generated`.
	pub auto_submitted: bool,
}

/// Write one delivery record to the per-domain JSONL file for today.
///
/// The day directory holds at most [`MAX_FILES_PER_DAY`] files and a
/// file at most [`MAX_FILE_BYTES`]: past either cap the record is
/// dropped, so a sender that invents a domain per message cannot make
/// the journal grow without bound. Errors are logged but not propagated
/// — losing a few records is preferable to blocking the delivery path.
pub fn record_delivery(data_dir: &Path, today: &str, record: &DeliveryRecord) {
	let dir = data_dir.join("dmarc-reports").join(today);
	if let Err(error) = crate::storage::create_private_dir(&dir) {
		tracing::warn!(path = %dir.display(), %error, "cannot create dmarc record directory");
		return;
	}
	let path = record_path(&dir, &record.header_from);
	let line = match serde_json::to_string(record) {
		Ok(line) => line,
		Err(error) => {
			tracing::warn!(%error, "cannot serialize dmarc record");
			return;
		}
	};
	match std::fs::metadata(&path) {
		// The domain already has its file: it keeps receiving records as
		// long as the file stays under the size cap.
		Ok(metadata) => {
			if metadata.len() + line.len() as u64 + 1 > MAX_FILE_BYTES {
				report_drop(today, "the file reached the size cap");
				return;
			}
		}
		// A new domain needs a new file, and the day directory holds a
		// bounded number of them.
		Err(_) => {
			if count_files(&dir) >= MAX_FILES_PER_DAY {
				report_drop(today, "the day directory reached the file cap");
				return;
			}
		}
	}
	let mut options = std::fs::OpenOptions::new();
	options.create(true).append(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	let Ok(mut file) = options.open(&path) else {
		tracing::warn!(path = %path.display(), "cannot open dmarc record file");
		return;
	};
	use std::io::Write;
	let _ = writeln!(file, "{line}");
}

/// How many files the day directory holds. The count stops at
/// [`MAX_FILES_PER_DAY`]: the answer is only used to know whether the
/// cap is reached.
fn count_files(dir: &Path) -> usize {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return 0;
	};
	entries
		.flatten()
		.filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
		.take(MAX_FILES_PER_DAY)
		.count()
}

/// Report a dropped record at debug level, once per day.
fn report_drop(today: &str, reason: &'static str) {
	let mut reported = REPORTED_DROPS
		.lock()
		.unwrap_or_else(|poison| poison.into_inner());
	if reported.iter().any(|day| day == today) {
		return;
	}
	if reported.len() >= 8 {
		reported.remove(0);
	}
	reported.push(today.to_string());
	drop(reported);
	tracing::debug!(day = today, reason, "dmarc delivery record dropped");
}

/// Generate and queue reports for every completed reporting day that has
/// accumulated records. Each day's records are deleted after the report
/// is queued, except when the day's `rua=` lookup failed (a transient
/// DNS error): the file is kept for the next pass, capped at the
/// internal `MAX_AGE_DAYS` constant so a permanently broken record
/// cannot pile up.
///
/// `today` is `"YYYYMMDD"` of the current day; completed days are those
/// that are older (different from `today`).
pub async fn flush_pending(sender: &Sender<'_>, today: &str) {
	let reports_root = sender.data_dir.join("dmarc-reports");
	let Ok(entries) = crate::util::fs_walk::read_dir(&reports_root) else {
		return;
	};

	for entry in entries.flatten() {
		let day = match entry.file_name().into_string() {
			Ok(s) if s != today && s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()) => s,
			_ => continue,
		};

		let day_dir = entry.path();
		let Ok(domain_files) = crate::util::fs_walk::read_dir(&day_dir) else {
			continue;
		};

		let day_too_old = is_older_than_cap(today, &day);
		let mut to_remove: Vec<PathBuf> = Vec::new();

		for domain_entry in domain_files.flatten() {
			if !domain_entry.file_type().is_ok_and(|kind| kind.is_file()) {
				continue;
			}
			let path = domain_entry.path();
			if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
				continue;
			}
			let from_domain = match path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) {
				Some(d) if !d.is_empty() => d,
				_ => continue,
			};

			let records = read_records(&path);
			if records.is_empty() {
				to_remove.push(path);
				continue;
			}

			// Look up rua= for this domain's DMARC record.
			let rua = match lookup_rua(sender.dns, &from_domain).await {
				Ok(r) => r,
				Err(LookupError::Transient) if !day_too_old => {
					// Transient DNS error, day is still recent: retry next pass.
					tracing::debug!(%from_domain, day, "DMARC record lookup failed; retrying next pass");
					continue;
				}
				Err(_) => {
					// No rua= or permanently-broken record, or the day has aged
					// past the cap: drop the file. We do not re-attempt old data
					// forever; RFC 7489 gives the receiver ~7 days to report.
					to_remove.push(path);
					continue;
				}
			};

			let (period_start, period_end) = day_period(&day);
			let reporting = sender.reporting_domain;
			let report_id = format!("{reporting}.{from_domain}.{period_start}");
			let gz = build_xml(
				sender.org_name,
				sender.org_email,
				&report_id,
				period_start,
				period_end,
				&from_domain,
				&records,
			);

			for uri in &rua {
				let Some(to_addr) = report_address(uri) else {
					tracing::debug!(policy_domain = %from_domain, %uri, "DMARC rua= is not a usable mailto: address; skipping");
					continue;
				};
				// RFC 7489 §7.1: when the rua= domain is not the policy
				// domain (or a subdomain sharing its organizational
				// domain), only send if the policy domain authorizes the
				// destination via
				// `<policy domain>._report._dmarc.<rua domain>`.
				if !authorized_external(&from_domain, to_addr, sender.dns).await {
					tracing::debug!(
						policy_domain = %from_domain,
						rua = %to_addr,
						"DMARC external destination not authorized; skipping"
					);
					continue;
				}
				let email_bytes = build_email(
					&from_domain,
					to_addr,
					&report_id,
					period_start,
					period_end,
					reporting,
					reporting,
					sender.now,
					&gz,
					sender.auto_submitted,
				);
				let message = AcceptedMessage {
					reverse_path: format!("postmaster@{reporting}"),
					recipients: vec![to_addr.to_string()],
					data: crate::util::header_block::frame_generated(email_bytes),
					require_tls: false,
					mailbox: None,
					tlsrpt_verified: false,
					sender_verified: false,
					no_dsn: Vec::new(),
				};
				if let Err(error) = sender.sink.deliver(message) {
					tracing::warn!(%error, %from_domain, "DMARC report not queued");
				}
			}
			to_remove.push(path);
		}

		// Remove processed files.
		for path in to_remove {
			let _ = std::fs::remove_file(&path);
		}
		// Remove empty day directory (if every domain was processed).
		let _ = std::fs::remove_dir(&day_dir);
	}
}

enum LookupError {
	/// The lookup did not return a usable `rua=` (no record, no `rua=` tag,
	/// record that is not a `v=DMARC1` policy, or a malformed record).
	Permanent,
	/// A transient DNS error; retrying later may succeed.
	Transient,
}

/// Return the `rua=` list of the domain's `_dmarc` record.
async fn lookup_rua(dns: &dyn DnsLookup, domain: &str) -> Result<Vec<String>, LookupError> {
	let txt = format!("_dmarc.{domain}");
	let records = match dns.txt(&txt).await {
		Ok(records) => records,
		Err(DnsFailure::Temporary) => return Err(LookupError::Transient),
	};
	for record in &records {
		match super::record::parse(record) {
			Some(Ok(dmarc)) if !dmarc.rua.is_empty() => return Ok(dmarc.rua),
			Some(Ok(_)) => continue,
			Some(Err(())) => continue,
			None => continue,
		}
	}
	Err(LookupError::Permanent)
}

/// The mailbox of a `mailto:` `rua=` URI, or `None` when it is not a plain
/// `local@domain` address. The URI comes from a TXT record the sending
/// domain controls and ends up in the `To:` header of a message we sign,
/// so anything that could break out of that header (CR, LF, spaces,
/// commas, angle brackets, quotes) is refused rather than escaped.
pub(crate) fn report_address(uri: &str) -> Option<&str> {
	let mailbox = uri.strip_prefix("mailto:")?.split('?').next()?;
	let (local, domain) = mailbox.split_once('@')?;
	let plain = |part: &str| {
		!part.is_empty()
			&& part
				.bytes()
				.all(|byte| byte.is_ascii_graphic() && !b"@<>,;:\\\"()[]".contains(&byte))
	};
	(plain(local) && plain(domain) && mailbox.len() <= 254).then_some(mailbox)
}

/// RFC 7489 §7.1: an `rua=` is authorized to receive reports for
/// `policy_domain` when the local-part is not interesting and either:
///
/// - the `rua` domain matches the policy domain (case-insensitive), or
/// - the `rua` domain is a subdomain of the same organizational domain as
///   the policy domain, or
/// - the policy domain publishes a TXT record at
///   `<policy>._report._dmarc.<rua domain>` whose value starts with
///   `v=DMARC1`.
///
/// The authorization record is published by the receiving domain. A
/// transient DNS failure means we do not send: without the record we cannot
/// tell an authorized collector from a third party.
async fn authorized_external(policy_domain: &str, to_address: &str, dns: &dyn DnsLookup) -> bool {
	let Some((_, rua_domain)) = to_address.rsplit_once('@') else {
		return false;
	};
	let rua_domain = rua_domain.to_ascii_lowercase();
	let policy_domain = policy_domain.to_ascii_lowercase();

	if rua_domain == policy_domain {
		return true;
	}
	if rua_domain.ends_with(&format!(".{policy_domain}")) {
		return true;
	}
	let policy_org = super::evaluate::organizational_domain(&policy_domain);
	if super::evaluate::organizational_domain(&rua_domain) == policy_org {
		return true;
	}
	let probe = format!("{policy_domain}._report._dmarc.{rua_domain}");
	let records = match dns.txt(&probe).await {
		Ok(records) => records,
		Err(DnsFailure::Temporary) => return false,
	};
	records.iter().any(|record| {
		record
			.trim_start()
			.to_ascii_lowercase()
			.starts_with("v=dmarc1")
	})
}

/// True when `day` is more than [`MAX_AGE_DAYS`] before `today`.
/// Returns `false` for unparseable days so the day is not dropped on a
/// date-formatting glitch.
fn is_older_than_cap(today: &str, day: &str) -> bool {
	let Some(today_secs) = day_to_unix(today) else {
		return false;
	};
	let Some(day_secs) = day_to_unix(day) else {
		return false;
	};
	today_secs.saturating_sub(day_secs) > MAX_AGE_DAYS * 86_400
}

fn day_to_unix(day: &str) -> Option<u64> {
	if day.len() != 8 || !day.bytes().all(|b| b.is_ascii_digit()) {
		return None;
	}
	let y: u64 = day[..4].parse().ok()?;
	let m: u64 = day[4..6].parse().ok()?;
	let d: u64 = day[6..8].parse().ok()?;
	let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
	let era = y / 400;
	let yoe = y - era * 400;
	let doy = (153 * m + 2) / 5 + d - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	Some((era * 146_097 + doe).wrapping_sub(719_468) * 86_400)
}

fn record_path(dir: &Path, domain: &str) -> PathBuf {
	// Sanitize domain for use as a filename: keep alnum, dots, hyphens.
	let safe: String = domain
		.chars()
		.map(|c| {
			if c.is_alphanumeric() || c == '.' || c == '-' {
				c
			} else {
				'_'
			}
		})
		.collect();
	dir.join(format!("{safe}.jsonl"))
}

fn read_records(path: &Path) -> Vec<DeliveryRecord> {
	let Ok(file) = std::fs::File::open(path) else {
		return Vec::new();
	};
	std::io::BufReader::new(file)
		.lines()
		.map_while(Result::ok)
		.filter(|l| !l.is_empty())
		.filter_map(|l| serde_json::from_str::<DeliveryRecord>(&l).ok())
		.collect()
}

/// Convert a `"YYYYMMDD"` day string to a (period_start, period_end) in Unix seconds.
fn day_period(day: &str) -> (u64, u64) {
	let start = day_to_unix(day).unwrap_or(0);
	(start, start + 86_400)
}

/// Return today's date as `"YYYYMMDD"` using the given Unix timestamp.
pub fn unix_to_day(ts: u64) -> String {
	// Reverse Hinnant: days since epoch → Gregorian.
	let days = ts / 86400;
	let z = days.wrapping_add(719468);
	let era = z / 146097;
	let doe = z - era * 146097;
	let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	let y = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	let y = if m <= 2 { y + 1 } else { y };
	format!("{y:04}{m:02}{d:02}")
}

#[cfg(test)]
mod tests;
