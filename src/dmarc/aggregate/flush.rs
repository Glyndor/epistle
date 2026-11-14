//! Sending the accumulated DMARC aggregate reports.
//!
//! Pulled out of `mod.rs` so the module stays under the per-file line
//! limit: this is the part of the aggregate report that talks to the
//! network (DNS lookups and the outbound mail path).

use std::path::PathBuf;

use crate::smtp::session::AcceptedMessage;

use super::super::report::{build_email, build_xml};
use super::{
	LookupError, Sender, authorized_external, day_period, is_older_than_cap, lookup_rua,
	report_address,
};

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

			let records = super::read_records(&path);
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
					sender.org_email,
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
