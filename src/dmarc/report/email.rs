//! The MIME message that carries a DMARC aggregate report.
//!
//! Pulled out of `mod.rs` so the module that builds the report XML and the
//! one that wraps it in a message stay apart: this is the part that writes
//! headers, and a header is where a bad value escapes into the wire.

/// Build the MIME email carrying the report as a gzip attachment.
/// Returns raw RFC 5322 bytes ready for [`crate::smtp::sink::MessageSink`].
/// `from_address` is the `From:` (`[queue] dmarc_report_from`, already a
/// plain mailbox: the configuration refuses anything else).
/// `reporting_hostname` is the host part of the `Message-ID:` (RFC 7489
/// §7.2.1.1 wants a unique `Message-ID` in the reporting hostname), and
/// `now` is the `Date:` value. `auto_submitted` writes
/// `Auto-Submitted: auto-generated`, as RFC 3834 section 5 asks of a
/// machine-generated report; `false` leaves the field out (the
/// `system_auto_submitted` switch).
#[allow(clippy::too_many_arguments)]
pub fn build_email(
	from_address: &str,
	from_domain: &str,
	to_address: &str,
	report_id: &str,
	period_start: u64,
	period_end: u64,
	reporting_domain: &str,
	reporting_hostname: &str,
	now: std::time::SystemTime,
	attachment: &[u8],
	auto_submitted: bool,
) -> Vec<u8> {
	use base64::Engine;
	let b64 = base64::engine::general_purpose::STANDARD.encode(attachment);
	let filename = format!("{reporting_domain}!{from_domain}!{period_start}!{period_end}.xml.gz");
	let boundary = format!("report-boundary-{report_id}");
	let mut email = String::with_capacity(512 + b64.len());

	email.push_str(&format!("Date: {}\r\n", crate::clock::rfc5322(now)));
	email.push_str(&format!(
		"Message-ID: <{report_id}@{reporting_hostname}>\r\n"
	));
	email.push_str(&format!("From: {from_address}\r\n"));
	email.push_str(&format!("To: {to_address}\r\n"));
	email.push_str(&format!(
		"Subject: Report Domain: {from_domain} Submitter: {reporting_domain} Report-ID: <{report_id}>\r\n"
	));
	if auto_submitted {
		email.push_str("Auto-Submitted: auto-generated\r\n");
	}
	email.push_str("MIME-Version: 1.0\r\n");
	email.push_str(&format!(
		"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
	));
	email.push_str("\r\n");
	email.push_str(&format!("--{boundary}\r\n"));
	email.push_str("Content-Type: text/plain\r\n\r\n");
	email.push_str(&format!(
		"This is a DMARC aggregate report for {from_domain}.\r\n"
	));
	email.push_str("\r\n");
	email.push_str(&format!("--{boundary}\r\n"));
	email.push_str(&format!(
		"Content-Type: application/gzip; name=\"{filename}\"\r\n"
	));
	email.push_str("Content-Transfer-Encoding: base64\r\n");
	email.push_str(&format!(
		"Content-Disposition: attachment; filename=\"{filename}\"\r\n"
	));
	email.push_str("\r\n");
	// Fold base64 at 76 chars per RFC 2045.
	for chunk in b64.as_bytes().chunks(76) {
		email.push_str(std::str::from_utf8(chunk).unwrap_or(""));
		email.push_str("\r\n");
	}
	email.push_str(&format!("\r\n--{boundary}--\r\n"));
	email.into_bytes()
}
