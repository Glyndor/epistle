//! `mail report-abuse`: read an offending message on stdin and emit an RFC 5965
//! Abuse Reporting Format (ARF) report — `multipart/report;
//! report-type=feedback-report` with the human-readable note, the structured
//! `message/feedback-report`, and the original message. The operator sends the
//! emitted report to the offending sender's abuse address.

use std::io::Read;
use std::process::ExitCode;
use std::time::SystemTime;

use crate::config::Config;

/// Build an ARF report for the message read from `input` and write it to `out`.
pub(super) fn run(
	config: &Config,
	mut input: impl Read,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let mut message = Vec::new();
	if input.read_to_end(&mut message).is_err() {
		eprintln!("error: reading the offending message from stdin");
		return ExitCode::FAILURE;
	}
	if message.is_empty() {
		eprintln!("error: no message on stdin");
		return ExitCode::FAILURE;
	}
	let report = build_report(config, &message);
	if out.write_all(report.as_bytes()).is_err()
		|| out.write_all(b"\r\n").is_err()
		|| out.write_all(&message).is_err()
		|| out
			.write_all(format!("\r\n--{}--\r\n", boundary(&message)).as_bytes())
			.is_err()
	{
		eprintln!("error: writing report");
		return ExitCode::FAILURE;
	}
	ExitCode::SUCCESS
}

/// The MIME boundary, derived from the message so it cannot appear inside it.
fn boundary(message: &[u8]) -> String {
	let digest = ring::digest::digest(&ring::digest::SHA256, message);
	let hex: String = digest.as_ref()[..8]
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect();
	format!("epistle-arf-{hex}")
}

/// Build everything up to (and including) the `message/rfc822` part header; the
/// caller appends the original message and the closing boundary.
fn build_report(config: &Config, message: &[u8]) -> String {
	let headers = String::from_utf8_lossy(message);
	let boundary = boundary(message);
	let date = crate::clock::rfc5322(SystemTime::now());
	let host = &config.hostname;
	let mail_from = header(&headers, "return-path")
		.or_else(|| header(&headers, "from"))
		.unwrap_or_else(|| "unknown".to_string());
	let arrival = header(&headers, "date").unwrap_or_else(|| date.clone());
	let source_ip = received_ip(&headers);
	let version = env!("CARGO_PKG_VERSION");

	let mut feedback = format!(
		"Feedback-Type: abuse\r\nUser-Agent: epistle/{version}\r\nVersion: 1\r\n\
		 Original-Mail-From: {mail_from}\r\nArrival-Date: {arrival}\r\n"
	);
	if let Some(ip) = source_ip {
		feedback.push_str(&format!("Source-IP: {ip}\r\n"));
	}

	format!(
		"From: abuse@{host}\r\nDate: {date}\r\nSubject: Abuse report\r\n\
		 MIME-Version: 1.0\r\n\
		 Content-Type: multipart/report; report-type=feedback-report; boundary=\"{boundary}\"\r\n\
		 \r\n\
		 --{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
		 This is an abuse report for a message received from {mail_from}.\r\n\
		 \r\n\
		 --{boundary}\r\nContent-Type: message/feedback-report\r\n\r\n{feedback}\r\n\
		 --{boundary}\r\nContent-Type: message/rfc822\r\n\r\n"
	)
}

/// First value of header `name` (case-insensitive), reading only the header
/// block (up to the blank line). Folded continuations are ignored.
fn header(message: &str, name: &str) -> Option<String> {
	let prefix = format!("{name}:");
	for line in message.lines() {
		if line.is_empty() {
			break;
		}
		if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(&prefix) {
			return Some(line[prefix.len()..].trim().to_string());
		}
	}
	None
}

/// Best-effort extraction of the connecting client's IP from the first
/// `Received` header's `[1.2.3.4]` / `[IPv6:…]` token.
fn received_ip(message: &str) -> Option<String> {
	let received = header(message, "received")?;
	let start = received.find('[')? + 1;
	let end = received[start..].find(']')? + start;
	let token = &received[start..end];
	let ip = token.strip_prefix("IPv6:").unwrap_or(token);
	Some(ip.to_string())
}

#[cfg(test)]
#[path = "report_abuse_tests.rs"]
mod tests;
