use super::{log_absent, log_failure};
use crate::cli::trace::capture::run_with_capture;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::rr::RecordType;
use tracing::Level;

fn lines(events: &[crate::cli::trace::capture::CapturedEvent]) -> Vec<(Level, String)> {
	events
		.iter()
		.map(|event| (event.level, event.fields["message"].clone()))
		.collect()
}

#[test]
fn an_unsigned_zone_without_tlsa_is_one_debug_line() {
	let events = run_with_capture(|| log_absent("_25._tcp.mail.example.net", &[RecordType::SOA]));
	assert_eq!(
		lines(&events),
		[(
			Level::DEBUG,
			"no TLSA for _25._tcp.mail.example.net: zone is not signed (insecure)".to_string()
		)]
	);
}

#[test]
fn a_signed_zone_without_tlsa_says_so() {
	let events = run_with_capture(|| log_absent("_25._tcp.mail.example.net", &[RecordType::NSEC3]));
	let lines = lines(&events);
	assert_eq!(lines.len(), 1);
	assert_eq!(lines[0].0, Level::DEBUG);
	assert!(lines[0].1.contains("(secure)"), "{lines:?}");
}

#[test]
fn a_broken_signature_is_one_warn_with_the_name_and_the_reason() {
	let events = run_with_capture(|| {
		log_failure(
			"_25._tcp.mail.example.net",
			&NetError::Dns(DnsError::DnssecBogus),
		);
	});
	let lines = lines(&events);
	assert_eq!(lines.len(), 1, "{lines:?}");
	assert_eq!(lines[0].0, Level::WARN);
	assert!(
		lines[0].1.contains("_25._tcp.mail.example.net"),
		"{lines:?}"
	);
	assert!(lines[0].1.contains("DNSSEC validation failed"), "{lines:?}");
}

#[test]
fn another_failure_is_not_a_warning() {
	let events = run_with_capture(|| log_failure("_25._tcp.mail.example.net", &NetError::Timeout));
	let lines = lines(&events);
	assert_eq!(lines.len(), 1);
	assert_eq!(lines[0].0, Level::DEBUG);
}

#[test]
fn a_long_reason_is_cut() {
	let error = NetError::Msg("x".repeat(5000));
	let events = run_with_capture(|| log_failure("_25._tcp.mail.example.net", &error));
	let line = &lines(&events)[0].1;
	assert!(line.len() < 400, "{} bytes", line.len());
	assert!(line.ends_with("..."));
}
