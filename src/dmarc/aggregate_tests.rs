use super::*;
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

use crate::smtp::sink::MemorySink;

#[derive(Default)]
struct FakeDns {
	txt: HashMap<String, Vec<String>>,
	fail: bool,
	fail_names: Vec<String>,
}

impl crate::spf::DnsLookup for FakeDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>> {
		let result = if self.fail || self.fail_names.iter().any(|failing| failing == name) {
			Err(crate::spf::DnsFailure::Temporary)
		} else {
			Ok(self.txt.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, crate::spf::DnsFailure>> + Send + '_>> {
		Box::pin(async move { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>> {
		Box::pin(async move { Ok(Vec::new()) })
	}
}

fn dns_with_dmarc(domain: &str, policy: &str) -> FakeDns {
	let mut dns = FakeDns::default();
	dns.txt
		.entry(format!("_dmarc.{domain}"))
		.or_default()
		.push(format!("v=DMARC1; p={policy}; rua=mailto:dmarc@{domain}"));
	dns
}

fn sample_record(domain: &str) -> DeliveryRecord {
	DeliveryRecord {
		timestamp: 1_700_000_000,
		source_ip: "1.2.3.4".to_string(),
		envelope_from: domain.to_string(),
		header_from: domain.to_string(),
		spf: "pass".to_string(),
		dkim: "pass".to_string(),
		dkim_domain: domain.to_string(),
		dmarc: "pass".to_string(),
		disposition: "none".to_string(),
		policy_domain: domain.to_string(),
		published_policy: "reject".to_string(),
		pct: 100,
	}
}

fn fixed_now() -> std::time::SystemTime {
	std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
}

fn build_sender<'a>(
	data_dir: &'a std::path::Path,
	dns: &'a dyn crate::spf::DnsLookup,
	sink: &'a dyn MessageSink,
) -> Sender<'a> {
	Sender {
		data_dir,
		org_name: "Org",
		org_email: "admin@org.example",
		reporting_domain: "mail.reporter.example",
		dns,
		sink,
		now: fixed_now(),
		auto_submitted: true,
	}
}

#[test]
fn unix_to_day_known_dates() {
	// 2024-01-01 00:00:00 UTC = 1704067200
	assert_eq!(unix_to_day(1_704_067_200), "20240101");
	// 2024-02-29 00:00:00 UTC = 1709164800 (leap day)
	assert_eq!(unix_to_day(1_709_164_800), "20240229");
	// 2024-12-31 23:59:59 → still 20241231
	assert_eq!(unix_to_day(1_735_689_599), "20241231");
}

#[test]
fn day_period_round_trips() {
	let day = "20240101";
	let (start, end) = day_period(day);
	assert_eq!(end - start, 86400);
	assert_eq!(unix_to_day(start), day);
	assert_eq!(unix_to_day(end - 1), day);
}

#[test]
fn record_path_sanitizes_domain() {
	let dir = std::path::Path::new("/tmp");
	let path = record_path(dir, "example.org");
	assert_eq!(
		path.file_name().unwrap().to_str().unwrap(),
		"example.org.jsonl"
	);
	let path = record_path(dir, "bad/domain");
	let filename = path.file_name().unwrap().to_str().unwrap();
	assert!(!filename.contains('/'), "{filename}");
}

#[test]
fn record_and_read_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = DeliveryRecord {
		timestamp: 1_700_000_000,
		source_ip: "1.2.3.4".to_string(),
		envelope_from: "example.org".to_string(),
		header_from: "example.org".to_string(),
		spf: "pass".to_string(),
		dkim: "pass".to_string(),
		dkim_domain: "example.org".to_string(),
		dmarc: "pass".to_string(),
		disposition: "none".to_string(),
		policy_domain: "example.org".to_string(),
		published_policy: "reject".to_string(),
		pct: 100,
	};
	record_delivery(dir.path(), "20240101", &record);
	let path = dir
		.path()
		.join("dmarc-reports")
		.join("20240101")
		.join("example.org.jsonl");
	let records = read_records(&path);
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].source_ip, "1.2.3.4");
}

#[tokio::test]
async fn flush_pending_delivers_to_sink_and_removes_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = sample_record("example.org");
	record_delivery(dir.path(), "20240101", &record);

	let dns = dns_with_dmarc("example.org", "reject");
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;

	let messages = sink.messages();
	assert_eq!(messages.len(), 1, "one message per mailto rua");
	assert_eq!(messages[0].recipients, ["dmarc@example.org"]);
	assert_eq!(messages[0].reverse_path, "postmaster@mail.reporter.example");
	assert!(!messages[0].data.is_empty());

	let jsonl = dir
		.path()
		.join("dmarc-reports")
		.join("20240101")
		.join("example.org.jsonl");
	assert!(!jsonl.exists(), "JSONL must be removed after flush");
}

#[tokio::test]
async fn flush_pending_skips_today_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = sample_record("example.org");
	record_delivery(dir.path(), "20240101", &record);

	// Pass today = same day as the record directory.
	let dns = dns_with_dmarc("example.org", "reject");
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240101").await;

	assert!(
		sink.messages().is_empty(),
		"today's directory must not be flushed"
	);
	let jsonl = dir
		.path()
		.join("dmarc-reports")
		.join("20240101")
		.join("example.org.jsonl");
	assert!(jsonl.exists(), "file must remain when directory is skipped");
}

#[tokio::test]
async fn flush_pending_no_rua_removes_file_without_sending() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = sample_record("example.org");
	record_delivery(dir.path(), "20240101", &record);

	// DNS returns no DMARC record at all.
	let dns = FakeDns::default();
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;

	assert!(
		sink.messages().is_empty(),
		"no rua= must produce no messages"
	);
	let jsonl = dir
		.path()
		.join("dmarc-reports")
		.join("20240101")
		.join("example.org.jsonl");
	assert!(
		!jsonl.exists(),
		"file must still be removed when rua= absent"
	);
}

#[tokio::test]
async fn flush_pending_empty_records_removes_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let day_dir = dir.path().join("dmarc-reports").join("20240101");
	std::fs::create_dir_all(&day_dir).expect("mkdir");
	std::fs::write(day_dir.join("example.org.jsonl"), b"").expect("write");

	let dns = dns_with_dmarc("example.org", "reject");
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;

	assert!(sink.messages().is_empty());
	assert!(!day_dir.join("example.org.jsonl").exists());
}

#[tokio::test]
async fn flush_pending_empty_root_returns_empty() {
	let dir = tempfile::tempdir().expect("tempdir");
	// No dmarc-reports directory at all.
	let dns = dns_with_dmarc("example.org", "reject");
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn flush_pending_dns_failure_keeps_recent_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = sample_record("example.org");
	record_delivery(dir.path(), "20240101", &record);

	// DNS fails: the recent day is kept for the next pass.
	let dns = FakeDns {
		fail: true,
		..FakeDns::default()
	};
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;

	assert!(
		sink.messages().is_empty(),
		"DNS failure must produce no messages"
	);
	let jsonl = dir
		.path()
		.join("dmarc-reports")
		.join("20240101")
		.join("example.org.jsonl");
	assert!(jsonl.exists(), "recent file must be kept on DNS failure");
}

#[tokio::test]
async fn flush_pending_dns_failure_drops_old_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Eight full days old (today = 20240109, record day = 20240101).
	let record = sample_record("example.org");
	record_delivery(dir.path(), "20240101", &record);

	let dns = FakeDns {
		fail: true,
		..FakeDns::default()
	};
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240109").await;

	assert!(sink.messages().is_empty());
	let jsonl = dir
		.path()
		.join("dmarc-reports")
		.join("20240101")
		.join("example.org.jsonl");
	assert!(
		!jsonl.exists(),
		"8-day-old file must be dropped even on DNS failure"
	);
}

#[tokio::test]
async fn flush_pending_same_domain_rua_sends_without_external_check() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = sample_record("example.org");
	record_delivery(dir.path(), "20240101", &record);

	// Same-domain rua, no authorization TXT present.
	let dns = dns_with_dmarc("example.org", "reject");
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;

	assert_eq!(sink.messages().len(), 1, "same-domain rua must send");
}

#[tokio::test]
async fn flush_pending_external_rua_sends_when_authorized() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = sample_record("victim.example");
	record_delivery(dir.path(), "20240101", &record);

	let mut dns = FakeDns::default();
	dns.txt
		.entry("_dmarc.victim.example".to_string())
		.or_default()
		.push("v=DMARC1; p=reject; rua=mailto:agg@collector.example".to_string());
	// The authorization record lives at victim.example._report._dmarc.collector.example.
	dns.txt
		.entry("victim.example._report._dmarc.collector.example".to_string())
		.or_default()
		.push("v=DMARC1".to_string());
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;

	assert_eq!(
		sink.messages().len(),
		1,
		"external rua with the authorization TXT must send"
	);
	assert_eq!(sink.messages()[0].recipients, ["agg@collector.example"]);
}

#[tokio::test]
async fn flush_pending_external_rua_skipped_when_unauthorized() {
	let dir = tempfile::tempdir().expect("tempdir");
	let record = sample_record("victim.example");
	record_delivery(dir.path(), "20240101", &record);

	let mut dns = FakeDns::default();
	dns.txt
		.entry("_dmarc.victim.example".to_string())
		.or_default()
		.push("v=DMARC1; p=reject; rua=mailto:agg@collector.example".to_string());
	// No authorization record under victim.example._report._dmarc.collector.example.
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;

	assert!(
		sink.messages().is_empty(),
		"external rua without authorization TXT must not send"
	);
}

#[tokio::test]
async fn flush_pending_external_rua_skipped_when_the_authorization_lookup_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	record_delivery(dir.path(), "20240101", &sample_record("victim.example"));

	let mut dns = FakeDns::default();
	dns.txt
		.entry("_dmarc.victim.example".to_string())
		.or_default()
		.push("v=DMARC1; p=reject; rua=mailto:agg@collector.example".to_string());
	dns.fail_names
		.push("victim.example._report._dmarc.collector.example".to_string());
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;

	assert!(
		sink.messages().is_empty(),
		"an external rua whose authorization cannot be looked up must not be sent"
	);
}

#[tokio::test]
async fn flush_pending_refuses_a_rua_that_would_inject_headers() {
	let dir = tempfile::tempdir().expect("tempdir");
	record_delivery(dir.path(), "20240101", &sample_record("evil.example"));

	let mut dns = FakeDns::default();
	dns.txt.entry("_dmarc.evil.example".to_string()).or_default().push(
		"v=DMARC1; p=reject; rua=mailto:a@evil.example\r\nBcc: victim@other.example,mailto:b c@evil.example,mailto:ok@evil.example"
			.to_string(),
	);
	let sink = MemorySink::new();
	let sender = build_sender(dir.path(), &dns, &sink);
	flush_pending(&sender, "20240102").await;

	let messages = sink.messages();
	assert_eq!(messages.len(), 1, "only the plain address may be sent to");
	assert_eq!(messages[0].recipients, ["ok@evil.example"]);
	let data = String::from_utf8_lossy(&messages[0].data);
	assert!(!data.contains("Bcc:"), "no injected header: {data}");
}

#[test]
fn report_address_accepts_only_plain_mailboxes() {
	assert_eq!(
		report_address("mailto:agg@example.org"),
		Some("agg@example.org")
	);
	assert_eq!(
		report_address("mailto:agg@example.org?subject=x"),
		Some("agg@example.org")
	);
	for bad in [
		"https://example.org/report",
		"mailto:",
		"mailto:noat",
		"mailto:@example.org",
		"mailto:a@",
		"mailto:a@b@example.org",
		"mailto:a\r\nBcc: x@y@example.org",
		"mailto:a b@example.org",
		"mailto:<a@example.org>",
		"mailto:a@example.org,b@example.org",
		"mailto:\"a\"@example.org",
	] {
		assert_eq!(report_address(bad), None, "{bad:?} must be refused");
	}
}

#[tokio::test]
async fn a_queued_report_is_framed() {
	let dir = tempfile::tempdir().expect("tempdir");
	record_delivery(dir.path(), "20240101", &sample_record("example.org"));
	let dns = dns_with_dmarc("example.org", "reject");
	let sink = MemorySink::new();
	let mut sender = build_sender(dir.path(), &dns, &sink);
	sender.reporting_domain = "mail\r.reporter\0.example";
	flush_pending(&sender, "20240102").await;
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	assert!(!crate::util::header_block::has_unframed_byte(
		&messages[0].data
	));
}
