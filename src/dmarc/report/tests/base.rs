use super::*;

fn sample_records() -> Vec<DeliveryRecord> {
	vec![
		DeliveryRecord {
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
		},
		DeliveryRecord {
			timestamp: 1_700_000_100,
			source_ip: "5.6.7.8".to_string(),
			envelope_from: "attacker.example".to_string(),
			header_from: "example.org".to_string(),
			spf: "fail".to_string(),
			dkim: "fail".to_string(),
			dkim_domain: String::new(),
			dmarc: "fail".to_string(),
			disposition: "reject".to_string(),
			policy_domain: "example.org".to_string(),
			published_policy: "reject".to_string(),
			pct: 100,
		},
	]
}

#[test]
fn xml_contains_required_elements() {
	let records = sample_records();
	let xml = generate_xml(
		"Test Org",
		"dmarc@test.org",
		"report-1",
		1_700_000_000,
		1_700_086_400,
		"example.org",
		&records,
	);
	assert!(xml.contains("<feedback>"), "{xml}");
	assert!(xml.contains("<report_metadata>"), "{xml}");
	assert!(xml.contains("<policy_published>"), "{xml}");
	assert!(xml.contains("<record>"), "{xml}");
	assert!(xml.contains("1.2.3.4"), "{xml}");
	assert!(xml.contains("5.6.7.8"), "{xml}");
	assert!(xml.contains("<disposition>reject</disposition>"), "{xml}");
}

#[test]
fn build_xml_returns_valid_gzip() {
	use flate2::read::GzDecoder;
	use std::io::Read;
	let records = sample_records();
	let gz = build_xml(
		"Test Org",
		"dmarc@test.org",
		"report-2",
		1_700_000_000,
		1_700_086_400,
		"example.org",
		&records,
	);
	let mut decoder = GzDecoder::new(gz.as_slice());
	let mut xml = String::new();
	decoder.read_to_string(&mut xml).expect("valid gzip");
	assert!(xml.contains("<feedback>"), "{xml}");
}

#[test]
fn xml_escapes_special_characters() {
	assert_eq!(
		xml_escape("a&b<c>d\"e'f"),
		"a&amp;b&lt;c&gt;d&quot;e&apos;f"
	);
}

#[test]
fn build_email_has_correct_structure() {
	let attachment = build_xml(
		"Test Org",
		"dmarc@test.org",
		"r1",
		1_700_000_000,
		1_700_086_400,
		"example.org",
		&sample_records(),
	);
	let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
	let email = build_email(
		"sender.example",
		"reports@example.org",
		"r1",
		1_700_000_000,
		1_700_086_400,
		"example.org",
		"mail.reporter.example",
		now,
		&attachment,
		true,
	);
	let email_str = String::from_utf8_lossy(&email);
	assert!(
		email_str.contains("From: postmaster@example.org"),
		"{email_str}"
	);
	assert!(email_str.contains("To: reports@example.org"), "{email_str}");
	assert!(
		email_str.contains("Report Domain: sender.example"),
		"{email_str}"
	);
	assert!(email_str.contains("application/gzip"), "{email_str}");
	assert!(email_str.contains(".xml.gz"), "{email_str}");
	assert!(email_str.contains("Date: "), "{email_str}");
	assert!(
		email_str.contains("Message-ID: <r1@mail.reporter.example>"),
		"{email_str}"
	);
}

#[test]
fn records_with_same_ip_are_aggregated() {
	let mut records = sample_records();
	records.push(DeliveryRecord {
		source_ip: "1.2.3.4".to_string(),
		..records[0].clone()
	});
	let xml = generate_xml("Org", "e@o.org", "r", 0, 86400, "example.org", &records);
	// 1.2.3.4 should appear once with count 2.
	assert!(xml.contains("<count>2</count>"), "{xml}");
}
