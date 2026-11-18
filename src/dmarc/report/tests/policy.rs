//! `<policy_published>` quotes the record that was evaluated, in the
//! element order of RFC 7489 appendix C.

use super::*;

fn record(published_policy: &str, published_subdomain_policy: &str, pct: u8) -> DeliveryRecord {
	DeliveryRecord {
		timestamp: 1_700_000_000,
		source_ip: "192.0.2.1".to_string(),
		envelope_from: "example.org".to_string(),
		header_from: "example.org".to_string(),
		spf: "pass".to_string(),
		dkim: "pass".to_string(),
		dkim_domain: "example.org".to_string(),
		dmarc: "pass".to_string(),
		disposition: "none".to_string(),
		policy_domain: "example.org".to_string(),
		published_policy: published_policy.to_string(),
		published_subdomain_policy: published_subdomain_policy.to_string(),
		pct,
	}
}

fn policy_published(records: &[DeliveryRecord]) -> String {
	let xml = generate_xml("Org", "e@o.example", "r", 0, 86400, "example.org", records);
	let start = xml
		.find("  <policy_published>\n")
		.expect("policy_published");
	let end = xml.find("  </policy_published>\n").expect("end") + "  </policy_published>\n".len();
	xml[start..end].to_string()
}

#[test]
fn the_published_p_sp_and_pct_are_quoted() {
	assert_eq!(
		policy_published(&[record("quarantine", "reject", 42)]),
		"  <policy_published>\n    <domain>example.org</domain>\n    <p>quarantine</p>\n    \
		 <sp>reject</sp>\n    <pct>42</pct>\n  </policy_published>\n"
	);
}

#[test]
fn the_first_record_that_carries_a_policy_is_quoted() {
	let block = policy_published(&[record("", "", 100), record("reject", "none", 30)]);
	assert!(block.contains("<p>reject</p>"), "{block}");
	assert!(block.contains("<sp>none</sp>"), "{block}");
	assert!(block.contains("<pct>30</pct>"), "{block}");
}

#[test]
fn without_any_published_policy_the_rfc_defaults_stand() {
	let block = policy_published(&[record("", "", 100)]);
	assert!(block.contains("<p>none</p>"), "{block}");
	assert!(block.contains("<sp>none</sp>"), "{block}");
	assert!(block.contains("<pct>100</pct>"), "{block}");
}

#[test]
fn a_journal_line_written_before_sp_was_kept_falls_back_to_p() {
	// The shape a journal had before `published_subdomain_policy` existed:
	// a day recorded by the previous version is still read and reported.
	let line = r#"{"timestamp":1700000000,"source_ip":"192.0.2.1","envelope_from":"example.org","header_from":"example.org","spf":"pass","dkim":"pass","dkim_domain":"example.org","dmarc":"pass","disposition":"none","policy_domain":"example.org","published_policy":"reject","pct":60}"#;
	let old: DeliveryRecord = serde_json::from_str(line).expect("old journal line");
	assert_eq!(old.published_subdomain_policy, "");
	let block = policy_published(&[old]);
	assert!(block.contains("<p>reject</p>"), "{block}");
	assert!(block.contains("<sp>reject</sp>"), "{block}");
	assert!(block.contains("<pct>60</pct>"), "{block}");
}
