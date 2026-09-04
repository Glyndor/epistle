use super::*;

/// A Google-shaped report: full metadata, published policy, two records
/// (one passing, one failing both SPF and DKIM).
const GOOGLE_SHAPED: &str = r#"<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>12345678901234567890</report_id>
    <date_range>
      <begin>1704067200</begin>
      <end>1704153600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>5</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.org</header_from>
    </identifiers>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.7</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.org</header_from>
    </identifiers>
  </record>
</feedback>
"#;

#[test]
fn parses_a_google_shaped_report() {
	let report = parse(GOOGLE_SHAPED.as_bytes()).expect("parses");
	assert_eq!(report.org_name, "google.com");
	assert_eq!(
		report.email.as_deref(),
		Some("noreply-dmarc-support@google.com")
	);
	assert_eq!(report.policy_published.domain, "example.org");
	assert_eq!(report.policy_published.p, "reject");
	assert_eq!(report.records.len(), 2);
	assert_eq!(report.records[0].source_ip, "209.85.220.41");
	assert_eq!(report.records[0].count, 5);
	assert_eq!(report.records[0].disposition, "none");
	assert_eq!(report.records[1].source_ip, "203.0.113.7");
	assert_eq!(report.records[1].disposition, "reject");
}

/// A document carrying an `extension` block the parser has never heard of.
/// RFC 7489 says to ignore unknown children; the parse must succeed.
#[test]
fn parses_a_report_with_unknown_elements() {
	let xml = r#"<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>example-reporter</org_name>
    <extra_metadata>ignored</extra_metadata>
    <report_id>rid-42</report_id>
    <date_range>
      <begin>1704067200</begin>
      <end>1704153600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain>
    <p>quarantine</p>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>198.51.100.4</source_ip>
      <count>2</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.org</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.org</domain>
        <result>pass</result>
      </dkim>
    </auth_results>
  </record>
  <extra_top_level>forward compatibility</extra_top_level>
</feedback>
"#;
	let report = parse(xml.as_bytes()).expect("unknown elements ignored");
	assert_eq!(report.org_name, "example-reporter");
	assert_eq!(report.report_id, "rid-42");
	assert_eq!(report.policy_published.p, "quarantine");
	assert_eq!(report.records.len(), 1);
}

/// More than 10 000 rows is refused. We synthesise 10 001 cheaply.
#[test]
fn more_than_10000_rows_is_refused() {
	let mut xml = String::from(
		r#"<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>spam</org_name>
    <report_id>big</report_id>
    <date_range>
      <begin>0</begin>
      <end>86400</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain>
    <p>none</p>
    <pct>100</pct>
  </policy_published>
"#,
	);
	for i in 0..10_001 {
		xml.push_str(&format!(
			"  <record>\n\
			 \x20\x20\x20\x20<row>\n\
			 \x20\x20\x20\x20\x20\x20\x20\x20<source_ip>1.2.3.{i}</source_ip>\n\
			 \x20\x20\x20\x20\x20\x20\x20\x20<count>1</count>\n\
			 \x20\x20\x20\x20\x20\x20\x20\x20<policy_evaluated>\n\
			 \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<disposition>none</disposition>\n\
			 \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<dkim>pass</dkim>\n\
			 \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<spf>pass</spf>\n\
			 \x20\x20\x20\x20\x20\x20\x20\x20</policy_evaluated>\n\
			 \x20\x20\x20\x20</row>\n\
			 \x20\x20\x20\x20<identifiers>\n\
			 \x20\x20\x20\x20\x20\x20\x20\x20<header_from>example.org</header_from>\n\
			 \x20\x20\x20\x20</identifiers>\n\
			 \x20\x20</record>\n"
		));
	}
	xml.push_str("</feedback>\n");
	let err = parse(xml.as_bytes()).expect_err("over the row cap");
	assert!(matches!(err, ParseError::TooManyRows), "{err:?}");
}

/// The failing-row counter sums by `count`, so a single reject row with
/// `count=10` contributes ten.
#[test]
fn failing_count_sums_by_count() {
	let report = parse(GOOGLE_SHAPED.as_bytes()).expect("parses");
	// 5 pass + 3 reject = 3 failing.
	assert_eq!(report.failing_count(), 3);
}

/// A row whose disposition is `none` but with both dkim and spf `fail`
/// must also count as failing (the receiver would have rejected had a
/// `reject` policy been in effect).
#[test]
fn failing_count_includes_both_auth_failures() {
	let xml = r#"<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>x</org_name>
    <report_id>r</report_id>
    <date_range>
      <begin>0</begin>
      <end>1</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>x.example</domain>
    <p>none</p>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>1.2.3.4</source_ip>
      <count>4</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>x.example</header_from>
    </identifiers>
  </record>
</feedback>
"#;
	let report = parse(xml.as_bytes()).expect("parses");
	assert_eq!(report.failing_count(), 4);
}

/// The filename under which the report is persisted is the sanitised org
/// name. An org with a `/` lands on disk as `_` to stay a single path
/// segment.
#[test]
fn org_filename_is_sanitised() {
	assert_eq!(sanitise_org("google.com"), "google.com");
	let sanitised = sanitise_org("with/slash");
	assert!(!sanitised.contains('/'), "{sanitised}");
}
