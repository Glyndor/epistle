use super::*;

#[test]
fn three_rows_over_the_limit_keep_the_prefix() {
	let report = parse(report_with_empty_records(MAX_ROWS + 3).as_bytes()).expect("overflow kept");
	assert_eq!(report.records.len(), MAX_ROWS);
	assert!(report.truncated);
}

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

/// More than 10 000 rows is truncated and the JSONL marker is set. The
/// first MAX_ROWS survive, the rest are dropped, and the document still
/// parses so a hostile bulk report cannot deny a small legitimate one.
#[test]
fn more_than_10000_rows_is_truncated_and_marked() {
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
			 \x20\x20\x20\x20</record>\n"
		));
	}
	xml.push_str("</feedback>\n");
	let report = parse(xml.as_bytes()).expect("truncated, not refused");
	assert_eq!(report.records.len(), MAX_ROWS);
	assert!(report.truncated);
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

/// One report whose metadata and single record are filled by the caller.
fn report_with(org: &str, report_id: &str, source_ip: &str, header_from: &str) -> String {
	format!(
		"<feedback><report_metadata><org_name>{org}</org_name>\
		 <email>{org}</email><report_id>{report_id}</report_id></report_metadata>\
		 <policy_published><domain>{header_from}</domain><p>{source_ip}</p>\
		 <sp>{source_ip}</sp></policy_published>\
		 <record><row><source_ip>{source_ip}</source_ip><count>1</count>\
		 <policy_evaluated><disposition>{source_ip}</disposition><dkim>{source_ip}</dkim>\
		 <spf>{source_ip}</spf></policy_evaluated></row>\
		 <identifiers><header_from>{header_from}</header_from></identifiers></record>\
		 </feedback>"
	)
}

#[test]
fn fields_at_their_limits_are_stored_whole() {
	let text = "t".repeat(MAX_TEXT);
	let keyword = "k".repeat(MAX_KEYWORD);
	let report = parse(report_with(&text, &text, &keyword, &text).as_bytes()).expect("parses");
	assert_eq!(report.org_name, text);
	assert_eq!(report.email.as_deref(), Some(text.as_str()));
	assert_eq!(report.report_id, text);
	assert_eq!(report.policy_published.domain, text);
	assert_eq!(report.policy_published.p, keyword);
	assert_eq!(
		report.policy_published.sp.as_deref(),
		Some(keyword.as_str())
	);
	let row = &report.records[0];
	assert_eq!(row.source_ip, keyword);
	assert_eq!(row.disposition, keyword);
	assert_eq!(row.dkim, keyword);
	assert_eq!(row.spf, keyword);
	assert_eq!(row.header_from, text);
}

#[test]
fn fields_over_their_limits_are_cut() {
	let text = "t".repeat(MAX_TEXT + 1);
	let keyword = "k".repeat(MAX_KEYWORD + 1);
	let report = parse(report_with(&text, &text, &keyword, &text).as_bytes()).expect("parses");
	let text_lengths = [
		report.org_name.len(),
		report.email.as_deref().map_or(0, str::len),
		report.report_id.len(),
		report.policy_published.domain.len(),
		report.records[0].header_from.len(),
	];
	assert_eq!(text_lengths, [MAX_TEXT; 5]);
	let row = &report.records[0];
	let keyword_lengths = [
		report.policy_published.p.len(),
		report.policy_published.sp.as_deref().map_or(0, str::len),
		row.source_ip.len(),
		row.disposition.len(),
		row.dkim.len(),
		row.spf.len(),
	];
	assert_eq!(keyword_lengths, [MAX_KEYWORD; 6]);
}

fn report_with_empty_records(records: usize) -> String {
	let mut xml = String::from("<feedback>");
	for _ in 0..records {
		xml.push_str("<record/>");
	}
	xml.push_str("</feedback>");
	xml
}

#[test]
fn exactly_the_row_limit_is_accepted() {
	let report = parse(report_with_empty_records(MAX_ROWS).as_bytes()).expect("at the cap");
	assert_eq!(report.records.len(), MAX_ROWS);
}

#[test]
fn one_row_over_the_limit_is_truncated_and_marked() {
	let report = parse(report_with_empty_records(MAX_ROWS + 1).as_bytes()).expect("kept");
	assert_eq!(report.records.len(), MAX_ROWS);
	assert!(report.truncated);
}

#[test]
fn at_the_row_limit_truncated_is_false() {
	let report = parse(report_with_empty_records(MAX_ROWS).as_bytes()).expect("kept");
	assert_eq!(report.records.len(), MAX_ROWS);
	assert!(!report.truncated);
}

/// The file name comes from the shared component mapping, so a hostile
/// `org_name` still lands inside the day directory.
#[test]
fn a_hostile_org_name_stays_inside_the_day_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut report = parse(GOOGLE_SHAPED.as_bytes()).expect("parses");
	report.org_name = "../../../escape/..".into();
	append(dir.path(), "20240101", &report).expect("append");
	let day_dir = dir.path().join("reports").join("dmarc").join("20240101");
	let written: Vec<_> = std::fs::read_dir(&day_dir)
		.expect("day dir")
		.map(|entry| entry.expect("entry").path())
		.collect();
	assert_eq!(written.len(), 1, "{written:?}");
	assert_eq!(written[0].parent(), Some(day_dir.as_path()));
	assert_eq!(
		written[0].file_name().and_then(|name| name.to_str()),
		Some(".._.._.._escape_...jsonl")
	);
	assert!(!dir.path().join("escape").exists());
	// The record itself keeps the name the sender wrote.
	let line = std::fs::read_to_string(&written[0]).expect("read");
	let stored: DmarcReport = serde_json::from_str(line.trim()).expect("json");
	assert_eq!(stored.org_name, "../../../escape/..");
}

#[test]
fn a_failing_count_near_the_integer_limit_saturates() {
	let mut report = parse(GOOGLE_SHAPED.as_bytes()).expect("parses");
	for row in &mut report.records {
		row.count = u64::MAX;
		row.disposition = "reject".into();
	}
	assert_eq!(report.failing_count(), u64::MAX);
}

/// A DMARC aggregate with a `<!DOCTYPE>` declaring an internal entity
/// and the entity referenced inside the body must not expand the
/// reference. quick-xml 0.42 ships a `PredefinedEntityResolver` that
/// only resolves the five XML predefined entities (`lt`, `gt`, `amp`,
/// `apos`, `quot`); the resolver ignores `<!ENTITY>` declarations in
/// the DOCTYPE, so any reference the deserialiser hits comes back as
/// `EscapeError::UnrecognizedEntity`. The error short-circuits the
/// parse into our `ParseError::Invalid`, which means the report is
/// dropped and counted, never expanded into the billion-laughs bomb
/// the entity chain (`&outer;` -> `&inner;&inner;&inner;&inner;`)
/// would have produced.
#[test]
fn a_dmarc_xml_with_internal_entities_does_not_expand_them() {
	let xml = r#"<?xml version="1.0"?>
<!DOCTYPE feedback [
  <!ENTITY inner "pwned">
  <!ENTITY outer "&inner;&inner;&inner;&inner;">
]>
<feedback>
  <report_metadata>
    <org_name>&outer;</org_name>
    <report_id>rid</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain>
    <p>none</p>
    <pct>100</pct>
  </policy_published>
  <record/>
</feedback>
"#;
	let err = parse(xml.as_bytes()).expect_err("unknown entity refused");
	let ParseError::Invalid(text) = &err;
	assert!(
		text.contains("unrecognized entity"),
		"unexpected error text: {text}"
	);
}
