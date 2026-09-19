use super::*;

const SAMPLE: &str = r#"{
  "organization-name": "google.com",
  "date-range": {
    "start-datetime": "2024-01-01T00:00:00Z",
    "end-datetime": "2024-01-02T00:00:00Z"
  },
  "contact-info": "tlsrpt@google.com",
  "report-id": "2024-01-01-2024-01-02-google.com",
  "policies": [
    {
      "policy-type": "sts",
      "policy-domain": "example.org",
      "summary": {
        "total-successful-session-count": 8,
        "total-failure-session-count": 2
      },
      "failure-details": [
        {
          "result-type": "starttls-not-supported",
          "sending-mta-ip": "192.0.2.10",
          "receiving-mx-hostname": "mx.example.org",
          "failed-session-count": 2
        }
      ]
    },
    {
      "policy-type": "no-policy-found",
      "policy-domain": "example.org",
      "summary": {
        "total-successful-session-count": 0,
        "total-failure-session-count": 0
      }
    }
  ]
}
"#;

#[test]
fn parses_a_tlsrpt_json() {
	let report = parse(SAMPLE.as_bytes()).expect("parses");
	assert_eq!(report.organization_name, "google.com");
	assert_eq!(report.date_range.start_datetime, "2024-01-01T00:00:00Z");
	assert_eq!(report.date_range.end_datetime, "2024-01-02T00:00:00Z");
	assert_eq!(report.contact_info.as_deref(), Some("tlsrpt@google.com"));
	assert_eq!(report.policies.len(), 2);
	assert_eq!(report.policies[0].policy_type, "sts");
	assert_eq!(report.policies[0].summary.total_successful_session_count, 8);
	assert_eq!(report.policies[0].summary.total_failure_session_count, 2);
	assert_eq!(report.policies[0].failure_details.len(), 1);
	assert_eq!(
		report.policies[0].failure_details[0].result_type,
		"starttls-not-supported"
	);
	assert_eq!(report.policies[1].failure_details.len(), 0);
}

/// `failed-session-count` summed across every failure-detail block is
/// what the metrics counter increments by. A report with two policies,
/// each with one failure-detail, contributes `2 + 3 = 5`.
#[test]
fn failing_count_sums_across_policies() {
	let json = r#"{
  "organization-name": "x",
  "date-range": {
    "start-datetime": "2024-01-01T00:00:00Z",
    "end-datetime": "2024-01-02T00:00:00Z"
  },
  "report-id": "r",
  "policies": [
    {
      "policy-type": "sts",
      "policy-domain": "example.org",
      "summary": {"total-successful-session-count": 0, "total-failure-session-count": 5},
      "failure-details": [
        {"result-type": "starttls-not-supported", "sending-mta-ip": "1.1.1.1", "receiving-mx-hostname": "mx", "failed-session-count": 2}
      ]
    },
    {
      "policy-type": "tlsa",
      "policy-domain": "example.org",
      "summary": {"total-successful-session-count": 0, "total-failure-session-count": 3},
      "failure-details": [
        {"result-type": "certificate-expired", "sending-mta-ip": "1.1.1.2", "receiving-mx-hostname": "mx2", "failed-session-count": 3}
      ]
    }
  ]
}
"#;
	let report = parse(json.as_bytes()).expect("parses");
	assert_eq!(report.failing_count(), 5);
}

/// Unknown top-level fields are dropped, not fatal. RFC 8460 §4.4
/// specifies the schema but reserves room for forward-compatible additions.
#[test]
fn parses_with_unknown_top_level_field() {
	let json = r#"{"organization-name": "x", "date-range": {"start-datetime": "0", "end-datetime": "1"}, "report-id": "r", "future-field": "ignored", "policies": []}"#.to_string();
	let report = parse(json.as_bytes()).expect("unknown field ignored");
	assert_eq!(report.organization_name, "x");
	assert!(report.policies.is_empty());
}

fn report_json(policies: usize, failures: usize, text: &str, keyword: &str) -> String {
	let failure = format!(
		r#"{{"result-type":"{keyword}","sending-mta-ip":"{keyword}","receiving-mx-hostname":"{text}","failed-session-count":1}}"#
	);
	let policy = format!(
		r#"{{"policy-type":"{keyword}","policy-domain":"{text}","summary":{{"total-successful-session-count":0,"total-failure-session-count":0}},"failure-details":[{}]}}"#,
		vec![failure; failures].join(",")
	);
	format!(
		r#"{{"organization-name":"{text}","date-range":{{"start-datetime":"{keyword}","end-datetime":"{keyword}"}},"contact-info":"{text}","report-id":"{text}","policies":[{}]}}"#,
		vec![policy; policies].join(",")
	)
}

#[test]
fn fields_at_their_limits_are_stored_whole() {
	let text = "t".repeat(MAX_TEXT);
	let keyword = "k".repeat(MAX_KEYWORD);
	let report = parse(report_json(1, 1, &text, &keyword).as_bytes()).expect("parses");
	assert_eq!(report.organization_name, text);
	assert_eq!(report.contact_info.as_deref(), Some(text.as_str()));
	assert_eq!(report.report_id, text);
	assert_eq!(report.date_range.start_datetime, keyword);
	assert_eq!(report.date_range.end_datetime, keyword);
	let policy = &report.policies[0];
	assert_eq!(policy.policy_type, keyword);
	assert_eq!(policy.policy_domain, text);
	let failure = &policy.failure_details[0];
	assert_eq!(failure.result_type, keyword);
	assert_eq!(failure.sending_mta_ip, keyword);
	assert_eq!(failure.receiving_mx_hostname, text);
}

#[test]
fn fields_over_their_limits_are_cut() {
	let text = "t".repeat(MAX_TEXT + 1);
	let keyword = "k".repeat(MAX_KEYWORD + 1);
	let report = parse(report_json(1, 1, &text, &keyword).as_bytes()).expect("parses");
	let policy = &report.policies[0];
	let failure = &policy.failure_details[0];
	let text_lengths = [
		report.organization_name.len(),
		report.contact_info.as_deref().map_or(0, str::len),
		report.report_id.len(),
		policy.policy_domain.len(),
		failure.receiving_mx_hostname.len(),
	];
	assert_eq!(text_lengths, [MAX_TEXT; 5]);
	let keyword_lengths = [
		report.date_range.start_datetime.len(),
		report.date_range.end_datetime.len(),
		policy.policy_type.len(),
		failure.result_type.len(),
		failure.sending_mta_ip.len(),
	];
	assert_eq!(keyword_lengths, [MAX_KEYWORD; 5]);
}

#[test]
fn the_policy_limit_is_kept_and_one_more_marks_truncated() {
	let inside = parse(report_json(MAX_POLICIES, 0, "o", "k").as_bytes()).expect("at the cap");
	assert_eq!(inside.policies.len(), MAX_POLICIES);
	assert!(!inside.truncated);
	let over = parse(report_json(MAX_POLICIES + 1, 0, "o", "k").as_bytes()).expect("truncated");
	assert_eq!(over.policies.len(), MAX_POLICIES);
	assert!(over.truncated);
}

#[test]
fn the_failure_detail_limit_is_kept_and_one_more_marks_truncated() {
	let inside =
		parse(report_json(1, MAX_FAILURE_DETAILS, "o", "k").as_bytes()).expect("at the cap");
	assert_eq!(
		inside.policies[0].failure_details.len(),
		MAX_FAILURE_DETAILS
	);
	assert!(!inside.truncated);
	let over =
		parse(report_json(1, MAX_FAILURE_DETAILS + 1, "o", "k").as_bytes()).expect("truncated");
	assert_eq!(over.policies[0].failure_details.len(), MAX_FAILURE_DETAILS);
	assert!(over.truncated);
}

#[test]
fn a_hostile_organisation_name_stays_inside_the_day_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut report = parse(SAMPLE.as_bytes()).expect("parses");
	report.organization_name = "../up/and/out".into();
	append(dir.path(), "20240101", &report).expect("append");
	let day_dir = dir.path().join("reports").join("tlsrpt").join("20240101");
	let written: Vec<_> = std::fs::read_dir(&day_dir)
		.expect("day dir")
		.map(|entry| entry.expect("entry").path())
		.collect();
	assert_eq!(written.len(), 1, "{written:?}");
	assert_eq!(written[0].parent(), Some(day_dir.as_path()));
	assert!(
		!dir.path()
			.join("reports")
			.join("tlsrpt")
			.join("up")
			.exists()
	);
}

#[test]
fn a_failing_count_near_the_integer_limit_saturates() {
	let mut report = parse(SAMPLE.as_bytes()).expect("parses");
	let mut extra = report.policies[0].failure_details[0].clone();
	extra.failed_session_count = u64::MAX;
	report.policies[0].failure_details.push(extra);
	assert_eq!(report.failing_count(), u64::MAX);
}
