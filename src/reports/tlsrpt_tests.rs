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
	let json = format!(
		r#"{{"organization-name": "x", "date-range": {{"start-datetime": "0", "end-datetime": "1"}}, "report-id": "r", "future-field": "ignored", "policies": []}}"#
	);
	let report = parse(json.as_bytes()).expect("unknown field ignored");
	assert_eq!(report.organization_name, "x");
	assert!(report.policies.is_empty());
}
