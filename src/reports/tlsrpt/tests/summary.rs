use super::*;

fn report() -> TlsReport {
	parse(br#"{"organization-name":"org","date-range":{"start-datetime":"0","end-datetime":"1"},"report-id":"r","policies":[{"policy":{"policy-type":"sts","policy-domain":"example.org"},"summary":{"total-successful-session-count":0,"total-failure-session-count":3},"failure-details":[{"result-type":"certificate-expired","sending-mta-ip":"192.0.2.1","receiving-mx-hostname":"mx.example.org","failed-session-count":3},{"result-type":"validation-failure","sending-mta-ip":"192.0.2.1","receiving-mx-hostname":"mx.example.org","failed-session-count":3}]}]}"#).expect("valid report")
}

#[test]
fn overlapping_failure_types_count_summary_sessions_once() {
	assert_eq!(
		report().failing_count(),
		3,
		"overlapping failure types must count only the policy summary sessions"
	);
}

#[test]
fn omitted_failure_details_still_count_summary_sessions() {
	let mut report = report();
	report.policies[0].failure_details.clear();
	assert_eq!(
		report.failing_count(),
		3,
		"missing failure details must retain the policy summary session count"
	);
}
