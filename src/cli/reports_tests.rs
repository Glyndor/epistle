//! Tests for `mail reports`.

use super::*;
use crate::reports::dmarc::{DateRange, DmarcReport, PolicyPublished, Row};
use crate::reports::tlsrpt::{DateRange as TlsDateRange, Policy, Summary, TlsReport};
use std::io::Write;

fn dmarc_row(source_ip: &str, count: u64, dkim: &str, spf: &str, disp: &str) -> Row {
	Row {
		source_ip: source_ip.into(),
		count,
		disposition: disp.into(),
		dkim: dkim.into(),
		spf: spf.into(),
		header_from: "example.org".into(),
	}
}

fn google_report() -> DmarcReport {
	DmarcReport {
		org_name: "google.com".into(),
		email: Some("noreply@google.com".into()),
		report_id: "rid-1".into(),
		date_range: DateRange {
			begin: 1704067200,
			end: 1704153600,
		},
		policy_published: PolicyPublished {
			domain: "example.org".into(),
			p: "reject".into(),
			sp: Some("reject".into()),
			pct: 100,
		},
		records: vec![
			dmarc_row("209.85.220.41", 5, "pass", "pass", "none"),
			dmarc_row("203.0.113.7", 3, "fail", "fail", "reject"),
		],
		truncated: false,
	}
}

fn tlsrpt_report() -> TlsReport {
	TlsReport {
		organization_name: "google.com".into(),
		date_range: TlsDateRange {
			start_datetime: "2024-01-01T00:00:00Z".into(),
			end_datetime: "2024-01-02T00:00:00Z".into(),
		},
		contact_info: None,
		report_id: "rid-2".into(),
		policies: vec![Policy {
			policy_type: "sts".into(),
			policy_domain: "example.org".into(),
			summary: Summary {
				total_successful_session_count: 8,
				total_failure_session_count: 2,
			},
			failure_details: vec![crate::reports::tlsrpt::Failure {
				result_type: "starttls-not-supported".into(),
				sending_mta_ip: "192.0.2.10".into(),
				receiving_mx_hostname: "mx.example.org".into(),
				failed_session_count: 2,
			}],
		}],
		truncated: false,
	}
}

/// Build a tempdir, write one DMARC and one TLS-RPT report for today, and
/// return the path plus the captured stdout.
fn fixture_with_reports() -> (tempfile::TempDir, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let today = crate::dmarc::aggregate::unix_to_day(
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs(),
	);
	let dmarc_dir = dir.path().join("reports").join("dmarc").join(&today);
	std::fs::create_dir_all(&dmarc_dir).expect("mkdir");
	let line = serde_json::to_string(&google_report()).expect("ser");
	let path = dmarc_dir.join("google.com.jsonl");
	std::fs::write(&path, format!("{line}\n")).expect("write");

	let tlsrpt_dir = dir.path().join("reports").join("tlsrpt").join(&today);
	std::fs::create_dir_all(&tlsrpt_dir).expect("mkdir");
	let line = serde_json::to_string(&tlsrpt_report()).expect("ser");
	let path = tlsrpt_dir.join("google.com.jsonl");
	std::fs::write(&path, format!("{line}\n")).expect("write");

	let mut out = Vec::new();
	let cfg = load_test_config(dir.path());
	let _ = run(&cfg, DEFAULT_DAYS, &mut out);
	(dir, String::from_utf8(out).expect("utf8"))
}

fn load_test_config(data_dir: &std::path::Path) -> crate::config::Config {
	let mut file = tempfile::NamedTempFile::new().expect("temp config");
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		data_dir
	)
	.expect("write config");
	crate::config::Config::load(file.path()).expect("valid config")
}

/// Top failing source_ips appear in the output, sorted by descending count.
#[test]
fn reports_summarises_failing_rows_by_source_ip() {
	let (_dir, output) = fixture_with_reports();
	assert!(output.contains("DMARC aggregate reports"), "{output}");
	assert!(output.contains("TLS-RPT reports"), "{output}");
	// Failing DMARC source IP (3 failed rows) appears.
	assert!(output.contains("203.0.113.7"), "{output}");
	// The passing IP does not appear in the failing list.
	assert!(!output.contains("209.85.220.41"), "{output}");
	// TLS-RPT failing mta_ip appears.
	assert!(output.contains("192.0.2.10"), "{output}");
	// The policy domain is reported.
	assert!(output.contains("example.org"), "{output}");
}

/// A report older than the requested window is excluded.
#[test]
fn older_than_the_window_is_skipped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let old_day = "20200101";
	let dmarc_dir = dir.path().join("reports").join("dmarc").join(old_day);
	std::fs::create_dir_all(&dmarc_dir).expect("mkdir");
	let line = serde_json::to_string(&google_report()).expect("ser");
	std::fs::write(dmarc_dir.join("google.com.jsonl"), format!("{line}\n")).expect("write");

	let mut out = Vec::new();
	let cfg = load_test_config(dir.path());
	let _ = run(&cfg, DEFAULT_DAYS, &mut out);
	let output = String::from_utf8(out).expect("utf8");
	assert!(
		!output.contains("203.0.113.7"),
		"old report must be excluded: {output}"
	);
	// Header still prints so the operator sees the bucket exists.
	assert!(output.contains("DMARC aggregate reports"), "{output}");
	// Empty domain list.
	assert!(output.contains("(no reports yet)"), "{output}");
}

/// When no reports directory exists at all, the command exits success and
/// still prints a header per kind.
#[test]
fn no_reports_directory_yet_is_empty_summary() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut out = Vec::new();
	let cfg = load_test_config(dir.path());
	let code = run(&cfg, DEFAULT_DAYS, &mut out);
	assert_eq!(code, ExitCode::SUCCESS);
	let output = String::from_utf8(out).expect("utf8");
	assert!(output.contains("DMARC aggregate reports"), "{output}");
	assert!(output.contains("TLS-RPT reports"), "{output}");
}

#[test]
fn top_n_sorts_by_descending_count() {
	let mut m = HashMap::new();
	m.insert("a".into(), 5u64);
	m.insert("b".into(), 10u64);
	m.insert("c".into(), 3u64);
	let v = top_n(&m);
	assert_eq!(v[0].0, "b");
	assert_eq!(v[1].0, "a");
	assert_eq!(v[2].0, "c");
}

#[test]
fn failing_count_filters_passing_dmarc_rows() {
	let agg = Aggregate {
		domain: "example.org".into(),
		reporters: ["google.com".into()].into_iter().collect(),
		total_rows: 0,
		failing_by_ip: HashMap::new(),
		failing_by_result: HashMap::new(),
	};
	let mut agg = agg;
	let mut report = google_report();
	agg.add_dmarc(&report);
	assert_eq!(agg.total_rows, 8);
	assert_eq!(agg.failing_by_ip.len(), 1);
	assert_eq!(agg.failing_by_ip.get("203.0.113.7"), Some(&3));

	// An all-pass row contributes zero to failing_by_ip.
	report.records = vec![dmarc_row("198.51.100.1", 4, "pass", "pass", "none")];
	agg.add_dmarc(&report);
	assert_eq!(agg.total_rows, 12);
	assert_eq!(agg.failing_by_ip.len(), 1);
}

#[test]
fn failing_count_aggregates_tlsrpt_sessions() {
	let mut agg = Aggregate::default();
	agg.add_tlsrpt(&tlsrpt_report());
	assert_eq!(agg.domain, "example.org");
	assert_eq!(agg.failing_by_ip.get("192.0.2.10"), Some(&2));
	assert_eq!(
		agg.failing_by_result.get("starttls-not-supported"),
		Some(&2)
	);
}
