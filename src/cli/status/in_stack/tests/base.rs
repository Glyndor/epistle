use super::super::super::report::Level;

/// The verdict printed by `epistle check <area> --json` inside the container
/// is the area's verdict on the host.
#[test]
fn the_container_verdict_is_read_from_check_json() {
	let ok = br#"{"db":{"status":"ok","detail":"SELECT 1 answered","items":[]}}"#;
	let report = super::parse(ok, "db", "database");
	assert_eq!(report.status, Level::Ok);
	assert_eq!(report.detail, "SELECT 1 answered");
	let failed = br#"{"db":{"status":"fail","detail":"cannot reach PostgreSQL","items":[]}}"#;
	assert_eq!(super::parse(failed, "db", "database").status, Level::Fail);
	assert_eq!(
		super::parse(b"podup: no such service", "db", "database").status,
		Level::Fail
	);
}

/// A command that never finishes is killed at the limit instead of hanging
/// `epistle status`.
#[test]
fn a_hung_command_is_killed_at_the_limit() {
	let mut command = std::process::Command::new("sleep");
	command.arg("30");
	let started = std::time::Instant::now();
	let result = super::run_bounded(command, std::time::Duration::from_millis(300), "database");
	assert!(result.is_err(), "a hung command must be reported");
	assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// The antivirus verdict is read from its own key, not the database's.
#[test]
fn the_antivirus_verdict_is_read_from_its_own_key() {
	let ok = br#"{"antivirus":{"status":"ok","detail":"clamd answers","items":[]}}"#;
	assert_eq!(super::parse(ok, "antivirus", "antivirus").status, Level::Ok);
	let wrong_key = br#"{"db":{"status":"ok","detail":"SELECT 1 answered","items":[]}}"#;
	let report = super::parse(wrong_key, "antivirus", "antivirus");
	assert_eq!(report.status, Level::Fail);
	assert_eq!(
		report.detail,
		"the antivirus check in the mail container gave no answer"
	);
}
