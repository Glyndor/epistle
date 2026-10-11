//! Tests for reading the mail container start time. `sh -f <compose>` plays
//! the part of `podup -f <compose> ps ...`: it runs the compose file as a
//! script, so the stub needs no executable file written during the test
//! (writing then executing a file races with other test threads forking).

use std::time::{Duration, Instant};

use super::{mail_started_at, parse_started, started_at_with};

fn stack(dir: &std::path::Path, script: &str) -> std::path::PathBuf {
	let compose = dir.join("compose");
	std::fs::create_dir_all(&compose).expect("compose dir");
	let file = compose.join("compose.yaml");
	std::fs::write(&file, script).expect("compose file");
	file
}

#[test]
fn the_mail_row_start_time_is_read_from_rfc3339_or_epoch() {
	let rfc = r#"[{"Service":"db","StartedAt":"2020-01-01T00:00:00Z"},
		{"Service":"mail","StartedAt":"2026-10-09T08:00:00Z"}]"#;
	assert_eq!(parse_started(rfc), Ok(1_791_532_800));
	let epoch = r#"[{"Service":"mail","StartedAt":1791532800}]"#;
	assert_eq!(parse_started(epoch), Ok(1_791_532_800));
}

#[test]
fn a_missing_field_or_service_is_a_reason_not_a_guess() {
	assert_eq!(
		parse_started(r#"[{"Service":"mail"}]"#),
		Err("podup does not report when the container started".to_string())
	);
	assert_eq!(
		parse_started(r#"[{"Service":"db","StartedAt":"2026-10-09T08:00:00Z"}]"#),
		Err("the mail service is not running".to_string())
	);
	assert!(parse_started("not json").is_err());
}

#[test]
fn without_a_compose_file_the_start_time_is_not_observable() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(mail_started_at(dir.path(), "sh"), Ok(None));
}

#[test]
fn the_start_time_comes_from_the_podup_output() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = stack(
		dir.path(),
		r#"printf '%s' '[{"Service":"mail","StartedAt":"2026-10-09T08:00:00Z"}]'"#,
	);
	assert_eq!(
		started_at_with("sh", &file, Duration::from_secs(5)),
		Ok(1_791_532_800)
	);
}

#[test]
fn a_failing_podup_is_reported() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = stack(dir.path(), "exit 3");
	let error = started_at_with("sh", &file, Duration::from_secs(5)).unwrap_err();
	assert!(error.contains("podup ps exited"), "{error}");
}

#[test]
fn a_hung_podup_is_abandoned_at_the_deadline() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = stack(dir.path(), "exec sleep 30");
	let began = Instant::now();
	let error = started_at_with("sh", &file, Duration::from_millis(200)).unwrap_err();
	assert_eq!(error, "podup ps timed out after 0s");
	assert!(began.elapsed() < Duration::from_secs(5), "waited too long");
}
