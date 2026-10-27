//! Tests for reading a service's health from `podup ps --format json`.

use super::service_status;

#[test]
fn the_named_service_row_is_read() {
	let json = r#"[{"Service":"db","State":"running","Health":"starting","ExitCode":0},
		{"Service":"mail","State":"running","Health":"healthy","ExitCode":0}]"#;
	assert_eq!(
		service_status(json, "mail"),
		Some(("running".to_string(), "healthy".to_string()))
	);
	assert_eq!(
		service_status(json, "db"),
		Some(("running".to_string(), "starting".to_string()))
	);
	assert_eq!(service_status(json, "clamav"), None);
	assert_eq!(service_status("not json", "mail"), None);
}

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::wait_with_interval;

/// A compose file whose `mail` has a healthcheck and whose `freshclam` has
/// none, the way `epistle init` writes them.
fn compose(dir: &Path) -> PathBuf {
	let path = dir.join("compose.yaml");
	std::fs::write(
		&path,
		r#"{"services":{"mail":{"image":"m","healthcheck":{"test":["CMD","true"]}},
			"freshclam":{"image":"f"},
			"off":{"image":"o","healthcheck":{"disable":true}}}}"#,
	)
	.unwrap();
	path
}

/// A fake `podup` that answers `ps --format json` with the next of
/// `healths` for `service` on each call, then keeps repeating the last one.
fn fake_podup(dir: &Path, service: &str, state: &str, healths: &[&str]) -> String {
	let rows: Vec<String> = healths
		.iter()
		.map(|health| {
			format!(r#"[{{"Service":"{service}","State":"{state}","Health":"{health}"}}]"#)
		})
		.collect();
	for (index, row) in rows.iter().enumerate() {
		std::fs::write(dir.join(format!("ps{index}")), row).unwrap();
	}
	let script = dir.join("podup");
	std::fs::write(
		&script,
		format!(
			"#!/bin/sh\nn=$(cat {dir}/count 2>/dev/null || echo 0)\n\
			 last={last}\n[ \"$n\" -gt \"$last\" ] && n=$last\n\
			 cat {dir}/ps$n\necho $((n + 1)) > {dir}/count\necho \"$*\" >> {dir}/calls\n",
			dir = dir.display(),
			last = rows.len() - 1
		),
	)
	.unwrap();
	std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
	script.display().to_string()
}

fn calls(dir: &Path) -> usize {
	std::fs::read_to_string(dir.join("calls"))
		.unwrap_or_default()
		.lines()
		.count()
}

#[test]
fn an_empty_or_starting_health_keeps_waiting_until_healthy() {
	let dir = tempfile::tempdir().unwrap();
	let podup = fake_podup(dir.path(), "mail", "running", &["", "starting", "healthy"]);
	wait_with_interval(
		&podup,
		&compose(dir.path()),
		"mail",
		Duration::from_secs(20),
		Duration::from_millis(10),
	)
	.unwrap();
	assert_eq!(calls(dir.path()), 3, "it returned only on the third answer");
}

#[test]
fn a_service_that_never_turns_healthy_times_out_naming_what_it_saw() {
	let dir = tempfile::tempdir().unwrap();
	let podup = fake_podup(dir.path(), "mail", "running", &["", "starting"]);
	let error = wait_with_interval(
		&podup,
		&compose(dir.path()),
		"mail",
		Duration::from_millis(300),
		Duration::from_millis(10),
	)
	.unwrap_err();
	assert!(error.contains("starting"), "{error}");
	assert!(calls(dir.path()) > 2);
}

#[test]
fn a_service_without_a_healthcheck_only_has_to_run() {
	let dir = tempfile::tempdir().unwrap();
	for service in ["freshclam", "off"] {
		let podup = fake_podup(dir.path(), service, "running", &[""]);
		std::fs::remove_file(dir.path().join("count")).ok();
		wait_with_interval(
			&podup,
			&compose(dir.path()),
			service,
			Duration::from_secs(5),
			Duration::from_millis(10),
		)
		.unwrap_or_else(|error| panic!("{service}: {error}"));
	}
	let podup = fake_podup(dir.path(), "freshclam", "created", &[""]);
	std::fs::remove_file(dir.path().join("count")).ok();
	assert!(
		wait_with_interval(
			&podup,
			&compose(dir.path()),
			"freshclam",
			Duration::from_millis(200),
			Duration::from_millis(10)
		)
		.is_err(),
		"a service that is not running is not ready"
	);
}
