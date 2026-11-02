//! The order of a switch, and what a failure puts back.

use super::*;

#[test]
fn turning_on_retires_the_data_dir_key_only_after_both_services_are_up() {
	let mut host = Recorder::with_certs(false);
	assert_eq!(switch(&mut host, true), Ok(Switched::Done));
	assert_eq!(
		host.steps,
		[
			"place true",
			"render true",
			"write certs=true",
			"podup up -d --remove-orphans",
			"ready mail",
			"ready certs",
			"retire",
		]
	);
}

#[test]
fn a_certs_container_that_does_not_come_up_puts_the_stack_back_and_keeps_the_key() {
	let mut host = Recorder::with_certs(false);
	host.fail_ready = Some("certs");
	let error = switch(&mut host, true).expect_err("certs down");
	assert!(error.contains("certs did not come up"), "{error}");
	assert!(error.contains("written back"), "{error}");
	assert!(
		!host.steps.contains(&"retire".to_string()),
		"{:?}",
		host.steps
	);
	assert_eq!(
		host.steps.last().map(String::as_str),
		Some("podup up -d --remove-orphans")
	);
	assert!(!host.compose.contains("certs"), "{}", host.compose);
}

#[test]
fn a_failed_up_puts_the_previous_file_back() {
	let mut host = Recorder::with_certs(false);
	host.fail_podup_once = true;
	let error = switch(&mut host, true).expect_err("podup failed");
	assert!(error.contains("written back"), "{error}");
	assert_eq!(
		&host.steps[host.steps.len() - 2..],
		["write certs=false", "podup up -d --remove-orphans"]
	);
}

#[test]
fn turning_off_puts_the_key_back_before_mail_renews_again() {
	let mut host = Recorder::with_certs(true);
	assert_eq!(switch(&mut host, false), Ok(Switched::Done));
	assert_eq!(
		host.steps,
		[
			"place false",
			"render false",
			"write certs=false",
			"podup up -d --remove-orphans",
			"ready mail",
		]
	);
}

#[test]
fn asking_for_the_layout_that_runs_checks_the_keys_and_changes_nothing() {
	let mut on = Recorder::with_certs(true);
	assert_eq!(switch(&mut on, true), Ok(Switched::AlreadyThere));
	assert_eq!(on.steps, ["place true", "retire"]);
	let mut off = Recorder::with_certs(false);
	assert_eq!(switch(&mut off, false), Ok(Switched::AlreadyThere));
	assert_eq!(off.steps, ["place false"]);
}

#[test]
fn runs_certs_reads_the_service_from_the_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("compose.yaml");
	assert!(!runs_certs(&path), "no file");
	std::fs::write(&path, Recorder::with_certs(true).compose).expect("write");
	assert!(runs_certs(&path));
	std::fs::write(&path, Recorder::with_certs(false).compose).expect("write");
	assert!(!runs_certs(&path));
}
