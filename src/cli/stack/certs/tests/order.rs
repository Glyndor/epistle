//! The order of a switch, and what a failure puts back.

use super::*;

#[test]
fn turning_on_retires_the_data_dir_key_only_after_both_services_are_up() {
	let mut host = Recorder::split_layout(false);
	assert_eq!(switch(&mut host, true), Ok(Switched::Done));
	assert_eq!(
		host.steps,
		[
			"render true",
			"podup stop mail",
			"place true",
			"write certs=true",
			"podup up -d --remove-orphans",
			"ready mail",
			"ready certs",
			"retire",
		]
	);
}

/// `mail` writes data_dir until it runs with the split mounts: it is
/// stopped before the directories `certs` binds are checked, and a stop
/// that fails leaves the keys alone and brings the stack up as it was.
#[test]
fn turning_on_stops_mail_before_the_bound_directories_are_checked() {
	let mut host = Recorder::split_layout(false);
	host.fail = vec!["podup stop mail"];
	let error = switch(&mut host, true).expect_err("stop failed");
	assert!(error.contains("written back"), "{error}");
	assert_eq!(
		host.steps,
		[
			"render true",
			"podup stop mail",
			"write certs=false",
			"podup up -d --remove-orphans",
		]
	);
}

#[test]
fn a_certs_container_that_does_not_come_up_puts_the_stack_back_and_keeps_the_key() {
	let mut host = Recorder::split_layout(false);
	host.fail = vec!["ready certs"];
	let error = switch(&mut host, true).expect_err("certs down");
	assert!(error.contains("ready certs failed"), "{error}");
	assert!(error.contains("written back"), "{error}");
	assert!(
		!host.steps.contains(&"retire".to_string()),
		"the steps say otherwise"
	);
	assert_eq!(
		host.steps.last().map(String::as_str),
		Some("podup up -d --remove-orphans")
	);
	assert!(
		!host.compose.contains("certs"),
		"the compose file says otherwise"
	);
}

#[test]
fn a_failed_up_puts_the_previous_file_back() {
	let mut host = Recorder::split_layout(false);
	host.fail = vec!["podup up"];
	let error = switch(&mut host, true).expect_err("podup failed");
	assert!(error.contains("written back"), "{error}");
	assert_eq!(
		&host.steps[host.steps.len() - 2..],
		["write certs=false", "podup up -d --remove-orphans"]
	);
}

#[test]
fn turning_off_puts_the_key_back_before_mail_renews_again() {
	let mut host = Recorder::split_layout(true);
	assert_eq!(switch(&mut host, false), Ok(Switched::Done));
	assert_eq!(
		host.steps,
		[
			"render false",
			"place false",
			"write certs=false",
			"podup up -d --remove-orphans",
			"ready mail",
		]
	);
}

#[test]
fn asking_for_the_layout_that_runs_checks_the_keys_and_changes_nothing() {
	let mut on = Recorder::split_layout(true);
	assert_eq!(switch(&mut on, true), Ok(Switched::AlreadyThere));
	assert_eq!(on.steps, ["place true", "retire"]);
	let mut off = Recorder::split_layout(false);
	assert_eq!(switch(&mut off, false), Ok(Switched::AlreadyThere));
	assert_eq!(off.steps, ["place false"]);
}

#[test]
fn runs_certs_reads_the_service_from_the_file_and_fails_closed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("compose.yaml");
	assert_eq!(runs_certs(&path), Ok(false), "a host install has no file");
	std::fs::write(&path, Recorder::split_layout(true).compose).expect("write");
	assert_eq!(runs_certs(&path), Ok(true));
	std::fs::write(&path, Recorder::split_layout(false).compose).expect("write");
	assert_eq!(runs_certs(&path), Ok(false));
	std::fs::write(&path, "services: [certs").expect("write");
	let error = runs_certs(&path).expect_err("not the JSON init writes");
	assert!(error.contains("nothing was changed"), "{error}");
}

/// A failed `disable` puts the split back: the copy of the key it placed
/// under data_dir, where `mail` reads, goes again.
#[test]
fn a_failed_disable_removes_the_key_copy_it_placed_for_mail() {
	let mut host = Recorder::split_layout(true);
	host.fail = vec!["ready mail"];
	let error = switch(&mut host, false).expect_err("mail down");
	assert!(error.contains("removed again"), "{error}");
	assert_eq!(
		&host.steps[host.steps.len() - 3..],
		["write certs=true", "podup up -d --remove-orphans", "retire"]
	);
	assert!(
		host.compose.contains("certs"),
		"the compose file says otherwise"
	);
}

/// A failed `enable` puts the whole layout back, where `mail` renews and
/// reads the key under data_dir: that copy stays.
#[test]
fn a_failed_enable_leaves_the_key_mail_renews_with() {
	let mut host = Recorder::split_layout(false);
	host.fail = vec!["ready mail"];
	let error = switch(&mut host, true).expect_err("mail down");
	assert!(error.contains("left in place"), "{error}");
	assert!(
		!host.steps.contains(&"retire".to_string()),
		"the steps say otherwise"
	);
}
