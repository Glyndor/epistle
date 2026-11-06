//! Every way a `disable` can fail after it starts: the copy of the account
//! key it places under data_dir, where `mail` reads, never outlives a split
//! that stays, and when it cannot be removed safely the message names it.

use super::*;

fn disable_failing(steps: Vec<&'static str>) -> (Recorder, String) {
	let mut host = Recorder::split_layout(true);
	host.fail = steps;
	let error = switch(&mut host, false).expect_err("the disable fails");
	(host, error)
}

#[test]
fn a_render_that_fails_places_no_key() {
	let (host, error) = disable_failing(vec!["render"]);
	assert!(error.contains("render false failed"), "{error}");
	assert_eq!(host.steps, ["render false"]);
}

#[test]
fn a_compose_write_that_fails_removes_the_placed_copy() {
	let (host, error) = disable_failing(vec!["write certs=false"]);
	assert_eq!(
		host.steps,
		[
			"render false",
			"place false",
			"write certs=false",
			"write certs=true",
			"podup up -d --remove-orphans",
			"retire",
		]
	);
	assert!(error.contains("removed again"), "{error}");
}

#[test]
fn a_failed_up_removes_the_placed_copy() {
	let (host, error) = disable_failing(vec!["podup"]);
	assert_eq!(host.steps.last().map(String::as_str), Some("retire"));
	assert!(error.contains("/data/acme/account.key"), "{error}");
}

#[test]
fn a_failed_restore_before_the_new_layout_ran_still_removes_the_copy() {
	let (host, error) = disable_failing(vec!["write certs=false", "write certs=true"]);
	assert_eq!(host.steps.last().map(String::as_str), Some("retire"));
	assert!(error.contains("failed as well"), "{error}");
	assert!(error.contains("removed again"), "{error}");
}

/// The layout without `certs` started and could not be replaced: `mail`
/// may be renewing with that copy, so it stays, and the message says where
/// it is and that `mail` can read it.
#[test]
fn a_failed_restore_after_the_new_layout_ran_names_the_copy_to_delete() {
	let (host, error) = disable_failing(vec!["ready mail", "write certs=true"]);
	assert!(
		!host.steps.contains(&"retire".to_string()),
		"the steps say otherwise"
	);
	assert!(error.contains("/data/acme/account.key"), "{error}");
	assert!(error.contains("mail can read it"), "{error}");
}

#[test]
fn a_copy_that_cannot_be_removed_is_named() {
	let (_, error) = disable_failing(vec!["ready mail", "retire"]);
	assert!(error.contains("could not be removed"), "{error}");
	assert!(error.contains("/data/acme/account.key"), "{error}");
}

/// Measured on the Debian 13 machine: a `certs` that exits at start is
/// "running" again a second later, so one look is not enough.
#[test]
fn a_container_that_restarted_between_two_looks_is_not_up() {
	let at = |state: &str, started: &str| {
		format!(
			r#"[{{"Service":"mail","State":"running"}},{{"Service":"certs","State":"{state}","StartedAt":"{started}"}}]"#
		)
	};
	let first = at("running", "2026-11-02T06:30:01Z");
	assert_eq!(steady(&first, &first, "certs"), Ok(()));
	let restarted = at("running", "2026-11-02T06:30:13Z");
	let error = steady(&first, &restarted, "certs").expect_err("restarted");
	assert!(error.contains("did not stay up"), "{error}");
	assert!(steady(&first, &at("exited", "2026-11-02T06:30:01Z"), "certs").is_err());
	assert!(steady(&first, "[]", "certs").is_err());
}

/// A `podup` that answers `ps` with `first` the first time and `second` from
/// the second time on.
fn podup_that_changes(dir: &std::path::Path, first: &str, second: &str) -> String {
	let counter = dir.join("podup.calls").display().to_string();
	let podup = dir.join("podup");
	std::fs::write(
		&podup,
		format!(
			"#!/bin/sh\nn=0\nif [ -f \"{counter}\" ]; then n=$(cat \"{counter}\"); fi\nn=$((n + 1))\n\
			 printf '%s' \"$n\" > \"{counter}\"\nif [ \"$n\" -eq 1 ]; then printf '%s' '{first}'; \
			 else printf '%s' '{second}'; fi\n"
		),
	)
	.expect("podup");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&podup, std::fs::Permissions::from_mode(0o755)).expect("mode");
	podup.display().to_string()
}

fn rows(state: &str, started: &str) -> String {
	format!(
		r#"[{{"Service":"mail","State":"running"}},{{"Service":"certs","State":"{state}","StartedAt":"{started}"}}]"#
	)
}

/// The same rule the switch applies, with the two looks a stub podup
/// answers: a container that restarts between them is not up.
#[test]
fn two_looks_that_disagree_leave_the_container_down() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = dir.path().join("compose.yaml");
	std::fs::write(&compose, "{}").expect("compose");
	let podup = podup_that_changes(
		dir.path(),
		&rows("running", "2026-11-02T06:30:01Z"),
		&rows("running", "2026-11-02T06:30:13Z"),
	);
	let upness = upness(&podup, &compose, "certs", std::time::Duration::ZERO);
	let Upness::Unsteady(text) = upness else {
		panic!("a container that restarted is not up");
	};
	assert!(text.contains("did not stay up"), "{text}");
}

/// A container that keeps the same start in both looks is up.
#[test]
fn two_looks_that_agree_leave_the_container_up() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = dir.path().join("compose.yaml");
	std::fs::write(&compose, "{}").expect("compose");
	let podup = podup_that_changes(
		dir.path(),
		&rows("running", "2026-11-02T06:30:01Z"),
		&rows("running", "2026-11-02T06:30:01Z"),
	);
	assert_eq!(
		upness(&podup, &compose, "certs", std::time::Duration::ZERO),
		Upness::Up
	);
}
