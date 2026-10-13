//! Tests for planning `stack update` against compose files `epistle init`
//! wrote, current and older.

use super::{Step, plan_update};
use crate::cli::init::rendered_for_tests;
use crate::config::Listener;

/// The listeners `stack_answers` gives a fresh install.
fn listeners() -> Vec<Listener> {
	let text = rendered_for_tests(std::path::Path::new("/var/lib/epistle"), None);
	let value: serde_json::Value = serde_json::from_str(&text).unwrap();
	value["services"]["mail"]["ports"]
		.as_array()
		.unwrap()
		.iter()
		.map(|port| {
			let port: u16 = port
				.as_str()
				.unwrap()
				.split(':')
				.next()
				.unwrap()
				.parse()
				.unwrap();
			let kind = match port {
				25 => "smtp",
				143 => "imap",
				993 => "imaps",
				587 => "submission",
				465 => "submissions",
				_ => "acme",
			};
			toml::from_str(&format!(
				"kind = \"{kind}\"\naddr = \"0.0.0.0\"\nport = {port}\n"
			))
			.unwrap()
		})
		.collect()
}

/// Write `text` as the compose file of a data directory and plan an update.
fn plan(text: &str) -> (tempfile::TempDir, Result<super::UpdatePlan, String>) {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compose.yaml");
	std::fs::write(&path, text).unwrap();
	let plan = plan_update(
		&path,
		std::path::Path::new("/var/lib/epistle"),
		&listeners(),
	);
	(dir, plan)
}

fn steps(parts: &[&[&str]]) -> Vec<Step> {
	parts
		.iter()
		.map(|step| Step(step.iter().map(|part| part.to_string()).collect()))
		.collect()
}

#[test]
fn a_current_file_is_left_alone_and_mail_restarts_on_the_new_binary() {
	let current = rendered_for_tests(std::path::Path::new("/var/lib/epistle"), None);
	let (_dir, plan) = plan(&current);
	let plan = plan.expect("plan");
	assert!(plan.rewrite.is_none(), "{:?}", plan.diff);
	assert_eq!(plan.steps, steps(&[&["up", "-d"], &["restart", "mail"]]));
}

#[test]
fn an_older_file_is_rewritten_and_the_change_is_shown() {
	let current = rendered_for_tests(std::path::Path::new("/var/lib/epistle"), None);
	let old = current.replace(
		&format!("\"{}\"", crate::cli::init::images::clamav()),
		"\"docker.io/clamav/clamav:1.4\"",
	);
	assert_ne!(old, current, "the fixture must differ");
	let (_dir, plan) = plan(&old);
	let plan = plan.expect("plan");
	assert_eq!(plan.rewrite.as_deref(), Some(current.as_str()));
	assert!(
		plan.diff
			.iter()
			.any(|line| line.starts_with('-') && line.contains("clamav:1.4\""))
			&& plan
				.diff
				.iter()
				.any(|line| line.starts_with('+') && line.contains("@sha256:")),
		"{:?}",
		plan.diff
	);
	assert!(!plan.notes.is_empty());
	assert_eq!(
		plan.steps,
		steps(&[&["up", "-d"], &["restart", "mail"]]),
		"mail itself did not change, so it is restarted for the new binary"
	);
}

#[test]
fn a_changed_mail_service_is_recreated_by_up_alone() {
	let current = rendered_for_tests(std::path::Path::new("/var/lib/epistle"), None);
	let old = current.replace("\"interval\": \"30s\"", "\"interval\": \"60s\"");
	assert_ne!(old, current);
	let (_dir, plan) = plan(&old);
	assert_eq!(plan.expect("plan").steps, steps(&[&["up", "-d"]]));
}

#[test]
fn a_custom_image_is_pulled_before_up() {
	let custom = rendered_for_tests(
		std::path::Path::new("/var/lib/epistle"),
		Some("ghcr.io/example/mail:0.9.1"),
	);
	let (_dir, plan) = plan(&custom);
	let plan = plan.expect("plan");
	assert!(plan.rewrite.is_none());
	assert_eq!(plan.steps, steps(&[&["pull"], &["up", "-d"]]));
}

#[test]
fn unreadable_or_foreign_files_are_refused() {
	for text in [
		"not json at all",
		"{\"name\":\"epistle\",\"services\":{\"mail\":{\"image\":\"x\"}}}",
	] {
		let (_dir, plan) = plan(text);
		assert!(plan.is_err(), "{text}");
	}
	let dir = tempfile::tempdir().unwrap();
	let missing = dir.path().join("absent.yaml");
	assert!(plan_update(&missing, dir.path(), &[]).is_err());
}
