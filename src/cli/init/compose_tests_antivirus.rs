//! A stack without clamav: what `init` writes when `services.antivirus` is
//! off, and what `stack update` keeps.

use super::*;
use serde_json::json;

fn without_antivirus(database: bool) -> crate::cli::init::Answers {
	let mut answers = if database {
		stack_answers()
	} else {
		minimal_answers()
	};
	answers.services.antivirus = Some(false);
	answers
}

#[test]
fn antivirus_off_leaves_clamav_freshclam_and_their_volumes_out() {
	let value = render(&without_antivirus(true), true);
	let services: Vec<&String> = value["services"]
		.as_object()
		.expect("services")
		.keys()
		.collect();
	assert_eq!(services, ["db", "mail"]);
	assert_eq!(value["x-epistle-antivirus"], false);
	let volumes: Vec<&String> = value["volumes"]
		.as_object()
		.expect("volumes")
		.keys()
		.collect();
	assert_eq!(volumes, ["epistle-pgdata", "epistle-pgsock"]);
	let mail = &value["services"]["mail"];
	assert_eq!(
		mail["depends_on"],
		json!({"db": {"condition": "service_healthy"}})
	);
	assert!(
		!mail["volumes"]
			.as_array()
			.expect("volumes")
			.contains(&json!("clamd-socket:/run/clamav")),
		"{}",
		mail["volumes"]
	);
}

#[test]
fn antivirus_off_without_a_database_has_no_dependency_at_all() {
	let value = render(&without_antivirus(false), false);
	assert!(value["services"]["mail"].get("depends_on").is_none());
	assert!(value.get("volumes").is_none(), "{}", value["volumes"]);
}

#[test]
fn stack_update_keeps_clamav_out() {
	let answers = without_antivirus(true);
	let text = render_for(&answers, true).expect("render");
	let again = crate::cli::init::regenerate(&answers.data_dir, &[], &text).expect("regenerate");
	let value: serde_json::Value = serde_json::from_str(&again.text).expect("json");
	assert!(value["services"].get("clamav").is_none());
	assert!(value["services"].get("freshclam").is_none());
	let with = render_for(&stack_answers(), true).expect("render");
	let again = crate::cli::init::regenerate(&answers.data_dir, &[], &with).expect("regenerate");
	let value: serde_json::Value = serde_json::from_str(&again.text).expect("json");
	assert!(
		value["services"].get("clamav").is_some(),
		"a stack with clamav keeps it"
	);
	assert!(value.get("x-epistle-antivirus").is_none());
}

#[test]
fn a_file_from_before_clamav_gets_it_on_update() {
	let answers = stack_answers();
	let mut old: serde_json::Value =
		serde_json::from_str(&render_for(&answers, true).expect("render")).expect("json");
	let services = old["services"].as_object_mut().expect("services");
	services.remove("clamav");
	services.remove("freshclam");
	let again =
		crate::cli::init::regenerate(&answers.data_dir, &[], &old.to_string()).expect("regenerate");
	let value: serde_json::Value = serde_json::from_str(&again.text).expect("json");
	assert!(value["services"]["clamav"].is_object());
	assert!(value["services"]["freshclam"].is_object());
}
