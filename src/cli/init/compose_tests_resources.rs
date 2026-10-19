//! Memory and process limits of the generated services, and the answers
//! that override them.

use super::render;
use super::services::{host_hard_nofile, mail_nofile};
use super::*;
use crate::cli::init::resources::ServiceResources;
use serde_json::json;

fn limits(value: &serde_json::Value, service: &str) -> (serde_json::Value, serde_json::Value) {
	let service = &value["services"][service];
	(service["mem_limit"].clone(), service["pids_limit"].clone())
}

#[test]
fn every_service_has_a_memory_and_a_process_limit() {
	let value = render(&stack_answers(), true);
	assert_eq!(limits(&value, "mail"), (json!("1g"), json!(1024)));
	assert_eq!(limits(&value, "db"), (json!("1g"), json!(256)));
	assert_eq!(limits(&value, "clamav"), (json!("3g"), json!(128)));
	assert_eq!(limits(&value, "freshclam"), (json!("2g"), json!(32)));
	assert!(
		value.get("x-epistle-resources").is_none(),
		"no override was answered, so none is recorded"
	);
}

#[test]
fn an_answer_overrides_one_value_of_one_service() {
	let mut answers = stack_answers();
	answers.resources.insert(
		"clamav".to_string(),
		ServiceResources {
			memory: Some("4g".to_string()),
			pids: None,
		},
	);
	let value = render(&answers, true);
	assert_eq!(limits(&value, "clamav"), (json!("4g"), json!(128)));
	assert_eq!(limits(&value, "mail"), (json!("1g"), json!(1024)));
	assert_eq!(
		value["x-epistle-resources"],
		json!({"clamav": {"memory": "4g"}}),
		"stack update reads the override back from here; init does not keep its answers"
	);
}

fn nofile_in(nofile: Option<u64>) -> serde_json::Value {
	let answers = stack_answers();
	let file = ComposeFile::build_with_nofile(&answers, Vec::new(), true, nofile);
	let value: serde_json::Value =
		serde_json::from_str(&render_document(&file).expect("render")).expect("parse");
	value["services"]["mail"]["ulimits"].clone()
}

#[test]
fn the_mail_service_raises_its_open_file_limit() {
	let value = render(&stack_answers(), true);
	let expected = mail_nofile(host_hard_nofile());
	assert_eq!(
		value["services"]["mail"].get("ulimits").is_some(),
		expected.is_some()
	);
	assert_eq!(nofile_in(Some(65536)), json!({"nofile": 65536}));
	for name in ["db", "clamav", "freshclam"] {
		assert!(
			value["services"][name].get("ulimits").is_none(),
			"{name} opens few files and keeps the default"
		);
	}
}

#[test]
fn the_request_follows_the_hard_limit_of_the_host() {
	// Podman cannot start a container above the hard limit of its user.
	assert_eq!(mail_nofile(None), Some(65_536));
	assert_eq!(mail_nofile(Some(524_288)), Some(65_536));
	assert_eq!(mail_nofile(Some(65_536)), Some(65_536));
	assert_eq!(mail_nofile(Some(4_096)), Some(4_096));
	assert_eq!(mail_nofile(Some(1_024)), None);
	assert_eq!(nofile_in(mail_nofile(Some(4_096))), json!({"nofile": 4096}));
	assert!(nofile_in(mail_nofile(Some(1_024))).is_null());
}
