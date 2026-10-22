//! Tests for re-rendering the compose file from an existing one.

use super::regenerate;
use crate::cli::init::answers::DnsAnswers;
use crate::cli::init::apply::listeners_to_write;
use crate::cli::init::compose::{local_image_answers, minimal_answers, render_for, stack_answers};

/// What `init` wrote for `answers`, and what regenerating it gives back.
fn round_trip(answers: &crate::cli::init::Answers) -> (String, String) {
	let written = render_for(answers, answers.services.database).expect("render");
	let listeners = listeners_to_write(answers).expect("listeners");
	let again = regenerate(&answers.data_dir, &listeners, &written).expect("regenerate");
	(written, again.text)
}

#[test]
fn a_current_compose_file_regenerates_byte_for_byte() {
	for answers in [minimal_answers(), stack_answers(), local_image_answers()] {
		let (written, again) = round_trip(&answers);
		assert_eq!(again, written, "image {:?}", answers.image);
	}
}

#[test]
fn the_dns_token_forwarding_survives() {
	let mut answers = stack_answers();
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".into(),
		zone: "example.org".into(),
		token_env: Some("EPI_DNS_TOKEN".into()),
		..Default::default()
	});
	let (written, again) = round_trip(&answers);
	assert_eq!(again, written);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".into(),
		zone: "example.org".into(),
		token_file: Some("/secure/dns/token".into()),
		..Default::default()
	});
	let (written, again) = round_trip(&answers);
	assert_eq!(again, written);
}

#[test]
fn an_older_compose_file_gets_the_current_images_and_services() {
	let answers = stack_answers();
	let current = render_for(&answers, true).expect("render");
	let mut old: serde_json::Value = serde_json::from_str(&current).unwrap();
	old["services"]["clamav"]["image"] = "docker.io/clamav/clamav:1.4".into();
	old["services"].as_object_mut().unwrap().remove("freshclam");
	let old = serde_json::to_string_pretty(&old).unwrap();
	let listeners = listeners_to_write(&answers).unwrap();
	let again = regenerate(&answers.data_dir, &listeners, &old).expect("regenerate");
	assert_eq!(
		again.text, current,
		"the old file is brought to what init writes today"
	);
	assert!(
		again.notes.iter().any(|note| note.contains("compose.yaml")),
		"the operator is told where the inputs came from: {:?}",
		again.notes
	);
}

#[test]
fn the_published_ports_follow_the_config_listeners() {
	let answers = stack_answers();
	let written = render_for(&answers, true).unwrap();
	let again = regenerate(&answers.data_dir, &[], &written).unwrap();
	let value: serde_json::Value = serde_json::from_str(&again.text).unwrap();
	assert_eq!(value["services"]["mail"]["ports"], serde_json::json!([]));
}

#[test]
fn a_file_init_did_not_write_is_refused() {
	let answers = stack_answers();
	for text in ["{}", "not json", "{\"services\": {\"mail\": {}}}"] {
		let error = regenerate(&answers.data_dir, &[], text).expect_err(text);
		assert!(error.contains("compose"), "{error}");
	}
}

#[test]
fn a_running_postgres_major_is_kept_and_the_upgrade_is_named() {
	let answers = stack_answers();
	let current = render_for(&answers, true).unwrap();
	let pinned = crate::cli::init::images::postgres();
	let older = "docker.io/library/postgres:17@sha256:f4c66b820c6f974249089d3d16d86a3698eae11e8746eb6644b2271031e91232";
	let old = current.replace(pinned, older);
	let listeners = listeners_to_write(&answers).unwrap();
	let again = regenerate(&answers.data_dir, &listeners, &old).unwrap();
	let value: serde_json::Value = serde_json::from_str(&again.text).unwrap();
	assert_eq!(
		value["services"]["db"]["image"], older,
		"a new major is never swapped in by a render"
	);
	assert!(
		again
			.notes
			.iter()
			.any(|note| note.contains("epistle db upgrade")),
		"{:?}",
		again.notes
	);
	let same_major = current.replace(
		pinned,
		"docker.io/library/postgres:18@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae",
	);
	let again = regenerate(&answers.data_dir, &listeners, &same_major).unwrap();
	assert_eq!(
		again.text, current,
		"a new digest on the same major is taken"
	);
}

#[test]
fn an_answered_resource_limit_survives() {
	let mut answers = stack_answers();
	answers.resources.insert(
		"mail".to_string(),
		crate::cli::init::resources::ServiceResources {
			memory: None,
			pids: Some(4096),
		},
	);
	let (written, again) = round_trip(&answers);
	assert_eq!(again, written);
	assert!(again.contains("\"pids_limit\": 4096"));
}

#[test]
fn a_compose_file_from_before_the_limits_gets_the_defaults() {
	let answers = stack_answers();
	let written = render_for(&answers, true).expect("render");
	let mut old: serde_json::Value = serde_json::from_str(&written).unwrap();
	for service in old["services"].as_object_mut().unwrap().values_mut() {
		let service = service.as_object_mut().unwrap();
		service.remove("mem_limit");
		service.remove("pids_limit");
	}
	let listeners = listeners_to_write(&answers).expect("listeners");
	let again = regenerate(&answers.data_dir, &listeners, &old.to_string()).expect("regenerate");
	assert_eq!(again.text, written);
}

/// The host address `epistle service set` narrowed one mapping to is the
/// operator's decision, and the file is the only place it lives. A `stack
/// update` re-renders the map from the listeners, so it has to read that
/// address back or the listener returns to every host address.
#[test]
fn a_narrow_published_address_survives_a_regeneration() {
	let answers = stack_answers();
	let written = render_for(&answers, true).expect("render");
	let narrowed = written.replace("\"25:25\"", "\"127.0.0.1:25:25\"");
	assert_ne!(narrowed, written, "the fixture has to carry the mapping");
	let listeners = listeners_to_write(&answers).unwrap();
	let again = regenerate(&answers.data_dir, &listeners, &narrowed).expect("regenerate");
	let value: serde_json::Value = serde_json::from_str(&again.text).unwrap();
	assert_eq!(
		value["services"]["mail"]["ports"][0],
		serde_json::json!("127.0.0.1:25:25"),
		"a regeneration must not widen a mapping back to every host address"
	);
}
