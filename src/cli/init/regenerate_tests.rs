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
